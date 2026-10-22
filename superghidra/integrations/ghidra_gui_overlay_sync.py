"""
Interactive Ghidra GUI Overlay Sync Bridge for SuperGhidra.
============================================================

Bridges agent mutations (stored in `ghidra_overlay.json` or `.ghidra-delta.jsonl`)
into the interactive Ghidra GUI and Headless Ghidra environments.

Features:
- Ingests `ghidra_overlay.json` or `.ghidra-delta.jsonl` mutation streams.
- Generates executable Ghidra Python scripts (compatible with Ghidra Script Manager
  and FlatProgramAPI).
- Wraps mutations in an atomic transaction: `currentProgram.startTransaction(...)`.
- Produces clean summary diff reports grouped by target address / RVA.
- Provides a CLI interface (`sync_to_script`).
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union

logger = logging.getLogger("SuperGhidra.OverlaySync")


def normalize_address_key(addr_val: Any) -> str:
    """Normalize numeric, hex string, or decimal address representation into '0x<HEX>'."""
    if isinstance(addr_val, int):
        return f"0x{addr_val:X}"
    s = str(addr_val).strip()
    if s.startswith("0x") or s.startswith("0X"):
        try:
            return f"0x{int(s, 16):X}"
        except ValueError:
            return s.upper()
    try:
        val = int(s, 16) if any(c in "abcdefABCDEF" for c in s) else int(s, 10)
        return f"0x{val:X}"
    except ValueError:
        return s


class OverlaySyncBridge:
    """
    Bridge between SuperGhidra write overlays / delta event streams and Ghidra GUI scripts.
    """

    def __init__(
        self,
        overlay_source: Optional[Union[str, Path, Dict[str, Any], List[Dict[str, Any]]]] = None,
    ):
        self.overlay_data: Dict[str, Any] = {
            "renames": {},
            "comments": {},
            "prototypes": {},
            "types": {},
            "structs": [],
        }
        if overlay_source is not None:
            self.load(overlay_source)

    def load(
        self, source: Union[str, Path, Dict[str, Any], List[Dict[str, Any]]]
    ) -> Dict[str, Any]:
        """
        Load overlay definitions from a filepath (JSON or JSONL), an in-memory dict,
        or a list of delta events.
        """
        if isinstance(source, (str, Path)):
            p = Path(source)
            if not p.is_file():
                raise FileNotFoundError(f"Overlay source file not found: {p}")

            text = p.read_text(encoding="utf-8").strip()
            if not text:
                return self.overlay_data

            if p.suffix.lower() == ".jsonl" or "\n" in text and not text.startswith("{"):
                # Parse as JSON Lines (.ghidra-delta.jsonl)
                events = []
                for line in text.splitlines():
                    line = line.strip()
                    if line:
                        try:
                            events.append(json.loads(line))
                        except json.JSONDecodeError as err:
                            logger.warning(f"Skipping malformed delta event line: {err}")
                self._ingest_delta_events(events)
            else:
                try:
                    data = json.loads(text)
                    if isinstance(data, list):
                        self._ingest_delta_events(data)
                    elif isinstance(data, dict):
                        self._ingest_dict(data)
                except json.JSONDecodeError as e:
                    raise ValueError(f"Failed to parse overlay JSON from {p}: {e}")
        elif isinstance(source, dict):
            self._ingest_dict(source)
        elif isinstance(source, list):
            self._ingest_delta_events(source)
        else:
            raise TypeError(f"Unsupported overlay source type: {type(source)}")

        return self.overlay_data

    def _ingest_dict(self, data: Dict[str, Any]) -> None:
        """Ingest standard WriteOverlay dictionary format."""
        for addr, name in data.get("renames", {}).items():
            k = normalize_address_key(addr)
            self.overlay_data["renames"][k] = name

        for addr, comment in data.get("comments", {}).items():
            k = normalize_address_key(addr)
            if isinstance(comment, dict):
                self.overlay_data["comments"][k] = {
                    "text": comment.get("text") or comment.get("comment", ""),
                    "type": comment.get("type") or comment.get("comment_type", "PLATE"),
                }
            else:
                self.overlay_data["comments"][k] = {
                    "text": str(comment),
                    "type": "PLATE",
                }

        for addr, proto in data.get("prototypes", {}).items():
            k = normalize_address_key(addr)
            self.overlay_data["prototypes"][k] = proto

        for addr, t_name in data.get("types", {}).items():
            k = normalize_address_key(addr)
            self.overlay_data["types"][k] = t_name

        if "structs" in data and isinstance(data["structs"], list):
            self.overlay_data["structs"].extend(data["structs"])

    def _ingest_delta_events(self, events: List[Dict[str, Any]]) -> None:
        """Ingest append-only .ghidra-delta.jsonl events."""
        for evt in events:
            evt_type = evt.get("event_type", "")
            target_addr = evt.get("target_address")
            target_sym = evt.get("target_symbol")
            payload = evt.get("payload", {})

            addr_key = normalize_address_key(target_addr) if target_addr is not None else None

            if evt_type == "RenameSymbol":
                new_name = payload.get("new_name") or target_sym
                if addr_key and new_name:
                    self.overlay_data["renames"][addr_key] = new_name
            elif evt_type == "SetComment":
                cmt_text = payload.get("comment", "")
                cmt_type = payload.get("comment_type", "PLATE")
                if addr_key and cmt_text:
                    self.overlay_data["comments"][addr_key] = {
                        "text": cmt_text,
                        "type": cmt_type,
                    }
            elif evt_type == "SetFunctionSignature":
                proto = payload.get("prototype")
                if addr_key and proto:
                    self.overlay_data["prototypes"][addr_key] = proto
            elif evt_type == "DefineStructField":
                self.overlay_data["structs"].append(payload)
            elif evt_type in ("SetType", "SetVariableType"):
                type_name = payload.get("type") or payload.get("type_name")
                if addr_key and type_name:
                    self.overlay_data["types"][addr_key] = type_name

    def generate_diff_report(self, overlay_data: Optional[Dict[str, Any]] = None) -> str:
        """
        Generates a summary diff report showing pending changes grouped by RVA/Address.
        """
        data = overlay_data if overlay_data is not None else self.overlay_data

        renames: Dict[str, str] = data.get("renames", {})
        comments: Dict[str, Any] = data.get("comments", {})
        prototypes: Dict[str, str] = data.get("prototypes", {})
        types: Dict[str, str] = data.get("types", {})
        structs: List[Dict[str, Any]] = data.get("structs", [])

        # Collect all unique addresses and sort numerically when possible
        all_addresses = set(renames.keys()) | set(comments.keys()) | set(prototypes.keys()) | set(types.keys())

        def _sort_key(a: str) -> int:
            try:
                return int(a, 16) if a.startswith("0x") or a.startswith("0X") else int(a)
            except ValueError:
                return 0

        sorted_addresses = sorted(all_addresses, key=_sort_key)

        lines: List[str] = [
            "=" * 78,
            "SUPERGHIDRA WRITE-OVERLAY SUMMARY DIFF REPORT",
            "=" * 78,
            f"Total Target Addresses: {len(sorted_addresses)}",
            f"Total Symbol Renames:   {len(renames)}",
            f"Total Comments:         {len(comments)}",
            f"Total Function Protos:  {len(prototypes)}",
            f"Total Type Assignments: {len(types)}",
            f"Total Struct Fields:    {len(structs)}",
            "-" * 78,
        ]

        if not sorted_addresses and not structs:
            lines.append("No pending mutations in write overlay.")
            lines.append("=" * 78)
            return "\n".join(lines)

        for addr in sorted_addresses:
            lines.append(f"[{addr}]")
            if addr in renames:
                lines.append(f"  + Symbol Rename : {renames[addr]}")
            if addr in prototypes:
                lines.append(f"  + Prototype     : {prototypes[addr]}")
            if addr in types:
                lines.append(f"  + Type Binding  : {types[addr]}")
            if addr in comments:
                c_val = comments[addr]
                if isinstance(c_val, dict):
                    c_text = c_val.get("text", "")
                    c_type = c_val.get("type", "PLATE")
                    lines.append(f"  + Comment ({c_type}): {c_text}")
                else:
                    lines.append(f"  + Comment (PLATE): {c_val}")
            lines.append("")

        if structs:
            lines.append("-" * 78)
            lines.append("STRUCT FIELD DEFINITIONS:")
            for st in structs:
                s_name = st.get("struct_name", "UnknownStruct")
                f_name = st.get("field_name", "field")
                offset = st.get("offset", 0)
                f_type = st.get("field_type", "void*")
                lines.append(f"  * {s_name} +0x{offset:X}: {f_type} {f_name}")
            lines.append("")

        lines.append("=" * 78)
        return "\n".join(lines)

    def generate_ghidra_python_script(
        self,
        overlay_data: Optional[Dict[str, Any]] = None,
        dry_run: bool = False,
    ) -> str:
        """
        Generates an executable Ghidra Python script (Jython / PyGhidra compatible).
        Uses Ghidra FlatProgramAPI, Listing, and SymbolTable wrapped in an atomic transaction.
        """
        data = overlay_data if overlay_data is not None else self.overlay_data

        serialized_data = json.dumps(data, indent=2)

        script = f'''# SuperGhidra Generated Overlay Synchronizer Script
# @category SuperGhidra
# @menupath Tools.SuperGhidra.Apply Overlay
# @toolbar
#
# Generated automatically by SuperGhidra OverlaySyncBridge.
# Applies write-overlay symbols, comments, and prototypes to currentProgram.

from __future__ import print_function
import sys

# Ghidra imports
try:
    from ghidra.program.model.symbol import SourceType
    from ghidra.program.model.listing import CodeUnit
except ImportError:
    SourceType = None
    CodeUnit = None

OVERLAY_DATA = {serialized_data}
DRY_RUN = {repr(dry_run)}


def _resolve_address(prog, addr_str):
    """Resolve an address string into a Ghidra Address object."""
    try:
        # Check FlatProgramAPI toAddr
        if "toAddr" in globals():
            return toAddr(addr_str)
    except Exception:
        pass
    addr_factory = prog.getAddressFactory()
    default_space = addr_factory.getDefaultAddressSpace()
    val = int(addr_str, 16) if addr_str.startswith("0x") or addr_str.startswith("0X") else int(addr_str)
    return default_space.getAddress(val)


def _apply_overlay(prog, data, dry_run=False):
    """Applies overlay data to currentProgram within an atomic transaction."""
    listing = prog.getListing()
    sym_table = prog.getSymbolTable()

    renames = data.get("renames", {{}})
    comments = data.get("comments", {{}})
    prototypes = data.get("prototypes", {{}})
    types = data.get("types", {{}})

    total_mutations = len(renames) + len(comments) + len(prototypes) + len(types)
    print("[SuperGhidra] Beginning overlay sync (dry_run=%s, total_mutations=%d)..." % (dry_run, total_mutations))

    applied_renames = 0
    applied_comments = 0
    applied_prototypes = 0
    applied_types = 0

    tx_id = prog.startTransaction("SuperGhidra Overlay Sync")
    success = False
    try:
        # 1. Apply Symbol Renames
        for addr_str, new_name in renames.items():
            try:
                addr = _resolve_address(prog, addr_str)
                if not addr:
                    print("[SuperGhidra] Warning: Unresolved address %s" % addr_str)
                    continue

                if dry_run:
                    print("[SuperGhidra] [DRY RUN] Rename %s -> %s" % (addr_str, new_name))
                else:
                    fn = listing.getFunctionAt(addr)
                    if fn is not None:
                        if SourceType is not None:
                            fn.setName(new_name, SourceType.USER_DEFINED)
                        else:
                            fn.setName(new_name, 1)
                    else:
                        if "createLabel" in globals():
                            createLabel(addr, new_name, True)
                        elif SourceType is not None:
                            sym_table.createLabel(addr, new_name, SourceType.USER_DEFINED)
                        else:
                            sym_table.createLabel(addr, new_name, 1)
                applied_renames += 1
            except Exception as e:
                print("[SuperGhidra] Error renaming %s to %s: %s" % (addr_str, new_name, e))

        # 2. Apply Comments
        comment_type_map = {{
            "EOL": getattr(CodeUnit, "EOL_COMMENT", 0) if CodeUnit else 0,
            "PRE": getattr(CodeUnit, "PRE_COMMENT", 1) if CodeUnit else 1,
            "POST": getattr(CodeUnit, "POST_COMMENT", 2) if CodeUnit else 2,
            "PLATE": getattr(CodeUnit, "PLATE_COMMENT", 3) if CodeUnit else 3,
            "REPEATABLE": getattr(CodeUnit, "REPEATABLE_COMMENT", 4) if CodeUnit else 4,
        }}

        for addr_str, c_val in comments.items():
            try:
                addr = _resolve_address(prog, addr_str)
                if not addr:
                    continue

                if isinstance(c_val, dict):
                    c_text = c_val.get("text", "")
                    c_type_str = c_val.get("type", "PLATE").upper()
                else:
                    c_text = str(c_val)
                    c_type_str = "PLATE"

                code_unit_id = comment_type_map.get(c_type_str, comment_type_map["PLATE"])

                if dry_run:
                    print("[SuperGhidra] [DRY RUN] Set %s Comment %s: %s" % (c_type_str, addr_str, c_text))
                else:
                    # Prefer FlatProgramAPI setComment or listing.setComment
                    if "setComment" in globals() and c_type_str == "PLATE":
                        setComment(addr, c_text)
                    else:
                        listing.setComment(addr, code_unit_id, c_text)
                applied_comments += 1
            except Exception as e:
                print("[SuperGhidra] Error setting comment at %s: %s" % (addr_str, e))

        # 3. Apply Prototypes & Function Signatures
        for addr_str, proto in prototypes.items():
            try:
                addr = _resolve_address(prog, addr_str)
                if not addr:
                    continue

                if dry_run:
                    print("[SuperGhidra] [DRY RUN] Set Prototype %s: %s" % (addr_str, proto))
                else:
                    fn = listing.getFunctionAt(addr)
                    if fn is not None:
                        # Append prototype to function repeatable/plate comment for reference
                        existing = fn.getComment() or ""
                        if proto not in existing:
                            new_cmt = (existing + "\\n[Prototype] " + proto).strip()
                            fn.setComment(new_cmt)
                applied_prototypes += 1
            except Exception as e:
                print("[SuperGhidra] Error setting prototype at %s: %s" % (addr_str, e))

        # 4. Apply Types
        for addr_str, type_name in types.items():
            try:
                addr = _resolve_address(prog, addr_str)
                if not addr:
                    continue
                if dry_run:
                    print("[SuperGhidra] [DRY RUN] Set Type %s: %s" % (addr_str, type_name))
                else:
                    fn = listing.getFunctionAt(addr)
                    if fn is not None:
                        existing = fn.getComment() or ""
                        new_cmt = (existing + "\\n[Type] " + type_name).strip()
                        fn.setComment(new_cmt)
                applied_types += 1
            except Exception as e:
                print("[SuperGhidra] Error setting type at %s: %s" % (addr_str, e))

        success = True
    finally:
        commit = success and not dry_run
        prog.endTransaction(tx_id, commit)
        status_word = "Applied" if commit else ("Rolled back (dry run)" if dry_run else "Rolled back (failure)")
        print("[SuperGhidra] Transaction %s: %d renames, %d comments, %d prototypes, %d types." % (
            status_word, applied_renames, applied_comments, applied_prototypes, applied_types
        ))


def run():
    if "currentProgram" not in globals() or currentProgram is None:
        print("[SuperGhidra] Error: currentProgram is not available in environment.", file=sys.stderr)
        return
    _apply_overlay(currentProgram, OVERLAY_DATA, dry_run=DRY_RUN)


if __name__ == "__main__" or "currentProgram" in globals():
    run()
'''
        return script

    def sync_to_script(
        self,
        overlay_path: Optional[str] = None,
        out_path: Optional[str] = None,
        dry_run: bool = False,
    ) -> str:
        """
        Ingests overlay from overlay_path (if provided) and generates the Ghidra Python sync script.
        Writes to out_path if given.
        """
        if overlay_path is not None:
            self.load(overlay_path)

        script = self.generate_ghidra_python_script(dry_run=dry_run)

        if out_path:
            p = Path(out_path)
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(script, encoding="utf-8")
            logger.info(f"Generated Ghidra sync script written to {p}")

        return script


# ------------------------------------------------------------------------------
# Module-level convenience functions
# ------------------------------------------------------------------------------

def generate_ghidra_python_script(overlay_data: Dict[str, Any], dry_run: bool = False) -> str:
    """Convenience wrapper to generate Ghidra sync script from overlay dict."""
    bridge = OverlaySyncBridge(overlay_data)
    return bridge.generate_ghidra_python_script(dry_run=dry_run)


def generate_diff_report(overlay_data: Dict[str, Any]) -> str:
    """Convenience wrapper to generate diff summary report from overlay dict."""
    bridge = OverlaySyncBridge(overlay_data)
    return bridge.generate_diff_report()


def sync_to_script(
    overlay_path: str,
    out_path: Optional[str] = None,
    dry_run: bool = False,
) -> str:
    """Convenience wrapper to sync overlay file to a Ghidra Python script."""
    bridge = OverlaySyncBridge()
    return bridge.sync_to_script(overlay_path=overlay_path, out_path=out_path, dry_run=dry_run)
