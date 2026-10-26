"""
Interactive Ghidra GUI Overlay Sync Bridge for SuperGhidra.
============================================================

Bridges agent mutations (stored in `ghidra_overlay.json` or `.ghidra-delta.jsonl`)
into the interactive Ghidra GUI and Headless Ghidra environments.

Features:
- Ingests `ghidra_overlay.json` or `.ghidra-delta.jsonl` mutation streams (including
  optional `before` / `expected_before` expectations from `merge_fork` journals).
- Computes incremental deltas across overlay revisions (`compute_incremental_delta`)
  and verifies conflicts against live CodeBrowser state (`verify_conflicts`).
- Generates executable one-shot Ghidra Python scripts (`generate_ghidra_python_script`)
  and live background CodeBrowser watcher scripts (`generate_ghidra_watcher_script`).
- Wraps mutations in an atomic transaction: `currentProgram.startTransaction(...)`.
- Produces clean summary diff reports grouped by target address / RVA.
- Provides a CLI interface (`sync_to_script`, `build_arg_parser`, `main`).
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
from pathlib import Path
from typing import Any, Dict, List, Tuple

logger = logging.getLogger("SuperGhidra.OverlaySync")

DEFAULT_SYMBOL_PREFIXES = (
    "FUN_",
    "sub_",
    "LAB_",
    "DAT_",
    "thunk_FUN_",
    "unk_",
    "PTR_",
    "s_",
    "u_",
    "dword_",
    "qword_",
    "byte_",
    "word_",
)


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


def is_default_ghidra_symbol(name: str | None) -> bool:
    """Return True if symbol name matches an auto-generated Ghidra/disassembler prefix."""
    if not name or not isinstance(name, str):
        return True
    stripped = name.strip()
    if not stripped:
        return True
    lower = stripped.lower()
    return any(lower.startswith(prefix.lower()) for prefix in DEFAULT_SYMBOL_PREFIXES)


def _default_fun_name(addr_key: str) -> str:
    """Construct default Ghidra FUN_<hex> name from a normalized '0x<HEX>' address key."""
    hex_part = addr_key[2:] if addr_key.lower().startswith("0x") else addr_key
    return f"FUN_{hex_part}"


class OverlaySyncBridge:
    """
    Bridge between SuperGhidra write overlays / delta event streams and Ghidra GUI scripts.
    """

    def __init__(
        self,
        overlay_source: str | Path | Dict[str, Any] | List[Dict[str, Any]] | None = None,
    ):
        self.source_path: Path | None = None
        self.overlay_data: Dict[str, Any] = {
            "renames": {},
            "comments": {},
            "prototypes": {},
            "types": {},
            "structs": [],
        }
        self.before_expectations: Dict[str, Dict[str, Any]] = {
            "renames": {},
            "comments": {},
            "prototypes": {},
            "types": {},
        }
        if overlay_source is not None:
            self.load(overlay_source)

    def load(
        self, source: str | Path | Dict[str, Any] | List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """
        Load overlay definitions from a filepath (JSON or JSONL), an in-memory dict,
        or a list of delta events.
        """
        if isinstance(source, (str, Path)):
            p = Path(source)
            self.source_path = p
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

    def _ingest_before_map(self, before_map: Dict[str, Any]) -> None:
        """Ingest top-level 'before' or 'expected_before' expectations."""
        categories = ("renames", "comments", "prototypes", "types")
        if any(cat in before_map for cat in categories):
            for cat in categories:
                cat_dict = before_map.get(cat, {})
                if isinstance(cat_dict, dict):
                    for addr, val in cat_dict.items():
                        k = normalize_address_key(addr)
                        if isinstance(val, dict) and cat == "comments":
                            self.before_expectations[cat][k] = val.get("text") or val.get("comment", "")
                        else:
                            self.before_expectations[cat][k] = val
        else:
            for addr, val in before_map.items():
                k = normalize_address_key(addr)
                self.before_expectations["renames"][k] = val

    def _ingest_dict(self, data: Dict[str, Any]) -> None:
        """Ingest standard WriteOverlay dictionary format (with optional 'before' expectations)."""
        for b_key in ("before", "expected_before"):
            if b_key in data and isinstance(data[b_key], dict):
                self._ingest_before_map(data[b_key])

        for list_key in ("journal", "events", "mutations"):
            if list_key in data and isinstance(data[list_key], list):
                self._ingest_delta_events(data[list_key])

        for addr, name in data.get("renames", {}).items():
            k = normalize_address_key(addr)
            if isinstance(name, dict):
                actual_name = (
                    name.get("after")
                    or name.get("new_name")
                    or name.get("name")
                    or name.get("value")
                    or ""
                )
                before_val = (
                    name.get("before")
                    if "before" in name
                    else (
                        name.get("expected_before")
                        if "expected_before" in name
                        else name.get("old_name")
                    )
                )
                if actual_name:
                    self.overlay_data["renames"][k] = str(actual_name)
                if before_val is not None:
                    self.before_expectations["renames"][k] = str(before_val)
            else:
                self.overlay_data["renames"][k] = name

        for addr, comment in data.get("comments", {}).items():
            k = normalize_address_key(addr)
            if isinstance(comment, dict):
                entry: Dict[str, Any] = {
                    "text": comment.get("text") or comment.get("comment") or comment.get("after") or "",
                    "type": comment.get("type") or comment.get("comment_type", "PLATE"),
                }
                before_val = (
                    comment.get("before")
                    if "before" in comment
                    else (
                        comment.get("expected_before")
                        if "expected_before" in comment
                        else comment.get("old_comment")
                    )
                )
                if before_val is not None:
                    self.before_expectations["comments"][k] = str(before_val)
                self.overlay_data["comments"][k] = entry
            else:
                self.overlay_data["comments"][k] = {
                    "text": str(comment),
                    "type": "PLATE",
                }

        for addr, proto in data.get("prototypes", {}).items():
            k = normalize_address_key(addr)
            if isinstance(proto, dict):
                actual_proto = (
                    proto.get("after")
                    or proto.get("prototype")
                    or proto.get("new_prototype")
                    or proto.get("value")
                    or ""
                )
                before_val = (
                    proto.get("before")
                    if "before" in proto
                    else (
                        proto.get("expected_before")
                        if "expected_before" in proto
                        else proto.get("old_prototype")
                    )
                )
                if actual_proto:
                    self.overlay_data["prototypes"][k] = str(actual_proto)
                if before_val is not None:
                    self.before_expectations["prototypes"][k] = str(before_val)
            else:
                self.overlay_data["prototypes"][k] = proto

        for addr, t_name in data.get("types", {}).items():
            k = normalize_address_key(addr)
            if isinstance(t_name, dict):
                actual_type = (
                    t_name.get("after")
                    or t_name.get("type")
                    or t_name.get("type_name")
                    or t_name.get("value")
                    or ""
                )
                before_val = (
                    t_name.get("before")
                    if "before" in t_name
                    else (
                        t_name.get("expected_before")
                        if "expected_before" in t_name
                        else t_name.get("old_type")
                    )
                )
                if actual_type:
                    self.overlay_data["types"][k] = str(actual_type)
                if before_val is not None:
                    self.before_expectations["types"][k] = str(before_val)
            else:
                self.overlay_data["types"][k] = t_name

        if "structs" in data and isinstance(data["structs"], list):
            self.overlay_data["structs"].extend(data["structs"])

    def _ingest_delta_events(self, events: List[Dict[str, Any]]) -> None:
        """Ingest append-only .ghidra-delta.jsonl events and merge_fork journals."""
        for evt in events:
            if not isinstance(evt, dict):
                continue
            evt_type = evt.get("event_type") or evt.get("op") or evt.get("category") or ""
            target_addr = (
                evt.get("target_address")
                if "target_address" in evt
                else (evt.get("address") if "address" in evt else evt.get("rva"))
            )
            target_sym = evt.get("target_symbol")
            payload = evt.get("payload", {}) if isinstance(evt.get("payload"), dict) else {}

            addr_key = normalize_address_key(target_addr) if target_addr is not None else None

            def _extract_before(*keys: str) -> str | None:
                for key in ("before", "expected_before", *keys):
                    if key in payload and payload[key] is not None:
                        return str(payload[key])
                    if key in evt and evt[key] is not None:
                        return str(evt[key])
                return None

            if evt_type in ("RenameSymbol", "rename", "renames") or (
                not evt_type and addr_key and ("new_name" in evt or "after" in evt or "new_name" in payload or "after" in payload)
            ):
                new_name = (
                    payload.get("new_name")
                    or payload.get("after")
                    or evt.get("new_name")
                    or evt.get("after")
                    or target_sym
                )
                if addr_key and new_name:
                    self.overlay_data["renames"][addr_key] = str(new_name)
                    before_val = _extract_before("old_name", "old_symbol")
                    if before_val is not None:
                        self.before_expectations["renames"][addr_key] = before_val
            elif evt_type in ("SetComment", "comment", "comments"):
                cmt_text = (
                    payload.get("comment")
                    or payload.get("text")
                    or payload.get("after")
                    or evt.get("comment")
                    or evt.get("text")
                    or evt.get("after")
                    or ""
                )
                cmt_type = (
                    payload.get("comment_type")
                    or payload.get("type")
                    or evt.get("comment_type")
                    or "PLATE"
                )
                if addr_key and cmt_text:
                    self.overlay_data["comments"][addr_key] = {
                        "text": str(cmt_text),
                        "type": str(cmt_type),
                    }
                    before_val = _extract_before("old_comment", "old_text")
                    if before_val is not None:
                        self.before_expectations["comments"][addr_key] = before_val
            elif evt_type in ("SetFunctionSignature", "prototype", "prototypes"):
                proto = (
                    payload.get("prototype")
                    or payload.get("after")
                    or evt.get("prototype")
                    or evt.get("after")
                )
                if addr_key and proto:
                    self.overlay_data["prototypes"][addr_key] = str(proto)
                    before_val = _extract_before("old_prototype", "old_signature")
                    if before_val is not None:
                        self.before_expectations["prototypes"][addr_key] = before_val
            elif evt_type == "DefineStructField":
                self.overlay_data["structs"].append(payload or evt)
            elif evt_type in ("SetType", "SetVariableType", "type", "types"):
                type_name = (
                    payload.get("type")
                    or payload.get("type_name")
                    or payload.get("after")
                    or evt.get("type_name")
                    or evt.get("after")
                )
                if addr_key and type_name:
                    self.overlay_data["types"][addr_key] = str(type_name)
                    before_val = _extract_before("old_type")
                    if before_val is not None:
                        self.before_expectations["types"][addr_key] = before_val

    def compute_incremental_delta(self, previous_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Return only the newly added or modified renames, comments, prototypes,
        types, and structs compared to `previous_data`.
        """
        prev = previous_data or {}
        prev_renames = {
            normalize_address_key(k): (
                v.get("after") or v.get("new_name") or v.get("name") or ""
                if isinstance(v, dict)
                else v
            )
            for k, v in prev.get("renames", {}).items()
        }
        prev_comments: Dict[str, Dict[str, str]] = {}
        for k, v in prev.get("comments", {}).items():
            nk = normalize_address_key(k)
            if isinstance(v, dict):
                prev_comments[nk] = {
                    "text": str(v.get("text") or v.get("comment") or ""),
                    "type": str(v.get("type") or v.get("comment_type", "PLATE")),
                }
            else:
                prev_comments[nk] = {"text": str(v), "type": "PLATE"}

        prev_prototypes = {
            normalize_address_key(k): (
                v.get("after") or v.get("prototype") or "" if isinstance(v, dict) else v
            )
            for k, v in prev.get("prototypes", {}).items()
        }
        prev_types = {
            normalize_address_key(k): (
                v.get("after") or v.get("type") or v.get("type_name") or ""
                if isinstance(v, dict)
                else v
            )
            for k, v in prev.get("types", {}).items()
        }
        prev_structs = prev.get("structs", []) if isinstance(prev.get("structs"), list) else []

        delta_renames = {
            addr: name
            for addr, name in self.overlay_data.get("renames", {}).items()
            if addr not in prev_renames or prev_renames[addr] != name
        }
        delta_comments = {}
        for addr, c_val in self.overlay_data.get("comments", {}).items():
            c_norm = (
                {
                    "text": str(c_val.get("text") or c_val.get("comment") or ""),
                    "type": str(c_val.get("type") or c_val.get("comment_type", "PLATE")),
                }
                if isinstance(c_val, dict)
                else {"text": str(c_val), "type": "PLATE"}
            )
            if addr not in prev_comments or prev_comments[addr] != c_norm:
                delta_comments[addr] = c_val

        delta_prototypes = {
            addr: proto
            for addr, proto in self.overlay_data.get("prototypes", {}).items()
            if addr not in prev_prototypes or prev_prototypes[addr] != proto
        }
        delta_types = {
            addr: t_name
            for addr, t_name in self.overlay_data.get("types", {}).items()
            if addr not in prev_types or prev_types[addr] != t_name
        }
        delta_structs = [
            st for st in self.overlay_data.get("structs", []) if st not in prev_structs
        ]

        return {
            "renames": delta_renames,
            "comments": delta_comments,
            "prototypes": delta_prototypes,
            "types": delta_types,
            "structs": delta_structs,
        }

    def verify_conflicts(
        self, live_program_state: Dict[str, Dict[str, Any]]
    ) -> Tuple[Dict[str, Any], List[Dict[str, Any]]]:
        """
        Compare proposed overlay/journal mutations against `live_program_state`.

        Any address whose live symbol/comment/prototype/type in CodeBrowser was modified
        by the analyst to something different from `before` (or default Ghidra `FUN_<addr>` /
        `sub_<addr>` prefix) and different from the proposed target value is flagged as a
        conflict and skipped.

        Returns `(accepted_overlay_data, conflicts_list)`.
        """
        state = live_program_state or {}
        known_categories = ("renames", "comments", "prototypes", "types", "symbols")
        if state and not any(k in state for k in known_categories):
            raw_live_renames = state
        else:
            raw_live_renames = state.get("renames") or state.get("symbols") or {}

        live_renames = {
            normalize_address_key(k): str(v)
            for k, v in raw_live_renames.items()
            if v is not None
        }
        live_comments = {
            normalize_address_key(k): (
                str(v.get("text") or v.get("comment") or "") if isinstance(v, dict) else str(v)
            )
            for k, v in (state.get("comments") or {}).items()
            if v is not None
        }
        live_prototypes = {
            normalize_address_key(k): str(v)
            for k, v in (state.get("prototypes") or {}).items()
            if v is not None
        }
        live_types = {
            normalize_address_key(k): str(v)
            for k, v in (state.get("types") or {}).items()
            if v is not None
        }

        accepted_renames: Dict[str, str] = {}
        accepted_comments: Dict[str, Any] = {}
        accepted_prototypes: Dict[str, str] = {}
        accepted_types: Dict[str, str] = {}
        conflicts: List[Dict[str, Any]] = []

        # 1. Verify Renames
        for addr, target_name in self.overlay_data.get("renames", {}).items():
            expected_before = self.before_expectations["renames"].get(addr)
            default_before = _default_fun_name(addr)
            live_name = live_renames.get(addr)

            if live_name is None or live_name == "" or live_name == target_name:
                accepted_renames[addr] = target_name
                continue

            if expected_before is not None:
                is_match = (live_name == expected_before) or (
                    is_default_ghidra_symbol(expected_before) and is_default_ghidra_symbol(live_name)
                )
                if is_match:
                    accepted_renames[addr] = target_name
                else:
                    conflicts.append(
                        {
                            "address": addr,
                            "category": "renames",
                            "before": expected_before,
                            "expected_before": expected_before,
                            "live": live_name,
                            "live_value": live_name,
                            "current": live_name,
                            "proposed": target_name,
                            "after": target_name,
                            "reason": (
                                f"Live symbol '{live_name}' at {addr} differs from expected "
                                f"before='{expected_before}' and proposed='{target_name}'"
                            ),
                        }
                    )
            else:
                if is_default_ghidra_symbol(live_name):
                    accepted_renames[addr] = target_name
                else:
                    conflicts.append(
                        {
                            "address": addr,
                            "category": "renames",
                            "before": default_before,
                            "expected_before": default_before,
                            "live": live_name,
                            "live_value": live_name,
                            "current": live_name,
                            "proposed": target_name,
                            "after": target_name,
                            "reason": (
                                f"Live symbol '{live_name}' at {addr} was modified in CodeBrowser "
                                f"(expected default '{default_before}')"
                            ),
                        }
                    )

        # 2. Verify Comments
        for addr, c_val in self.overlay_data.get("comments", {}).items():
            target_text = c_val.get("text", "") if isinstance(c_val, dict) else str(c_val)
            expected_before = self.before_expectations["comments"].get(addr)
            live_text = live_comments.get(addr)

            if live_text is None or live_text == "" or live_text == target_text:
                accepted_comments[addr] = c_val
                continue

            if expected_before is not None and live_text == expected_before:
                accepted_comments[addr] = c_val
            else:
                exp = expected_before if expected_before is not None else ""
                conflicts.append(
                    {
                        "address": addr,
                        "category": "comments",
                        "before": exp,
                        "expected_before": exp,
                        "live": live_text,
                        "live_value": live_text,
                        "current": live_text,
                        "proposed": target_text,
                        "after": target_text,
                        "reason": (
                            f"Live comment '{live_text}' at {addr} differs from expected "
                            f"before='{exp}' and proposed='{target_text}'"
                        ),
                    }
                )

        # 3. Verify Prototypes
        for addr, target_proto in self.overlay_data.get("prototypes", {}).items():
            expected_before = self.before_expectations["prototypes"].get(addr)
            live_proto = live_prototypes.get(addr)

            if live_proto is None or live_proto == "" or live_proto == target_proto:
                accepted_prototypes[addr] = target_proto
                continue

            if expected_before is not None and live_proto == expected_before:
                accepted_prototypes[addr] = target_proto
            else:
                exp = expected_before if expected_before is not None else ""
                conflicts.append(
                    {
                        "address": addr,
                        "category": "prototypes",
                        "before": exp,
                        "expected_before": exp,
                        "live": live_proto,
                        "live_value": live_proto,
                        "current": live_proto,
                        "proposed": target_proto,
                        "after": target_proto,
                        "reason": (
                            f"Live prototype '{live_proto}' at {addr} differs from expected "
                            f"before='{exp}' and proposed='{target_proto}'"
                        ),
                    }
                )

        # 4. Verify Types
        for addr, target_type in self.overlay_data.get("types", {}).items():
            expected_before = self.before_expectations["types"].get(addr)
            live_type = live_types.get(addr)

            if live_type is None or live_type == "" or live_type == target_type:
                accepted_types[addr] = target_type
                continue

            if expected_before is not None:
                if live_type == expected_before:
                    accepted_types[addr] = target_type
                else:
                    conflicts.append(
                        {
                            "address": addr,
                            "category": "types",
                            "before": expected_before,
                            "expected_before": expected_before,
                            "live": live_type,
                            "live_value": live_type,
                            "current": live_type,
                            "proposed": target_type,
                            "after": target_type,
                            "reason": (
                                f"Live type '{live_type}' at {addr} differs from expected "
                                f"before='{expected_before}' and proposed='{target_type}'"
                            ),
                        }
                    )
            else:
                if live_type.lower() in (
                    "undefined",
                    "undefined1",
                    "undefined2",
                    "undefined4",
                    "undefined8",
                    "void",
                ):
                    accepted_types[addr] = target_type
                else:
                    conflicts.append(
                        {
                            "address": addr,
                            "category": "types",
                            "before": "undefined",
                            "expected_before": "undefined",
                            "live": live_type,
                            "live_value": live_type,
                            "current": live_type,
                            "proposed": target_type,
                            "after": target_type,
                            "reason": (
                                f"Live type '{live_type}' at {addr} was modified in CodeBrowser"
                            ),
                        }
                    )

        accepted_overlay_data: Dict[str, Any] = {
            "renames": accepted_renames,
            "comments": accepted_comments,
            "prototypes": accepted_prototypes,
            "types": accepted_types,
            "structs": list(self.overlay_data.get("structs", [])),
        }
        return accepted_overlay_data, conflicts

    def generate_diff_report(self, overlay_data: Dict[str, Any] | None = None) -> str:
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
        overlay_data: Dict[str, Any] | None = None,
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

    def generate_ghidra_watcher_script(
        self,
        poll_interval_ms: int = 1000,
        dry_run: bool = False,
        verify_conflicts: bool = True,
        overlay_path: str | Path | None = None,
    ) -> str:
        """
        Generates a self-contained Ghidra Python/Jython/PyGhidra script that monitors
        the target `ghidra_overlay.json` or `.ghidra-delta.jsonl` file on a daemon
        background thread inside an open Ghidra CodeBrowser session.

        On each poll tick (`poll_interval_ms`), checks file `(mtime_ns, size, sha256)`;
        when changed, parses only newly added or modified mutations, checks `before`
        expectations against `currentProgram` symbol table (`getFunctionAt(addr).getName()`)
        to avoid clobbering concurrent GUI edits, and applies accepted diffs atomically
        inside `currentProgram.startTransaction("SuperGhidra Live Overlay Sync")`.
        """
        target_path_str = (
            str(overlay_path)
            if overlay_path is not None
            else (str(self.source_path) if self.source_path is not None else "ghidra_overlay.json")
        )
        serialized_initial_data = json.dumps(self.overlay_data, indent=2)
        serialized_initial_before = json.dumps(self.before_expectations, indent=2)
        poll_ms = max(10, int(poll_interval_ms))

        script = f'''# SuperGhidra Generated Live Overlay Watcher Script
# @category SuperGhidra
# @menupath Tools.SuperGhidra.Watch Overlay Live
# @toolbar
#
# Generated automatically by SuperGhidra OverlaySyncBridge.
# Polls ghidra_overlay.json or .ghidra-delta.jsonl on a background daemon thread
# and applies conflict-checked incremental diffs to currentProgram.

from __future__ import print_function
import hashlib
import json
import os
import sys
import threading
import time

try:
    from ghidra.program.model.symbol import SourceType
    from ghidra.program.model.listing import CodeUnit
except ImportError:
    SourceType = None
    CodeUnit = None

try:
    from javax.swing import SwingUtilities
except ImportError:
    SwingUtilities = None

try:
    from java.lang import System
except ImportError:
    System = None

OVERLAY_PATH = {repr(target_path_str)}
POLL_INTERVAL_MS = {poll_ms}
DRY_RUN = {repr(bool(dry_run))}
VERIFY_CONFLICTS = {repr(bool(verify_conflicts))}
INITIAL_OVERLAY_DATA = {serialized_initial_data}
INITIAL_BEFORE_EXPECTATIONS = {serialized_initial_before}

DEFAULT_SYMBOL_PREFIXES = (
    "FUN_",
    "sub_",
    "LAB_",
    "DAT_",
    "thunk_FUN_",
    "unk_",
    "PTR_",
    "s_",
    "u_",
    "dword_",
    "qword_",
    "byte_",
    "word_",
)

WATCHER_STOP_EVENT = threading.Event()
WATCHER_STATE = {{
    "last_fingerprint": None,
    "previous_data": {{
        "renames": {{}},
        "comments": {{}},
        "prototypes": {{}},
        "types": {{}},
        "structs": [],
    }},
    "before_expectations": {{
        "renames": dict(INITIAL_BEFORE_EXPECTATIONS.get("renames", {{}})),
        "comments": dict(INITIAL_BEFORE_EXPECTATIONS.get("comments", {{}})),
        "prototypes": dict(INITIAL_BEFORE_EXPECTATIONS.get("prototypes", {{}})),
        "types": dict(INITIAL_BEFORE_EXPECTATIONS.get("types", {{}})),
    }},
    "conflicts": [],
    "applied_batches": 0,
    "thread": None,
}}


def _normalize_address_key(addr_val):
    if isinstance(addr_val, int):
        return "0x%X" % addr_val
    s = str(addr_val).strip()
    if s.startswith("0x") or s.startswith("0X"):
        try:
            return "0x%X" % int(s, 16)
        except ValueError:
            return s.upper()
    try:
        val = int(s, 16) if any(c in "abcdefABCDEF" for c in s) else int(s, 10)
        return "0x%X" % val
    except ValueError:
        return s


def _is_default_symbol(name):
    if not name or not isinstance(name, str):
        return True
    stripped = name.strip()
    if not stripped:
        return True
    lower = stripped.lower()
    return any(lower.startswith(p.lower()) for p in DEFAULT_SYMBOL_PREFIXES)


def _resolve_address(prog, addr_str):
    try:
        if "toAddr" in globals():
            return toAddr(addr_str)
    except Exception:
        pass
    addr_factory = prog.getAddressFactory()
    default_space = addr_factory.getDefaultAddressSpace()
    val = int(addr_str, 16) if addr_str.startswith("0x") or addr_str.startswith("0X") else int(addr_str)
    return default_space.getAddress(val)


def _file_fingerprint(path):
    """Compute (mtime_ns, size, sha256) tuple for change detection."""
    st = os.stat(path)
    mtime_ns = getattr(st, "st_mtime_ns", int(st.st_mtime * 1000000000))
    size = st.st_size
    with open(path, "rb") as f:
        digest = hashlib.sha256(f.read()).hexdigest()
    return (mtime_ns, size, digest)


def _parse_overlay_file(path):
    """Parse ghidra_overlay.json or .ghidra-delta.jsonl into (overlay_data, before_expectations)."""
    overlay_data = {{
        "renames": {{}},
        "comments": {{}},
        "prototypes": {{}},
        "types": {{}},
        "structs": [],
    }}
    before_expectations = {{
        "renames": {{}},
        "comments": {{}},
        "prototypes": {{}},
        "types": {{}},
    }}
    with open(path, "r", encoding="utf-8") as f:
        text = f.read().strip()
    if not text:
        return overlay_data, before_expectations

    def _ingest_events(events):
        for evt in events:
            if not isinstance(evt, dict):
                continue
            evt_type = evt.get("event_type") or evt.get("op") or evt.get("category") or ""
            target_addr = (
                evt.get("target_address")
                if "target_address" in evt
                else (evt.get("address") if "address" in evt else evt.get("rva"))
            )
            payload = evt.get("payload", {{}}) if isinstance(evt.get("payload"), dict) else {{}}
            addr_key = _normalize_address_key(target_addr) if target_addr is not None else None
            before_val = (
                payload.get("before")
                or payload.get("expected_before")
                or payload.get("old_name")
                or evt.get("before")
                or evt.get("expected_before")
                or evt.get("old_name")
            )
            if evt_type in ("RenameSymbol", "rename", "renames") or (
                not evt_type and addr_key and ("new_name" in evt or "after" in evt or "new_name" in payload or "after" in payload)
            ):
                new_name = (
                    payload.get("new_name")
                    or payload.get("after")
                    or evt.get("new_name")
                    or evt.get("after")
                    or evt.get("target_symbol")
                )
                if addr_key and new_name:
                    overlay_data["renames"][addr_key] = str(new_name)
                    if before_val is not None:
                        before_expectations["renames"][addr_key] = str(before_val)
            elif evt_type in ("SetComment", "comment", "comments"):
                cmt_text = payload.get("comment") or payload.get("text") or evt.get("comment") or evt.get("after") or ""
                cmt_type = payload.get("comment_type") or payload.get("type") or evt.get("comment_type") or "PLATE"
                if addr_key and cmt_text:
                    overlay_data["comments"][addr_key] = {{"text": str(cmt_text), "type": str(cmt_type)}}
                    if before_val is not None:
                        before_expectations["comments"][addr_key] = str(before_val)
            elif evt_type in ("SetFunctionSignature", "prototype", "prototypes"):
                proto = payload.get("prototype") or payload.get("after") or evt.get("prototype") or evt.get("after")
                if addr_key and proto:
                    overlay_data["prototypes"][addr_key] = str(proto)
                    if before_val is not None:
                        before_expectations["prototypes"][addr_key] = str(before_val)
            elif evt_type == "DefineStructField":
                overlay_data["structs"].append(payload or evt)
            elif evt_type in ("SetType", "SetVariableType", "type", "types"):
                t_name = payload.get("type") or payload.get("type_name") or payload.get("after") or evt.get("after")
                if addr_key and t_name:
                    overlay_data["types"][addr_key] = str(t_name)
                    if before_val is not None:
                        before_expectations["types"][addr_key] = str(before_val)

    if path.lower().endswith(".jsonl") or ("\\n" in text and not text.startswith("{{")):
        events = [json.loads(line.strip()) for line in text.splitlines() if line.strip()]
        _ingest_events(events)
    else:
        raw = json.loads(text)
        if isinstance(raw, list):
            _ingest_events(raw)
        elif isinstance(raw, dict):
            for b_key in ("before", "expected_before"):
                if isinstance(raw.get(b_key), dict):
                    b_map = raw[b_key]
                    if any(c in b_map for c in ("renames", "comments", "prototypes", "types")):
                        for c in ("renames", "comments", "prototypes", "types"):
                            for k, v in (b_map.get(c) or {{}}).items():
                                before_expectations[c][_normalize_address_key(k)] = str(v)
                    else:
                        for k, v in b_map.items():
                            before_expectations["renames"][_normalize_address_key(k)] = str(v)
            for addr, name in (raw.get("renames") or {{}}).items():
                k = _normalize_address_key(addr)
                if isinstance(name, dict):
                    actual = name.get("after") or name.get("new_name") or name.get("name") or ""
                    b_val = name.get("before") or name.get("expected_before") or name.get("old_name")
                    if actual:
                        overlay_data["renames"][k] = str(actual)
                    if b_val is not None:
                        before_expectations["renames"][k] = str(b_val)
                else:
                    overlay_data["renames"][k] = str(name)
            for addr, comment in (raw.get("comments") or {{}}).items():
                k = _normalize_address_key(addr)
                if isinstance(comment, dict):
                    overlay_data["comments"][k] = {{
                        "text": str(comment.get("text") or comment.get("comment") or ""),
                        "type": str(comment.get("type") or comment.get("comment_type") or "PLATE"),
                    }}
                    b_val = comment.get("before") or comment.get("expected_before")
                    if b_val is not None:
                        before_expectations["comments"][k] = str(b_val)
                else:
                    overlay_data["comments"][k] = {{"text": str(comment), "type": "PLATE"}}
            for addr, proto in (raw.get("prototypes") or {{}}).items():
                k = _normalize_address_key(addr)
                if isinstance(proto, dict):
                    actual = proto.get("after") or proto.get("prototype") or ""
                    b_val = proto.get("before") or proto.get("expected_before")
                    if actual:
                        overlay_data["prototypes"][k] = str(actual)
                    if b_val is not None:
                        before_expectations["prototypes"][k] = str(b_val)
                else:
                    overlay_data["prototypes"][k] = str(proto)
            for addr, t_name in (raw.get("types") or {{}}).items():
                k = _normalize_address_key(addr)
                if isinstance(t_name, dict):
                    actual = t_name.get("after") or t_name.get("type") or t_name.get("type_name") or ""
                    b_val = t_name.get("before") or t_name.get("expected_before")
                    if actual:
                        overlay_data["types"][k] = str(actual)
                    if b_val is not None:
                        before_expectations["types"][k] = str(b_val)
                else:
                    overlay_data["types"][k] = str(t_name)
            if isinstance(raw.get("structs"), list):
                overlay_data["structs"].extend(raw["structs"])

    return overlay_data, before_expectations


def _compute_incremental_delta(current_data, previous_data):
    """Return only newly added or modified mutations compared to previous_data."""
    prev = previous_data or {{}}
    prev_renames = prev.get("renames", {{}})
    prev_comments = prev.get("comments", {{}})
    prev_prototypes = prev.get("prototypes", {{}})
    prev_types = prev.get("types", {{}})
    prev_structs = prev.get("structs", [])

    return {{
        "renames": {{
            k: v for k, v in current_data.get("renames", {{}}).items()
            if k not in prev_renames or prev_renames[k] != v
        }},
        "comments": {{
            k: v for k, v in current_data.get("comments", {{}}).items()
            if k not in prev_comments or prev_comments[k] != v
        }},
        "prototypes": {{
            k: v for k, v in current_data.get("prototypes", {{}}).items()
            if k not in prev_prototypes or prev_prototypes[k] != v
        }},
        "types": {{
            k: v for k, v in current_data.get("types", {{}}).items()
            if k not in prev_types or prev_types[k] != v
        }},
        "structs": [
            st for st in current_data.get("structs", [])
            if st not in prev_structs
        ],
    }}


def _apply_live_delta(prog, delta, before_expectations=None, dry_run=False, verify_conflicts=True):
    """Apply incremental delta inside an atomic transaction after checking live symbols for conflicts."""
    listing = prog.getListing()
    sym_table = prog.getSymbolTable()
    before_map = before_expectations or {{}}
    renames_before = before_map.get("renames", {{}})

    renames = delta.get("renames", {{}})
    comments = delta.get("comments", {{}})
    prototypes = delta.get("prototypes", {{}})
    types = delta.get("types", {{}})

    total_mutations = len(renames) + len(comments) + len(prototypes) + len(types)
    if total_mutations == 0:
        return [], 0

    conflicts = []
    applied_count = 0

    tx_id = prog.startTransaction("SuperGhidra Live Overlay Sync")
    success = False
    try:
        # 1. Apply conflict-checked symbol renames
        for addr_str, new_name in renames.items():
            try:
                addr = _resolve_address(prog, addr_str)
                if not addr:
                    continue
                fn = listing.getFunctionAt(addr)
                if verify_conflicts and fn is not None and hasattr(fn, "getName"):
                    live_name = fn.getName()
                    if isinstance(live_name, str) and live_name and live_name != new_name:
                        expected_before = renames_before.get(addr_str)
                        if expected_before is not None:
                            is_ok = (live_name == expected_before) or (
                                _is_default_symbol(expected_before) and _is_default_symbol(live_name)
                            )
                        else:
                            is_ok = _is_default_symbol(live_name)
                        if not is_ok:
                            conflict_entry = {{
                                "address": addr_str,
                                "category": "renames",
                                "before": expected_before or ("FUN_%s" % addr_str[2:]),
                                "live": live_name,
                                "proposed": new_name,
                            }}
                            conflicts.append(conflict_entry)
                            WATCHER_STATE["conflicts"].append(conflict_entry)
                            print(
                                "[SuperGhidra] [CONFLICT] Skipping %s -> %s (live symbol in CodeBrowser is '%s')"
                                % (addr_str, new_name, live_name)
                            )
                            continue

                if dry_run:
                    print("[SuperGhidra] [DRY RUN] Live Rename %s -> %s" % (addr_str, new_name))
                else:
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
                applied_count += 1
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
                if not dry_run:
                    if "setComment" in globals() and c_type_str == "PLATE":
                        setComment(addr, c_text)
                    else:
                        listing.setComment(addr, code_unit_id, c_text)
                applied_count += 1
            except Exception as e:
                print("[SuperGhidra] Error setting comment at %s: %s" % (addr_str, e))

        # 3. Apply Prototypes
        for addr_str, proto in prototypes.items():
            try:
                addr = _resolve_address(prog, addr_str)
                if not addr:
                    continue
                if not dry_run:
                    fn = listing.getFunctionAt(addr)
                    if fn is not None:
                        existing = fn.getComment() or ""
                        if not isinstance(existing, str):
                            existing = ""
                        if proto not in existing:
                            fn.setComment((existing + "\\n[Prototype] " + proto).strip())
                applied_count += 1
            except Exception as e:
                print("[SuperGhidra] Error setting prototype at %s: %s" % (addr_str, e))

        # 4. Apply Types
        for addr_str, type_name in types.items():
            try:
                addr = _resolve_address(prog, addr_str)
                if not addr:
                    continue
                if not dry_run:
                    fn = listing.getFunctionAt(addr)
                    if fn is not None:
                        existing = fn.getComment() or ""
                        if not isinstance(existing, str):
                            existing = ""
                        fn.setComment((existing + "\\n[Type] " + type_name).strip())
                applied_count += 1
            except Exception as e:
                print("[SuperGhidra] Error setting type at %s: %s" % (addr_str, e))

        success = True
    finally:
        commit = success and not dry_run
        prog.endTransaction(tx_id, commit)
        WATCHER_STATE["applied_batches"] += 1

    return conflicts, applied_count


def _should_stop():
    if WATCHER_STOP_EVENT.is_set():
        return True
    if globals().get("SUPERGHIDRA_WATCHER_STOP", False):
        return True
    try:
        if "state" in globals() and state is not None and hasattr(state, "getVar"):
            if str(state.getVar("superghidra.watcher.stop")).lower() in ("true", "1", "stop"):
                return True
    except Exception:
        pass
    try:
        if System is not None:
            prop = System.getProperty("superghidra.watcher.stop")
            if prop is not None and str(prop).lower() in ("true", "1", "stop"):
                return True
    except Exception:
        pass
    return False


def stop_watcher():
    """Signal the background overlay watcher thread to stop cleanly."""
    WATCHER_STOP_EVENT.set()
    try:
        if System is not None:
            System.setProperty("superghidra.watcher.stop", "true")
    except Exception:
        pass


def _poll_once(prog=None, state_dict=None):
    """Execute a single poll tick: check (mtime_ns, size, sha256) and apply incremental delta."""
    target_prog = prog if prog is not None else globals().get("currentProgram")
    if target_prog is None:
        return False
    st = state_dict if state_dict is not None else WATCHER_STATE

    if OVERLAY_PATH and os.path.isfile(OVERLAY_PATH):
        fp = _file_fingerprint(OVERLAY_PATH)
        if fp == st["last_fingerprint"]:
            return False
        current_data, current_before = _parse_overlay_file(OVERLAY_PATH)
        for cat in ("renames", "comments", "prototypes", "types"):
            st["before_expectations"][cat].update(current_before.get(cat, {{}}))
    elif st["last_fingerprint"] is None:
        fp = ("in_memory", 0, "initial")
        current_data = INITIAL_OVERLAY_DATA
    else:
        return False

    delta = _compute_incremental_delta(current_data, st["previous_data"])
    if SwingUtilities is not None and hasattr(SwingUtilities, "isEventDispatchThread") and not SwingUtilities.isEventDispatchThread():
        SwingUtilities.invokeLater(
            lambda: _apply_live_delta(
                target_prog,
                delta,
                st["before_expectations"],
                dry_run=DRY_RUN,
                verify_conflicts=VERIFY_CONFLICTS,
            )
        )
    else:
        _apply_live_delta(
            target_prog,
            delta,
            st["before_expectations"],
            dry_run=DRY_RUN,
            verify_conflicts=VERIFY_CONFLICTS,
        )

    st["previous_data"] = {{
        "renames": dict(current_data.get("renames", {{}})),
        "comments": dict(current_data.get("comments", {{}})),
        "prototypes": dict(current_data.get("prototypes", {{}})),
        "types": dict(current_data.get("types", {{}})),
        "structs": list(current_data.get("structs", [])),
    }}
    st["last_fingerprint"] = fp
    return True


def _watch_loop():
    poll_sec = max(0.01, float(POLL_INTERVAL_MS) / 1000.0)
    while not _should_stop():
        try:
            _poll_once(globals().get("currentProgram"), WATCHER_STATE)
        except Exception as e:
            print("[SuperGhidra] Live watcher poll error: %s" % e)
        WATCHER_STOP_EVENT.wait(poll_sec)


def run():
    if "currentProgram" not in globals() or currentProgram is None:
        print("[SuperGhidra] Error: currentProgram is not available in environment.", file=sys.stderr)
        return
    _poll_once(currentProgram, WATCHER_STATE)
    if not _should_stop() and OVERLAY_PATH and os.path.isfile(OVERLAY_PATH) and not globals().get("SUPERGHIDRA_WATCHER_SINGLE_SHOT", False):
        watcher_thread = threading.Thread(
            target=_watch_loop,
            name="SuperGhidraOverlayWatcher",
            daemon=True,
        )
        watcher_thread.start()
        WATCHER_STATE["thread"] = watcher_thread


if __name__ == "__main__" or "currentProgram" in globals():
    run()
'''
        return script

    def sync_to_script(
        self,
        overlay_path: str | None = None,
        out_path: str | None = None,
        dry_run: bool = False,
        watch: bool = False,
        poll_interval_ms: int = 1000,
        verify_conflicts: bool = True,
    ) -> str:
        """
        Ingests overlay from overlay_path (if provided) and generates the Ghidra Python sync script
        (or background live watcher script when `watch=True`). Writes to out_path if given.
        """
        if overlay_path is not None:
            self.load(overlay_path)

        if watch:
            script = self.generate_ghidra_watcher_script(
                poll_interval_ms=poll_interval_ms,
                dry_run=dry_run,
                verify_conflicts=verify_conflicts,
                overlay_path=overlay_path,
            )
        else:
            script = self.generate_ghidra_python_script(dry_run=dry_run)

        if out_path:
            p = Path(out_path)
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(script, encoding="utf-8")
            logger.info(f"Generated Ghidra sync script written to {p}")

        return script


# ------------------------------------------------------------------------------
# Module-level convenience functions & CLI
# ------------------------------------------------------------------------------


def generate_ghidra_python_script(overlay_data: Dict[str, Any], dry_run: bool = False) -> str:
    """Convenience wrapper to generate Ghidra sync script from overlay dict."""
    bridge = OverlaySyncBridge(overlay_data)
    return bridge.generate_ghidra_python_script(dry_run=dry_run)


def generate_ghidra_watcher_script(
    overlay_source: str | Path | Dict[str, Any] | List[Dict[str, Any]],
    poll_interval_ms: int = 1000,
    dry_run: bool = False,
    verify_conflicts: bool = True,
) -> str:
    """Convenience wrapper to generate live CodeBrowser watcher script."""
    bridge = OverlaySyncBridge(overlay_source)
    return bridge.generate_ghidra_watcher_script(
        poll_interval_ms=poll_interval_ms,
        dry_run=dry_run,
        verify_conflicts=verify_conflicts,
    )


def generate_diff_report(overlay_data: Dict[str, Any]) -> str:
    """Convenience wrapper to generate diff summary report from overlay dict."""
    bridge = OverlaySyncBridge(overlay_data)
    return bridge.generate_diff_report()


def sync_to_script(
    overlay_path: str,
    out_path: str | None = None,
    dry_run: bool = False,
    watch: bool = False,
    poll_interval_ms: int = 1000,
    verify_conflicts: bool = True,
) -> str:
    """Convenience wrapper to sync overlay file to a Ghidra Python script."""
    bridge = OverlaySyncBridge()
    return bridge.sync_to_script(
        overlay_path=overlay_path,
        out_path=out_path,
        dry_run=dry_run,
        watch=watch,
        poll_interval_ms=poll_interval_ms,
        verify_conflicts=verify_conflicts,
    )


def build_arg_parser() -> argparse.ArgumentParser:
    """Build CLI argument parser for standalone overlay synchronization and live watch."""
    parser = argparse.ArgumentParser(
        prog="ghidra_gui_overlay_sync",
        description="Synchronize SuperGhidra write-overlay and delta journals into Ghidra GUI scripts.",
    )
    parser.add_argument(
        "--overlay",
        "-i",
        type=Path,
        required=True,
        help="Path to ghidra_overlay.json or .ghidra-delta.jsonl",
    )
    parser.add_argument(
        "--out",
        "-o",
        type=Path,
        help="Output Ghidra Python script path",
    )
    parser.add_argument(
        "--diff",
        action="store_true",
        help="Print summary diff report instead of generating script",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Configure generated script for dry run",
    )
    parser.add_argument(
        "--watch",
        action="store_true",
        help="Generate a live CodeBrowser background watcher script",
    )
    parser.add_argument(
        "--poll-ms",
        type=int,
        default=1000,
        help="Polling interval in ms for --watch mode (default: 1000)",
    )
    parser.add_argument(
        "--no-verify-conflicts",
        action="store_true",
        help="Disable before-state symbol conflict verification in --watch mode",
    )
    return parser


def main(argv: List[str] | None = None) -> int:
    """CLI entry point for `ghidra_gui_overlay_sync`."""
    parser = build_arg_parser()
    args = parser.parse_args(argv)

    if not args.overlay.is_file():
        print(f"Error: overlay file not found: {args.overlay}", file=sys.stderr)
        return 1

    bridge = OverlaySyncBridge(args.overlay)

    if args.diff:
        print(bridge.generate_diff_report())
        return 0

    if args.watch:
        script = bridge.generate_ghidra_watcher_script(
            poll_interval_ms=args.poll_ms,
            dry_run=args.dry_run,
            verify_conflicts=not args.no_verify_conflicts,
            overlay_path=args.overlay,
        )
    else:
        script = bridge.generate_ghidra_python_script(dry_run=args.dry_run)

    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(script, encoding="utf-8")
        print(f"Ghidra sync script written to {args.out}")
    else:
        print(script)
    return 0


if __name__ == "__main__":
    sys.exit(main())
