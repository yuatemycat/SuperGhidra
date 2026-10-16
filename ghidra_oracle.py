#!/usr/bin/env python3
"""
ghidra_oracle.py
================
Dual-mode persistent TCP/JSON daemon (127.0.0.1:5073) and high-speed CLI client
for headless Ghidra / PyGhidra reverse engineering and binary analysis.

Modes:
  1. serve:  Boots OpenJDK 21 + PyGhidra once, loads project in read-only mode,
             warms up DecompInterface and FlatProgramAPI, and listens on TCP 5073.
  2. client: High-speed sub-millisecond CLI queries. Auto-spawns daemon if offline.

Supported Commands:
  - decompile <addr...>          : Decompiled C code with VA and runtime RVA (- 0x100000).
  - vtable <addr> [count=12]     : VTable slots, function names, and runtime hook RVAs.
  - disassemble <addr> [count=30]: Instruction disassembly, hex bytes, and operands.
  - refs <addr> [count=20]       : Incoming cross-references with caller function names.
  - adrp_add <symbol_or_addr>    : Fast PC-relative string & pointer references via page index.
  - opcodes <min> <max>          : Fast opcode enumeration for `mov w0, #imm; ret` dispatcher gates.
  - rva <addr>                   : Instant VA <-> RVA translation (<1 ms, zero JVM call).
  - rename <addr> <name>         : Sets function/symbol rename in JSON write-overlay table.
  - comment <addr> <text>        : Sets address comment in JSON write-overlay table.
  - overlay [list|clear]         : Inspects or clears active JSON write-overlay entries.
  - status                       : Reports daemon uptime, function count, and LRU cache hit rate.
  - stop                         : Cleanly shuts down the daemon.
"""

import os
import sys
import time
import json
import socket
import struct
import logging
import subprocess
import threading
from typing import Dict, Any, List, Optional, Tuple
from collections import OrderedDict

# ==============================================================================
# Configuration & Constants
# ==============================================================================

DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 5073
DEFAULT_IMAGE_BASE = 0x100000  # Default ELF image base offset (- 0x100000)
DAEMON_STARTUP_TIMEOUT = 40.0   # Maximum seconds to wait for daemon JVM warmup
OVERLAY_FILENAME = "ghidra_overlay.json"
DAEMON_LOG_FILENAME = "ghidra_oracle_daemon.log"

PROJECT_CANDIDATES = [
    # 1. Intra-farm libg_analysis
    (
        r"E:\02_Projects\Intra-farm\pyghidra_mcp_projects",
        "libg_analysis",
        "libg_17381_exact.so-3c8447",
    ),
    # 2. Intra-farm hayday_startup
    (
        r"E:\02_Projects\Intra-farm\Emulator\ghidra_proj\hayday_startup",
        "hayday_startup",
        "libg.so",
    ),
    # 3. Intra-farm old_my_project
    (
        r"E:\02_Projects\Intra-farm\pyghidra_mcp_projects\old_my_project",
        "my_project",
        "libndk_translation_orig.so-012633",
    ),
    # 4. SuperGhidra / custom project dir if placed in local directory
    (
        r"E:\02_Projects\SuperGhidra\pyghidra_mcp_projects",
        "libg_analysis",
        "libg_17381_exact.so-3c8447",
    ),
    # 5. Legacy D:\
    (
        r"D:\01_Apps\DevTools\ghidra_projects",
        "hayday_cli",
        "libg.so-b3ae02",
    ),
]

logger = logging.getLogger("ghidra_oracle")


# ==============================================================================
# Environment Configuration
# ==============================================================================

def setup_environment():
    """Configures JDK 21 and Ghidra environment paths before starting PyGhidra."""
    if "GHIDRA_INSTALL_DIR" not in os.environ:
        if os.path.exists(r"E:\03_Devops\Ghidra"):
            os.environ["GHIDRA_INSTALL_DIR"] = r"E:\03_Devops\Ghidra"
        elif os.path.exists(r"D:\01_Apps\DevTools\ghidra_12.1.3_PUBLIC"):
            os.environ["GHIDRA_INSTALL_DIR"] = r"D:\01_Apps\DevTools\ghidra_12.1.3_PUBLIC"

    if "JAVA_HOME" not in os.environ:
        if os.path.exists(r"E:\03_Devops\JDK"):
            os.environ["JAVA_HOME"] = r"E:\03_Devops\JDK"
        elif os.path.exists(r"D:\01_Apps\DevTools\Java21"):
            os.environ["JAVA_HOME"] = r"D:\01_Apps\DevTools\Java21"

    if "JAVA_HOME" in os.environ:
        java_bin = os.path.join(os.environ["JAVA_HOME"], "bin")
        cur_path = os.environ.get("PATH", "")
        if java_bin not in cur_path:
            os.environ["PATH"] = java_bin + ";" + cur_path


# ==============================================================================
# Address Parsing & VA <-> RVA Arithmetic (Zero JVM call, <1ms)
# ==============================================================================

def parse_addr_int(addr_input: Any) -> int:
    """Parses hex or decimal address representations to integer."""
    if isinstance(addr_input, int):
        return addr_input
    s = str(addr_input).strip()
    if s.lower().startswith("0x"):
        return int(s, 16)
    try:
        return int(s, 16) if any(c in "abcdefABCDEF" for c in s) else int(s)
    except ValueError:
        return int(s, 16)


def va_to_rva(va: int, base: int = DEFAULT_IMAGE_BASE) -> int:
    """Translates Ghidra VA to runtime RVA."""
    return va - base if va >= base else va


def rva_to_va(rva: int, base: int = DEFAULT_IMAGE_BASE) -> int:
    """Translates runtime RVA to Ghidra VA."""
    return rva + base if rva < base else rva


def normalize_address_pair(addr_input: Any, base: int = DEFAULT_IMAGE_BASE) -> Tuple[int, int]:
    """Returns (va, rva) pair from either VA or RVA input."""
    val = parse_addr_int(addr_input)
    if val >= base:
        va = val
        rva = val - base
    else:
        rva = val
        va = val + base
    return va, rva


# ==============================================================================
# LRU Cache
# ==============================================================================

class LRUCache:
    """Thread-safe LRU Cache with hit/miss metric tracking."""

    def __init__(self, capacity: int = 512):
        self.capacity = capacity
        self.cache: OrderedDict = OrderedDict()
        self.hits = 0
        self.misses = 0
        self._lock = threading.Lock()

    def get(self, key: Any) -> Optional[Any]:
        with self._lock:
            if key in self.cache:
                self.hits += 1
                self.cache.move_to_end(key)
                return self.cache[key]
            self.misses += 1
            return None

    def put(self, key: Any, value: Any) -> None:
        with self._lock:
            if key in self.cache:
                self.cache.move_to_end(key)
            self.cache[key] = value
            if len(self.cache) > self.capacity:
                self.cache.popitem(last=False)

    def stats(self) -> Dict[str, Any]:
        with self._lock:
            total = self.hits + self.misses
            rate = (self.hits / total * 100.0) if total > 0 else 0.0
            return {
                "size": len(self.cache),
                "capacity": self.capacity,
                "hits": self.hits,
                "misses": self.misses,
                "hit_rate_pct": round(rate, 2),
            }

    def clear(self) -> None:
        with self._lock:
            self.cache.clear()
            self.hits = 0
            self.misses = 0


# ==============================================================================
# In-Memory + JSON Write-Overlay Table
# ==============================================================================

class WriteOverlay:
    """
    Maintains an in-memory and persistent JSON overlay table for symbol renames
    and address comments without modifying the read-only Ghidra project database.
    """

    def __init__(self, filepath: Optional[str] = None):
        if filepath is None:
            base_dir = os.path.dirname(os.path.abspath(__file__))
            filepath = os.path.join(base_dir, OVERLAY_FILENAME)
        self.filepath = filepath
        self._lock = threading.Lock()
        self.renames: Dict[str, str] = {}
        self.comments: Dict[str, str] = {}
        self.load()

    def load(self) -> None:
        with self._lock:
            if os.path.exists(self.filepath):
                try:
                    with open(self.filepath, "r", encoding="utf-8") as f:
                        data = json.load(f)
                        self.renames = data.get("renames", {})
                        self.comments = data.get("comments", {})
                except Exception as e:
                    logger.warning(f"Failed to load write-overlay from {self.filepath}: {e}")

    def save(self) -> None:
        with self._lock:
            try:
                temp_file = self.filepath + ".tmp"
                with open(temp_file, "w", encoding="utf-8") as f:
                    json.dump(
                        {"renames": self.renames, "comments": self.comments},
                        f,
                        indent=2,
                    )
                if os.path.exists(self.filepath):
                    os.replace(temp_file, self.filepath)
                else:
                    os.rename(temp_file, self.filepath)
            except Exception as e:
                logger.error(f"Failed to save write-overlay to {self.filepath}: {e}")

    def set_rename(self, addr_key: str, name: str) -> None:
        with self._lock:
            self.renames[addr_key.upper()] = name
        self.save()

    def set_comment(self, addr_key: str, comment: str) -> None:
        with self._lock:
            self.comments[addr_key.upper()] = comment
        self.save()

    def get_rename(self, va: int, rva: int) -> Optional[str]:
        with self._lock:
            for k in [f"0x{va:08X}", f"0x{rva:08X}", hex(va).upper(), hex(rva).upper()]:
                if k in self.renames:
                    return self.renames[k]
        return None

    def get_comment(self, va: int, rva: int) -> Optional[str]:
        with self._lock:
            for k in [f"0x{va:08X}", f"0x{rva:08X}", hex(va).upper(), hex(rva).upper()]:
                if k in self.comments:
                    return self.comments[k]
        return None

    def clear(self) -> None:
        with self._lock:
            self.renames.clear()
            self.comments.clear()
        self.save()

    def to_dict(self) -> Dict[str, Any]:
        with self._lock:
            return {
                "renames": dict(self.renames),
                "comments": dict(self.comments),
                "file": self.filepath,
            }


# ==============================================================================
# Ghidra Oracle Session (Headless PyGhidra Core)
# ==============================================================================

class GhidraOracleSession:
    """Manages the single loaded Ghidra project in read-only mode."""

    def __init__(
        self,
        project_dir: Optional[str] = None,
        project_name: Optional[str] = None,
        program_name: Optional[str] = None,
    ):
        self.project_dir = project_dir
        self.project_name = project_name
        self.program_name = program_name

        self.project = None
        self.program = None
        self.flat_api = None
        self.decompiler = None
        self.monitor = None
        self.image_base = DEFAULT_IMAGE_BASE

        self.start_time = time.time()
        self.decompile_cache = LRUCache(256)
        self.vtable_cache = LRUCache(512)
        self.overlay = WriteOverlay()

        # Pre-indexed opcode gates: list of (imm, va, rva)
        self._opcode_gates: List[Tuple[int, int, int]] = []
        # Pre-indexed ADRP pages: dict mapping page_va -> list of (insn_va, dest_reg, paired_insn_info)
        self._adrp_pages: Dict[int, List[Dict[str, Any]]] = {}

    def clean_locks(self, proj_dir: str, proj_name: str) -> None:
        """Removes orphaned lock files to prevent lock collisions."""
        for lock_name in [f"{proj_name}.lock", f"{proj_name}.lock~"]:
            p = os.path.join(proj_dir, lock_name)
            if os.path.exists(p):
                try:
                    os.remove(p)
                except Exception:
                    pass

    def initialize(self) -> None:
        """Boots PyGhidra and opens the project in read-only mode."""
        setup_environment()
        import pyghidra
        pyghidra.start(False)

        from ghidra.base.project import GhidraProject
        from ghidra.program.flatapi import FlatProgramAPI
        from ghidra.app.decompiler import DecompInterface, DecompileOptions
        from ghidra.util.task import ConsoleTaskMonitor

        candidates = []
        if self.project_dir and self.project_name:
            candidates.append((self.project_dir, self.project_name, self.program_name))
        candidates.extend(PROJECT_CANDIDATES)

        opened = False
        last_err = None
        for p_dir, p_name, prg_name in candidates:
            if not os.path.exists(p_dir):
                continue
            self.clean_locks(p_dir, p_name)
            try:
                # restoreProject=False prevents lock collisions and overhead
                proj = GhidraProject.openProject(p_dir, p_name, False)
                prog = None
                if prg_name:
                    try:
                        prog = proj.openProgram("/", prg_name, False)
                    except Exception:
                        pass
                if prog is None:
                    # Pick first program from root folder
                    files = proj.getRootFolder().getFiles()
                    if files:
                        prog = proj.openProgram("/", files[0].getName(), False)

                if prog is not None:
                    self.project = proj
                    self.program = prog
                    self.project_dir = p_dir
                    self.project_name = p_name
                    self.program_name = prog.getName()
                    self.image_base = prog.getImageBase().getOffset()
                    opened = True
                    logger.info(
                        f"Loaded Ghidra program '{self.program_name}' from project '{p_name}' at {p_dir}"
                    )
                    break
                else:
                    proj.close()
            except Exception as e:
                last_err = e
                continue

        if not opened:
            raise RuntimeError(
                f"Could not open any Ghidra project in read-only mode! Last error: {last_err}"
            )

        self.flat_api = FlatProgramAPI(self.program)
        self.monitor = ConsoleTaskMonitor()

        # Warm up decompiler
        self.decompiler = DecompInterface()
        options = DecompileOptions()
        self.decompiler.setOptions(options)
        self.decompiler.openProgram(self.program)

        # Warm up & build fast indexes (opcodes & ADRP pages)
        self._build_fast_indexes()

    def _build_fast_indexes(self) -> None:
        """Extracts executable segments into memory to build instant opcode & ADRP tables."""
        from java.lang.reflect import Array
        from java.lang import Byte
        import re

        try:
            mem = self.program.getMemory()
            b = mem.getBlock(self.flat_api.toAddr(self.image_base))
            if not b:
                # Find first executable or main segment
                for blk in mem.getBlocks():
                    if blk.getSize() > 1024 * 1024:
                        b = blk
                        break
            if not b:
                return

            size = int(b.getSize())
            jbytes = Array.newInstance(Byte.TYPE, size)
            mem.getBytes(b.getStart(), jbytes)
            raw = bytes(jbytes)
            base_va = b.getStart().getOffset()

            # 1. Opcode gates: movz w0, #imm; ret
            # In ARM64: [b0, b1, b2, 0x52], [0xc0, 0x03, 0x5f, 0xd6]
            pattern_op = re.compile(b"([\x00-\xe0][\x00-\xff][\x80-\x9f]\x52)\xc0\x03\x5f\xd6")
            gates = []
            for m in pattern_op.finditer(raw):
                offset = m.start()
                b0 = raw[offset]
                b1 = raw[offset + 1]
                b2 = raw[offset + 2]
                imm = ((b0 >> 5) & 7) | (b1 << 3) | ((b2 & 0x1f) << 11)
                va = base_va + offset
                rva = va - self.image_base
                gates.append((imm, va, rva))
            self._opcode_gates = gates

            # 2. ADRP instructions: 0x90000000 mask 0x9F000000
            # Scan 4-byte aligned instructions for ADRP
            adrp_dict: Dict[int, List[Dict[str, Any]]] = {}
            for offset in range(0, size - 8, 4):
                inst = struct.unpack_from("<I", raw, offset)[0]
                if (inst & 0x9F000000) == 0x90000000:
                    rd = inst & 0x1F
                    immlo = (inst >> 29) & 0x3
                    immhi = (inst >> 5) & 0x7FFFF
                    imm = (immhi << 2) | immlo
                    if imm & (1 << 20):
                        imm -= (1 << 21)
                    pc = base_va + offset
                    pc_page = pc & ~0xFFF
                    target_page = pc_page + (imm << 12)

                    # Inspect next instruction (paired add or ldr)
                    next_inst = struct.unpack_from("<I", raw, offset + 4)[0]
                    paired_info = None
                    paired_offset = None
                    # add xd, xd, #imm12: mask 0xFF800000 == 0x91000000 or 0x11000000
                    if (next_inst & 0x7F800000) == 0x11000000 and ((next_inst >> 5) & 0x1F) == rd:
                        paired_offset = (next_inst >> 10) & 0xFFF
                        paired_info = f"add x{next_inst & 0x1F}, x{rd}, #0x{paired_offset:x}"
                    # ldr xd, [xd, #imm12]: mask 0xFFC00000 == 0xF9400000
                    elif (next_inst & 0xFFC00000) == 0xF9400000 and ((next_inst >> 5) & 0x1F) == rd:
                        shift = (next_inst >> 30) & 0x3
                        paired_offset = ((next_inst >> 10) & 0xFFF) << shift
                        paired_info = f"ldr x{next_inst & 0x1F}, [x{rd}, #0x{paired_offset:x}]"

                    if target_page not in adrp_dict:
                        adrp_dict[target_page] = []
                    adrp_dict[target_page].append({
                        "insn_va": pc,
                        "insn_rva": pc - self.image_base,
                        "rd": rd,
                        "target_page": target_page,
                        "paired_offset": paired_offset,
                        "paired_info": paired_info,
                    })
            self._adrp_pages = adrp_dict
            logger.info(
                f"Warmed up indexes: {len(self._opcode_gates)} opcode gates, "
                f"{len(self._adrp_pages)} unique ADRP target pages indexed."
            )
        except Exception as e:
            logger.warning(f"Error during fast index building: {e}")

    def close(self) -> None:
        """Cleanly releases program and closes the project."""
        if self.decompiler is not None:
            try:
                self.decompiler.dispose()
            except Exception:
                pass
            self.decompiler = None

        if self.project is not None and self.program is not None:
            try:
                self.project.close(self.program)
            except Exception:
                pass
            self.program = None

        if self.project is not None:
            try:
                self.project.close()
            except Exception:
                pass
            self.project = None

    # --------------------------------------------------------------------------
    # Core Queries
    # --------------------------------------------------------------------------

    def query_rva(self, addr_input: Any) -> Dict[str, Any]:
        """Instant VA <-> RVA translation (<1 ms, zero JVM call)."""
        t0 = time.perf_counter()
        va, rva = normalize_address_pair(addr_input, self.image_base)
        t_ms = (time.perf_counter() - t0) * 1000.0
        return {
            "status": "ok",
            "va": f"0x{va:08X}",
            "rva": f"0x{rva:08X}",
            "va_int": va,
            "rva_int": rva,
            "image_base": f"0x{self.image_base:08X}",
            "time_ms": round(t_ms, 4),
        }

    def query_decompile(self, targets: List[Any]) -> Dict[str, Any]:
        """Returns decompiled C code, mapping Ghidra VA and runtime RVA."""
        results = []
        for t in targets:
            va, rva = normalize_address_pair(t, self.image_base)
            cached = self.decompile_cache.get(va)
            if cached is not None:
                cached_copy = dict(cached)
                cached_copy["cached"] = True
                results.append(cached_copy)
                continue

            addr = self.flat_api.toAddr(va)
            fm = self.program.getFunctionManager()
            func = fm.getFunctionAt(addr)
            if not func:
                func = fm.getFunctionContaining(addr)

            # In read-only mode, use transient transaction if function needs creation
            tx = self.program.startTransaction("decompile_transient")
            try:
                if not func:
                    self.flat_api.disassemble(addr)
                    func = fm.getFunctionAt(addr) or fm.getFunctionContaining(addr)
                    if not func:
                        func = self.flat_api.createFunction(addr, f"func_{va:08X}")

                if func is None:
                    entry = {
                        "target": str(t),
                        "va": f"0x{va:08X}",
                        "rva": f"0x{rva:08X}",
                        "error": "Could not locate or disassemble function at address",
                    }
                    results.append(entry)
                    continue

                res = self.decompiler.decompileFunction(func, 45, self.monitor)
                if res.decompileCompleted():
                    c_code = res.getDecompiledFunction().getC()
                    entry_addr = func.getEntryPoint().getOffset()
                    entry_rva = entry_addr - self.image_base
                    fn_name = self.overlay.get_rename(entry_addr, entry_rva) or func.getName()
                    comment = self.overlay.get_comment(entry_addr, entry_rva)

                    data = {
                        "target": str(t),
                        "va": f"0x{va:08X}",
                        "rva": f"0x{rva:08X}",
                        "name": fn_name,
                        "entry_va": f"0x{entry_addr:08X}",
                        "entry_rva": f"0x{entry_rva:08X}",
                        "code": c_code,
                        "comment": comment,
                        "cached": False,
                    }
                    self.decompile_cache.put(va, data)
                    results.append(data)
                else:
                    results.append({
                        "target": str(t),
                        "va": f"0x{va:08X}",
                        "rva": f"0x{rva:08X}",
                        "error": res.getErrorMessage(),
                    })
            finally:
                # Rollback leaves project DB untouched
                self.program.endTransaction(tx, False)

        return {"status": "ok", "results": results}

    def query_vtable(self, target: Any, count: int = 12) -> Dict[str, Any]:
        """Dumps VTable slots, function names, and runtime hook RVAs."""
        vt_va, vt_rva = normalize_address_pair(target, self.image_base)
        cache_key = (vt_va, count)
        cached = self.vtable_cache.get(cache_key)
        if cached is not None:
            c = dict(cached)
            c["cached"] = True
            return c

        addr = self.flat_api.toAddr(vt_va)
        mem = self.program.getMemory()
        fm = self.program.getFunctionManager()
        af = self.program.getAddressFactory().getDefaultAddressSpace()

        entries = []
        for i in range(count):
            slot_va = vt_va + (i * 8)
            slot_rva = vt_rva + (i * 8)
            try:
                fn_ptr = mem.getLong(af.getAddress(slot_va))
                fn_va = fn_ptr
                fn_rva = fn_ptr - self.image_base if fn_ptr >= self.image_base else fn_ptr
                fn = fm.getFunctionAt(af.getAddress(fn_va))
                fn_name = (
                    self.overlay.get_rename(fn_va, fn_rva)
                    or (fn.getName() if fn else None)
                    or "None"
                )
                slot_comment = self.overlay.get_comment(slot_va, slot_rva)
                entries.append({
                    "slot": i,
                    "slot_va": f"0x{slot_va:08X}",
                    "slot_rva": f"0x{slot_rva:08X}",
                    "fn_va": f"0x{fn_va:08X}",
                    "fn_rva": f"0x{fn_rva:08X}",
                    "name": fn_name,
                    "comment": slot_comment,
                })
            except Exception as e:
                entries.append({
                    "slot": i,
                    "slot_va": f"0x{slot_va:08X}",
                    "slot_rva": f"0x{slot_rva:08X}",
                    "error": str(e),
                })

        vt_name = self.overlay.get_rename(vt_va, vt_rva)
        result = {
            "status": "ok",
            "vtable_va": f"0x{vt_va:08X}",
            "vtable_rva": f"0x{vt_rva:08X}",
            "name": vt_name,
            "count": count,
            "entries": entries,
            "cached": False,
        }
        self.vtable_cache.put(cache_key, result)
        return result

    def query_disassemble(self, target: Any, count: int = 30) -> Dict[str, Any]:
        """Returns instruction disassembly, hex bytes, and operands."""
        va, rva = normalize_address_pair(target, self.image_base)
        addr = self.flat_api.toAddr(va)
        listing = self.program.getListing()

        tx = self.program.startTransaction("disasm_transient")
        try:
            if listing.getInstructionAt(addr) is None:
                self.flat_api.disassemble(addr)

            rows = []
            for insn in listing.getInstructions(addr, True):
                if len(rows) >= count:
                    break
                insn_va = insn.getAddress().getOffset()
                insn_rva = insn_va - self.image_base
                raw_hex = bytes([b & 0xFF for b in insn.getBytes()]).hex()
                ops = [
                    insn.getDefaultOperandRepresentation(i)
                    for i in range(insn.getNumOperands())
                ]
                comment = self.overlay.get_comment(insn_va, insn_rva)
                rows.append({
                    "va": f"0x{insn_va:08X}",
                    "rva": f"0x{insn_rva:08X}",
                    "bytes": raw_hex,
                    "mnemonic": insn.getMnemonicString(),
                    "operands": ", ".join(filter(None, ops)),
                    "comment": comment,
                })
        finally:
            self.program.endTransaction(tx, False)

        return {
            "status": "ok",
            "target_va": f"0x{va:08X}",
            "target_rva": f"0x{rva:08X}",
            "count": len(rows),
            "instructions": rows,
        }

    def query_refs(self, target: Any, max_count: int = 20) -> Dict[str, Any]:
        """Queries incoming cross-references with caller function names."""
        va, rva = normalize_address_pair(target, self.image_base)
        addr = self.flat_api.toAddr(va)
        ref_mgr = self.program.getReferenceManager()
        fm = self.program.getFunctionManager()

        refs = list(ref_mgr.getReferencesTo(addr))
        entries = []
        for r in refs[:max_count]:
            from_addr = r.getFromAddress()
            from_va = from_addr.getOffset()
            from_rva = from_va - self.image_base
            fn = fm.getFunctionContaining(from_addr)
            caller_name = None
            caller_va = None
            caller_rva = None
            if fn:
                caller_va = fn.getEntryPoint().getOffset()
                caller_rva = caller_va - self.image_base
                caller_name = self.overlay.get_rename(caller_va, caller_rva) or fn.getName()

            comment = self.overlay.get_comment(from_va, from_rva)
            entries.append({
                "from_va": f"0x{from_va:08X}",
                "from_rva": f"0x{from_rva:08X}",
                "ref_type": str(r.getReferenceType()),
                "caller_name": caller_name or "None",
                "caller_entry_va": f"0x{caller_va:08X}" if caller_va else None,
                "caller_entry_rva": f"0x{caller_rva:08X}" if caller_rva else None,
                "comment": comment,
            })

        return {
            "status": "ok",
            "target_va": f"0x{va:08X}",
            "target_rva": f"0x{rva:08X}",
            "total_refs": len(refs),
            "count": len(entries),
            "references": entries,
        }

    def query_adrp_add(self, symbol_or_addr: str) -> Dict[str, Any]:
        """Fast lookup for PC-relative string and pointer references via cached page index."""
        target_va = None
        target_sym = None

        # Check if input is symbol name
        s = symbol_or_addr.strip()
        is_num = False
        try:
            if s.lower().startswith("0x") or all(c in "0123456789abcdefABCDEF" for c in s):
                target_va, _ = normalize_address_pair(s, self.image_base)
                is_num = True
        except Exception:
            pass

        if not is_num:
            target_sym = s
            # Search symbol table
            sym_tab = self.program.getSymbolTable()
            syms = list(sym_tab.getGlobalSymbols(s))
            if syms:
                target_va = syms[0].getAddress().getOffset()
            else:
                # Check write-overlay
                for k, v in self.overlay.renames.items():
                    if v == s:
                        target_va, _ = normalize_address_pair(k, self.image_base)
                        break

        if target_va is None:
            return {"status": "error", "message": f"Symbol or address '{symbol_or_addr}' could not be resolved"}

        target_rva = target_va - self.image_base
        target_page = target_va & ~0xFFF
        target_offset = target_va & 0xFFF

        fm = self.program.getFunctionManager()
        ref_mgr = self.program.getReferenceManager()

        # 1. References from Ghidra reference manager
        direct_refs = []
        for r in ref_mgr.getReferencesTo(self.flat_api.toAddr(target_va)):
            f_addr = r.getFromAddress()
            f_va = f_addr.getOffset()
            f_rva = f_va - self.image_base
            fn = fm.getFunctionContaining(f_addr)
            direct_refs.append({
                "source": "ReferenceManager",
                "insn_va": f"0x{f_va:08X}",
                "insn_rva": f"0x{f_rva:08X}",
                "ref_type": str(r.getReferenceType()),
                "caller": fn.getName() if fn else "None",
            })

        # 2. Fast Page Index lookup
        page_refs = []
        if target_page in self._adrp_pages:
            for item in self._adrp_pages[target_page]:
                p_offset = item.get("paired_offset")
                is_exact = (p_offset == target_offset)
                f_va = item["insn_va"]
                fn = fm.getFunctionContaining(self.flat_api.toAddr(f_va))
                page_refs.append({
                    "source": "ADRPPageIndex",
                    "insn_va": f"0x{f_va:08X}",
                    "insn_rva": f"0x{item['insn_rva']:08X}",
                    "register": f"x{item['rd']}",
                    "target_page": f"0x{target_page:08X}",
                    "paired_insn": item.get("paired_info"),
                    "exact_offset_match": is_exact,
                    "caller": fn.getName() if fn else "None",
                })

        return {
            "status": "ok",
            "symbol": target_sym,
            "target_va": f"0x{target_va:08X}",
            "target_rva": f"0x{target_rva:08X}",
            "target_page": f"0x{target_page:08X}",
            "target_offset": f"0x{target_offset:03X}",
            "direct_refs_count": len(direct_refs),
            "page_refs_count": len(page_refs),
            "direct_references": direct_refs,
            "page_references": page_refs,
        }

    def query_opcodes(self, min_op: int, max_op: int) -> Dict[str, Any]:
        """Fast opcode enumeration for `mov w0, #imm; ret` dispatcher gates."""
        matches = []
        fm = self.program.getFunctionManager()
        for imm, va, rva in self._opcode_gates:
            if min_op <= imm <= max_op:
                fn = fm.getFunctionAt(self.flat_api.toAddr(va))
                fn_name = (
                    self.overlay.get_rename(va, rva)
                    or (fn.getName() if fn else None)
                )
                comment = self.overlay.get_comment(va, rva)
                matches.append({
                    "opcode": imm,
                    "opcode_hex": f"0x{imm:04X}",
                    "va": f"0x{va:08X}",
                    "rva": f"0x{rva:08X}",
                    "func_name": fn_name,
                    "comment": comment,
                    "asm": f"mov w0, #0x{imm:x}; ret",
                })

        matches.sort(key=lambda x: x["opcode"])
        return {
            "status": "ok",
            "min": min_op,
            "max": max_op,
            "count": len(matches),
            "total_indexed_gates": len(self._opcode_gates),
            "gates": matches,
        }

    def query_status(self) -> Dict[str, Any]:
        """Reports daemon uptime, function count, and LRU cache hit rate."""
        uptime = time.time() - self.start_time
        fm = self.program.getFunctionManager()
        func_count = fm.getFunctionCount()

        d_stats = self.decompile_cache.stats()
        v_stats = self.vtable_cache.stats()
        total_hits = d_stats["hits"] + v_stats["hits"]
        total_queries = total_hits + d_stats["misses"] + v_stats["misses"]
        overall_hit_rate = (
            round((total_hits / total_queries * 100.0), 2)
            if total_queries > 0
            else 0.0
        )

        return {
            "status": "ok",
            "uptime_seconds": round(uptime, 2),
            "uptime_human": f"{int(uptime // 3600)}h {int((uptime % 3600) // 60)}m {int(uptime % 60)}s",
            "project_name": self.project_name,
            "project_dir": self.project_dir,
            "program_name": self.program_name,
            "image_base": f"0x{self.image_base:08X}",
            "function_count": func_count,
            "indexed_opcode_gates": len(self._opcode_gates),
            "indexed_adrp_pages": len(self._adrp_pages),
            "decompile_cache": d_stats,
            "vtable_cache": v_stats,
            "overall_hit_rate_pct": overall_hit_rate,
            "overlay_renames_count": len(self.overlay.renames),
            "overlay_comments_count": len(self.overlay.comments),
        }


# ==============================================================================
# TCP/JSON Daemon Server
# ==============================================================================

class GhidraDaemonServer:
    """Threaded TCP server processing newline-delimited JSON RPC requests."""

    def __init__(self, session: GhidraOracleSession, host: str = DEFAULT_HOST, port: int = DEFAULT_PORT):
        self.session = session
        self.host = host
        self.port = port
        self.server_socket = None
        self.running = False
        self._threads: List[threading.Thread] = []

    def start(self) -> None:
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_socket.bind((self.host, self.port))
        self.server_socket.listen(16)
        self.running = True
        logger.info(f"Ghidra Oracle daemon listening on {self.host}:{self.port}")
        print(f"[*] Ghidra Oracle daemon online & listening on {self.host}:{self.port}")

        while self.running:
            try:
                conn, addr = self.server_socket.accept()
                t = threading.Thread(target=self._handle_client, args=(conn, addr), daemon=True)
                t.start()
                self._threads.append(t)
            except OSError:
                break

    def stop(self) -> None:
        self.running = False
        if self.server_socket:
            try:
                self.server_socket.close()
            except Exception:
                pass
        self.session.close()
        logger.info("Ghidra Oracle daemon shut down cleanly.")

    def _handle_client(self, conn: socket.socket, addr: Any) -> None:
        with conn:
            conn.settimeout(60.0)
            buffer = ""
            while self.running:
                try:
                    data = conn.recv(8192)
                    if not data:
                        break
                    buffer += data.decode("utf-8")
                    while "\n" in buffer:
                        line, buffer = buffer.split("\n", 1)
                        line = line.strip()
                        if not line:
                            continue
                        response = self._dispatch_command(line)
                        conn.sendall((json.dumps(response) + "\n").encode("utf-8"))
                        if response.get("should_stop"):
                            threading.Thread(target=self.stop, daemon=True).start()
                            return
                except socket.timeout:
                    break
                except Exception as e:
                    err_resp = {"status": "error", "message": str(e)}
                    try:
                        conn.sendall((json.dumps(err_resp) + "\n").encode("utf-8"))
                    except Exception:
                        pass
                    break

    def _dispatch_command(self, raw_line: str) -> Dict[str, Any]:
        try:
            req = json.loads(raw_line)
        except Exception:
            return {"status": "error", "message": "Invalid JSON payload"}

        cmd = req.get("cmd", "").lower()
        args = req.get("args", {})

        try:
            if cmd == "rva":
                addr = args.get("addr") or req.get("addr")
                return self.session.query_rva(addr)
            elif cmd == "decompile":
                targets = args.get("targets") or req.get("targets") or [args.get("addr")]
                return self.session.query_decompile(targets)
            elif cmd == "vtable":
                addr = args.get("addr") or req.get("addr")
                count = int(args.get("count", req.get("count", 12)))
                return self.session.query_vtable(addr, count)
            elif cmd == "disassemble":
                addr = args.get("addr") or req.get("addr")
                count = int(args.get("count", req.get("count", 30)))
                return self.session.query_disassemble(addr, count)
            elif cmd in ("refs", "references"):
                addr = args.get("addr") or req.get("addr")
                count = int(args.get("count", req.get("count", 20)))
                return self.session.query_refs(addr, count)
            elif cmd == "adrp_add":
                target = args.get("target") or req.get("target") or args.get("addr")
                return self.session.query_adrp_add(str(target))
            elif cmd == "opcodes":
                min_op = int(args.get("min", req.get("min", 0)))
                max_op = int(args.get("max", req.get("max", 1000)))
                return self.session.query_opcodes(min_op, max_op)
            elif cmd == "rename":
                addr = args.get("addr")
                name = args.get("name")
                va, rva = normalize_address_pair(addr, self.session.image_base)
                key = f"0x{va:08X}"
                self.session.overlay.set_rename(key, name)
                return {"status": "ok", "message": f"Renamed {key} to '{name}'"}
            elif cmd == "comment":
                addr = args.get("addr")
                comment = args.get("comment")
                va, rva = normalize_address_pair(addr, self.session.image_base)
                key = f"0x{va:08X}"
                self.session.overlay.set_comment(key, comment)
                return {"status": "ok", "message": f"Set comment on {key}"}
            elif cmd == "overlay":
                action = args.get("action", "list")
                if action == "clear":
                    self.session.overlay.clear()
                    return {"status": "ok", "message": "Write-overlay table cleared"}
                return {"status": "ok", "overlay": self.session.overlay.to_dict()}
            elif cmd == "status":
                return self.session.query_status()
            elif cmd == "ping":
                return {"status": "ok", "message": "pong"}
            elif cmd == "stop":
                return {"status": "ok", "message": "Daemon shutting down", "should_stop": True}
            else:
                return {"status": "error", "message": f"Unknown command '{cmd}'"}
        except Exception as e:
            logger.exception(f"Error handling command '{cmd}': {e}")
            return {"status": "error", "message": str(e)}


# ==============================================================================
# Client & Auto-Spawn Daemon Helper
# ==============================================================================

def is_daemon_online(host: str = DEFAULT_HOST, port: int = DEFAULT_PORT) -> bool:
    """Checks if the TCP daemon is reachable."""
    try:
        with socket.create_connection((host, port), timeout=0.5):
            return True
    except (ConnectionRefusedError, socket.timeout, OSError):
        return False


def spawn_background_daemon(host: str = DEFAULT_HOST, port: int = DEFAULT_PORT) -> None:
    """Spawns persistent background daemon if offline."""
    script_path = os.path.abspath(__file__)
    log_path = os.path.join(os.path.dirname(script_path), DAEMON_LOG_FILENAME)

    cmd = [sys.executable, script_path, "serve", "--host", host, "--port", str(port)]
    print(f"[*] Spawning background Ghidra daemon on {host}:{port}...")

    if os.name == "nt":
        creationflags = (
            subprocess.CREATE_NEW_PROCESS_GROUP
            | subprocess.DETACHED_PROCESS
            | getattr(subprocess, "CREATE_NO_WINDOW", 0x08000000)
        )
        with open(log_path, "a", encoding="utf-8") as log_f:
            subprocess.Popen(
                cmd,
                creationflags=creationflags,
                stdout=log_f,
                stderr=log_f,
                close_fds=True,
            )
    else:
        with open(log_path, "a", encoding="utf-8") as log_f:
            subprocess.Popen(
                cmd,
                stdout=log_f,
                stderr=log_f,
                close_fds=True,
                start_new_session=True,
            )


def wait_for_daemon_ready(host: str = DEFAULT_HOST, port: int = DEFAULT_PORT, timeout: float = DAEMON_STARTUP_TIMEOUT) -> bool:
    """Waits for the daemon to boot OpenJDK + PyGhidra and accept TCP connections."""
    t0 = time.time()
    print("[*] Warming up JVM & Ghidra project (this takes ~10-15s on first boot)", end="", flush=True)
    while time.time() - t0 < timeout:
        if is_daemon_online(host, port):
            print(" [OK]")
            return True
        print(".", end="", flush=True)
        time.sleep(1.0)
    print(" [TIMEOUT]")
    return False


def client_send_request(
    cmd: str,
    args: Dict[str, Any],
    host: str = DEFAULT_HOST,
    port: int = DEFAULT_PORT,
    auto_spawn: bool = True,
) -> Dict[str, Any]:
    """Sends JSON-RPC command to the daemon, auto-spawning if offline."""
    # Fast path for rva: zero JVM required
    if cmd == "rva" and not is_daemon_online(host, port):
        addr = args.get("addr")
        va, rva = normalize_address_pair(addr, DEFAULT_IMAGE_BASE)
        return {
            "status": "ok",
            "va": f"0x{va:08X}",
            "rva": f"0x{rva:08X}",
            "va_int": va,
            "rva_int": rva,
            "image_base": f"0x{DEFAULT_IMAGE_BASE:08X}",
            "time_ms": 0.05,
            "local_fallback": True,
        }

    if not is_daemon_online(host, port):
        if cmd == "stop":
            return {"status": "ok", "message": "Ghidra daemon is already offline."}
        if not auto_spawn:
            return {"status": "error", "message": f"Ghidra daemon offline on {host}:{port}"}

        spawn_background_daemon(host, port)
        if not wait_for_daemon_ready(host, port):
            return {
                "status": "error",
                "message": f"Daemon failed to start within {DAEMON_STARTUP_TIMEOUT} seconds. Check {DAEMON_LOG_FILENAME}",
            }

    payload = json.dumps({"cmd": cmd, "args": args}) + "\n"
    with socket.create_connection((host, port), timeout=60.0) as s:
        s.sendall(payload.encode("utf-8"))
        buf = ""
        while True:
            chunk = s.recv(8192)
            if not chunk:
                break
            buf += chunk.decode("utf-8")
            if "\n" in buf:
                line = buf.split("\n", 1)[0]
                return json.loads(line)

    return {"status": "error", "message": "No response from daemon"}


# ==============================================================================
# CLI Pretty Printers
# ==============================================================================

def print_decompile_result(res: Dict[str, Any]) -> None:
    if res.get("status") != "ok":
        print(f"ERROR: {res.get('message')}")
        return
    for item in res.get("results", []):
        t = item.get("target")
        va = item.get("va")
        rva = item.get("rva")
        name = item.get("name", "Unknown")
        entry_rva = item.get("entry_rva", rva)
        cached_str = " (CACHED)" if item.get("cached") else ""
        print(f"\n{'='*80}")
        print(f"=== DECOMPILED {t} ({name} @ VA: {va} | RVA: {rva} | Hook RVA: {entry_rva}){cached_str} ===")
        print(f"{'='*80}")
        if "error" in item:
            print(f"ERROR: {item['error']}")
        else:
            print(item.get("code", ""))


def print_vtable_result(res: Dict[str, Any]) -> None:
    if res.get("status") != "ok":
        print(f"ERROR: {res.get('message')}")
        return
    vt_va = res.get("vtable_va")
    vt_rva = res.get("vtable_rva")
    cnt = res.get("count")
    cached_str = " (CACHED)" if res.get("cached") else ""
    print(f"\n{'='*85}")
    print(f"=== VTABLE @ {vt_va} (RVA: {vt_rva}) [{cnt} entries]{cached_str} ===")
    print(f"{'='*85}")
    print(f"{'Slot':<6} {'Slot RVA':<12} {'Target VA':<12} {'Runtime Hook RVA':<18} {'Function Name / Symbol'}")
    print(f"{'-'*85}")
    for e in res.get("entries", []):
        slot = f"[{e.get('slot'):2d}]"
        s_rva = e.get("slot_rva", "")
        fn_va = e.get("fn_va", "")
        fn_rva = e.get("fn_rva", "")
        name = e.get("name", "")
        comment = f" ; {e['comment']}" if e.get("comment") else ""
        print(f"{slot:<6} {s_rva:<12} {fn_va:<12} {fn_rva:<18} {name}{comment}")


def print_disasm_result(res: Dict[str, Any]) -> None:
    if res.get("status") != "ok":
        print(f"ERROR: {res.get('message')}")
        return
    t_va = res.get("target_va")
    t_rva = res.get("target_rva")
    cnt = res.get("count")
    print(f"\n{'='*85}")
    print(f"=== DISASSEMBLY @ {t_va} (RVA: {t_rva}) [{cnt} instructions] ===")
    print(f"{'='*85}")
    print(f"{'VA':<12} {'RVA':<12} {'Hex Bytes':<10} {'Mnemonic':<8} {'Operands'}")
    print(f"{'-'*85}")
    for insn in res.get("instructions", []):
        va = insn.get("va")
        rva = insn.get("rva")
        raw = insn.get("bytes")
        mnem = insn.get("mnemonic")
        ops = insn.get("operands")
        comment = f" ; {insn['comment']}" if insn.get("comment") else ""
        print(f"{va:<12} {rva:<12} {raw:<10} {mnem:<8} {ops}{comment}")


def print_refs_result(res: Dict[str, Any]) -> None:
    if res.get("status") != "ok":
        print(f"ERROR: {res.get('message')}")
        return
    t_va = res.get("target_va")
    t_rva = res.get("target_rva")
    tot = res.get("total_refs")
    print(f"\n{'='*85}")
    print(f"=== REFERENCES TO {t_va} (RVA: {t_rva}) [{tot} total] ===")
    print(f"{'='*85}")
    for r in res.get("references", []):
        f_va = r.get("from_va")
        f_rva = r.get("from_rva")
        rtype = r.get("ref_type")
        cname = r.get("caller_name")
        c_rva = r.get("caller_entry_rva")
        c_str = f" in {cname} (Hook RVA: {c_rva})" if cname != "None" else ""
        print(f"From {f_va} (RVA: {f_rva}) [{rtype}]{c_str}")


def print_adrp_add_result(res: Dict[str, Any]) -> None:
    if res.get("status") != "ok":
        print(f"ERROR: {res.get('message')}")
        return
    t_va = res.get("target_va")
    t_rva = res.get("target_rva")
    sym = res.get("symbol") or "Unknown"
    d_cnt = res.get("direct_refs_count", 0)
    p_cnt = res.get("page_refs_count", 0)
    print(f"\n{'='*85}")
    print(f"=== PC-RELATIVE ADRP/ADD REFERENCES FOR {t_va} (RVA: {t_rva} | {sym}) ===")
    print(f"Target Page: {res.get('target_page')} | Offset: {res.get('target_offset')} | Direct Xrefs: {d_cnt} | Page Hits: {p_cnt}")
    print(f"{'='*85}")
    if res.get("page_references"):
        print(f"{'Insn VA':<12} {'Insn RVA':<12} {'Reg':<5} {'Paired Insn':<30} {'Caller Function'}")
        print(f"{'-'*85}")
        for p in res.get("page_references", []):
            exact = " [EXACT MATCH]" if p.get("exact_offset_match") else ""
            print(f"{p['insn_va']:<12} {p['insn_rva']:<12} {p['register']:<5} {str(p['paired_insn']):<30} {p['caller']}{exact}")


def print_opcodes_result(res: Dict[str, Any]) -> None:
    if res.get("status") != "ok":
        print(f"ERROR: {res.get('message')}")
        return
    min_op = res.get("min")
    max_op = res.get("max")
    cnt = res.get("count")
    tot = res.get("total_indexed_gates")
    print(f"\n{'='*85}")
    print(f"=== DISPATCHER OPCODES [Range: {min_op} .. {max_op}] ({cnt} gates matching / {tot} total indexed) ===")
    print(f"{'='*85}")
    print(f"{'Opcode':<8} {'Hex':<8} {'Gate VA':<12} {'Gate RVA':<12} {'Instruction':<24} {'Associated Function'}")
    print(f"{'-'*85}")
    for g in res.get("gates", []):
        op = g["opcode"]
        op_h = g["opcode_hex"]
        va = g["va"]
        rva = g["rva"]
        asm = g["asm"]
        fn = g.get("func_name") or "-"
        print(f"{op:<8} {op_h:<8} {va:<12} {rva:<12} {asm:<24} {fn}")


def print_status_result(res: Dict[str, Any]) -> None:
    if res.get("status") != "ok":
        print(f"ERROR: {res.get('message')}")
        return
    print(f"\n{'='*75}")
    print("=== GHIDRA ORACLE DAEMON STATUS (127.0.0.1:5073) ===")
    print(f"{'='*75}")
    print(f"Uptime:             {res.get('uptime_human')} ({res.get('uptime_seconds')}s)")
    print(f"Ghidra Project:     {res.get('project_name')} in {res.get('project_dir')}")
    print(f"Program:            {res.get('program_name')} (Base: {res.get('image_base')})")
    print(f"Functions in DB:    {res.get('function_count'):,}")
    print(f"Indexed Opcode Gates: {res.get('indexed_opcode_gates'):,}")
    print(f"Indexed ADRP Pages: {res.get('indexed_adrp_pages'):,}")
    d_cache = res.get("decompile_cache", {})
    v_cache = res.get("vtable_cache", {})
    print(f"Decompile Cache:    {d_cache.get('size')}/{d_cache.get('capacity')} entries | Hit Rate: {d_cache.get('hit_rate_pct')}% ({d_cache.get('hits')} hits, {d_cache.get('misses')} misses)")
    print(f"VTable Cache:       {v_cache.get('size')}/{v_cache.get('capacity')} entries | Hit Rate: {v_cache.get('hit_rate_pct')}% ({v_cache.get('hits')} hits, {v_cache.get('misses')} misses)")
    print(f"Overall Hit Rate:   {res.get('overall_hit_rate_pct')}%")
    print(f"Write-Overlay:      {res.get('overlay_renames_count')} renames, {res.get('overlay_comments_count')} comments")


# ==============================================================================
# CLI Entry Point
# ==============================================================================

def main():
    import argparse

    parser = argparse.ArgumentParser(
        description="Ghidra Oracle: Dual-mode Persistent TCP/JSON Daemon & CLI Client",
        add_help=False,
    )
    parser.add_argument("command", nargs="?", default="status", help="Command to run")
    parser.add_argument("args", nargs="*", help="Command arguments")
    parser.add_argument("--host", default=DEFAULT_HOST, help="TCP daemon host (default 127.0.0.1)")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT, help="TCP daemon port (default 5073)")
    parser.add_argument("--json", action="store_true", help="Output raw JSON response")
    parser.add_argument("--project-dir", default=None, help="Custom Ghidra project directory")
    parser.add_argument("--project-name", default=None, help="Custom Ghidra project name")
    parser.add_argument("--program-name", default=None, help="Custom program name inside project")
    parser.add_argument("-h", "--help", action="store_true", help="Show help message")

    parsed, unknown = parser.parse_known_args()

    if parsed.help or not parsed.command:
        print(__doc__)
        return

    cmd = parsed.command.lower()
    c_args = parsed.args

    # 1. Daemon serve mode
    if cmd == "serve":
        logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
        session = GhidraOracleSession(
            project_dir=parsed.project_dir,
            project_name=parsed.project_name,
            program_name=parsed.program_name,
        )
        print("[*] Initializing Ghidra & OpenJDK 21...")
        session.initialize()
        server = GhidraDaemonServer(session, host=parsed.host, port=parsed.port)
        try:
            server.start()
        except KeyboardInterrupt:
            print("\n[*] Stopping Ghidra Oracle daemon...")
            server.stop()
        return

    # 2. Client Commands
    req_args = {}
    if cmd == "rva":
        if not c_args:
            print("Usage: python ghidra_oracle.py rva <addr>")
            return
        req_args["addr"] = c_args[0]
    elif cmd == "decompile":
        if not c_args:
            print("Usage: python ghidra_oracle.py decompile <addr...>")
            return
        req_args["targets"] = c_args
    elif cmd == "vtable":
        if not c_args:
            print("Usage: python ghidra_oracle.py vtable <addr> [count]")
            return
        req_args["addr"] = c_args[0]
        req_args["count"] = int(c_args[1]) if len(c_args) > 1 else 12
    elif cmd == "disassemble":
        if not c_args:
            print("Usage: python ghidra_oracle.py disassemble <addr> [count]")
            return
        req_args["addr"] = c_args[0]
        req_args["count"] = int(c_args[1]) if len(c_args) > 1 else 30
    elif cmd in ("refs", "references"):
        if not c_args:
            print("Usage: python ghidra_oracle.py refs <addr> [count]")
            return
        req_args["addr"] = c_args[0]
        req_args["count"] = int(c_args[1]) if len(c_args) > 1 else 20
    elif cmd == "adrp_add":
        if not c_args:
            print("Usage: python ghidra_oracle.py adrp_add <symbol_or_addr>")
            return
        req_args["target"] = c_args[0]
    elif cmd == "opcodes":
        min_op = int(c_args[0]) if len(c_args) > 0 else 500
        max_op = int(c_args[1]) if len(c_args) > 1 else 550
        req_args["min"] = min_op
        req_args["max"] = max_op
    elif cmd == "rename":
        if len(c_args) < 2:
            print("Usage: python ghidra_oracle.py rename <addr> <name>")
            return
        req_args["addr"] = c_args[0]
        req_args["name"] = c_args[1]
    elif cmd == "comment":
        if len(c_args) < 2:
            print("Usage: python ghidra_oracle.py comment <addr> <text>")
            return
        req_args["addr"] = c_args[0]
        req_args["comment"] = " ".join(c_args[1:])
    elif cmd == "overlay":
        req_args["action"] = c_args[0] if c_args else "list"
    elif cmd in ("status", "stop", "ping"):
        pass
    else:
        print(f"Unknown command: {cmd}")
        print("Available commands: decompile, vtable, disassemble, refs, adrp_add, opcodes, rva, rename, comment, overlay, status, stop, serve")
        return

    res = client_send_request(cmd, req_args, host=parsed.host, port=parsed.port)

    if parsed.json:
        print(json.dumps(res, indent=2))
        return

    # Human-readable output formatting
    if cmd == "rva":
        if res.get("status") == "ok":
            va = res.get("va")
            rva = res.get("rva")
            t_ms = res.get("time_ms", 0.0)
            print(f"VA:     {va}  (Ghidra Virtual Address)")
            print(f"RVA:    {rva}  (Runtime Relative Virtual Address, -0x100000)")
            print(f"Lookup: {t_ms:.4f} ms")
        else:
            print(f"ERROR: {res.get('message')}")
    elif cmd == "decompile":
        print_decompile_result(res)
    elif cmd == "vtable":
        print_vtable_result(res)
    elif cmd == "disassemble":
        print_disasm_result(res)
    elif cmd in ("refs", "references"):
        print_refs_result(res)
    elif cmd == "adrp_add":
        print_adrp_add_result(res)
    elif cmd == "opcodes":
        print_opcodes_result(res)
    elif cmd == "status":
        print_status_result(res)
    elif cmd in ("rename", "comment", "stop", "ping"):
        print(res.get("message") or res)
    elif cmd == "overlay":
        print(json.dumps(res.get("overlay", res), indent=2))


if __name__ == "__main__":
    main()
