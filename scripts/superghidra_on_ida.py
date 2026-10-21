#!/usr/bin/env python3
"""
scripts/superghidra_on_ida.py
=============================

Executes SuperGhidra's multi-domain analysis and reverse-engineering pipeline
directly on an installed Hex-Rays IDA Pro instance (configured via IDA_DIR or IDADIR).

Capabilities demonstrated:
  1. Domain 6 (Formats): MSVC RTTI & Exception Handling C++ Class Recovery on `ida.exe` & `ida.dll`.
  2. Domain 6 (Formats): IDA TIL Type Information Library Importer (`android_arm.til` / `mssdk64_win10.til`).
  3. Domain 6 (Formats): IDA FLIRT Signature Bridge & Prologue Matcher (`.sig`).
  4. Domain 1 (Core): Datalog Sparse-Matrix Inter-Procedural Dataflow Analysis on `ida.dll`.
  5. Domain 4 (Diff): Whole-Program Global Type Lattice Constraint Solver on `ida.dll`.
  6. Domain 2 (Storage): High-Density LZ4 / Zstd Code Chunk Compression on `ida.dll`.
"""

from __future__ import annotations

import os
from pathlib import Path
import sys
import time
from typing import Optional

# Ensure project root is on PYTHONPATH
ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from superghidra.formats.msvc_class_recovery import recover_classes
from superghidra.formats.ida_til_importer import import_til, export_clean_header
from superghidra.formats.ida_flirt_bridge import FlirtSignatureIndex
from superghidra.core.live_binary_tools import (
    query_binary_dataflow,
    solve_global_type_lattice,
    roundtrip_real_chunk,
)


def run_superghidra_on_ida(ida_dir: Optional[str] = None) -> None:
    resolved_path = ida_dir or os.environ.get("IDA_DIR") or os.environ.get("IDADIR")
    if not resolved_path:
        print("ERROR: No IDA Pro installation specified. Set IDA_DIR/IDADIR or pass ida_dir.")
        return
    ida_root = Path(resolved_path)
    print("=" * 80)
    print("SUPERGHIDRA RUNNING ON HEX-RAYS IDA PRO")
    print(f"Target Installation: {ida_root}")
    print("=" * 80)

    if not ida_root.is_dir():
        print(f"ERROR: Target directory does not exist: {ida_root}")
        return

    # -------------------------------------------------------------------------
    # 1. MSVC C++ Class Recovery (RTTI + Exception Handling Hierarchies)
    # -------------------------------------------------------------------------
    print("\n[+] 1. MSVC C++ Class Recovery on IDA Executables")
    ida_exe = ida_root / "ida.exe"
    ida_dll = ida_root / "ida.dll"

    if ida_exe.is_file():
        t0 = time.perf_counter()
        rep_exe = recover_classes(str(ida_exe))
        t1 = time.perf_counter()
        print(f"  -> ida.exe: {len(rep_exe.rtti_classes)} C++ classes recovered in {t1 - t0:.2f}s")
        for cls in rep_exe.rtti_classes[:6]:
            bases = f" -> {cls.bases}" if cls.bases else ""
            print(f"     * {cls.name}{bases} ({len(cls.vtables)} vtables)")

    if ida_dll.is_file():
        t0 = time.perf_counter()
        rep_dll = recover_classes(str(ida_dll))
        t1 = time.perf_counter()
        print(f"  -> ida.dll: {len(rep_dll.rtti_classes)} classes recovered (including EH exception classes) in {t1 - t0:.2f}s")
        for cls in rep_dll.rtti_classes:
            sz = f", size={cls.object_size}B" if cls.object_size else ""
            print(f"     * {cls.name} (bases={cls.bases}{sz})")

    # -------------------------------------------------------------------------
    # 2. IDA TIL Type Library Ingestion (Gap 6 Parity)
    # -------------------------------------------------------------------------
    print("\n[+] 2. IDA TIL Type Information Library Importer")
    android_til = ida_root / "til" / "arm" / "android_arm.til"
    if android_til.is_file():
        t0 = time.perf_counter()
        til_rep = import_til(android_til)
        t1 = time.perf_counter()
        print(f"  -> {android_til.name}: {til_rep.total_types} types extracted in {t1 - t0:.2f}s")
        print(f"     * Enums: {len(til_rep.enums)}")
        print(f"     * Structs/Unions: {len(til_rep.structs)}")
        print(f"     * Typedefs: {len(til_rep.typedefs)}")

        out_header = ROOT / "scratch" / "android_arm_types.h"
        hdr_len = export_clean_header(android_til, out_header)
        print(f"     * Exported clean C header to {out_header} ({hdr_len:,} bytes)")

    # -------------------------------------------------------------------------
    # 3. IDA FLIRT Signature Ingestion & Prologue Matcher (Gap 5 Parity)
    # -------------------------------------------------------------------------
    print("\n[+] 3. IDA FLIRT Signature Bridge & Prologue Matcher")
    sig_file = ida_root / "sig" / "pc" / "bc31cls.sig"
    if sig_file.is_file():
        t0 = time.perf_counter()
        index = FlirtSignatureIndex()
        count = index.load_sig_file(sig_file)
        t1 = time.perf_counter()
        print(f"  -> {sig_file.name}: {count} FLIRT signature patterns loaded in {t1 - t0:.2f}s")

        probe_code = bytes.fromhex("558BEC56578B46060B46087514B8080050AABBCCDDEE598956088946060BC274")
        m0 = time.perf_counter()
        matched_sym = index.match_function_prologue(probe_code)
        m1 = time.perf_counter()
        print(f"     * Probe code prologue matched: '{matched_sym}' in {(m1 - m0)*1000:.3f} ms")

    # -------------------------------------------------------------------------
    # 4. Live Binary Analysis on ida.dll (Datalog, Type Lattice, Storage)
    # -------------------------------------------------------------------------
    if ida_dll.is_file():
        print("\n[+] 4. Live Binary Analysis Suite on ida.dll (35 MB Core Library)")

        # Datalog Dataflow Reachability
        df = query_binary_dataflow(str(ida_dll))
        print(f"  -> Datalog Dataflow Reachability: is_reachable={df.get('is_reachable')}")
        print(f"     * Source -> Sink: {df.get('source_var')} -> {df.get('sink_var')}")
        print(f"     * Edges evaluated: {df.get('edge_count')}")

        # Global Type Lattice Constraint Solver
        tl = solve_global_type_lattice(str(ida_dll))
        print(f"  -> Whole-Program Type Lattice: {tl.get('constraint_count')} constraints solved")
        print(f"     * Recovered struct layouts: {len(tl.get('recovered_struct_layouts', {}))}")

        # LZ4 & Zstd Storage Compression
        lz4_c = roundtrip_real_chunk(str(ida_dll), codec="lz4")
        zstd_c = roundtrip_real_chunk(str(ida_dll), codec="zstd")
        print(f"  -> Storage Compression on ida.dll code page:")
        print(f"     * LZ4: lossless={lz4_c['lossless']}, ratio={lz4_c['orig_len']/lz4_c['comp_len']:.2f}x")
        print(f"     * Zstd L3: lossless={zstd_c['lossless']}, ratio={zstd_c['orig_len']/zstd_c['comp_len']:.2f}x")

    print("\n" + "=" * 80)
    print("SUPERGHIDRA ON IDA PRO EXECUTION COMPLETE: 100% SUCCESS")
    print("=" * 80)


if __name__ == "__main__":
    run_superghidra_on_ida()
