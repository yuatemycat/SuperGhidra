"""
superghidra.__main__
====================

Unified CLI entry point for SuperGhidra:
High-Performance Autonomous Reverse Engineering & Decompiler Suite.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Optional, Tuple


def create_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="superghidra",
        description="SuperGhidra: High-Performance Autonomous Decompiler & Reverse Engineering Suite",
    )
    parser.add_argument(
        "-v", "--version", action="store_true", help="Show SuperGhidra version and environment"
    )

    subparsers = parser.add_subparsers(dest="command", help="Available subcommands")

    # Subcommand: version
    subparsers.add_parser("version", help="Display version and active subsystems")

    # Subcommand: decompile
    decomp_parser = subparsers.add_parser("decompile", help="Run multi-stage P-Code decompiler")
    decomp_parser.add_argument("binary", type=Path, help="Path to binary file")
    decomp_addr_group = decomp_parser.add_mutually_exclusive_group()
    decomp_addr_group.add_argument("--rva", type=lambda x: int(x, 0), help="Function RVA (hex or dec)")
    decomp_addr_group.add_argument("--va", type=lambda x: int(x, 0), help="Function VA (hex or dec)")
    decomp_parser.add_argument("--arch", choices=["x86_64", "arm64", "x86"], default="x86_64", help="Architecture")
    decomp_parser.add_argument("--len", type=int, default=128, help="Max instruction bytes to lift")
    decomp_parser.add_argument("-o", "--output", type=Path, help="Output file for decompiled C")

    # Subcommand: til-import
    til_parser = subparsers.add_parser("til-import", help="Import IDA .til type library")
    til_parser.add_argument("til_file", type=Path, help="Path to .til file")
    til_parser.add_argument("-o", "--output", type=Path, help="Output JSON catalog path")

    # Subcommand: flirt-match
    flirt_parser = subparsers.add_parser("flirt-match", help="Match binary bytes against FLIRT .sig database")
    flirt_parser.add_argument("sig_file", type=Path, help="Path to .sig signature file")
    flirt_parser.add_argument("binary", type=Path, help="Path to target binary")
    flirt_addr_group = flirt_parser.add_mutually_exclusive_group()
    flirt_addr_group.add_argument("--rva", type=lambda x: int(x, 0), help="Target function RVA")
    flirt_addr_group.add_argument("--va", type=lambda x: int(x, 0), help="Target function VA")

    # Subcommand: rtti-recover
    rtti_parser = subparsers.add_parser("rtti-recover", help="Recover MSVC C++ classes, vtables, and catchable types")
    rtti_parser.add_argument("binary", type=Path, help="Path to PE/COFF binary")
    rtti_parser.add_argument("-o", "--output", type=Path, help="Output JSON file")

    # Subcommand: filter
    filter_parser = subparsers.add_parser("filter", help="Transform raw decompiler output into compilable C")
    filter_parser.add_argument("source", type=Path, help="Path to raw C file")
    filter_parser.add_argument("--no-headers", action="store_true", help="Exclude standard header injection")
    filter_parser.add_argument("-o", "--output", type=Path, help="Output file")

    # Subcommand: overlay-sync
    sync_parser = subparsers.add_parser("overlay-sync", help="Sync write-overlay mutations to Ghidra GUI script")
    sync_parser.add_argument("--overlay", "-i", type=Path, required=True, help="Path to ghidra_overlay.json or .ghidra-delta.jsonl")
    sync_parser.add_argument("--out", "-o", type=Path, help="Output Ghidra Python script path")
    sync_parser.add_argument("--diff", action="store_true", help="Print summary diff report instead of generating script")
    sync_parser.add_argument("--dry-run", action="store_true", help="Configure generated script for dry run")

    return parser


def cmd_version() -> int:
    import platform
    print("SuperGhidra v0.2.0")
    print(f"Platform: {platform.system()} {platform.machine()} ({platform.platform()})")
    print(f"Python: {sys.version.split()[0]}")

    # Check optional acceleration backends
    features = []
    try:
        import z3  # type: ignore
        features.append("SMT (z3)")
    except ImportError:
        pass

    try:
        import wgpu  # type: ignore
        features.append("GPU Acceleration (wgpu)")
    except ImportError:
        pass

    try:
        import lz4  # type: ignore
        features.append("LZ4 Compression")
    except ImportError:
        pass

    try:
        import zstandard  # type: ignore
        features.append("Zstandard Compression")
    except ImportError:
        pass

    print(f"Active Features: {', '.join(features) if features else 'Standard Core'}")
    return 0


def _function_bytes(
    path: Path | str,
    arch: Optional[str] = None,
    rva: Optional[int] = None,
    va: Optional[int] = None,
    length: int = 128,
) -> Tuple[bytes, int]:
    from superghidra.formats.binary_loader import load_binary

    p = Path(path)
    if not p.is_file():
        print(f"Error: binary file not found: {p}", file=sys.stderr)
        sys.exit(1)

    img = load_binary(str(p), raw_arch=arch or "unknown")

    if arch is not None and img.format in ("elf", "pe", "macho") and img.arch != arch:
        print(
            f"Error: binary architecture '{img.arch}' does not match requested architecture '{arch}'",
            file=sys.stderr,
        )
        sys.exit(2)

    if va is not None:
        target_va = va
        target_rva = img.va_to_rva(va)
    else:
        target_rva = 0x1000 if rva is None else rva
        target_va = img.rva_to_va(target_rva)

    offset = img.va_to_offset(target_va)
    if offset is None:
        print(f"Error: address {hex(target_va)} is not backed by file bytes", file=sys.stderr)
        sys.exit(2)

    sec = img.section_for_va(target_va)
    if sec is not None and not sec.executable:
        print(f"Error: section containing address {hex(target_va)} is not executable", file=sys.stderr)
        sys.exit(2)

    chunk = img.read_va(target_va, length)
    return chunk, target_rva


def cmd_decompile(args: argparse.Namespace) -> int:
    from superghidra.core.live_binary_tools import LiftError, staged_decompile_function

    chunk, target_rva = _function_bytes(
        args.binary,
        arch=args.arch,
        rva=args.rva,
        va=args.va,
        length=args.len,
    )

    try:
        result = staged_decompile_function(chunk, func_rva=target_rva, arch=args.arch)
    except LiftError as exc:
        print(f"Error: {exc.message}", file=sys.stderr)
        if exc.unhandled:
            print("Unhandled instructions:", file=sys.stderr)
            for addr, hex_bytes in exc.unhandled:
                print(f"  {hex(addr)}: {hex_bytes}", file=sys.stderr)
        return 3

    c_code = result.get("c_code", "")

    if args.output:
        args.output.write_text(c_code, encoding="utf-8")
        print(f"Decompiled code written to {args.output}")
    else:
        print(c_code)
    return 0


def cmd_til_import(args: argparse.Namespace) -> int:
    from superghidra.core.live_binary_tools import import_type_library

    if not args.til_file.is_file():
        print(f"Error: .til file not found: {args.til_file}", file=sys.stderr)
        return 1

    catalog = import_type_library(str(args.til_file))
    print(f"Imported {len(catalog)} types from {args.til_file.name}")
    if args.output:
        args.output.write_text(json.dumps(catalog, indent=2), encoding="utf-8")
        print(f"Saved catalog to {args.output}")
    return 0


def cmd_flirt_match(args: argparse.Namespace) -> int:
    from superghidra.core.live_binary_tools import match_flirt_signatures

    if not args.sig_file.is_file():
        print(f"Error: signature file not found: {args.sig_file}", file=sys.stderr)
        return 1

    chunk, target_rva = _function_bytes(
        args.binary,
        arch=None,
        rva=args.rva,
        va=args.va,
        length=64,
    )

    matches = match_flirt_signatures(str(args.sig_file), chunk, candidate_rva=target_rva)
    if matches:
        print(f"Found {len(matches)} signature match(es):")
        for m in matches:
            print(f"  - {m}")
    else:
        print("No signature matches found.")
    return 0


def cmd_rtti_recover(args: argparse.Namespace) -> int:
    from superghidra.formats.msvc_class_recovery import MSVCClassRecovery

    if not args.binary.is_file():
        print(f"Error: binary not found: {args.binary}", file=sys.stderr)
        return 1

    data = args.binary.read_bytes()
    recovery = MSVCClassRecovery(data)
    classes = recovery.recover_classes()
    print(f"Recovered {len(classes)} C++ classes.")

    if args.output:
        serializable = {
            name: {
                "vtable_rvas": [hex(v) for v in c.vtable_rvas],
                "methods_count": len(c.methods),
                "base_classes": c.base_classes,
                "has_rtti": c.has_rtti,
            }
            for name, c in classes.items()
        }
        args.output.write_text(json.dumps(serializable, indent=2), encoding="utf-8")
        print(f"Saved class hierarchy to {args.output}")
    return 0


def cmd_filter(args: argparse.Namespace) -> int:
    from superghidra.core.compilable_filter import CompilableDecompilerFilter

    if not args.source.is_file():
        print(f"Error: source file not found: {args.source}", file=sys.stderr)
        return 1

    raw = args.source.read_text(encoding="utf-8", errors="replace")
    clean = CompilableDecompilerFilter.filter(
        raw,
        emit_compilable=True,
        strip_canary=True,
        include_headers=not args.no_headers,
        collapse_strides=True,
    )

    if args.output:
        args.output.write_text(clean, encoding="utf-8")
        print(f"Cleaned compilable C written to {args.output}")
    else:
        print(clean)
    return 0


def cmd_overlay_sync(args: argparse.Namespace) -> int:
    from superghidra.integrations.ghidra_gui_overlay_sync import OverlaySyncBridge

    if not args.overlay.is_file():
        print(f"Error: overlay file not found: {args.overlay}", file=sys.stderr)
        return 1

    bridge = OverlaySyncBridge(args.overlay)

    if getattr(args, "diff", False):
        report = bridge.generate_diff_report()
        print(report)
        return 0

    script = bridge.generate_ghidra_python_script(dry_run=args.dry_run)
    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(script, encoding="utf-8")
        print(f"Ghidra sync script written to {args.out}")
    else:
        print(script)
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = create_parser()
    args = parser.parse_args(argv)

    if args.version or args.command == "version":
        return cmd_version()

    if args.command == "decompile":
        return cmd_decompile(args)
    elif args.command == "til-import":
        return cmd_til_import(args)
    elif args.command == "flirt-match":
        return cmd_flirt_match(args)
    elif args.command == "rtti-recover":
        return cmd_rtti_recover(args)
    elif args.command == "filter":
        return cmd_filter(args)
    elif args.command == "overlay-sync":
        return cmd_overlay_sync(args)
    else:
        parser.print_help()
        return 0


if __name__ == "__main__":
    sys.exit(main())
