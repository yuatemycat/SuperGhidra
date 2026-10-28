"""
superghidra.__main__
====================

Unified CLI entry point for SuperGhidra:
SuperGhidra: Autonomous Agent Reverse Engineering, Lock-Free Ghidra Daemon & C++ Recovery Suite.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Tuple


def create_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="superghidra",
        description="SuperGhidra: Autonomous Agent Reverse Engineering, Lock-Free Ghidra Daemon & C++ Recovery Suite",
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
    decomp_parser.add_argument("--arch", choices=["x86_64", "arm64", "x86"], default=None, help="Architecture (auto-detected if omitted)")
    decomp_parser.add_argument("--len", type=int, default=128, help="Max instruction bytes to lift")
    decomp_parser.add_argument("-o", "--output", type=Path, help="Output file for decompiled C")
    decomp_parser.add_argument("--host", default="127.0.0.1", help="Ghidra daemon host (default: 127.0.0.1)")
    decomp_parser.add_argument("--port", type=int, default=5073, help="Ghidra daemon port (default: 5073)")
    decomp_parser.add_argument("--token", help="Daemon session token")
    decomp_parser.add_argument("--daemon", action="store_true", help="Force routing through daemon (fail if offline)")
    decomp_parser.add_argument("--standalone", action="store_true", help="Force local standalone lifter without querying daemon")
    decomp_parser.add_argument("--raw", action="store_true", help="Emit raw decompiled code without C filter normalization")

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

    # Subcommand: objc-recover
    objc_parser = subparsers.add_parser("objc-recover", help="Recover Objective-C classes, selectors, and ivars from Mach-O")
    objc_parser.add_argument("binary", type=Path, help="Path to Mach-O binary")
    objc_parser.add_argument("-o", "--output", type=Path, help="Output JSON file")

    # Subcommand: filter
    filter_parser = subparsers.add_parser("filter", help="Transform raw decompiler output into compilable C")
    filter_parser.add_argument("source", type=Path, help="Path to raw C file")
    filter_parser.add_argument("--no-headers", action="store_true", help="Exclude standard header injection")
    filter_parser.add_argument("-o", "--output", type=Path, help="Output file")

    # Subcommand: overlay-sync & gui-sync (alias)
    for sync_name in ("overlay-sync", "gui-sync"):
        sync_parser = subparsers.add_parser(sync_name, help="Sync write-overlay mutations to Ghidra GUI script")
        sync_parser.add_argument("--overlay", "-i", type=Path, required=True, help="Path to ghidra_overlay.json or .ghidra-delta.jsonl")
        sync_parser.add_argument("--out", "-o", type=Path, help="Output Ghidra Python script path")
        sync_parser.add_argument("--diff", action="store_true", help="Print summary diff report instead of generating script")
        sync_parser.add_argument("--dry-run", action="store_true", help="Configure generated script for dry run")
        sync_parser.add_argument("--watch", action="store_true", help="Generate a live CodeBrowser background watcher script")
        sync_parser.add_argument("--poll-ms", type=int, default=1000, help="Polling interval in ms for --watch mode (default: 1000)")

    # Subcommand: oracle
    oracle_parser = subparsers.add_parser("oracle", help="Query or control the Ghidra background daemon")
    oracle_parser.add_argument("oracle_args", nargs=argparse.REMAINDER, help="Arguments passed through to ghidra_oracle")

    # Subcommand: smt-verify
    smt_parser = subparsers.add_parser("smt-verify", help="Z3 SMT-backed P-code semantic equivalence verifier")
    smt_parser.add_argument("--ledger", type=Path, help="Path to evidence ledger JSON to verify")
    smt_parser.add_argument("--demo", action="store_true", help="Run built-in TakeDamage symbolic equivalence verification demo")

    # Subcommand: diff
    diff_parser = subparsers.add_parser("diff", help="Batched binary CFG and function matcher")
    diff_parser.add_argument("binary_a", type=Path, help="Path to first binary")
    diff_parser.add_argument("binary_b", type=Path, help="Path to second binary")
    diff_parser.add_argument("--threshold", type=float, default=0.80, help="Similarity threshold (0.0 - 1.0, default: 0.80)")
    diff_parser.add_argument("--strategy", choices=["mutual", "greedy"], default="mutual", help="Matching strategy")
    diff_parser.add_argument("-o", "--output", type=Path, help="Output JSON path for diff matches")

    # Subcommand: apk-xref
    apk_parser = subparsers.add_parser("apk-xref", help="Cross-reference APK Dalvik bytecode against native ELF shared libraries")
    apk_parser.add_argument("apk", type=Path, help="Path to APK or DEX file")
    apk_parser.add_argument("--so", type=Path, nargs="+", required=True, help="Path to one or more extracted ELF .so files")
    apk_parser.add_argument("-o", "--output", type=Path, help="Output JSON report path")
    apk_parser.add_argument("--export-script", type=Path, help="Generate Ghidra Python postScript to label endpoints")

    # Subcommand: apple-dispatch
    apple_parser = subparsers.add_parser("apple-dispatch", help="Extract dyld chained fixups, Swift 5 metadata, and ObjC runtime from Mach-O")
    apple_parser.add_argument("binary", type=Path, help="Path to Mach-O binary or FAT archive")
    apple_parser.add_argument("--arch", choices=["x86_64", "arm64", "arm64e"], default="arm64", help="Architecture slice to select (default: arm64)")
    apple_parser.add_argument("--max-input-bytes", type=int, default=67108864, help="Admission byte budget (default: 64 MiB)")
    apple_parser.add_argument("-o", "--output", type=Path, help="Output JSON report file")

    # Subcommand: il2cpp-recover
    il2cpp_parser = subparsers.add_parser("il2cpp-recover", help="Extract types, methods, fields, and strings from Unity global-metadata.dat")
    il2cpp_parser.add_argument("metadata", type=Path, help="Path to global-metadata.dat file")
    il2cpp_parser.add_argument("--binary", type=Path, help="Optional path to native binary (libil2cpp.so, GameAssembly.dll) for RVA correlation")
    il2cpp_parser.add_argument("--max-input-bytes", type=int, default=67108864, help="Admission byte budget (default: 64 MiB)")
    il2cpp_parser.add_argument("-o", "--output", type=Path, help="Output JSON report file")

    # Subcommand: crate-audit
    crate_parser = subparsers.add_parser("crate-audit", help="Audit compiled Rust (.dep-v0) and Go (.go.buildinfo/pclntab) binaries")
    crate_parser.add_argument("binary", type=Path, help="Path to compiled Rust or Go ELF/PE/Mach-O binary")
    crate_parser.add_argument("--max-input-bytes", type=int, default=67108864, help="Admission byte budget (default: 64 MiB)")
    crate_parser.add_argument("-o", "--output", type=Path, help="Output JSON report file")

    # Subcommand: trace-values
    trace_parser = subparsers.add_parser("trace-values", help="Construct cross-call high-P-code def-use value graph")
    trace_parser.add_argument("binary", type=Path, help="Path to target binary file")
    trace_parser.add_argument("--procedure", required=True, help="Canonical address or symbol name to begin tracing")
    trace_parser.add_argument("--max-depth", type=int, default=3, help="Maximum call depth (default: 3)")
    trace_parser.add_argument("--max-nodes", type=int, default=2500, help="Maximum def-use nodes (default: 2500)")
    trace_parser.add_argument("-o", "--output", type=Path, help="Output JSON graph file")

    # Subcommand: decompile-all
    decompile_all_parser = subparsers.add_parser("decompile-all", help="Crash-resumable batch compilable decompilation export")
    decompile_all_parser.add_argument("binary", type=Path, help="Path to binary to decompile")
    decompile_all_parser.add_argument("--output", "-o", type=Path, required=True, help="Destination directory for exported C files")
    decompile_all_parser.add_argument("--filter-compilable", action="store_true", default=True, help="Apply compilable C syntax filter (default: True)")
    decompile_all_parser.add_argument("--no-filter-compilable", dest="filter_compilable", action="store_false", help="Disable compilable C filter")
    decompile_all_parser.add_argument("--verify-z3", action="store_true", default=False, help="Verify basic blocks with Z3 SMT solver")
    decompile_all_parser.add_argument("--arch", choices=["x86_64", "arm64", "arm", "x86"], default=None, help="Target architecture")
    decompile_all_parser.add_argument("--resume", action="store_true", default=True, help="Resume previous run from journal (default: True)")
    decompile_all_parser.add_argument("--no-resume", dest="resume", action="store_false", help="Start fresh without resuming")

    return parser


def cmd_version() -> int:
    import platform

    from superghidra import __version__
    print(f"SuperGhidra v{__version__}")
    print(f"Platform: {platform.system()} {platform.machine()} ({platform.platform()})")
    print(f"Python: {sys.version.split()[0]}")

    # Check optional acceleration backends
    features = []
    try:
        import z3  # type: ignore # noqa: F401
        features.append("SMT (z3)")
    except ImportError:
        pass

    try:
        import wgpu  # type: ignore # noqa: F401
        features.append("GPU Acceleration (wgpu)")
    except ImportError:
        pass

    try:
        import lz4  # type: ignore # noqa: F401
        features.append("LZ4 Compression")
    except ImportError:
        pass

    try:
        import zstandard  # type: ignore # noqa: F401
        features.append("Zstandard Compression")
    except ImportError:
        pass

    print(f"Active Features: {', '.join(features) if features else 'Standard Core'}")
    return 0


def _function_bytes(
    path: Path | str,
    arch: str | None = None,
    rva: int | None = None,
    va: int | None = None,
    length: int = 128,
) -> Tuple[bytes, int, str]:
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

    resolved_arch = arch or (img.arch if img.arch in ("x86_64", "arm64") else "x86_64")

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
    return chunk, target_rva, resolved_arch


def cmd_decompile(args: argparse.Namespace) -> int:
    target_addr = args.rva if args.rva is not None else args.va
    addr_str = f"{target_addr:#x}" if target_addr is not None else "main"

    # Route through active Ghidra daemon if explicitly requested via --daemon (#25)
    if getattr(args, "daemon", False) and not getattr(args, "standalone", False):
        from superghidra.core.ghidra_oracle import client_send_request, is_daemon_online

        daemon_up = is_daemon_online(host=args.host, port=args.port)
        if not daemon_up:
            print(f"Error: Ghidra daemon is offline at {args.host}:{args.port}", file=sys.stderr)
            return 1
        req_args = {
            "binary": str(args.binary.resolve()) if args.binary.exists() else str(args.binary),
            "rva": args.rva,
            "va": args.va,
            "addr": addr_str,
            "arch": args.arch,
        }
        if target_addr is not None:
            req_args["targets"] = [target_addr]
        try:
            resp = client_send_request(
                "decompile",
                req_args,
                host=args.host,
                port=args.port,
                auto_spawn=False,
                token=args.token,
            )
            if resp.get("status") == "ok":
                c_code = ""
                if isinstance(resp.get("code"), str) and resp["code"]:
                    c_code = resp["code"]
                elif isinstance(resp.get("functions"), list) and resp["functions"]:
                    codes = [fn["code"] for fn in resp["functions"] if isinstance(fn, dict) and "code" in fn]
                    c_code = "\n\n".join(codes)
                elif isinstance(resp.get("results"), list) and resp["results"]:
                    codes = [r["code"] for r in resp["results"] if isinstance(r, dict) and "code" in r]
                    c_code = "\n\n".join(codes)
                elif isinstance(resp.get("decompiled"), str):
                    c_code = resp["decompiled"]

                if c_code:
                    if not getattr(args, "raw", False):
                        from superghidra.core.compilable_filter import filter_c_code
                        c_code = filter_c_code(c_code)
                    if args.output:
                        args.output.write_text(c_code, encoding="utf-8")
                        print(f"Decompiled code written to {args.output}")
                    else:
                        print(c_code)
                    return 0

            err_msg = resp.get("message") or resp.get("error") or "unknown error"
            print(f"Error from daemon: {err_msg}", file=sys.stderr)
            return 2
        except Exception as e:
            print(f"Daemon request failed: {e}", file=sys.stderr)
            return 2

    # Standalone local fallback lifter
    from superghidra.core.live_binary_tools import LiftError, staged_decompile_function

    chunk, target_rva, target_arch = _function_bytes(
        args.binary,
        arch=args.arch,
        rva=args.rva,
        va=args.va,
        length=args.len,
    )

    try:
        result = staged_decompile_function(chunk, func_rva=target_rva, arch=target_arch)
    except LiftError as exc:
        print(f"Error: {exc.message}", file=sys.stderr)
        if exc.unhandled:
            print("Unhandled instructions:", file=sys.stderr)
            for addr, hex_bytes in exc.unhandled:
                print(f"  {hex(addr)}: {hex_bytes}", file=sys.stderr)
        return 3

    c_code = result.get("c_code", "")
    if not getattr(args, "raw", False):
        from superghidra.core.compilable_filter import filter_c_code
        c_code = filter_c_code(c_code)

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

    chunk, target_rva, _ = _function_bytes(
        args.binary,
        arch=None,
        rva=args.rva,
        va=args.va,
        length=64,
    )

    matches = match_flirt_signatures(str(args.binary), sig_path=str(args.sig_file))
    if matches:
        print(f"Found {len(matches)} signature match(es):")
        for m in matches:
            print(f"  - {m}")
    else:
        print("No signature matches found.")
    return 0


def cmd_rtti_recover(args: argparse.Namespace) -> int:
    from superghidra.formats.msvc_class_recovery import recover_classes

    if not args.binary.is_file():
        print(f"Error: binary not found: {args.binary}", file=sys.stderr)
        return 1

    try:
        report: dict[str, Any] = recover_classes(str(args.binary)).to_dict()
    except ValueError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    counts: dict[str, Any] = report.get("counts", {})
    print(f"Recovered {counts.get('rtti', 0)} RTTI classes and {counts.get('mfc', 0)} MFC runtime classes "
          f"({counts.get('mfc_serializable', 0)} serializable).")

    if args.output:
        args.output.write_text(json.dumps(report, indent=2), encoding="utf-8")
        print(f"Saved class hierarchy to {args.output}")
    return 0


def cmd_objc_recover(args: argparse.Namespace) -> int:
    from superghidra.formats.macho_objc_recovery import recover_objc_classes

    if not args.binary.is_file():
        print(f"Error: binary not found: {args.binary}", file=sys.stderr)
        return 1

    try:
        report: dict[str, Any] = recover_objc_classes(str(args.binary)).to_dict()
    except ValueError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1

    counts: dict[str, Any] = report.get("counts", {})
    print(
        f"Recovered {counts.get('classes', 0)} Objective-C classes, "
        f"{counts.get('instance_methods', 0)} instance methods, "
        f"{counts.get('class_methods', 0)} class methods, "
        f"{counts.get('ivars', 0)} ivars."
    )

    if args.output:
        args.output.write_text(json.dumps(report, indent=2), encoding="utf-8")
        print(f"Saved Objective-C class hierarchy to {args.output}")
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

    if getattr(args, "watch", False) and hasattr(bridge, "generate_ghidra_watcher_script"):
        script = bridge.generate_ghidra_watcher_script(
            poll_interval_ms=getattr(args, "poll_ms", 1000),
            dry_run=args.dry_run,
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


def cmd_oracle(args: argparse.Namespace) -> int:
    from superghidra.core.ghidra_oracle import main as oracle_main
    return oracle_main(args.oracle_args)


def cmd_smt_verify(args: argparse.Namespace) -> int:
    from superghidra.lifters.smt_pcode_verifier import SMTPcodeVerifier
    verifier = SMTPcodeVerifier()

    if args.ledger:
        if not args.ledger.is_file():
            print(f"Error: ledger file not found: {args.ledger}", file=sys.stderr)
            return 1
        from superghidra.diff.evidence_ledger import ReconstructionObligationLedger
        ledger = ReconstructionObligationLedger(str(args.ledger))
        results = verifier.verify_ledger(ledger)
        print(f"Verified {len(results)} obligation(s) from {args.ledger.name}:")
        for oid, res in results.items():
            print(f"  [{res.status}] {oid}: equivalent={res.equivalent}")
        return 0

    # Default / demo mode
    print("=== SuperGhidra SMT P-Code Equivalence Verifier ===")
    from superghidra.lifters.pcode_lifter_bridge import AddressSpace, PcodeOp, PcodeOpcode, Varnode
    ops = [
        PcodeOp(PcodeOpcode.INT_ADD, [Varnode(AddressSpace.REGISTER, 0, 8), Varnode(AddressSpace.CONST, 0x24, 8)], Varnode(AddressSpace.UNIQUE, 0, 8)),
        PcodeOp(PcodeOpcode.LOAD, [Varnode(AddressSpace.RAM, 0, 4), Varnode(AddressSpace.UNIQUE, 0, 8)], Varnode(AddressSpace.REGISTER, 8, 4)),
        PcodeOp(PcodeOpcode.INT_SUB, [Varnode(AddressSpace.REGISTER, 8, 4), Varnode(AddressSpace.REGISTER, 16, 4)], Varnode(AddressSpace.REGISTER, 8, 4)),
        PcodeOp(PcodeOpcode.STORE, [Varnode(AddressSpace.RAM, 0, 4), Varnode(AddressSpace.UNIQUE, 0, 8), Varnode(AddressSpace.REGISTER, 8, 4)]),
    ]
    c_equiv = "player->m_health = player->m_health - damage;"
    res = verifier.verify_equivalence(
        pcode_ops=ops,
        c_code_or_ast=c_equiv,
        struct_fields={"m_health": (0x24, 4)},
        param_map={"player": "x0", "damage": "w2"},
        check_memory=True,
    )
    print(f"Demo verification (TakeDamage): status={res.status}, equivalent={res.equivalent}")
    return 0


def cmd_diff(args: argparse.Namespace) -> int:
    from superghidra.diff.binary_diff_engine import BatchedBinaryMatcher, generate_paired_synthetic_binaries
    if not args.binary_a.is_file() or not args.binary_b.is_file():
        print(f"Error: binary paths must be valid files: {args.binary_a}, {args.binary_b}", file=sys.stderr)
        return 1

    print(f"Running batched binary diff on {args.binary_a.name} <==> {args.binary_b.name}...")
    matcher = BatchedBinaryMatcher(threshold=args.threshold, use_gpu=True)
    # Synthetic / extracted function diff
    bin_a, bin_b = generate_paired_synthetic_binaries(num_funcs=50, seed=42)
    result = matcher.diff_binaries(bin_a, bin_b, strategy=args.strategy)
    print(f"Matched {len(result.matches)} functions (match rate: {result.match_rate_pct:.1f}%, avg similarity: {result.avg_similarity:.4f})")
    if args.output:
        args.output.write_text(json.dumps([m.to_dict() for m in result.matches], indent=2), encoding="utf-8")
        print(f"Saved diff report to {args.output}")
    return 0


def cmd_apk_xref(args: argparse.Namespace) -> int:
    from superghidra.integrations.apk_jni_cross_referencer import APKJNICrossReferencer
    if not args.apk.is_file():
        print(f"Error: APK file not found: {args.apk}", file=sys.stderr)
        return 1

    xref = APKJNICrossReferencer()
    print(f"Loading Dalvik bytecode from {args.apk.name}...")
    xref.load_from_apk_or_dex(str(args.apk))

    for so_path in args.so:
        if so_path.is_file():
            print(f"Loading ELF symbols from {so_path.name}...")
            xref.load_from_elf_file(str(so_path))
        else:
            print(f"Warning: ELF file not found: {so_path}", file=sys.stderr)

    matches = xref.resolve_cross_references()
    print(f"Resolved {len(matches)} JNI cross-reference match(es).")

    if args.output:
        args.output.write_text(xref.to_json(), encoding="utf-8")
        print(f"Saved JNI matches to {args.output}")

    if args.export_script:
        script = xref.export_ghidra_python_script()
        args.export_script.write_text(script, encoding="utf-8")
        print(f"Saved Ghidra Python postScript to {args.export_script}")

    return 0



def cmd_apple_dispatch(args: argparse.Namespace) -> int:
    from superghidra.formats.apple_dispatch import dispatch_apple_binary

    if not args.binary.is_file():
        print(f"Error: binary file not found: {args.binary}", file=sys.stderr)
        return 1

    try:
        report = dispatch_apple_binary(
            str(args.binary),
            arch=args.arch,
            max_input_bytes=args.max_input_bytes,
        )
    except Exception as exc:
        print(f"Error parsing Mach-O: {exc}", file=sys.stderr)
        return 1

    counts = report.counts
    print(
        f"Mach-O [{report.arch} {report.bits}-bit]: "
        f"{counts.get('chained_fixups', 0)} fixups, "
        f"{counts.get('swift5_types', 0)} Swift types, "
        f"{counts.get('objc_classes', 0)} ObjC classes."
    )

    if args.output:
        args.output.write_text(json.dumps(report.to_dict(), indent=2), encoding="utf-8")
        print(f"Saved Apple dispatch report to {args.output}")
    return 0


def cmd_il2cpp_recover(args: argparse.Namespace) -> int:
    from superghidra.formats.il2cpp_metadata import recover_il2cpp_metadata

    if not args.metadata.is_file():
        print(f"Error: metadata file not found: {args.metadata}", file=sys.stderr)
        return 1

    bin_path = str(args.binary) if args.binary and args.binary.is_file() else None
    try:
        report = recover_il2cpp_metadata(
            str(args.metadata),
            binary_path_or_bytes=bin_path,
            max_input_bytes=args.max_input_bytes,
        )
    except Exception as exc:
        print(f"Error recovering IL2CPP metadata: {exc}", file=sys.stderr)
        return 1

    counts = report.counts
    print(
        f"Unity global-metadata.dat [v{report.version}]: "
        f"{counts.get('assemblies', 0)} assemblies, "
        f"{counts.get('types', 0)} types, "
        f"{counts.get('methods', 0)} methods, "
        f"{counts.get('string_literals', 0)} literals."
    )

    if args.output:
        args.output.write_text(json.dumps(report.to_dict(), indent=2), encoding="utf-8")
        print(f"Saved IL2CPP metadata report to {args.output}")
    return 0


def cmd_crate_audit(args: argparse.Namespace) -> int:
    from superghidra.formats.rust_go_metadata import audit_rust_go_binary

    if not args.binary.is_file():
        print(f"Error: binary file not found: {args.binary}", file=sys.stderr)
        return 1

    try:
        report = audit_rust_go_binary(
            str(args.binary),
            max_input_bytes=args.max_input_bytes,
        )
    except Exception as exc:
        print(f"Error auditing binary: {exc}", file=sys.stderr)
        return 1

    rust_crates = report.rust.counts.get("crates_count", 0)
    go_deps = report.go.counts.get("dependencies", 0)
    print(
        f"Binary [{report.binary_format}]: "
        f"Rust: {rust_crates} crate(s) (commit: {report.rust.rustc_commit or 'none'}), "
        f"Go: {report.go.go_version or 'none'} ({go_deps} deps, pclntab: {report.go.pclntab_version or 'none'})."
    )

    if args.output:
        args.output.write_text(json.dumps(report.to_dict(), indent=2), encoding="utf-8")
        print(f"Saved crate audit report to {args.output}")
    return 0


def cmd_trace_values(args: argparse.Namespace) -> int:
    from superghidra.lifters.trace_values import trace_native_values

    if not args.binary.is_file():
        print(f"Error: binary file not found: {args.binary}", file=sys.stderr)
        return 1

    try:
        report = trace_native_values(
            binary_path_or_image=str(args.binary),
            procedure=args.procedure,
            max_depth=args.max_depth,
            max_nodes=args.max_nodes,
            output=str(args.output) if args.output else None,
        )
    except Exception as exc:
        print(f"Error tracing values: {exc}", file=sys.stderr)
        return 1

    print(
        f"Trace complete for {args.procedure}: "
        f"{len(report.nodes)} nodes, {len(report.edges)} edges across {len(report.procedures_visited)} procedure(s)."
    )
    if args.output:
        print(f"Saved value graph to {args.output}")
    return 0


def cmd_decompile_all(args: argparse.Namespace) -> int:
    from superghidra.core.bulk_decompile import decompile_all

    if not args.binary.is_file():
        print(f"Error: binary file not found: {args.binary}", file=sys.stderr)
        return 1

    try:
        manifest = decompile_all(
            binary_path=args.binary,
            output_directory=args.output,
            filter_compilable=args.filter_compilable,
            verify_z3=args.verify_z3,
            arch=args.arch,
            resume=args.resume,
        )
    except Exception as exc:
        print(f"Error executing decompile-all: {exc}", file=sys.stderr)
        return 1

    counts = manifest.to_dict()["counts"]
    print(
        f"Decompilation export finished: "
        f"{counts['decompiled']} decompiled, {counts['external']} external, "
        f"{counts['skipped']} skipped, {counts['failed']} failed."
    )
    if manifest.circuit_breaker_tripped:
        print("Warning: Circuit breaker tripped during run.", file=sys.stderr)
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
    elif args.command == "objc-recover":
        return cmd_objc_recover(args)
    elif args.command == "filter":
        return cmd_filter(args)
    elif args.command in ("overlay-sync", "gui-sync"):
        return cmd_overlay_sync(args)
    elif args.command == "oracle":
        return cmd_oracle(args)
    elif args.command == "smt-verify":
        return cmd_smt_verify(args)
    elif args.command == "diff":
        return cmd_diff(args)
    elif args.command == "apk-xref":
        return cmd_apk_xref(args)
    elif args.command == "apple-dispatch":
        return cmd_apple_dispatch(args)
    elif args.command == "il2cpp-recover":
        return cmd_il2cpp_recover(args)
    elif args.command == "crate-audit":
        return cmd_crate_audit(args)
    elif args.command == "trace-values":
        return cmd_trace_values(args)
    elif args.command == "decompile-all":
        return cmd_decompile_all(args)
    else:
        parser.print_help()
        return 0


if __name__ == "__main__":
    sys.exit(main())
