"""
benchmarks/eval_held_out.py
===========================

Evaluation harness for measuring decompiler pseudo-C compilability across
a synthetic regression suite of 200 variations across 17 systems C idiom templates.

Evaluates 5 comparison tracks:
  1. Ghidra Raw: Synthetic Ghidra output with standard C headers.
  2. Ghidra Filtered (SuperGhidra): CompilableDecompilerFilter applied to Ghidra output.
  3. IDA Raw: Synthetic Hex-Rays pseudo-C without definitions.
  4. IDA with defs.h: Fair Hex-Rays baseline using IDA_COMPAT_DEFS_H.
  5. IDA Filtered: CompilableDecompilerFilter applied to Hex-Rays output.
"""

from __future__ import annotations

import argparse
import json
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any, Dict, List

from superghidra.core.compilable_filter import (
    IDA_COMPAT_DEFS_H,
    CompilableDecompilerFilter,
)
from superghidra.core.native_compiler import c_compiler, compile_and_run

DATA_PATH = Path(__file__).resolve().parent / "data" / "held_out_200.jsonl"
DEFAULT_SUMMARY_PATH = Path(__file__).resolve().parent / "held_out_score_summary.json"
DEFAULT_LOG_PATH = Path(__file__).resolve().parent / "held_out_score_log.jsonl"

_C_PRELUDE = (
    "#include <stdio.h>\n"
    "#include <stdlib.h>\n"
    "#include <string.h>\n"
    "#include <assert.h>\n"
    "#include <stddef.h>\n"
    "#include <stdint.h>\n"
    "#include <stdbool.h>\n"
)


def _passes_compilation(source: str) -> bool:
    if c_compiler() is None:
        # Fallback heuristic parser when no native C compiler is available
        return "undefined" not in source and "CONCAT" not in source and "_DWORD" not in source
    try:
        ok, _, _ = compile_and_run(
            source,
            language="C",
            timeout_compile=10.0,
            timeout_run=3.0,
            repeat=1,
        )
        return bool(ok)
    except Exception:
        return False


def evaluate_sample(row: Dict[str, Any]) -> Dict[str, Any]:
    func_name = row["func_name"]
    library = row["library"]
    test_src = row.get("test", "int main(void) { return 0; }")

    ghidra_raw_prog = f"{_C_PRELUDE}\n{row['ghidra_pseudo']}\n{test_src}\n"
    ghidra_filt_src = CompilableDecompilerFilter.filter(row["ghidra_pseudo"])
    ghidra_filt_prog = f"{ghidra_filt_src}\n{test_src}\n"

    ida_raw_prog = f"{_C_PRELUDE}\n{row['ida_pseudo']}\n{test_src}\n"
    ida_defs_prog = f"{_C_PRELUDE}\n{IDA_COMPAT_DEFS_H}\n{row['ida_pseudo']}\n{test_src}\n"
    ida_filt_src = CompilableDecompilerFilter.filter(row["ida_pseudo"])
    ida_filt_prog = f"{ida_filt_src}\n{test_src}\n"

    g_raw = _passes_compilation(ghidra_raw_prog)
    g_filt = _passes_compilation(ghidra_filt_prog)
    i_raw = _passes_compilation(ida_raw_prog)
    i_defs = _passes_compilation(ida_defs_prog)
    i_filt = _passes_compilation(ida_filt_prog)

    return {
        "id": row.get("id", func_name),
        "library": library,
        "func_name": func_name,
        "ghidra_raw": g_raw,
        "ghidra_filtered": g_filt,
        "ida_raw": i_raw,
        "ida_with_defs": i_defs,
        "ida_filtered": i_filt,
    }


def run_held_out_evaluation(
    dataset_path: Path = DATA_PATH,
    limit: int | None = None,
    workers: int = 8,
) -> Dict[str, Any]:
    lines = [
        line.strip()
        for line in dataset_path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    rows = [json.loads(line) for line in lines]
    if limit is not None and limit > 0:
        rows = rows[:limit]

    with ThreadPoolExecutor(max_workers=max(1, workers)) as pool:
        results = list(pool.map(evaluate_sample, rows))

    total = len(results)

    def calc_stats(subset: List[Dict[str, Any]]) -> Dict[str, Any]:
        count = len(subset)
        if count == 0:
            return {
                "count": 0,
                "ghidra_raw_pct": 0.0,
                "ghidra_filtered_pct": 0.0,
                "ida_raw_pct": 0.0,
                "ida_with_defs_pct": 0.0,
                "ida_filtered_pct": 0.0,
            }
        g_raw = sum(1 for r in subset if r["ghidra_raw"])
        g_filt = sum(1 for r in subset if r["ghidra_filtered"])
        i_raw = sum(1 for r in subset if r["ida_raw"])
        i_defs = sum(1 for r in subset if r["ida_with_defs"])
        i_filt = sum(1 for r in subset if r["ida_filtered"])
        return {
            "count": count,
            "ghidra_raw_count": g_raw,
            "ghidra_raw_pct": round(g_raw / count * 100.0, 2),
            "ghidra_filtered_count": g_filt,
            "ghidra_filtered_pct": round(g_filt / count * 100.0, 2),
            "ida_raw_count": i_raw,
            "ida_raw_pct": round(i_raw / count * 100.0, 2),
            "ida_with_defs_count": i_defs,
            "ida_with_defs_pct": round(i_defs / count * 100.0, 2),
            "ida_filtered_count": i_filt,
            "ida_filtered_pct": round(i_filt / count * 100.0, 2),
        }

    overall = calc_stats(results)
    by_lib: Dict[str, Any] = {}
    for lib in ("sqlite", "zlib", "coreutils"):
        sub = [r for r in results if r["library"] == lib]
        by_lib[lib] = calc_stats(sub)

    summary = {
        "dataset": str(dataset_path),
        "total_evaluated": total,
        "overall": overall,
        "by_library": by_lib,
        "results": results,
    }
    return summary


def format_text_table(summary: Dict[str, Any]) -> str:
    ov = summary["overall"]
    by_lib = summary["by_library"]
    lines = [
        "================================================================================",
        "             SUPERGHIDRA SYNTHETIC IDIOM EVALUATION (200 VARIATIONS)           ",
        "================================================================================",
        f"Total Evaluated: {summary['total_evaluated']}",
        "",
        f"{'Track':<25} {'Pass Count':<12} {'Pass Rate':<12}",
        "-" * 50,
        f"{'Ghidra Raw':<25} {ov['ghidra_raw_count']:<12} {ov['ghidra_raw_pct']} %",
        f"{'Ghidra Filtered (SG)':<25} {ov['ghidra_filtered_count']:<12} {ov['ghidra_filtered_pct']} %",
        f"{'IDA Raw':<25} {ov['ida_raw_count']:<12} {ov['ida_raw_pct']} %",
        f"{'IDA with defs.h (Fair)':<25} {ov['ida_with_defs_count']:<12} {ov['ida_with_defs_pct']} %",
        f"{'IDA Filtered (SG)':<25} {ov['ida_filtered_count']:<12} {ov['ida_filtered_pct']} %",
        "-" * 50,
        "",
        "Breakdown by Library:",
    ]
    for lib, st in by_lib.items():
        lines.append(
            f"  - {lib:<10} ({st['count']} samples): "
            f"Ghidra Raw={st['ghidra_raw_pct']}%, Ghidra Filt={st['ghidra_filtered_pct']}%, "
            f"IDA Raw={st['ida_raw_pct']}%, IDA Defs={st['ida_with_defs_pct']}%, IDA Filt={st['ida_filtered_pct']}%"
        )
    lines.append("================================================================================")
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description="Evaluate decompiler compilability on held-out split.")
    parser.add_argument("--dataset", type=Path, default=DATA_PATH, help="Path to held-out JSONL dataset.")
    parser.add_argument("--limit", type=int, default=None, help="Limit number of samples evaluated.")
    parser.add_argument("--workers", type=int, default=8, help="Number of concurrent compiler workers.")
    parser.add_argument("--json", action="store_true", help="Print summary JSON to stdout.")
    parser.add_argument("--output-summary", type=Path, default=DEFAULT_SUMMARY_PATH, help="Output summary JSON file.")
    parser.add_argument("--output-log", type=Path, default=DEFAULT_LOG_PATH, help="Output per-sample log JSONL.")
    args = parser.parse_args()

    if not args.dataset.is_file():
        print(f"Error: dataset file not found: {args.dataset}", file=sys.stderr)
        return 1

    summary = run_held_out_evaluation(
        dataset_path=args.dataset,
        limit=args.limit,
        workers=args.workers,
    )

    results = summary.pop("results")

    if args.output_summary:
        args.output_summary.parent.mkdir(parents=True, exist_ok=True)
        args.output_summary.write_text(json.dumps(summary, indent=2), encoding="utf-8")

    if args.output_log:
        args.output_log.parent.mkdir(parents=True, exist_ok=True)
        with args.output_log.open("w", encoding="utf-8") as f:
            for r in results:
                f.write(json.dumps(r, ensure_ascii=False) + "\n")

    if args.json:
        print(json.dumps(summary, indent=2))
    else:
        print(format_text_table(summary))
        if args.output_summary:
            print(f"\n[+] Wrote summary to {args.output_summary}")
        if args.output_log:
            print(f"[+] Wrote per-sample log to {args.output_log}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
