"""CLI entry point for python -m benchmarks.humaneval_decompile.

Prints strict, lenient, and compilable averages read back from the per-sample
score log. It does not reprint the historical results_baseline.json table.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .harness import format_summary, run_benchmark


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Score the pinned HumanEval-Decompile set by compiling each sample.")
    parser.add_argument(
        "--output-dir",
        default=str(Path(__file__).resolve().parent),
        help="Directory for score_log.jsonl and score_summary.json",
    )
    parser.add_argument("--workers", type=int, default=6, help="Parallel compile workers")
    args = parser.parse_args(argv)

    try:
        summary = run_benchmark(Path(args.output_dir), workers=args.workers)
    except Exception as exc:
        print(f"[FAIL] {exc}", file=sys.stderr)
        return 2

    if summary["evaluable_denominator"] <= 0:
        print("[FAIL] no evaluable samples were compiled", file=sys.stderr)
        print(format_summary(summary))
        return 1

    print(format_summary(summary))
    print(f"score_log: {summary['score_log']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
