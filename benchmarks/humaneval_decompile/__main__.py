"""
CLI entry point for python -m benchmarks.humaneval_decompile
"""

from __future__ import annotations

import argparse
import sys
from .harness import HumanEvalDecompileHarness


def main() -> int:
    parser = argparse.ArgumentParser(description="HumanEval-Decompile Benchmark Harness & Verifier")
    parser.add_argument("--tolerance", type=float, default=0.5, help="Acceptance tolerance in percentage points (default: 0.5)")
    parser.add_argument("--report", action="store_true", help="Print the full Markdown comparison report")
    args = parser.parse_args()

    harness = HumanEvalDecompileHarness()
    verification = harness.verify_reproduction(tolerance=args.tolerance)

    if not verification["all_passed"]:
        print(f"[FAIL] Benchmark reproduction failed outside tolerance ±{args.tolerance} pt:", file=sys.stderr)
        for metric, (val, target, passed) in verification["checks"].items():
            status = "PASS" if passed else "FAIL"
            print(f"  - {metric}: {val:.2f}% (target: {target:.2f}%) [{status}]", file=sys.stderr)
        return 1

    print(f"[PASS] HumanEval-Decompile Section 8 benchmark reproduced within ±{args.tolerance} pt.")
    for metric, (val, target, _) in verification["checks"].items():
        print(f"  - {metric}: {val:.2f}% (target: {target:.2f}%) [PASS]")

    report = harness.generate_markdown_report()
    print("\n" + report)
    return 0


if __name__ == "__main__":
    sys.exit(main())
