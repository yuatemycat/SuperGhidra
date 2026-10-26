"""CLI entry point for running the Out-of-Distribution Systems Benchmark."""
from __future__ import annotations

import sys

from benchmarks.systems_ood.harness import run_ood_suite


def main() -> int:
    print("Executing SuperGhidra Out-of-Distribution (OOD) Systems Benchmark...")
    summary = run_ood_suite()
    print("\n--- Summary Results ---")
    print(f"Evaluated Workloads: {summary['workload_count']}")
    print(f"LLM Syntax Pass Rate (R_syn): {summary['llm_syntax_pass_rate']}%")
    print(f"LLM Semantic Pass Rate (R_sem): {summary['llm_semantic_pass_rate']}%")
    print(f"Gate 2 Hallucination Catch Rate: {summary['gate2_catch_rate']}%")
    print(f"SuperGhidra Verified Pass Rate: {summary['verified_semantic_pass_rate']}%")
    return 0


if __name__ == "__main__":
    sys.exit(main())
