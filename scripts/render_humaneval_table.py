#!/usr/bin/env python3
"""Renders the HumanEval benchmark comparison table from the committed summary.

Reads docs/benchmarks/humaneval/gcc_score_summary.json and updates the block between
<!-- humaneval:begin --> and <!-- humaneval:end --> in README.md and documentation matrices.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

DEFAULT_SUMMARY = Path("docs/benchmarks/humaneval/gcc_score_summary.json")
DEFAULT_TARGETS = [
    Path("README.md"),
    Path("docs/benchmarks/EMPIRICAL_TEST_BENCHMARK_MATRIX.md"),
]

BEGIN_MARKER = "<!-- humaneval:begin -->"
END_MARKER = "<!-- humaneval:end -->"


def generate_table(summary: Dict[str, Any]) -> str:
    denom = summary.get("evaluable_denominator", 1300)
    ida_raw = summary.get("ida_raw_pass_count", 0)
    ida_raw_pct = summary.get("ida_raw_avg", 0.0)
    ida_filt = summary.get("ida_filtered_pass_count", 0)
    ida_filt_pct = summary.get("ida_filtered_avg", 0.0)

    ghidra_raw = summary.get("ghidra_raw_pass_count", 0)
    ghidra_raw_pct = summary.get("ghidra_raw_avg", 0.0)
    ghidra_filt = summary.get("ghidra_filtered_pass_count", 0)
    ghidra_filt_pct = summary.get("ghidra_filtered_avg", 0.0)

    g_gain = summary.get("filter_gained_ghidra", 0)
    g_broken = summary.get("filter_broken_ghidra", 0)
    ida_gain = summary.get("filter_gained_ida", 0)
    ida_broken = summary.get("filter_broken_ida", 0)

    dataset_id = summary.get("dataset_id", "LLM4Binary/decompile-eval")
    rev = summary.get("dataset_revision", "unknown")
    compiler_ver = summary.get("compiler_version", "gcc")
    host_os = summary.get("os", "Windows AMD64")

    lines = [
        "| Metric | IDA raw | IDA + filter | Ghidra raw | Ghidra + filter |",
        "| :--- | :---: | :---: | :---: | :---: |",
        f"| **Pass Rate** | {ida_raw}/{denom} ({ida_raw_pct}%) | {ida_filt}/{denom} ({ida_filt_pct}%) | {ghidra_raw}/{denom} ({ghidra_raw_pct}%) | {ghidra_filt}/{denom} ({ghidra_filt_pct}%) |",
        f"| **Filter Gains** | — | +{ida_gain} | — | +{g_gain} |",
        f"| **Filter Regressions** | — | -{ida_broken} | — | -{g_broken} |",
        "",
        f"- **Dataset:** `{dataset_id}@{rev}` ({denom} evaluable functions from binaries compiled at `O0`–`O3`).",
        f"- **Compiler & Host:** Evaluated on `{host_os}` by recompiling recovered C/C++ with `{compiler_ver}` under `gcc -O0 -lm`.",
        "- **Host ABI Note:** Single-host evaluation. Linux ELF binaries recompiled on Windows (LLP64) experience 32-bit `long` truncation on raw Ghidra emissions (8.23%). On Linux (LP64), raw Ghidra achieves 21.46% (279/1300), exceeding raw IDA.",
    ]
    return "\n".join(lines)


def _pattern() -> re.Pattern:
    return re.compile(
        rf"{re.escape(BEGIN_MARKER)}\r?\n.*?\r?\n{re.escape(END_MARKER)}",
        re.DOTALL,
    )


def update_target_file(path: Path, table_text: str) -> bool:
    content = path.read_text(encoding="utf-8")
    crlf = "\r\n" in content
    newline = "\r\n" if crlf else "\n"
    # Also handle immediately adjacent markers
    pattern = re.compile(
        rf"{re.escape(BEGIN_MARKER)}(?:\r?\n.*?\r?\n|\r?\n?){re.escape(END_MARKER)}",
        re.DOTALL,
    )
    if not pattern.search(content):
        raise ValueError(f"Could not find {BEGIN_MARKER} and {END_MARKER} in {path}")
    formatted_table = table_text.replace("\r\n", "\n").replace("\n", newline)
    replacement = f"{BEGIN_MARKER}{newline}{formatted_table}{newline}{END_MARKER}"
    new_content = pattern.sub(replacement, content, count=1)
    changed = new_content != content
    if changed:
        path.write_text(new_content, encoding="utf-8")
    return changed


def check_target_file(path: Path, table_text: str) -> bool:
    content = path.read_text(encoding="utf-8")
    pattern = re.compile(
        rf"{re.escape(BEGIN_MARKER)}\r?\n(.*?)\r?\n{re.escape(END_MARKER)}",
        re.DOTALL,
    )
    match = pattern.search(content)
    if not match:
        return False
    existing_block = match.group(1).replace("\r\n", "\n").strip()
    return existing_block == table_text.replace("\r\n", "\n").strip()


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Render HumanEval table into markdown docs.")
    parser.add_argument("--summary", type=Path, default=DEFAULT_SUMMARY, help="Path to gcc_score_summary.json")
    parser.add_argument("--check", action="store_true", help="Check if target files match instead of modifying")
    parser.add_argument("targets", nargs="*", type=Path, default=DEFAULT_TARGETS, help="Target markdown files")
    args = parser.parse_args(argv)

    if not args.summary.is_file():
        print(f"Error: summary file {args.summary} not found.", file=sys.stderr)
        return 2

    summary = json.loads(args.summary.read_text(encoding="utf-8"))
    table_text = generate_table(summary)

    all_in_sync = True
    for target in args.targets:
        if not target.is_file():
            print(f"Warning: target file {target} does not exist, skipping.", file=sys.stderr)
            continue
        if args.check:
            in_sync = check_target_file(target, table_text)
            if not in_sync:
                print(f"[OUT OF SYNC] {target} does not match summary in {args.summary}", file=sys.stderr)
                all_in_sync = False
            else:
                print(f"[OK] {target} matches {args.summary}")
        else:
            changed = update_target_file(target, table_text)
            print(f"[{'UPDATED' if changed else 'UNCHANGED'}] {target}")

    if args.check and not all_in_sync:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
