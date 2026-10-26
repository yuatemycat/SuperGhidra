"""Harness for running uncontaminated out-of-distribution systems benchmarks."""
from __future__ import annotations

import dataclasses
import json
from pathlib import Path
from typing import Any, Dict

from superghidra.diff.ood_decompiler_benchmark import (
    OODDecompilerBenchmarkRunner,
    format_markdown_report,
)

DEFAULT_REPORT_PATH = Path("docs") / "benchmarks" / "OOD_SYSTEMS_BENCHMARK_REPORT.md"
DEFAULT_JSON_PATH = Path("benchmarks") / "systems_ood" / "ood_score_summary.json"


def run_ood_suite(
    write_md: bool = True,
    write_json: bool = True,
    md_path: Path = DEFAULT_REPORT_PATH,
    json_path: Path = DEFAULT_JSON_PATH,
) -> Dict[str, Any]:
    """Execute all OOD benchmark cases and return telemetry summary."""
    rows = OODDecompilerBenchmarkRunner.run_all()
    md_text = format_markdown_report(rows)

    total = len(rows)
    llm_syn_pass = sum(1 for r in rows if r.llm_syntax_ok)
    llm_sem_pass = sum(1 for r in rows if r.llm_semantic_ok)
    llm_caught = sum(1 for r in rows if r.llm_caught_by_gate2)
    ref_pass = sum(1 for r in rows if r.refined_semantic_ok)

    summary: Dict[str, Any] = {
        "workload_count": total,
        "llm_syntax_pass_rate": round(llm_syn_pass / total * 100.0, 2),
        "llm_semantic_pass_rate": round(llm_sem_pass / total * 100.0, 2),
        "gate2_catch_rate": round(llm_caught / total * 100.0, 2),
        "verified_semantic_pass_rate": round(ref_pass / total * 100.0, 2),
        "rows": [dataclasses.asdict(r) for r in rows],
    }

    if write_md:
        md_path.parent.mkdir(parents=True, exist_ok=True)
        md_path.write_text(md_text, encoding="utf-8")

    if write_json:
        json_path.parent.mkdir(parents=True, exist_ok=True)
        json_path.write_text(json.dumps(summary, indent=2), encoding="utf-8")

    return summary
