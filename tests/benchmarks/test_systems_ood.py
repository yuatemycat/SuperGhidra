"""Tests for the uncontaminated out-of-distribution systems benchmark harness."""
from __future__ import annotations

from pathlib import Path

import pytest

from benchmarks.systems_ood.harness import run_ood_suite
from superghidra.core.native_compiler import c_compiler

pytestmark = pytest.mark.skipif(
    c_compiler() is None,
    reason="Native C compiler (GCC, Clang, or MSVC) required for physical benchmark execution",
)


def test_run_ood_suite_in_memory(tmp_path: Path) -> None:
    md_file = tmp_path / "test_report.md"
    json_file = tmp_path / "test_summary.json"

    summary = run_ood_suite(write_md=True, write_json=True, md_path=md_file, json_path=json_file)

    assert summary["workload_count"] == 6
    assert summary["llm_syntax_pass_rate"] == 100.0
    assert summary["llm_semantic_pass_rate"] == 0.0
    assert summary["gate2_catch_rate"] == 100.0
    assert summary["verified_semantic_pass_rate"] == 100.0

    assert md_file.is_file()
    assert json_file.is_file()

    content = md_file.read_text(encoding="utf-8")
    assert "SuperGhidra Out-of-Distribution (OOD) Systems Benchmark Report" in content
    assert "SHA256_ROUND" in content
