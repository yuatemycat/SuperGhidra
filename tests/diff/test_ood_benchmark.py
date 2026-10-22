"""
tests/diff/test_ood_benchmark.py
================================
Unit tests for the Out-of-Distribution (OOD) Systems Benchmark Suite.
Verifies compilation, differential execution, and hallucination rejection
across all 6 real-world systems workloads.
"""

from __future__ import annotations

import pytest

from superghidra.core.native_compiler import c_compiler
from superghidra.diff.ood_decompiler_benchmark import (
    BENCHMARK_CASES,
    BenchmarkResultRow,
    OODDecompilerBenchmarkRunner,
    format_markdown_report,
)

pytestmark = pytest.mark.skipif(
    c_compiler() is None,
    reason="Native C compiler (GCC, Clang, or MSVC cl.exe) required for physical benchmark execution",
)


def test_ood_benchmark_cases_count() -> None:
    """Ensure all 6 core systems categories are registered."""
    assert len(BENCHMARK_CASES) == 6
    ids = [c.identifier for c in BENCHMARK_CASES]
    assert "SHA256_ROUND" in ids
    assert "CHACHA20_QR" in ids
    assert "RFC1071_CHECKSUM" in ids
    assert "LEB128_DECODE" in ids
    assert "SPSC_RING_BUFFER" in ids
    assert "SLAB_ALLOC_HEADER" in ids


def test_ood_benchmark_case_sha256() -> None:
    """Test Case 1: SHA256 quarter-round bitwise invariants and rotation checking."""
    case = next(c for c in BENCHMARK_CASES if c.identifier == "SHA256_ROUND")
    row = OODDecompilerBenchmarkRunner.run_case(case)

    assert row.raw_semantic_ok is True
    assert row.llm_syntax_ok is True
    # LLM hallucination dropped rotation bits -> must fail semantic execution
    assert row.llm_semantic_ok is False
    assert row.llm_caught_by_gate2 is True
    # SuperGhidra verified candidate must pass cleanly
    assert row.refined_semantic_ok is True


def test_ood_benchmark_case_ring_buffer() -> None:
    """Test Case 5: SPSC ring buffer natural pointer alignment and displacement indexing."""
    case = next(c for c in BENCHMARK_CASES if c.identifier == "SPSC_RING_BUFFER")
    row = OODDecompilerBenchmarkRunner.run_case(case)

    assert row.raw_semantic_ok is True
    assert row.llm_syntax_ok is True
    # LLM hallucinated unpadded struct offset (0x0C instead of 0x10) -> must fail
    assert row.llm_semantic_ok is False
    assert row.llm_caught_by_gate2 is True
    assert row.refined_semantic_ok is True
    assert row.refined_evidence_ok is True


def test_ood_benchmark_full_matrix_execution() -> None:
    """Run the entire 6-case benchmark matrix and verify the report."""
    results = OODDecompilerBenchmarkRunner.run_all()
    assert len(results) == 6

    # Invariant: 100% of LLM candidates compile syntactically, but 100% fail semantic execution
    llm_compiles = sum(1 for r in results if r.llm_syntax_ok)
    llm_sem_fails = sum(1 for r in results if not r.llm_semantic_ok)
    ref_sem_passes = sum(1 for r in results if r.refined_semantic_ok)

    assert llm_compiles == 6, "All LLM candidates should produce valid C syntax"
    assert llm_sem_fails == 6, "All hallucinated candidates must be rejected by Gate 2"
    assert ref_sem_passes == 6, "All refined candidates must pass semantic execution"

    md_report = format_markdown_report(results)
    assert "# SuperGhidra Out-of-Distribution (OOD) Systems Benchmark Report" in md_report
    assert "LLM Benchmark Contamination Trap" in md_report
    assert "SHA256_ROUND" in md_report
    assert "SLAB_ALLOC_HEADER" in md_report
