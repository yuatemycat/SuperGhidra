"""Live neural skin path: Gate 2 is differential execution, not constant sets."""

from __future__ import annotations

import pytest

from superghidra.core.native_compiler import c_compiler
from superghidra.integrations.neural_decompiler_pipeline import NeuralDecompilerPipeline

pytestmark = pytest.mark.skipif(
    c_compiler() is None, reason="no C compiler (gcc/clang, or MSVC via SUPERGHIDRA_MSVC_ROOT)"
)

ORIGINAL = "int foo(int x, int y) { if (x == 0x16) return x + y; return 0; }"
BAD_CANDIDATE = "int foo(int x, int y) { if (x == 16) return x + y; return 0; }"
EQUIVALENT_CANDIDATE = (
    "int foo(int status, int offset) { if (status == 0x16) return status + offset; return 0; }"
)
SEMANTICS_METHOD = "CoExec+Symbolic-Trace-Oracle"


def test_skin_refine_rejects_hex_rewritten_as_decimal() -> None:
    result = NeuralDecompilerPipeline().skin_refine(ORIGINAL, BAD_CANDIDATE)
    assert result["accepted"] is False
    assert result["syntax_passed"] is True
    assert result["semantics_passed"] is False
    assert result["readability_ran"] is False
    assert result["semantics_method"] == SEMANTICS_METHOD
    assert result["counterexample"]
    assert "MISMATCH" in result["counterexample"]


def test_skin_refine_accepts_semantically_identical_candidate() -> None:
    result = NeuralDecompilerPipeline().skin_refine(ORIGINAL, EQUIVALENT_CANDIDATE)
    assert result["accepted"] is True
    assert result["syntax_passed"] is True
    assert result["semantics_passed"] is True
    assert result["readability_ran"] is True
    assert result["semantics_method"] == SEMANTICS_METHOD
    assert result["counterexample"] is None
