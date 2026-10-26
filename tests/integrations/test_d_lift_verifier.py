"""
Unit tests for SuperGhidra Section 2:
D-LiFT + Z3 Self-Verifying Neural Decompiler Backend & GRPO Reward Engine.

Target: superghidra/integrations/d_lift_verifier.py
"""

from __future__ import annotations

import pytest

from superghidra.integrations.d_lift_verifier import (
    CFunctionSymbolicLifter,
    ClangSyntaxGate,
    DLiFTPipeline,
    DLiftRewardEngine,
    DScoreReport,
    DScoreResult,
    GRPORewardManager,
    InMemClangSyntaxGate,
    ReadabilityGate,
    ReadabilityMetrics,
    SemanticCheckResult,
    SemanticEquivalenceGate,
    SyntaxCheckResult,
    Z3SemanticEquivalenceGate,
    build_dlift_benchmark_candidates,
    symbolic_write_retry_oracle,
)


class TestGate1SyntaxVerification:
    """Gate 1 (R_syn) Syntax Verification Tests."""

    def test_gate1_valid_c_syntax(self) -> None:
        gate = InMemClangSyntaxGate()
        code = """
int compute_sum(int a, int b) {
    int result = a + b;
    return result;
}
"""
        res = gate.verify_syntax(code)
        assert res.passed is True
        assert res.reward == 0.0
        assert res.error_count == 0
        assert len(res.diagnostics) == 0

    def test_gate1_unbalanced_braces_rejected(self) -> None:
        gate = ClangSyntaxGate()
        code = """
int broken(int x) {
    if (x > 0) {
        return x;
    // Missing closing brace!
}
"""
        res = gate.verify_syntax(code)
        assert res.passed is False
        assert res.reward <= -1.0
        assert res.error_count > 0
        assert any("unbalanced curly braces" in d for d in res.diagnostics)

    def test_gate1_missing_semicolon_rejected(self) -> None:
        gate = InMemClangSyntaxGate()
        code = """
int missing_semi(int x) {
    int y = x + 1
    return y;
}
"""
        res = gate.verify_syntax(code)
        assert res.passed is False
        assert res.reward <= -1.0
        assert res.error_count > 0
        assert any("expected ';'" in d for d in res.diagnostics)

    def test_gate1_unbalanced_parentheses_rejected(self) -> None:
        gate = ClangSyntaxGate()
        code = """
int bad_parens(int x) {
    if ((x > 0 {
        return x;
    }
    return 0;
}
"""
        res = gate.verify_syntax(code)
        assert res.passed is False
        assert res.reward <= -1.0
        assert any("unbalanced parentheses" in d for d in res.diagnostics)

    def test_gate1_non_void_missing_return_rejected(self) -> None:
        gate = ClangSyntaxGate()
        code = """
int no_return(int x) {
    int y = x + 1;
}
"""
        res = gate.verify_syntax(code)
        assert res.passed is False
        assert res.reward <= -1.0
        assert any("missing return statement" in d for d in res.diagnostics)


class TestGate2SemanticVerification:
    """Gate 2 (R_sem) Semantic Equivalence & SMT Verification Tests."""

    def test_gate2_oracle_exact_equivalence_passes(self) -> None:
        gate = Z3SemanticEquivalenceGate()
        orig, candidates = build_dlift_benchmark_candidates()
        verified_code = candidates["4_SuperGhidra_DLiFT_GRPO (Verified)"]

        res = gate.verify_semantics(
            original_c=orig,
            candidate_c=verified_code,
            func_name="safe_rw",
            oracle_runner=symbolic_write_retry_oracle,
        )
        assert res.passed is True
        assert res.reward == 0.0
        assert res.path_match_ratio == 1.0
        assert res.counterexample is None

    def test_gate2_oracle_constant_drift_rejected_with_counterexample(self) -> None:
        gate = SemanticEquivalenceGate()
        orig, candidates = build_dlift_benchmark_candidates()
        hallucinated_code = candidates["3_GPT4o_mini_Baseline (0x16->EBUSY Bug)"]

        res = gate.verify_semantics(
            original_c=orig,
            candidate_c=hallucinated_code,
            func_name="safe_rw",
            oracle_runner=symbolic_write_retry_oracle,
        )
        assert res.passed is False
        assert res.reward < 0.0
        assert res.path_match_ratio < 1.0
        assert res.counterexample is not None
        assert "0x16" in res.counterexample or "EBUSY" in res.counterexample or "EINVAL" in res.counterexample

    def test_gate2_fallback_constant_drift_z3_counterexample(self) -> None:
        gate = Z3SemanticEquivalenceGate()
        orig = """
int check(int err) {
    if (err == 0x16) return 1; // 22 EINVAL
    return 0;
}
"""
        cand = """
int check(int err) {
    if (err == 16) return 1;   // Hallucinated 16 EBUSY
    return 0;
}
"""
        res = gate.verify_semantics(orig, cand, func_name="check")
        assert res.passed is False
        assert res.reward < 0.0
        assert res.counterexample is not None
        assert ("22" in res.counterexample or "16" in res.counterexample or "0x16" in res.counterexample)

    def test_gate2_z3_expr_equivalence_algebraic_pass(self) -> None:
        gate = Z3SemanticEquivalenceGate()
        # (x << 3) - x is algebraically equivalent to x * 7
        res = gate.verify_z3_expr_equivalence("(x << 3) - x", "x * 7", bit_width=64)
        assert res.passed is True
        assert res.reward == 0.0
        assert res.path_match_ratio == 1.0
        assert res.counterexample is None

    def test_gate2_z3_expr_equivalence_mismatch_counterexample(self) -> None:
        gate = Z3SemanticEquivalenceGate()
        # x + 1 != x + 2
        res = gate.verify_z3_expr_equivalence("x + 1", "x + 2", bit_width=64)
        assert res.passed is False
        assert res.reward == -0.95
        assert res.counterexample is not None
        assert "x =" in res.counterexample


class TestGate3ReadabilityAssessment:
    """Gate 3 (R_read) Readability Assessment Tests."""

    def test_gate3_clean_vs_raw_ghidra_metrics(self) -> None:
        orig, candidates = build_dlift_benchmark_candidates()
        clean = candidates["4_SuperGhidra_DLiFT_GRPO (Verified)"]

        metrics = ReadabilityGate.compute_metrics(clean, orig)
        assert metrics.num_lines > 0
        assert metrics.goto_count == 0
        assert metrics.raw_decompiler_vars == 0  # No uVar or lStack in clean code
        assert metrics.bw_score > 0.0
        assert metrics.r2i_score > 0.5  # High decompiler-artifact reduction
        assert metrics.combined_r_read >= 0.05

    def test_gate3_penalizes_gotos_and_pointer_casts(self) -> None:
        orig, _ = build_dlift_benchmark_candidates()
        cluttered_code = """
int messy(void) {
    int *p = (int *)0x1000;
    int **pp = (int **)p;
    goto label1;
label1:
    goto label2;
label2:
    return *(int *)pp;
}
"""
        metrics = ReadabilityGate.compute_metrics(cluttered_code, orig)
        assert metrics.goto_count == 2
        assert metrics.pointer_deref_casts >= 2
        # Penalties reduce R2I score
        assert metrics.r2i_score < 0.6

    def test_gate3_penalizes_raw_decompiler_vars(self) -> None:
        orig, _ = build_dlift_benchmark_candidates()
        raw_code = """
int func(int param_1) {
    int uVar1 = param_1;
    int uVar2 = uVar1 + 1;
    int iVar3 = uVar2 * 2;
    int lStack_20 = iVar3;
    return lStack_20;
}
"""
        metrics = ReadabilityGate.compute_metrics(raw_code, orig)
        assert metrics.raw_decompiler_vars >= 4
        # Having multiple raw decompiler variables reduces var_improvement
        assert metrics.r2i_score < 0.8


class TestDScoreHierarchicalReward:
    """D-Score Hierarchical Reward Inequality & Policy Tests."""

    def test_hierarchical_reward_inequality_enforced(self) -> None:
        """
        Verifies D-Score Eq. (4) invariant:
          max(R_syn) < min(R_sem) < min(R_read)
        Where:
          failed R_syn in [-2.0, -1.0]
          failed R_sem in [-0.95, -0.05]
          passed R_read in [0.05, 2.15]
        """
        engine = DLiftRewardEngine()
        orig, candidates = build_dlift_benchmark_candidates()

        rep_syntax_fail = engine.evaluate_candidate(
            "syntax_fail",
            candidates["2_LLM4Decompile_SFT (Syntax Error)"],
            orig,
        )
        rep_sem_fail = engine.evaluate_candidate(
            "sem_fail",
            candidates["3_GPT4o_mini_Baseline (0x16->EBUSY Bug)"],
            orig,
            oracle_runner=symbolic_write_retry_oracle,
        )
        rep_verified = engine.evaluate_candidate(
            "verified",
            candidates["4_SuperGhidra_DLiFT_GRPO (Verified)"],
            orig,
            oracle_runner=symbolic_write_retry_oracle,
        )

        assert rep_syntax_fail.syntax.passed is False
        assert rep_syntax_fail.d_score <= -1.0

        assert rep_sem_fail.syntax.passed is True
        assert rep_sem_fail.semantics is not None
        assert rep_sem_fail.semantics.passed is False
        assert -0.95 <= rep_sem_fail.d_score <= -0.05

        assert rep_verified.syntax.passed is True
        assert rep_verified.semantics is not None
        assert rep_verified.semantics.passed is True
        assert rep_verified.readability is not None
        assert rep_verified.d_score >= 0.05

        # Strict inequality
        assert rep_syntax_fail.d_score < rep_sem_fail.d_score < rep_verified.d_score


class TestGRPOOptimization:
    """Group Relative Policy Optimization (GRPO) Tests."""

    def test_grpo_advantage_normalization_and_inference_selection(self) -> None:
        pipeline = DLiFTPipeline()
        orig, candidates = build_dlift_benchmark_candidates()

        reports: list[DScoreReport] = []
        for name, code in candidates.items():
            rep = pipeline.evaluate_candidate(
                candidate_name=name,
                candidate_c=code,
                original_c=orig,
                func_name="safe_rw",
                oracle_runner=symbolic_write_retry_oracle,
            )
            reports.append(rep)

        assert len(reports) == 4
        stats = pipeline.compute_grpo_group_advantages(reports)

        assert "group_mean_reward" in stats
        assert "group_std_reward" in stats

        # Normalized advantages should be centered around mean
        sum_adv = sum(r.grpo_advantage for r in reports)
        assert abs(sum_adv) < 0.1  # approximately zero

        # Top verified candidate must have positive advantage and highest score
        winner = pipeline.select_best_inference(reports)
        assert "Verified" in winner.candidate_name
        assert winner.grpo_advantage > 0.0
        assert winner.syntax.passed is True
        assert winner.semantics.passed is True

        # Syntax error candidate must have lowest advantage
        loser = min(reports, key=lambda r: r.d_score)
        assert "Syntax Error" in loser.candidate_name
        assert loser.grpo_advantage < 0.0

    def test_grpo_reward_manager_standalone(self) -> None:
        mgr = GRPORewardManager(beta_kl=0.0)
        syn_ok = SyntaxCheckResult(passed=True, reward=0.0, compiler_used="test")
        sem_ok = SemanticCheckResult(passed=True, reward=0.0, method="test", path_match_ratio=1.0)
        read_metrics = ReadabilityMetrics(
            num_lines=10, goto_count=0, raw_decompiler_vars=0, pointer_deref_casts=0,
            magic_hex_literals=0, max_nesting_depth=1, bw_score=0.9, r2i_score=0.9, combined_r_read=1.85,
        )

        rep1 = DScoreResult(
            candidate_name="cand1", code="void f(){}", syntax=syn_ok, semantics=sem_ok,
            readability=read_metrics, d_score=1.85,
        )
        rep2 = DScoreResult(
            candidate_name="cand2", code="void f(){}", syntax=syn_ok, semantics=None,
            readability=None, d_score=-0.50,
        )
        rep3 = DScoreResult(
            candidate_name="cand3", code="void f(){}", syntax=SyntaxCheckResult(passed=False, reward=-1.5, compiler_used="test"),
            semantics=None, readability=None, d_score=-1.50,
        )

        res = mgr.compute_advantages([rep1, rep2, rep3])
        assert res["group_mean_reward"] == pytest.approx(-0.05, abs=0.01)
        assert rep1.grpo_advantage > rep2.grpo_advantage > rep3.grpo_advantage

    def test_grpo_reward_manager_empty_and_zero_variance(self) -> None:
        mgr = GRPORewardManager()
        empty_res = mgr.compute_advantages([])
        assert empty_res["group_mean_reward"] == 0.0

        rep = DScoreReport(
            candidate_name="single", code="void f(){}",
            syntax=SyntaxCheckResult(passed=True, reward=0.0, compiler_used="test"),
            semantics=None, readability=None, d_score=1.0,
        )
        single_res = mgr.compute_advantages([rep])
        assert single_res["group_mean_reward"] == 1.0
        assert rep.grpo_advantage == 0.0


class TestBackwardCompatibilityAndAliases:
    """Verifies all required aliases and exports."""

    def test_alias_identities(self) -> None:
        assert InMemClangSyntaxGate is ClangSyntaxGate
        assert Z3SemanticEquivalenceGate is SemanticEquivalenceGate
        assert DScoreResult is DScoreReport
        assert DLiftRewardEngine is DLiFTPipeline

    def test_root_shim_exports(self) -> None:
        from superghidra.integrations import d_lift_verifier as root_mod
        assert hasattr(root_mod, "DLiftRewardEngine")
        assert hasattr(root_mod, "InMemClangSyntaxGate")
        assert hasattr(root_mod, "Z3SemanticEquivalenceGate")
        assert hasattr(root_mod, "ReadabilityGate")
        assert hasattr(root_mod, "GRPORewardManager")
        assert hasattr(root_mod, "DScoreResult")
        assert hasattr(root_mod, "SyntaxCheckResult")
        assert hasattr(root_mod, "SemanticCheckResult")
        assert hasattr(root_mod, "ReadabilityMetrics")
