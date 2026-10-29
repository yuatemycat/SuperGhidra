"""
test_evidence_ledger_obligations.py
===================================

Unit tests for superghidra.core.evidence_ledger:
- EvidenceEnvelope epistemic status (observed, inferred, unknown)
- ReferenceProvenance enum serialization
- CoverageBoundary truncation tracking
- ReconstructionObligationLedger struct natural alignment verification
- Struct boundary check (offset + size <= struct_size)
- Struct field overlap collision detection
- Allocation size verifier integration
- VTable slot index natural alignment
- VTable slot count bounds
- Compilable C syntax verification
- Cross-version struct rewrite CFG cosine similarity gate
- Cross-version access width alignment preservation
- Fork merge conflict detection (conflict_stale_base)
- Stale base divergence isolation
- Envelope to_dict serialization
"""

from __future__ import annotations

from superghidra.core.evidence_ledger import (
    CoverageBoundary,
    EpistemicStatus,
    EvidenceEnvelope,
    ReconstructionObligationLedger,
    ReferenceProvenance,
)


def test_epistemic_status_values():
    assert EpistemicStatus.OBSERVED == "observed"
    assert EpistemicStatus.INFERRED == "inferred"
    assert EpistemicStatus.UNKNOWN == "unknown"


def test_reference_provenance_values():
    assert ReferenceProvenance.ANALYSIS == "analysis"
    assert ReferenceProvenance.DEFAULT == "default"
    assert ReferenceProvenance.IMPORTED == "imported"
    assert ReferenceProvenance.USER_DEFINED == "user_defined"
    assert ReferenceProvenance.SMT_PROVEN == "smt_proven"
    assert ReferenceProvenance.OVERLAY_PENDING == "overlay_pending"


def test_coverage_boundary_dict():
    boundary = CoverageBoundary(
        facet="pcode_ops",
        examined_count=3500,
        decoded_count=3000,
        omitted_count=500,
        truncated=True,
        reason="budget_limit",
    )
    d = boundary.to_dict()
    assert d["facet"] == "pcode_ops"
    assert d["examined_count"] == 3500
    assert d["truncated"] is True
    assert d["reason"] == "budget_limit"


def test_evidence_envelope_serialization():
    boundary = CoverageBoundary(
        facet="def_use_edges",
        examined_count=100,
        decoded_count=100,
        omitted_count=0,
        truncated=False,
    )
    envelope = EvidenceEnvelope(
        evidence_id="ev_123456789abc",
        target_sha256="deadbeef" * 8,
        overlay_revision=2,
        epistemic_status=EpistemicStatus.OBSERVED,
        provenance=ReferenceProvenance.ANALYSIS,
        data={"symbol": "target_fn"},
        coverage=[boundary],
        limitations=["no_debug_symbols"],
    )
    d = envelope.to_dict()
    assert d["evidence_id"] == "ev_123456789abc"
    assert d["epistemic_status"] == "observed"
    assert d["provenance"] == "analysis"
    assert len(d["coverage"]) == 1
    assert d["coverage"][0]["facet"] == "def_use_edges"


def test_struct_natural_alignment_pass():
    ledger = ReconstructionObligationLedger()
    # Fields: (name, offset, size)
    fields = [("id", 0x0, 4), ("padding", 0x4, 4), ("ptr", 0x8, 8)]
    res = ledger.verify_struct_layout("MyStruct", 16, fields)
    assert res.passed is True


def test_struct_natural_alignment_fail():
    ledger = ReconstructionObligationLedger()
    # 4-byte int at offset 3 (misaligned)
    fields = [("misaligned_int", 0x3, 4)]
    res = ledger.verify_struct_layout("BadStruct", 16, fields)
    assert res.passed is False
    assert "misaligned" in res.reason


def test_struct_bounds_exceeded():
    ledger = ReconstructionObligationLedger()
    # 8-byte pointer starting at offset 16 in a 16-byte struct (16 + 8 = 24 > 16)
    fields = [("overflow_ptr", 0x10, 8)]
    res = ledger.verify_struct_layout("OverflowStruct", 16, fields)
    assert res.passed is False
    assert "exceeds" in res.reason


def test_struct_field_collision_overlap():
    ledger = ReconstructionObligationLedger()
    # Field A [0..4), Field B [2..4) -> overlap [2..4) with 2-byte alignment
    fields = [("fieldA", 0x0, 4), ("fieldB", 0x2, 2)]
    res = ledger.verify_struct_layout("OverlapStruct", 32, fields)
    assert res.passed is False
    assert "overlaps" in res.reason


def test_struct_allocation_source_pass():
    ledger = ReconstructionObligationLedger()
    fields = [("a", 0x0, 4), ("b", 0x4, 4)]
    # struct size 8 <= allocation 16
    res = ledger.verify_struct_layout("AllocStruct", 8, fields, allocation_source=("malloc", 16))
    assert res.passed is True


def test_struct_allocation_source_fail():
    ledger = ReconstructionObligationLedger()
    fields = [("a", 0x0, 16)]
    # struct size 16 > allocation 8
    res = ledger.verify_struct_layout("AllocStruct", 16, fields, allocation_source=("malloc", 8))
    assert res.passed is False
    assert "exceeds" in res.reason.lower() or "allocation" in res.reason.lower()


def test_vtable_slot_alignment_pass():
    ledger = ReconstructionObligationLedger()
    res = ledger.verify_vtable("BaseClass", 0x140005000, slot_index=3, pointer_size=8, expected_slots=10)
    assert res.passed is True


def test_vtable_slot_out_of_bounds():
    ledger = ReconstructionObligationLedger()
    res = ledger.verify_vtable("BaseClass", 0x140005000, slot_index=15, pointer_size=8, expected_slots=10)
    assert res.passed is False


def test_compilable_c_syntax_pass():
    ledger = ReconstructionObligationLedger()
    c_code = "int add(int a, int b) { return a + b; }"
    res = ledger.verify_compilable_c(c_code)
    assert res.passed is True


def test_compilable_c_syntax_unbalanced_braces():
    ledger = ReconstructionObligationLedger()
    c_code = "int broken() { return 1;"
    res = ledger.verify_compilable_c(c_code)
    assert res.passed is False
    assert "unbalanced" in res.reason.lower()


def test_cross_version_rewrite_pass():
    ledger = ReconstructionObligationLedger()
    res = ledger.verify_cross_version_rewrite(old_offset=0x20, new_offset=0x28, access_width=8, cosine_similarity=0.92)
    assert res.passed is True


def test_cross_version_rewrite_low_similarity():
    ledger = ReconstructionObligationLedger()
    res = ledger.verify_cross_version_rewrite(old_offset=0x20, new_offset=0x28, access_width=8, cosine_similarity=0.65, threshold=0.80)
    assert res.passed is False
    assert "similarity" in res.reason.lower()


def test_fork_conflict_stale_base_detection():
    ledger = ReconstructionObligationLedger()
    fork_journal = [
        {"canonical_address": "0x140001000", "before_value": "sub_140001000", "staged_value": "ProcessPacket"}
    ]
    # Current main overlay was modified to "HandleNetworkEvent" while fork was at revision 1
    current_main_overlay = {"0x140001000": "HandleNetworkEvent"}

    conflicts = ledger.detect_merge_conflicts(
        staged_fork_journal=fork_journal,
        current_main_overlay=current_main_overlay,
        fork_base_revision=1,
        current_main_revision=2,
    )
    assert len(conflicts) == 1
    assert conflicts[0].conflict_type == "conflict_stale_base"
    assert conflicts[0].canonical_address == "0x140001000"


def test_fork_merge_no_conflict_clean_replay():
    ledger = ReconstructionObligationLedger()
    fork_journal = [
        {"canonical_address": "0x140002000", "before_value": "sub_140002000", "staged_value": "InitAudio"}
    ]
    current_main_overlay = {"0x140002000": "sub_140002000"}  # Untouched in main

    conflicts = ledger.detect_merge_conflicts(
        staged_fork_journal=fork_journal,
        current_main_overlay=current_main_overlay,
        fork_base_revision=1,
        current_main_revision=2,
    )
    assert len(conflicts) == 0
