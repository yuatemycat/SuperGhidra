"""Unit tests for ARM64 Jump-Table Bounds Prover (12 test cases)."""

import struct

from superghidra.acceleration.jump_table_prover import (
    ARM64JumpTableProver,
    JumpTableCandidate,
)


def _encode_cmp_imm_32(rn: int, imm12: int) -> int:
    """Encodes CMP Wn, #imm12 (SUBS WZR, Wn, #imm12)."""
    return 0x7100001F | ((imm12 & 0xFFF) << 10) | ((rn & 0x1F) << 5)


def _encode_b_cond(cond: int, imm19: int) -> int:
    """Encodes B.cond #imm19 (0x54000000 | (imm19 << 5) | cond)."""
    return 0x54000000 | ((imm19 & 0x7FFFF) << 5) | (cond & 0xF)


def _encode_adr(rd: int, imm21: int) -> int:
    """Encodes ADR Xd, #imm21."""
    immlo = imm21 & 0x3
    immhi = (imm21 >> 2) & 0x7FFFF
    return 0x10000000 | (immlo << 29) | (immhi << 5) | (rd & 0x1F)


def _encode_br(rn: int) -> int:
    """Encodes BR Xn."""
    return 0xD61F0000 | ((rn & 0x1F) << 5)


def test_cmp_b_hi_bounds_proof():
    """1. B.HI (unsigned greater than imm) bounds proof yields N = imm + 1."""
    prover = ARM64JumpTableProver()
    n, proven = prover.prove_bounds(bound_imm=7, cond="HI", cmp_reg=0, index_reg=0, table_target_reg=1, dispatch_reg=1)
    assert n == 8
    assert proven is True


def test_cmp_b_hs_bounds_proof():
    """2. B.HS (unsigned greater or equal to imm) bounds proof yields N = imm."""
    prover = ARM64JumpTableProver()
    n, proven = prover.prove_bounds(bound_imm=8, cond="HS", cmp_reg=0, index_reg=0, table_target_reg=1, dispatch_reg=1)
    assert n == 8
    assert proven is True


def test_adr_table_base_load():
    """3. Parses ADR table base offset accurately."""
    # PC = 0x1008, table at 0x1100 -> offset = 0xf8
    adr_insn = _encode_adr(1, 0xF8)
    insns = [
        _encode_cmp_imm_32(0, 4),
        _encode_b_cond(8, 20),  # B.HI default (+80 bytes)
        adr_insn,
        0x38606822,  # LDRB W2, [X1, X0]
        _encode_br(2),
    ]
    code = struct.pack(f"<{len(insns)}I", *insns)
    prover = ARM64JumpTableProver()
    candidates = prover.scan_candidates(code, base_va=0x1000)
    assert len(candidates) == 1
    assert candidates[0].table_base_va == 0x1008 + 0xF8
    assert candidates[0].base_calc_type == "ADR"


def test_adrp_add_table_base_load():
    """4. Parses ADRP + page base calculation."""
    # ADRP X1, #0 (page of 0x1000 is 0x1000)
    adrp_insn = 0x90000001
    insns = [
        _encode_cmp_imm_32(0, 5),
        _encode_b_cond(8, 15),
        adrp_insn,
        0x38606822,  # LDRB W2, [X1, X0]
        _encode_br(2),
    ]
    code = struct.pack(f"<{len(insns)}I", *insns)
    prover = ARM64JumpTableProver()
    candidates = prover.scan_candidates(code, base_va=0x1000)
    assert len(candidates) == 1
    assert candidates[0].base_calc_type == "ADRP_ADD"


def test_ldrb_byte_table():
    """5. Extracts byte-width relative jump targets."""
    prover = ARM64JumpTableProver()
    candidate = JumpTableCandidate(
        pc=0x1000,
        cmp_pc=0x1000,
        cmp_reg=0,
        bound_imm=3,
        branch_cond="HI",
        default_target=0x1200,
        base_calc_type="ADR",
        table_base_va=0x2000,
        load_insn_type="LDRB",
        entry_size=1,
        dispatch_pc=0x1010,
        dispatch_reg=2,
    )
    # 4 byte offsets: 10, 20, 30, 40
    memory_data = bytes([10, 20, 30, 40])
    table = prover.recover_jump_table(candidate, memory_data=memory_data, memory_base_va=0x2000)
    assert table.bounds_n == 4
    assert table.entry_size == 1
    assert table.targets[0] == 0x2000 + (10 << 2)
    assert table.targets[1] == 0x2000 + (20 << 2)
    assert table.unresolved_cases == 0


def test_ldrh_halfword_table():
    """6. Extracts 16-bit halfword relative jump targets."""
    prover = ARM64JumpTableProver()
    candidate = JumpTableCandidate(
        pc=0x1000,
        cmp_pc=0x1000,
        cmp_reg=0,
        bound_imm=2,
        branch_cond="HS",
        default_target=0x1200,
        base_calc_type="ADR",
        table_base_va=0x3000,
        load_insn_type="LDRH",
        entry_size=2,
        dispatch_pc=0x1010,
        dispatch_reg=2,
    )
    memory_data = struct.pack("<2H", 100, 200)
    table = prover.recover_jump_table(candidate, memory_data=memory_data, memory_base_va=0x3000)
    assert table.bounds_n == 2
    assert table.targets[0] == 0x3000 + (100 << 2)
    assert table.targets[1] == 0x3000 + (200 << 2)


def test_ldrsw_word_table():
    """7. Extracts 32-bit signed word relative jump targets."""
    prover = ARM64JumpTableProver()
    candidate = JumpTableCandidate(
        pc=0x1000,
        cmp_pc=0x1000,
        cmp_reg=0,
        bound_imm=3,
        branch_cond="HI",
        default_target=0x1200,
        base_calc_type="ADR",
        table_base_va=0x4000,
        load_insn_type="LDRSW",
        entry_size=4,
        dispatch_pc=0x1010,
        dispatch_reg=2,
    )
    memory_data = struct.pack("<4i", 50, 60, 70, 80)
    table = prover.recover_jump_table(candidate, memory_data=memory_data, memory_base_va=0x4000)
    assert table.bounds_n == 4
    assert table.targets[0] == 0x4000 + (50 << 2)


def test_ldr_64bit_table():
    """8. Extracts 64-bit absolute jump targets."""
    prover = ARM64JumpTableProver()
    candidate = JumpTableCandidate(
        pc=0x1000,
        cmp_pc=0x1000,
        cmp_reg=0,
        bound_imm=2,
        branch_cond="HI",
        default_target=0x1200,
        base_calc_type="ADR",
        table_base_va=0x5000,
        load_insn_type="LDR",
        entry_size=8,
        dispatch_pc=0x1010,
        dispatch_reg=2,
    )
    memory_data = struct.pack("<3Q", 0x140001000, 0x140002000, 0x140003000)
    table = prover.recover_jump_table(candidate, memory_data=memory_data, memory_base_va=0x5000)
    assert table.bounds_n == 3
    assert table.targets[0] == 0x140001000
    assert table.targets[2] == 0x140003000


def test_default_target_identification():
    """9. Correctly computes default branch target from B.cond immediate."""
    # B.HI offset +16 bytes from pc=0x1004 -> 0x1014
    b_hi = _encode_b_cond(8, 4)
    insns = [
        _encode_cmp_imm_32(0, 3),
        b_hi,
        _encode_adr(1, 0x40),
        0x38606822,  # LDRB W2, [X1, X0]
        _encode_br(2),
    ]
    code = struct.pack(f"<{len(insns)}I", *insns)
    prover = ARM64JumpTableProver()
    candidates = prover.scan_candidates(code, base_va=0x1000)
    assert len(candidates) == 1
    assert candidates[0].default_target == 0x1004 + (4 << 2)


def test_out_of_bounds_maps_to_null():
    """10. Entries outside section bounds map to None and increment unresolved_cases."""
    prover = ARM64JumpTableProver()
    candidate = JumpTableCandidate(
        pc=0x1000,
        cmp_pc=0x1000,
        cmp_reg=0,
        bound_imm=4,
        branch_cond="HI",
        default_target=0x1200,
        base_calc_type="ADR",
        table_base_va=0x2000,
        load_insn_type="LDRB",
        entry_size=1,
        dispatch_pc=0x1010,
        dispatch_reg=2,
    )
    # Provided only 2 bytes for 5 expected cases
    memory_data = bytes([10, 20])
    table = prover.recover_jump_table(candidate, memory_data=memory_data, memory_base_va=0x2000)
    assert table.bounds_n == 5
    assert table.targets[0] is not None
    assert table.targets[1] is not None
    assert table.targets[2] is None
    assert table.targets[3] is None
    assert table.targets[4] is None
    assert table.unresolved_cases == 3


def test_non_literal_invalid_maps_to_null():
    """11. Sentinel 0xFF / 0xFFFFFFFF values map to None."""
    prover = ARM64JumpTableProver()
    candidate = JumpTableCandidate(
        pc=0x1000,
        cmp_pc=0x1000,
        cmp_reg=0,
        bound_imm=2,
        branch_cond="HI",
        default_target=0x1200,
        base_calc_type="ADR",
        table_base_va=0x2000,
        load_insn_type="LDRB",
        entry_size=1,
        dispatch_pc=0x1010,
        dispatch_reg=2,
    )
    # Middle byte is 0xFF (sentinel/invalid)
    memory_data = bytes([12, 0xFF, 14])
    table = prover.recover_jump_table(candidate, memory_data=memory_data, memory_base_va=0x2000)
    assert table.targets[0] is not None
    assert table.targets[1] is None
    assert table.targets[2] is not None
    assert table.unresolved_cases == 1


def test_full_recovery_integration():
    """12. End-to-end detection, bounds proof, and table extraction."""
    prover = ARM64JumpTableProver()
    insns = [
        _encode_cmp_imm_32(0, 3),  # CMP W0, #3 -> 4 cases
        _encode_b_cond(8, 25),  # B.HI default
        _encode_adr(1, 0x20),  # ADR X1, #32
        0x38606822,  # LDRB W2, [X1, X0]                 # LDRB W2, [X0, X1]
        _encode_br(2),  # BR X2
    ]
    code = struct.pack(f"<{len(insns)}I", *insns)
    candidates = prover.scan_candidates(code, base_va=0x1000)
    assert len(candidates) == 1

    table_data = bytes([4, 8, 12, 16])
    recovered = prover.recover_jump_table(
        candidate=candidates[0],
        memory_data=table_data,
        memory_base_va=candidates[0].table_base_va,
    )
    data = recovered.to_dict()
    assert data["bounds_n"] == 4
    assert len(data["targets"]) == 4
    assert data["unresolved_cases"] == 0
    assert data["proven"] is True


def test_compiler_pattern_load_x2_add_x1_branch_x1():
    """13. Standard compiler pattern: load into x2, add into x1, branch through x1."""
    prover = ARM64JumpTableProver()
    # CMP W0, #4 (cases 0..4, bounds_n = 5)
    # B.HI default (+80 bytes)
    # ADR X1, #32 (table base at 0x1008 + 32 = 0x1028)
    # LDRSW X2, [X1, W0, SXTW #2] (0xB8A0D822: load 32-bit signed offset into X2)
    # ADD X1, X1, X2 (0x8B020021: add base X1 + offset X2 -> X1)
    # BR X1 (_encode_br(1))
    ldrsw_x2_insn = 0xB8A0D822
    add_x1_x1_x2 = 0x8B020021
    insns = [
        _encode_cmp_imm_32(0, 4),
        _encode_b_cond(8, 20),
        _encode_adr(1, 0x20),
        ldrsw_x2_insn,
        add_x1_x1_x2,
        _encode_br(1),
    ]
    code = struct.pack(f"<{len(insns)}I", *insns)
    candidates = prover.scan_candidates(code, base_va=0x1000)
    assert len(candidates) == 1
    cand = candidates[0]
    assert cand.table_target_reg == 2
    assert cand.dispatch_reg == 1
    assert cand.target_flows_to_dispatch is True

    table_data = struct.pack("<5i", 10, 20, 30, 40, 50)
    recovered = prover.recover_jump_table(
        candidate=cand,
        memory_data=table_data,
        memory_base_va=cand.table_base_va,
    )
    assert recovered.bounds_n == 5
    assert recovered.proven is True
    assert recovered.unresolved_cases == 0
    assert len(recovered.targets) == 5
    assert recovered.targets[0] == cand.table_base_va + (10 << 2)


def test_compiler_pattern_clobbered_add_fails_safe():
    """14. If dispatch register is overwritten with unrelated value, proof fails safe."""
    prover = ARM64JumpTableProver()
    ldrsw_x2_insn = 0xB8A0D822
    # ADD X1, X3, X4 (0x8B040061: unrelated add into X1, does not flow from X2)
    add_unrelated = 0x8B040061
    insns = [
        _encode_cmp_imm_32(0, 4),
        _encode_b_cond(8, 20),
        _encode_adr(1, 0x20),
        ldrsw_x2_insn,
        add_unrelated,
        _encode_br(1),
    ]
    code = struct.pack(f"<{len(insns)}I", *insns)
    candidates = prover.scan_candidates(code, base_va=0x1000)
    assert len(candidates) == 1
    cand = candidates[0]
    assert cand.table_target_reg == 2
    assert cand.dispatch_reg == 1
    assert cand.target_flows_to_dispatch is False

    table_data = struct.pack("<5i", 10, 20, 30, 40, 50)
    recovered = prover.recover_jump_table(
        candidate=cand,
        memory_data=table_data,
        memory_base_va=cand.table_base_va,
    )
    assert recovered.proven is False


def test_add_unrelated_base_register_fails_safe():
    """15. ADD where other operand is not table base fails provenance proof."""
    prover = ARM64JumpTableProver()
    # ADD X1, X5, X2 (0x8B0200A1: adds unrelated X5 instead of table base X1)
    add_x1_x5_x2 = 0x8B0200A1
    ldrsw_x2_insn = 0xB8A0D822
    insns = [
        _encode_cmp_imm_32(0, 4),
        _encode_b_cond(8, 20),
        _encode_adr(1, 0x20),
        ldrsw_x2_insn,
        add_x1_x5_x2,
        _encode_br(1),
    ]
    code = struct.pack(f"<{len(insns)}I", *insns)
    candidates = prover.scan_candidates(code, base_va=0x1000)
    assert len(candidates) == 1
    cand = candidates[0]
    assert cand.target_flows_to_dispatch is False

    table_data = struct.pack("<5i", 10, 20, 30, 40, 50)
    recovered = prover.recover_jump_table(
        candidate=cand,
        memory_data=table_data,
        memory_base_va=cand.table_base_va,
    )
    assert recovered.proven is False


def test_table_base_overwritten_before_add_fails_safe():
    """16. Table base clobbered before relative ADD fails provenance proof."""
    prover = ARM64JumpTableProver()
    ldrsw_x2_insn = 0xB8A0D822
    # MOVZ X1, #0 (0xD2800001: overwrites X1 table base with 0)
    movz_x1_0 = 0xD2800001
    add_x1_x1_x2 = 0x8B020021
    insns = [
        _encode_cmp_imm_32(0, 4),
        _encode_b_cond(8, 20),
        _encode_adr(1, 0x20),
        ldrsw_x2_insn,
        movz_x1_0,
        add_x1_x1_x2,
        _encode_br(1),
    ]
    code = struct.pack(f"<{len(insns)}I", *insns)
    candidates = prover.scan_candidates(code, base_va=0x1000)
    assert len(candidates) == 1
    cand = candidates[0]
    assert cand.target_flows_to_dispatch is False

    table_data = struct.pack("<5i", 10, 20, 30, 40, 50)
    recovered = prover.recover_jump_table(
        candidate=cand,
        memory_data=table_data,
        memory_base_va=cand.table_base_va,
    )
    assert recovered.proven is False


def test_table_load_base_is_index_register_fails_safe():
    """17. Table load using index register as base register is rejected."""
    prover = ARM64JumpTableProver()
    # LDRSW X2, [X0, X1, SXTW #2] (0xB8A1D802: Rn=0 (cmp_reg), Rm=1)
    ldrsw_base_is_index = 0xB8A1D802
    add_x1_x1_x2 = 0x8B020021
    insns = [
        _encode_cmp_imm_32(0, 4),
        _encode_b_cond(8, 20),
        _encode_adr(1, 0x20),
        ldrsw_base_is_index,
        add_x1_x1_x2,
        _encode_br(1),
    ]
    code = struct.pack(f"<{len(insns)}I", *insns)
    candidates = prover.scan_candidates(code, base_va=0x1000)
    # Load's base register is cmp_reg and does not match table base, candidate rejected
    assert len(candidates) == 0


def test_table_base_clobbered_before_load_fails_safe():
    """18. Table base overwritten before table load is rejected."""
    prover = ARM64JumpTableProver()
    ldrsw_x2_insn = 0xB8A0D822
    movz_x1_0 = 0xD2800001
    add_x1_x1_x2 = 0x8B020021
    insns = [
        _encode_cmp_imm_32(0, 4),
        _encode_b_cond(8, 20),
        _encode_adr(1, 0x20),
        movz_x1_0,
        ldrsw_x2_insn,
        add_x1_x1_x2,
        _encode_br(1),
    ]
    code = struct.pack(f"<{len(insns)}I", *insns)
    candidates = prover.scan_candidates(code, base_va=0x1000)
    assert len(candidates) == 0


def test_prove_bounds_base_matches_cmp_reg_fails_safe():
    """19. prove_bounds explicitly fails if table_base_reg == cmp_reg."""
    prover = ARM64JumpTableProver()
    n, proven = prover.prove_bounds(
        bound_imm=4,
        cond="HI",
        cmp_reg=0,
        index_reg=0,
        table_target_reg=1,
        dispatch_reg=1,
        table_base_reg=0,  # base matches cmp_reg!
    )
    assert proven is False


def _encode_adrp(rd: int, target_page_va: int, pc: int) -> int:
    """Encodes ADRP Xd, #imm21 (page offset)."""
    imm21 = ((target_page_va & ~0xFFF) - (pc & ~0xFFF)) >> 12
    immlo = imm21 & 0x3
    immhi = (imm21 >> 2) & 0x7FFFF
    return 0x90000000 | (immlo << 29) | (immhi << 5) | (rd & 0x1F)


def _encode_add_imm_64(rd: int, rn: int, imm12: int) -> int:
    """Encodes ADD Xd, Xn, #imm12."""
    return 0x91000000 | ((imm12 & 0xFFF) << 10) | ((rn & 0x1F) << 5) | (rd & 0x1F)


def _encode_add_shifted_64(rd: int, rn: int, rm: int, shift_amount: int = 2) -> int:
    """Encodes ADD Xd, Xn, Xm, LSL #shift_amount."""
    return 0x8B000000 | ((rm & 0x1F) << 16) | ((shift_amount & 0x3F) << 10) | ((rn & 0x1F) << 5) | (rd & 0x1F)


def _encode_ldrsw_reg(rt: int, rn: int, rm: int) -> int:
    """Encodes LDRSW Xt, [Xn, Xm, LSL #2]."""
    return 0xB8A07800 | ((rm & 0x1F) << 16) | ((rn & 0x1F) << 5) | (rt & 0x1F)


def test_apple_clang_canonical_pattern_candidate_scan():
    """20. Bug 6: Apple Clang canonical switch pattern is not dropped by ADR code-anchor overwrite."""
    prover = ARM64JumpTableProver()

    # Canonical Apple Clang ARM64 switch dispatch:
    # 0x1000: CMP W2, #4               (cmp_reg = 2, bound = 4 -> 5 cases)
    # 0x1004: B.HI default             (+80 bytes)
    # 0x1008: ADRP X0, #0x8000         (table base page in .rodata)
    # 0x100C: ADD X0, X0, #0x100       (table base pageoff -> 0x8100)
    # 0x1010: .Ltmp0: ADR X1, .Ltmp0   (code anchor in .text at 0x1010)
    # 0x1014: LDRSW X3, [X0, X2, LSL #2] (table load from X0)
    # 0x1018: ADD X1, X1, X3, LSL #2   (code anchor X1 + offset X3 -> X1)
    # 0x101C: BR X1                    (dispatch through X1)
    insns = [
        _encode_cmp_imm_32(2, 4),
        _encode_b_cond(8, 20),
        _encode_adrp(0, 0x8000, 0x1008),
        _encode_add_imm_64(0, 0, 0x100),
        _encode_adr(1, 0),  # ADR X1, .Ltmp0 (offset 0 from 0x1010)
        _encode_ldrsw_reg(3, 0, 2),
        _encode_add_shifted_64(1, 1, 3, 2),
        _encode_br(1),
    ]
    code = struct.pack(f"<{len(insns)}I", *insns)
    candidates = prover.scan_candidates(code, base_va=0x1000)

    assert len(candidates) == 1, "Canonical Apple Clang switch sequence must be detected as candidate"
    cand = candidates[0]
    assert cand.table_base_va == 0x8100, "Table base in .rodata must not be overwritten by ADR anchor"
    assert cand.code_anchor_va == 0x1010, "Code anchor PC (.Ltmp0) must be captured accurately"
    assert cand.table_base_reg == 0
    assert cand.table_target_reg == 3
    assert cand.dispatch_reg == 1
    assert cand.target_flows_to_dispatch is True, "Target flow from table load + anchor to BR must be verified"


def test_apple_clang_relative_targets_resolve_against_code_anchor():
    """21. Bug 5: Jump table relative targets resolve with respect to code_anchor_va (.Ltmp0), not table_base_va."""
    prover = ARM64JumpTableProver()

    insns = [
        _encode_cmp_imm_32(2, 4),
        _encode_b_cond(8, 20),
        _encode_adrp(0, 0x8000, 0x1008),
        _encode_add_imm_64(0, 0, 0x100),
        _encode_adr(1, 0),  # .Ltmp0 at 0x1010
        _encode_ldrsw_reg(3, 0, 2),
        _encode_add_shifted_64(1, 1, 3, 2),
        _encode_br(1),
    ]
    code = struct.pack(f"<{len(insns)}I", *insns)
    cand = prover.scan_candidates(code, base_va=0x1000)[0]

    # Relative offsets from .Ltmp0 (0x1010) to code targets in .text (0x1000..0x2000):
    # case 0 -> 0x1030 (offset = 32 bytes -> val = 8)
    # case 1 -> 0x1040 (offset = 48 bytes -> val = 12)
    # case 2 -> 0x1060 (offset = 80 bytes -> val = 20)
    # case 3 -> 0x1080 (offset = 112 bytes -> val = 28)
    # case 4 -> 0x10A0 (offset = 144 bytes -> val = 36)
    table_data = struct.pack("<5i", 8, 12, 20, 28, 36)
    recovered = prover.recover_jump_table(
        candidate=cand,
        memory_data=table_data,
        memory_base_va=0x8100,
        valid_range=(0x1000, 0x2000),  # .text range
    )

    assert recovered.proven is True
    assert recovered.bounds_n == 5
    assert recovered.unresolved_cases == 0
    assert recovered.targets[0] == 0x1030, "Target must resolve relative to code anchor (0x1010), not table VA (0x8100)"
    assert recovered.targets[1] == 0x1040
    assert recovered.targets[2] == 0x1060
    assert recovered.targets[3] == 0x1080
    assert recovered.targets[4] == 0x10A0
    # Explicitly verify it did not compute against table_base_va
    assert recovered.targets[0] != 0x8100 + (8 << 2)


def test_apple_clang_reused_index_register():
    """22. Apple Clang variant where index register is reused as target register (Rt == cmp_reg)."""
    prover = ARM64JumpTableProver()

    insns = [
        _encode_cmp_imm_32(2, 3),  # CMP W2, #3 -> 4 cases
        _encode_b_cond(8, 20),
        _encode_adrp(0, 0x9000, 0x1008),
        _encode_add_imm_64(0, 0, 0x80),
        _encode_adr(1, 0),  # .Ltmp0 at 0x1010
        _encode_ldrsw_reg(2, 0, 2),  # LDRSW X2, [X0, X2, LSL #2] -> Rt == 2
        _encode_add_shifted_64(1, 1, 2, 2),  # ADD X1, X1, X2, LSL #2
        _encode_br(1),
    ]
    code = struct.pack(f"<{len(insns)}I", *insns)
    candidates = prover.scan_candidates(code, base_va=0x1000)
    assert len(candidates) == 1
    cand = candidates[0]
    assert cand.table_target_reg == 2
    assert cand.target_flows_to_dispatch is True

    table_data = struct.pack("<4i", 10, 20, 30, 40)
    recovered = prover.recover_jump_table(
        candidate=cand,
        memory_data=table_data,
        memory_base_va=0x9080,
    )
    assert recovered.proven is True
    assert recovered.bounds_n == 4
    assert recovered.targets[0] == 0x1010 + (10 << 2)


def test_swift_chromium_jump_table_in_data_fallback():
    """23. Swift/Chromium jump tables in data section fall back to code anchor/PC."""
    prover = ARM64JumpTableProver()

    # Candidate with explicit code_anchor_va located in .text while table is in .rodata
    cand = JumpTableCandidate(
        pc=0x1000,
        cmp_pc=0x1000,
        cmp_reg=0,
        bound_imm=2,
        branch_cond="HI",
        default_target=0x1050,
        base_calc_type="ADRP_ADD",
        table_base_va=0x40000,  # in .rodata
        load_insn_type="LDRSW",
        entry_size=4,
        dispatch_pc=0x1020,
        dispatch_reg=1,
        index_reg=0,
        table_target_reg=1,
        code_anchor_va=0x1008,  # code anchor in .text
    )

    table_data = struct.pack("<3i", 10, 20, 30)
    recovered = prover.recover_jump_table(
        candidate=cand,
        memory_data=table_data,
        memory_base_va=0x40000,
        valid_range=(0x1000, 0x2000),  # code section
    )
    assert recovered.bounds_n == 3
    assert recovered.unresolved_cases == 0
    assert recovered.targets[0] == 0x1008 + (10 << 2)

    # Candidate without explicit code_anchor_va, but table is in data outside valid_range
    cand_no_anchor = JumpTableCandidate(
        pc=0x1000,
        cmp_pc=0x1000,
        cmp_reg=0,
        bound_imm=2,
        branch_cond="HI",
        default_target=0x1050,
        base_calc_type="ADRP_ADD",
        table_base_va=0x40000,  # in data
        load_insn_type="LDRSW",
        entry_size=4,
        dispatch_pc=0x1020,
        dispatch_reg=1,
        index_reg=0,
        table_target_reg=1,
        code_anchor_va=None,
    )
    recovered_fallback = prover.recover_jump_table(
        candidate=cand_no_anchor,
        memory_data=table_data,
        memory_base_va=0x40000,
        valid_range=(0x1000, 0x2000),
    )
    assert recovered_fallback.bounds_n == 3
    assert recovered_fallback.unresolved_cases == 0
    # Falls back to candidate.pc (0x1000)
    assert recovered_fallback.targets[0] == 0x1000 + (10 << 2)


def test_absolute_jump_table_preserves_addresses():
    """24. Absolute jump table addresses (> 0x40000000 or 64-bit) are preserved."""
    prover = ARM64JumpTableProver()

    # 32-bit absolute table: entries > 0x40000000
    cand_32 = JumpTableCandidate(
        pc=0x1000,
        cmp_pc=0x1000,
        cmp_reg=0,
        bound_imm=1,
        branch_cond="HI",
        default_target=0x1050,
        base_calc_type="ADR",
        table_base_va=0x2000,
        load_insn_type="LDRSW",
        entry_size=4,
        dispatch_pc=0x1020,
        dispatch_reg=1,
        index_reg=0,
        table_target_reg=1,
    )
    data_32 = struct.pack("<2I", 0x50001000, 0x50002000)
    table_32 = prover.recover_jump_table(cand_32, memory_data=data_32, memory_base_va=0x2000)
    assert table_32.targets[0] == 0x50001000
    assert table_32.targets[1] == 0x50002000

    # 64-bit absolute table
    cand_64 = JumpTableCandidate(
        pc=0x1000,
        cmp_pc=0x1000,
        cmp_reg=0,
        bound_imm=1,
        branch_cond="HI",
        default_target=0x1050,
        base_calc_type="ADR",
        table_base_va=0x2000,
        load_insn_type="LDR",
        entry_size=8,
        dispatch_pc=0x1020,
        dispatch_reg=1,
        index_reg=0,
        table_target_reg=1,
    )
    data_64 = struct.pack("<2Q", 0x140001000, 0x140002000)
    table_64 = prover.recover_jump_table(cand_64, memory_data=data_64, memory_base_va=0x2000)
    assert table_64.targets[0] == 0x140001000
    assert table_64.targets[1] == 0x140002000
