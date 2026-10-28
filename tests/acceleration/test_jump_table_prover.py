"""Unit tests for ARM64 Jump-Table Bounds Prover (12 test cases)."""

import struct
import pytest

from superghidra.acceleration.jump_table_prover import (
    ARM64JumpTableProver,
    JumpTableCandidate,
    RecoveredJumpTable,
)


def _encode_cmp_imm_32(rn: int, imm12: int) -> int:
    """Encodes CMP Wn, #imm12 (SUBS WZR, Wn, #imm12)."""
    return 0x7100001f | ((imm12 & 0xfff) << 10) | ((rn & 0x1f) << 5)


def _encode_b_cond(cond: int, imm19: int) -> int:
    """Encodes B.cond #imm19 (0x54000000 | (imm19 << 5) | cond)."""
    return 0x54000000 | ((imm19 & 0x7ffff) << 5) | (cond & 0xf)


def _encode_adr(rd: int, imm21: int) -> int:
    """Encodes ADR Xd, #imm21."""
    immlo = imm21 & 0x3
    immhi = (imm21 >> 2) & 0x7ffff
    return 0x10000000 | (immlo << 29) | (immhi << 5) | (rd & 0x1f)


def _encode_br(rn: int) -> int:
    """Encodes BR Xn."""
    return 0xd61f0000 | ((rn & 0x1f) << 5)


def test_cmp_b_hi_bounds_proof():
    """1. B.HI (unsigned greater than imm) bounds proof yields N = imm + 1."""
    prover = ARM64JumpTableProver()
    n, proven = prover.prove_bounds(bound_imm=7, cond="HI")
    assert n == 8
    assert proven is True


def test_cmp_b_hs_bounds_proof():
    """2. B.HS (unsigned greater or equal to imm) bounds proof yields N = imm."""
    prover = ARM64JumpTableProver()
    n, proven = prover.prove_bounds(bound_imm=8, cond="HS")
    assert n == 8
    assert proven is True


def test_adr_table_base_load():
    """3. Parses ADR table base offset accurately."""
    # PC = 0x1008, table at 0x1100 -> offset = 0xf8
    adr_insn = _encode_adr(1, 0xf8)
    insns = [
        _encode_cmp_imm_32(0, 4),
        _encode_b_cond(8, 20),  # B.HI default (+80 bytes)
        adr_insn,
        0x38616802,  # LDRB W2, [X0, X1]
        _encode_br(2),
    ]
    code = struct.pack(f"<{len(insns)}I", *insns)
    prover = ARM64JumpTableProver()
    candidates = prover.scan_candidates(code, base_va=0x1000)
    assert len(candidates) == 1
    assert candidates[0].table_base_va == 0x1008 + 0xf8
    assert candidates[0].base_calc_type == "ADR"


def test_adrp_add_table_base_load():
    """4. Parses ADRP + page base calculation."""
    # ADRP X1, #0 (page of 0x1000 is 0x1000)
    adrp_insn = 0x90000001
    insns = [
        _encode_cmp_imm_32(0, 5),
        _encode_b_cond(8, 15),
        adrp_insn,
        0x38616802,
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
        0x38616802,
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
    memory_data = bytes([12, 0xff, 14])
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
        _encode_b_cond(8, 25),      # B.HI default
        _encode_adr(1, 0x20),       # ADR X1, #32
        0x38616802,                 # LDRB W2, [X0, X1]
        _encode_br(2),              # BR X2
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
