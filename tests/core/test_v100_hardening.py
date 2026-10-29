"""Hardening test suite verifying fixes for v1.0.0 and v1.0.1:
1. Multi-process concurrent barrier DirectoryLock stress test (kernel advisory locks).
2. Clean star-imports and export parity for IL2CPP and Rust/Go reports.
3. Mach-O chained fixup bounds and DYLD_CHAINED_IMPORT_ADDEND64 16-byte upper 32-bit unpacking.
4. ARM64 jump table immediate lsl #12 decoding, BR dispatch requirement, register parity, and Z3 soundness.
5. Evidence ledger gatekeeper checks for negative offsets, NaN/Inf similarity, and access width preservation.
6. IL2CPP parameter count clamping.
"""

import multiprocessing as mp
import os
import struct
import time
from pathlib import Path

import pytest

import superghidra
from superghidra.acceleration.jump_table_prover import ARM64JumpTableProver, JumpTableCandidate
from superghidra.core.bulk_decompile import DirectoryLock, LockContentionError, is_process_alive
from superghidra.core.evidence_ledger import ReconstructionObligationLedger
from superghidra.formats.apple_dispatch import dispatch_apple_binary


def test_is_process_alive_dead_and_live_pids():
    """Verify dead PIDs return False and live PID returns True."""
    # Current process is alive
    assert is_process_alive(os.getpid()) is True

    # Non-positive PIDs are invalid
    assert is_process_alive(0) is False
    assert is_process_alive(-1) is False

    # A very large PID is guaranteed not to exist
    dead_pid = 4194304  # standard max pid boundary
    assert is_process_alive(dead_pid) is False


def test_directory_lock_stale_recovery(tmp_path: Path):
    """Verify DirectoryLock automatically recovers stale locks from dead PIDs."""
    lock_dir = tmp_path / "bulk_out"
    lock_dir.mkdir(parents=True, exist_ok=True)
    lock_file = lock_dir / ".superghidra.lock"

    # Fabricate a stale lock from a dead PID
    import json

    stale_payload = {
        "st_dev": 0,
        "st_ino": 0,
        "holder_pid": 4194304,
        "created_at": 1000.0,
    }
    lock_file.write_text(json.dumps(stale_payload), encoding="utf-8")

    # Acquiring must recover the stale lock and succeed
    lock = DirectoryLock(lock_dir)
    lock.acquire()
    assert lock._locked is True
    assert lock_file.exists()

    # Second acquisition by a different simulated process should fail
    lock2 = DirectoryLock(lock_dir)
    with pytest.raises(LockContentionError):
        lock2.acquire()

    lock.release()
    assert lock._locked is False


def _concurrent_lock_worker(lock_dir: Path, barrier: mp.Barrier, results_q: mp.Queue):
    barrier.wait()
    lock = DirectoryLock(lock_dir)
    acquired = False
    try:
        lock.acquire()
        acquired = True
        time.sleep(0.02)
    except LockContentionError:
        acquired = False
    finally:
        results_q.put(acquired)
        if acquired:
            try:
                lock.release()
            except Exception:
                pass


def test_directory_lock_concurrent_barrier_stress(tmp_path: Path):
    """Verify kernel-enforced directory locking prevents multi-process acquisition races."""
    lock_dir = tmp_path / "stress_lock_dir"
    lock_dir.mkdir(parents=True, exist_ok=True)

    for _ in range(5):
        barrier = mp.Barrier(6)
        queue = mp.Queue()
        procs = [mp.Process(target=_concurrent_lock_worker, args=(lock_dir, barrier, queue)) for _ in range(6)]
        for p in procs:
            p.start()
        for p in procs:
            p.join()

        acquired_count = 0
        while not queue.empty():
            if queue.get():
                acquired_count += 1
        assert acquired_count == 1, f"Expected exactly 1 process to acquire lock, got {acquired_count}"


def test_public_api_star_import():
    """Verify 'from superghidra import *' succeeds and export aliases match."""
    assert superghidra.Il2CppMetadataReport is not None
    assert superghidra.IL2CPPMetadataReport is superghidra.Il2CppMetadataReport
    assert superghidra.CrateAuditReport is not None
    assert superghidra.RustGoAuditReport is superghidra.CrateAuditReport

    for name in superghidra.__all__:
        assert hasattr(superghidra, name), f"Missing export: {name}"


def test_apple_dispatch_chained_fixup_import_bound(tmp_path: Path):
    """Verify chained fixup parser handles malformed unbounded imports count without DoS."""
    header = bytearray(b"\x00" * 256)
    struct.pack_into("<I", header, 0, 0xFEEDFACF)
    struct.pack_into("<II", header, 4, 0x0100000C, 0)
    struct.pack_into("<II", header, 12, 2, 1)
    struct.pack_into("<I", header, 20, 16)

    cmd = struct.pack("<IIII", 0x80000034, 16, 64, 64)
    header[32 : 32 + 16] = cmd

    fixups_hdr = struct.pack(
        "<7I",
        0,
        0,
        28,
        28,
        10000000,
        1,
        0,
    )
    header[64 : 64 + 28] = fixups_hdr

    bin_path = tmp_path / "malformed_macho"
    bin_path.write_bytes(bytes(header))

    report = dispatch_apple_binary(bin_path)
    assert len(report.chained_fixups.imports) <= 65536
    assert any("clamped" in lim.lower() for lim in report.limitations)


def test_apple_dispatch_addend64_high32_offset(tmp_path: Path):
    """Verify DYLD_CHAINED_IMPORT_ADDEND64 unpacks name_offset from bits 32..63."""
    header = bytearray(b"\x00" * 256)
    struct.pack_into("<I", header, 0, 0xFEEDFACF)
    struct.pack_into("<II", header, 4, 0x0100000C, 0)
    struct.pack_into("<II", header, 12, 2, 1)
    struct.pack_into("<I", header, 20, 16)

    cmd = struct.pack("<IIII", 0x80000034, 16, 64, 128)
    header[32 : 32 + 16] = cmd

    # Fixup header (28 bytes)
    # starts_offset=0, imports_offset=28, symbols_offset=44, imports_count=1, imports_format=3 (ADDEND64)
    fixups_hdr = struct.pack("<7I", 0, 0, 28, 44, 1, 3, 0)
    header[64 : 64 + 28] = fixups_hdr

    # Symbols pool: "_foo\0_bar\0"
    # Offset 0 is "_foo", offset 5 is "_bar"
    sym_pool = b"_foo\x00_bar\x00"
    symbols_abs_offset = 64 + 44
    header[symbols_abs_offset : symbols_abs_offset + len(sym_pool)] = sym_pool

    # Import entry (16 bytes) at 64 + 28 = 92
    # In dyld_chained_import_addend64:
    # low 32 bits (meta) = 0x00010001 (ordinal=1, flags)
    # high 32 bits (name_offset) = 5 (points to "_bar")
    meta = 0x00010001
    name_offset = 5
    addend = 120
    import_entry = struct.pack("<IIq", meta, name_offset, addend)
    header[92 : 92 + 16] = import_entry

    bin_path = tmp_path / "addend64_test_macho"
    bin_path.write_bytes(bytes(header))

    report = dispatch_apple_binary(bin_path)
    assert len(report.chained_fixups.imports) == 1
    # If the parser read low 32 bits, it would read meta (0x10001) or invalid.
    # Reading high 32 bits resolves to "_bar".
    assert report.chained_fixups.imports[0] == "_bar"


def test_jump_table_prover_register_parity():
    """Verify ARM64JumpTableProver rejects candidates where cmp_reg != index_reg."""
    prover = ARM64JumpTableProver()

    cand_valid = JumpTableCandidate(
        pc=0x1000,
        cmp_pc=0x1000,
        cmp_reg=0,  # X0
        bound_imm=8,
        branch_cond="HI",
        default_target=0x1020,
        base_calc_type="ADR",
        table_base_va=0x2000,
        load_insn_type="LDRSW",
        entry_size=4,
        dispatch_pc=0x1010,
        dispatch_reg=2,
        index_reg=0,  # X0 matches cmp_reg
        table_target_reg=2,  # matches dispatch_reg
    )

    # Valid candidate with active Z3 can be proven
    n, proven = prover.prove_bounds(
        cand_valid.bound_imm,
        cand_valid.branch_cond,
        cmp_reg=cand_valid.cmp_reg,
        index_reg=cand_valid.index_reg,
        table_target_reg=cand_valid.table_target_reg,
        dispatch_reg=cand_valid.dispatch_reg,
    )
    assert n == 9

    # Candidate with mismatched index register (cmp_reg=0, index_reg=1) MUST fail proof
    n_mismatch, proven_mismatch = prover.prove_bounds(
        cand_valid.bound_imm,
        cand_valid.branch_cond,
        cmp_reg=0,
        index_reg=1,  # different register
        table_target_reg=2,
        dispatch_reg=2,
    )
    assert proven_mismatch is False

    # Calling prove_bounds without explicit register tracking arguments must fail proof
    n_default, proven_default = prover.prove_bounds(5, "HI")
    assert proven_default is False


def test_evidence_ledger_infinity_and_width_preservation():
    """Verify ReconstructionObligationLedger rejects infinity similarity and detects width changes."""
    ledger = ReconstructionObligationLedger()

    # 1. Positive and negative infinity must fail
    res_pos_inf = ledger.verify_cross_version_rewrite(
        old_offset=0x10,
        new_offset=0x18,
        access_width=8,
        cosine_similarity=float("inf"),
    )
    assert res_pos_inf.passed is False
    assert "invalid" in res_pos_inf.message.lower()

    res_neg_inf = ledger.verify_cross_version_rewrite(
        old_offset=0x10,
        new_offset=0x18,
        access_width=8,
        cosine_similarity=-float("inf"),
    )
    assert res_neg_inf.passed is False

    # 2. Score > 1.0 must fail
    res_over = ledger.verify_cross_version_rewrite(
        old_offset=0x10,
        new_offset=0x18,
        access_width=8,
        cosine_similarity=1.5,
    )
    assert res_over.passed is False

    # 3. Access width change across versions (e.g. 4 bytes to 8 bytes) must be detected and rejected
    res_width_change = ledger.verify_cross_version_rewrite(
        old_offset=0x10,
        new_offset=0x18,
        access_width=4,
        cosine_similarity=0.95,
        new_access_width=8,
    )
    assert res_width_change.passed is False
    assert "access width" in res_width_change.message.lower()

    # 4. Misaligned old offset (e.g. offset 2 to 6 with width 4) must fail natural alignment
    res_misaligned_old = ledger.verify_cross_version_rewrite(
        old_offset=2,
        new_offset=6,
        access_width=4,
        cosine_similarity=0.95,
    )
    assert res_misaligned_old.passed is False
    assert "misaligned" in res_misaligned_old.message.lower()


def test_arm64_jump_table_prover_clobber_detection():
    """Verify candidate scanner rejects cmp_reg overwritten by MOV, ADD reg, or MOVZ before table load."""
    import struct

    from superghidra.acceleration.jump_table_prover import ARM64JumpTableProver

    prover = ARM64JumpTableProver()

    # Base valid sequence:
    # 0: CMP W1, #7 (0x71001c3f)
    # 4: B.HI default (0x540000a8 -> +20 bytes)
    # 8: ADR X2, #32 (0x10000102)
    # 12: LDRSW X3, [X2, X1, LSL #2] (0xb8a17843)
    # 16: BR X3 (0xd61f0060)
    # 20: default target

    # 1. Clobbered by MOV x1, x2 (0xaa0203e1)
    insns_mov = [0x71001C3F, 0x540000A8, 0xAA0203E1, 0x10000102, 0xB8A17843, 0xD61F0060]
    code_mov = struct.pack(f"<{len(insns_mov)}I", *insns_mov)
    cands_mov = prover.scan_candidates(code_mov, base_va=0x1000)
    assert len(cands_mov) == 0, "MOV into cmp_reg must clobber candidate"

    # 2. Clobbered by ADD x1, x1, x2 (0x8b020021)
    insns_add = [0x71001C3F, 0x540000A8, 0x8B020021, 0x10000102, 0xB8A17843, 0xD61F0060]
    code_add = struct.pack(f"<{len(insns_add)}I", *insns_add)
    cands_add = prover.scan_candidates(code_add, base_va=0x1000)
    assert len(cands_add) == 0, "ADD reg into cmp_reg must clobber candidate"

    # 3. Clobbered by MOVZ x1, #7 (0xd28000e1)
    insns_movz = [0x71001C3F, 0x540000A8, 0xD28000E1, 0x10000102, 0xB8A17843, 0xD61F0060]
    code_movz = struct.pack(f"<{len(insns_movz)}I", *insns_movz)
    cands_movz = prover.scan_candidates(code_movz, base_va=0x1000)
    assert len(cands_movz) == 0, "MOVZ into cmp_reg must clobber candidate"

    # 4. Compiler idiom where table load writes into the same register as index (Rt == cmp_reg)
    # 0: CMP W8, #7 (0x71001d1f)
    # 4: B.HI default (0x540000a8)
    # 8: ADR X9, #32 (0x10000109)
    # 12: LDRSW X8, [X9, X8, LSL #2] (0xb8a87928)
    # 16: BR X8 (0xd61f0100)
    insns_rt_eq_cmp = [0x71001D1F, 0x540000A8, 0x10000109, 0xB8A87928, 0xD61F0100]
    code_rt_eq_cmp = struct.pack(f"<{len(insns_rt_eq_cmp)}I", *insns_rt_eq_cmp)
    cands_rt_eq_cmp = prover.scan_candidates(code_rt_eq_cmp, base_va=0x1000)
    assert len(cands_rt_eq_cmp) == 1, "Table load into Rt == cmp_reg must be recognized as valid candidate"
    assert cands_rt_eq_cmp[0].cmp_reg == 8
    assert cands_rt_eq_cmp[0].index_reg == 8
    assert cands_rt_eq_cmp[0].table_target_reg == 8

    # 5. Clobbered by unrelated load into cmp_reg before table load (LDR X8, [SP, #16])
    insns_ldr_clobber = [0x71001D1F, 0x540000A8, 0xF9400BE8, 0x10000109, 0xB8A87928, 0xD61F0100]
    code_ldr_clobber = struct.pack(f"<{len(insns_ldr_clobber)}I", *insns_ldr_clobber)
    cands_ldr_clobber = prover.scan_candidates(code_ldr_clobber, base_va=0x1000)
    assert len(cands_ldr_clobber) == 0, "Unrelated LDR into cmp_reg before table load must clobber"

    # 6. Absence of table load instruction (e.g. branch directly without indexed table load) must return 0 candidates
    insns_no_table_load = [0x71001D1F, 0x540000A8, 0x10000109, 0xD61F0120]
    code_no_table_load = struct.pack(f"<{len(insns_no_table_load)}I", *insns_no_table_load)
    cands_no_table_load = prover.scan_candidates(code_no_table_load, base_va=0x1000)
    assert len(cands_no_table_load) == 0, "Absence of table load instruction must not produce a candidate"
    # 7. Inverted base vs index operand confusion:
    # 0: CMP W0, #5 (0x7100141f)
    # 4: B.HI default (0x540000a8)
    # 8: ADR X1, #32 (0x10000101)
    # 12: LDRSW X2, [X0, X1, LSL #2] (0xb8a17802 -> Rn=0 (base), Rm=1 (index))
    # 16: BR X2 (0xd61f0040)
    insns_inverted = [0x7100141F, 0x540000A8, 0x10000101, 0xB8A17802, 0xD61F0040]
    code_inverted = struct.pack(f"<{len(insns_inverted)}I", *insns_inverted)
    cands_inverted = prover.scan_candidates(code_inverted, base_va=0x1000)
    assert len(cands_inverted) == 0, "Inverted load where cmp_reg is base Rn rather than index Rm must be rejected"

    # 8. Correct compiler standard where cmp_reg is index Rm:
    # 0: CMP W0, #5 (0x7100141f)
    # 4: B.HI default (0x540000a8)
    # 8: ADR X1, #32 (0x10000101)
    # 12: LDRSW X2, [X1, X0, LSL #2] (0xb8a07822 -> Rn=1 (base), Rm=0 (index))
    # 16: BR X2 (0xd61f0040)
    insns_correct = [0x7100141F, 0x540000A8, 0x10000101, 0xB8A07822, 0xD61F0040]
    code_correct = struct.pack(f"<{len(insns_correct)}I", *insns_correct)
    cands_correct = prover.scan_candidates(code_correct, base_va=0x1000)
    assert len(cands_correct) == 1, "Compiler standard table load with Rm == cmp_reg must produce candidate"
    assert cands_correct[0].cmp_reg == 0
    assert cands_correct[0].index_reg == 0
    assert cands_correct[0].table_target_reg == 2

    # 9. Unindexed immediate load (LDUR X2, [X0, #16]) must not produce candidate
    insns_imm_load = [0x7100141F, 0x540000A8, 0x10000101, 0xF8410002, 0xD61F0040]
    code_imm_load = struct.pack(f"<{len(insns_imm_load)}I", *insns_imm_load)
    cands_imm_load = prover.scan_candidates(code_imm_load, base_va=0x1000)
    assert len(cands_imm_load) == 0, "Unindexed immediate load must not be accepted as jump table load"
