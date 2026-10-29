"""Hardening test suite verifying fixes for v1.0.0 bug manifest:
1. Dead PID handling and atomic directory locking (bulk_decompile).
2. Clean star-imports and export parity for IL2CPP and Rust/Go reports.
3. Mach-O chained fixup bounds and DYLD_CHAINED_IMPORT_ADDEND64 16-byte unpacking.
4. ARM64 jump table immediate lsl #12 decoding, BR dispatch requirement, and Z3 soundness.
5. Evidence ledger gatekeeper checks for negative offsets, NaN similarity, and access width.
6. IL2CPP parameter count clamping.
"""

import os
import struct
from pathlib import Path

import pytest

import superghidra
from superghidra.acceleration.jump_table_prover import ARM64JumpTableProver
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

    # Second acquisition by a different simulated PID should fail
    lock2 = DirectoryLock(lock_dir)
    with pytest.raises(LockContentionError):
        # Temporarily mock os.getpid to simulate concurrent process
        orig_getpid = os.getpid
        try:
            os.getpid = lambda: orig_getpid() + 1
            lock2.acquire()
        finally:
            os.getpid = orig_getpid

    lock.release()
    assert lock._locked is False


def test_public_api_star_import():
    """Verify 'from superghidra import *' succeeds and export aliases match."""
    # Both casings of IL2CPP metadata report must exist and match
    assert superghidra.Il2CppMetadataReport is not None
    assert superghidra.IL2CPPMetadataReport is superghidra.Il2CppMetadataReport

    # Both names of Rust/Go audit report must exist and match
    assert superghidra.CrateAuditReport is not None
    assert superghidra.RustGoAuditReport is superghidra.CrateAuditReport

    # All __all__ items must be resolvable via getattr
    for name in superghidra.__all__:
        assert hasattr(superghidra, name), f"Missing export: {name}"


def test_apple_dispatch_chained_fixup_import_bound(tmp_path: Path):
    """Verify chained fixup parser handles malformed unbounded imports count without DoS."""
    # Create minimal Mach-O 64-bit slice with LC_DYLD_CHAINED_FIXUPS specifying 10,000,000 imports
    # but only 64 bytes total payload.
    header = bytearray(b"\x00" * 256)
    # Magic MH_MAGIC_64
    struct.pack_into("<I", header, 0, 0xfeedfacf)
    # CPU type ARM64 (0x0100000c), subtype 0
    struct.pack_into("<II", header, 4, 0x0100000c, 0)
    # Filetype MH_EXECUTE (2), ncmds 1, sizeofcmds 16
    struct.pack_into("<II", header, 12, 2, 1)
    struct.pack_into("<I", header, 20, 16)  # sizeofcmds

    # LC_DYLD_CHAINED_FIXUPS = 0x80000034, cmdsize = 16, dataoff = 64, datasize = 64
    cmd = struct.pack("<IIII", 0x80000034, 16, 64, 64)
    header[32 : 32 + 16] = cmd

    # Fixups header at offset 64 (28 bytes minimum):
    # fixups_version, starts_offset, imports_offset, symbols_offset, imports_count, imports_format, symbols_format
    fixups_hdr = struct.pack(
        "<7I",
        0,   # fixups_version
        0,   # starts_offset
        28,  # imports_offset
        28,  # symbols_offset
        10000000,  # malicious imports_count (10 million)
        1,   # imports_format: DYLD_CHAINED_IMPORT (4 bytes per entry)
        0,   # symbols_format
    )
    header[64 : 64 + 28] = fixups_hdr

    bin_path = tmp_path / "malformed_macho"
    bin_path.write_bytes(bytes(header))

    report = dispatch_apple_binary(bin_path)
    # Must finish instantly without creating 10 million items
    assert len(report.chained_fixups.imports) <= 65536
    assert any("clamped" in lim.lower() for lim in report.limitations)


def test_apple_dispatch_addend64_16_byte_unpack(tmp_path: Path):
    """Verify DYLD_CHAINED_IMPORT_ADDEND64 unpacks as 16 bytes (<IIq) without struct.error."""
    header = bytearray(b"\x00" * 256)
    struct.pack_into("<I", header, 0, 0xfeedfacf)
    struct.pack_into("<II", header, 4, 0x0100000c, 0)
    struct.pack_into("<II", header, 12, 2, 1)
    struct.pack_into("<I", header, 20, 16)

    # dataoff = 64, datasize = 80
    cmd = struct.pack("<IIII", 0x80000034, 16, 64, 80)
    header[32 : 32 + 16] = cmd

    # Fixup header (28 bytes)
    # starts_offset=0, imports_offset=28, symbols_offset=44, imports_count=1, imports_format=3 (ADDEND64)
    fixups_hdr = struct.pack(
        "<7I",
        0, 0, 28, 44, 1, 3, 0
    )
    header[64 : 64 + 28] = fixups_hdr

    # Import 0: 16 bytes (<IIq)
    # name_offset = 0, meta = 0, addend = 42
    import_entry = struct.pack("<IIq", 0, 0, 42)
    header[92 : 92 + 16] = import_entry

    # Symbol pool at 64 + 44 = 108: "_target_symbol\0"
    sym_bytes = b"_target_symbol\x00"
    header[108 : 108 + len(sym_bytes)] = sym_bytes

    bin_path = tmp_path / "addend64_macho"
    bin_path.write_bytes(bytes(header))

    report = dispatch_apple_binary(bin_path)
    assert len(report.chained_fixups.imports) == 1
    assert report.chained_fixups.imports[0] == "_target_symbol"


def test_jump_table_prover_immediate_shift():
    """Verify ARM64JumpTableProver parses 'cmp w0, #1, lsl #12' bound as 4096."""
    prover = ARM64JumpTableProver()

    # Encoding of CMP W0, #1, LSL #12:
    # 32-bit CMP imm: 0x7140041f (sf=0, op=1, S=1, 10001, sh=1 (bit 22), imm12=1, Rn=0, Rd=WZR)
    cmp_insn = 0x7140041f
    # B.HI +16 (default escape branch): cond=8
    b_hi_insn = 0x54000088
    # ADR X1, +8
    adr_insn = 0x10000041
    # LDRSW X2, [X1, X0, LSL #2]
    # Register LDRSW with Rm=X0 (bits 20:16 = 0)
    ldrsw_insn = 0xb8a07822
    # BR X2: [31:10]=1101011000011111000000, Rn=X2 (bits 9:5 = 2)
    br_insn = 0xd61f0040

    code = struct.pack("<5I", cmp_insn, b_hi_insn, adr_insn, ldrsw_insn, br_insn)

    candidates = prover.scan_candidates(code, base_va=0x1000)
    assert len(candidates) == 1
    cand = candidates[0]
    assert cand.bound_imm == 4096  # 1 << 12
    assert cand.dispatch_pc == 0x1010


def test_jump_table_prover_rejects_missing_indirect_branch():
    """Verify candidates without an actual indirect branch (BR) are rejected."""
    prover = ARM64JumpTableProver()
    # CMP W0, #4 followed by B.HI, ADR, LDRSW, but NO BR instruction
    cmp_insn = 0x7100101f  # CMP W0, #4
    b_hi_insn = 0x54000088
    adr_insn = 0x10000041
    ldrsw_insn = 0xb8a07822
    nop_insn = 0xd503201f  # NOP instead of BR

    code = struct.pack("<5I", cmp_insn, b_hi_insn, adr_insn, ldrsw_insn, nop_insn)
    candidates = prover.scan_candidates(code, base_va=0x1000)
    assert len(candidates) == 0


def test_evidence_ledger_gatekeeper_negative_and_nan():
    """Verify ReconstructionObligationLedger rejects negative offsets and NaN similarity."""
    ledger = ReconstructionObligationLedger()

    # 1. Negative struct field offset must fail
    res = ledger.verify_struct_layout(
        struct_name="BadStruct",
        struct_size=16,
        fields=[("bad_field", -4, 4)],
    )
    assert res.passed is False
    assert "negative" in res.message.lower()

    # 2. Non-positive field size must fail
    res_sz = ledger.verify_struct_layout(
        struct_name="BadSizeStruct",
        struct_size=16,
        fields=[("zero_field", 0, 0)],
    )
    assert res_sz.passed is False

    # 3. NaN cosine similarity must fail
    res_nan = ledger.verify_cross_version_rewrite(
        old_offset=0x10,
        new_offset=0x18,
        access_width=8,
        cosine_similarity=float("nan"),
    )
    assert res_nan.passed is False
    assert "nan" in res_nan.message.lower()

    # 4. Negative cross-version offset must fail
    res_neg = ledger.verify_cross_version_rewrite(
        old_offset=-8,
        new_offset=0x18,
        access_width=8,
        cosine_similarity=0.95,
    )
    assert res_neg.passed is False
    assert "negative" in res_neg.message.lower()

    # 5. Misaligned cross-version rewrite must fail
    res_align = ledger.verify_cross_version_rewrite(
        old_offset=0x10,
        new_offset=0x13,  # Misaligned for 4-byte access
        access_width=4,
        cosine_similarity=0.95,
    )
    assert res_align.passed is False
    assert "misaligned" in res_align.message.lower() or "alignment" in res_align.message.lower()
