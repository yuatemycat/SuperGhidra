"""Unit test suite for crash-resumable bulk decompiler (15 test cases)."""

import hashlib
import json
import os
from pathlib import Path
import pytest

from superghidra.core.bulk_decompile import (
    BulkDecompileRunner,
    DirectoryLock,
    LockContentionError,
    TargetMismatchError,
    decompile_all,
    hash_file_chunks,
    is_process_alive,
)


def _create_dummy_binary(tmp_path: Path, name: str = "test.bin", size: int = 1024) -> Path:
    bin_path = tmp_path / name
    bin_path.write_bytes(b"\x90" * size)
    return bin_path


def test_directory_lock_acquisition_and_release(tmp_path):
    """1. Directory lock creates .superghidra.lock on acquire and deletes it on release."""
    out_dir = tmp_path / "out"
    lock = DirectoryLock(out_dir)
    with lock:
        assert (out_dir / ".superghidra.lock").exists()
        lock_data = json.loads((out_dir / ".superghidra.lock").read_text(encoding="utf-8"))
        assert lock_data["holder_pid"] == os.getpid()
    assert not (out_dir / ".superghidra.lock").exists()


def test_directory_lock_contention_active_pid(tmp_path):
    """2. Concurrent lock attempt by another active PID raises LockContentionError."""
    out_dir = tmp_path / "out"
    out_dir.mkdir(parents=True, exist_ok=True)
    # Simulate an active process holding the lock (using current PID with fake another instance)
    lock_file = out_dir / ".superghidra.lock"
    # Current PID is definitely alive
    lock_file.write_text(json.dumps({"holder_pid": os.getpid(), "created_at": 100.0}))

    # If holder_pid != os.getpid(), it should raise. Let's find an active PID that isn't ours (e.g. PID 4 on Windows: System)
    # Or test by writing another active PID (like parent process or system PID 4)
    active_pid = 4 if os.name == "nt" else 1
    lock_file.write_text(json.dumps({"holder_pid": active_pid, "created_at": 100.0}))

    lock = DirectoryLock(out_dir)
    with pytest.raises(LockContentionError) as exc_info:
        lock.acquire()
    assert str(active_pid) in str(exc_info.value)


def test_directory_lock_stale_pid_recovery(tmp_path):
    """3. Dead holder PID (stale lock from hard crash) is recovered automatically."""
    out_dir = tmp_path / "out"
    out_dir.mkdir(parents=True, exist_ok=True)
    lock_file = out_dir / ".superghidra.lock"
    # PID 99999999 is dead
    dead_pid = 99999999
    assert not is_process_alive(dead_pid)
    lock_file.write_text(json.dumps({"holder_pid": dead_pid, "created_at": 100.0}))

    lock = DirectoryLock(out_dir)
    with lock:
        # Re-acquired cleanly by current process
        lock_data = json.loads(lock_file.read_text(encoding="utf-8"))
        assert lock_data["holder_pid"] == os.getpid()


def test_append_only_journal_creation(tmp_path):
    """4. Verified that .superghidra-export.journal.jsonl records completed functions."""
    bin_path = _create_dummy_binary(tmp_path)
    out_dir = tmp_path / "out"
    funcs = [{"address": "0x1000", "name": "fn1", "is_external": False}]

    manifest = decompile_all(
        binary_path=bin_path,
        output_directory=out_dir,
        functions_provider=lambda p: funcs,
    )
    assert manifest.decompiled_count == 1
    journal = out_dir / ".superghidra-export.journal.jsonl"
    assert journal.exists()
    lines = [json.loads(line) for line in journal.read_text(encoding="utf-8").splitlines() if line.strip()]
    assert len(lines) == 1
    assert lines[0]["canonical_address"] == "0x1000"
    assert lines[0]["status"] == "decompiled"


def test_resume_skips_intact_files(tmp_path):
    """5. On --resume, existing files matching 64 KB chunked SHA-256 are skipped."""
    bin_path = _create_dummy_binary(tmp_path)
    out_dir = tmp_path / "out"
    funcs = [
        {"address": "0x1000", "name": "fn1", "is_external": False},
        {"address": "0x2000", "name": "fn2", "is_external": False},
    ]

    # First run
    m1 = decompile_all(
        binary_path=bin_path,
        output_directory=out_dir,
        functions_provider=lambda p: funcs,
        resume=True,
    )
    assert m1.decompiled_count == 2
    assert m1.skipped_count == 0

    # Second run with resume
    m2 = decompile_all(
        binary_path=bin_path,
        output_directory=out_dir,
        functions_provider=lambda p: funcs,
        resume=True,
    )
    assert m2.skipped_count == 2
    assert m2.decompiled_count == 2


def test_resume_requeues_corrupt_files(tmp_path):
    """6. Truncated or modified .c file is re-decompiled upon resume."""
    bin_path = _create_dummy_binary(tmp_path)
    out_dir = tmp_path / "out"
    funcs = [{"address": "0x1000", "name": "fn1", "is_external": False}]

    decompile_all(
        binary_path=bin_path,
        output_directory=out_dir,
        functions_provider=lambda p: funcs,
        resume=True,
    )
    # Corrupt the written .c file
    c_file = out_dir / "funcs" / "fn1.c"
    c_file.write_text("corrupted content", encoding="utf-8")

    # Resume: SHA-256 mismatch should cause fn1 to not be recognized as completed
    m = decompile_all(
        binary_path=bin_path,
        output_directory=out_dir,
        functions_provider=lambda p: funcs,
        resume=True,
    )
    assert m.decompiled_count == 1
    # File was re-written with clean template
    assert "corrupted content" not in c_file.read_text(encoding="utf-8")


def test_resume_ignores_torn_final_line(tmp_path):
    """7. Torn / partial JSON at end of journal from power-loss is ignored cleanly."""
    bin_path = _create_dummy_binary(tmp_path)
    out_dir = tmp_path / "out"
    funcs = [{"address": "0x1000", "name": "fn1", "is_external": False}]

    decompile_all(
        binary_path=bin_path,
        output_directory=out_dir,
        functions_provider=lambda p: funcs,
        resume=True,
    )
    # Append a torn line to journal
    journal = out_dir / ".superghidra-export.journal.jsonl"
    with open(journal, "a", encoding="utf-8") as f:
        f.write('{"canonical_address": "0x2000", "file_relpath": "funcs/\n')

    # Resume should reconcile fn1 and not crash
    runner = BulkDecompileRunner(bin_path, out_dir, resume=True)
    completed = runner._reconcile_journal()
    assert "0x1000" in completed
    assert "0x2000" not in completed


def test_external_import_skipping(tmp_path):
    """8. External imports are marked in index with status 'external' without writing .c."""
    bin_path = _create_dummy_binary(tmp_path)
    out_dir = tmp_path / "out"
    funcs = [
        {"address": "0x1000", "name": "printf", "is_external": True},
        {"address": "0x2000", "name": "internal_func", "is_external": False},
    ]

    m = decompile_all(
        binary_path=bin_path,
        output_directory=out_dir,
        functions_provider=lambda p: funcs,
    )
    assert m.external_count == 1
    assert m.decompiled_count == 1

    # printf.c should NOT exist
    assert not (out_dir / "funcs" / "printf.c").exists()
    assert (out_dir / "funcs" / "internal_func.c").exists()

    index = json.loads((out_dir / "decompile-index.json").read_text(encoding="utf-8"))
    assert index["0x1000"]["status"] == "external"
    assert index["0x2000"]["status"] == "decompiled"


def test_circuit_breaker_5_consecutive_errors(tmp_path):
    """9. Five consecutive decompilation errors trip the circuit breaker and halt."""
    bin_path = _create_dummy_binary(tmp_path)
    out_dir = tmp_path / "out"
    funcs = [{"address": f"0x{1000 + i * 4:x}", "name": f"bad_fn{i}", "is_external": False} for i in range(10)]

    def failing_decompiler(addr, name):
        raise RuntimeError("Simulated decompiler crash")

    m = decompile_all(
        binary_path=bin_path,
        output_directory=out_dir,
        functions_provider=lambda p: funcs,
        decompiler_fn=failing_decompiler,
    )
    assert m.circuit_breaker_tripped is True
    assert m.failed_count == 5
    assert "Circuit breaker tripped" in m.diagnostics


def test_circuit_breaker_resets_on_success(tmp_path):
    """10. A success resets consecutive failure count before reaching 5."""
    bin_path = _create_dummy_binary(tmp_path)
    out_dir = tmp_path / "out"
    funcs = [{"address": f"0x{1000 + i * 4:x}", "name": f"fn_{i}", "is_external": False} for i in range(8)]

    # Fail 4, succeed 1, fail 3 -> total 7 failures, but circuit breaker does not trip
    fail_indices = {0, 1, 2, 3, 5, 6, 7}

    def intermittent_decompiler(addr, name):
        idx = int(name.replace("fn_", ""))
        if idx in fail_indices:
            raise RuntimeError(f"Simulated error on {name}")
        return f"void {name}() {{}}\n"

    m = decompile_all(
        binary_path=bin_path,
        output_directory=out_dir,
        functions_provider=lambda p: funcs,
        decompiler_fn=intermittent_decompiler,
    )
    assert m.circuit_breaker_tripped is False
    assert m.failed_count == 7
    assert m.decompiled_count == 1


def test_target_sha256_mismatch_detection(tmp_path):
    """11. Resuming against output directory initialized with a different binary raises TargetMismatchError."""
    bin1 = _create_dummy_binary(tmp_path, "bin1.bin", size=512)
    bin2 = _create_dummy_binary(tmp_path, "bin2.bin", size=1024)
    out_dir = tmp_path / "out"

    # Initialize with bin1
    decompile_all(binary_path=bin1, output_directory=out_dir)

    # Resume with bin2
    with pytest.raises(TargetMismatchError):
        decompile_all(binary_path=bin2, output_directory=out_dir, resume=True)


def test_compilable_c_filter_application(tmp_path):
    """12. Compilable C filter is applied when filter_compilable=True."""
    bin_path = _create_dummy_binary(tmp_path)
    out_dir = tmp_path / "out"
    funcs = [{"address": "0x1000", "name": "fn1", "is_external": False}]

    # Return raw decompiler code with undefined types
    def raw_decompiler(addr, name):
        return "undefined4 fn1(undefined8 param1) {\n    return 0;\n}\n"

    decompile_all(
        binary_path=bin_path,
        output_directory=out_dir,
        functions_provider=lambda p: funcs,
        decompiler_fn=raw_decompiler,
        filter_compilable=True,
    )
    c_content = (out_dir / "funcs" / "fn1.c").read_text(encoding="utf-8")
    assert "stdint.h" in c_content
    assert "uint32_t" in c_content or "int32_t" in c_content


def test_manifest_compact_byte_budget(tmp_path):
    """13. Manifest diagnostics capped at 2,048 UTF-8 bytes."""
    bin_path = _create_dummy_binary(tmp_path)
    out_dir = tmp_path / "out"
    funcs = [{"address": f"0x{1000 + i * 4:x}", "name": f"failing_{i}", "is_external": False} for i in range(5)]

    def huge_error_decompiler(addr, name):
        raise RuntimeError("X" * 1000)

    m = decompile_all(
        binary_path=bin_path,
        output_directory=out_dir,
        functions_provider=lambda p: funcs,
        decompiler_fn=huge_error_decompiler,
    )
    manifest_dict = m.to_dict()
    assert len(manifest_dict["diagnostics"].encode("utf-8")) <= 2048 + 30  # with truncation note
    assert "[truncated]" in manifest_dict["diagnostics"]


def test_decompile_index_json_structure(tmp_path):
    """14. decompile-index.json accurately stores all entries."""
    bin_path = _create_dummy_binary(tmp_path)
    out_dir = tmp_path / "out"
    funcs = [
        {"address": "0x1000", "name": "f1", "is_external": False},
        {"address": "0x2000", "name": "f2", "is_external": True},
    ]
    decompile_all(
        binary_path=bin_path,
        output_directory=out_dir,
        functions_provider=lambda p: funcs,
    )
    index = json.loads((out_dir / "decompile-index.json").read_text(encoding="utf-8"))
    assert "0x1000" in index
    assert index["0x1000"]["status"] == "decompiled"
    assert "0x2000" in index
    assert index["0x2000"]["status"] == "external"


def test_unvisited_procedure_priority(tmp_path):
    """15. Unvisited procedures are attempted first."""
    bin_path = _create_dummy_binary(tmp_path)
    out_dir = tmp_path / "out"
    funcs_run1 = [{"address": "0x1000", "name": "fn1", "is_external": False}]

    decompile_all(
        binary_path=bin_path,
        output_directory=out_dir,
        functions_provider=lambda p: funcs_run1,
        resume=True,
    )

    visited_order = []

    def tracking_decompiler(addr, name):
        visited_order.append(addr)
        return "void foo() {}\n"

    funcs_run2 = [
        {"address": "0x1000", "name": "fn1", "is_external": False},
        {"address": "0x2000", "name": "fn2", "is_external": False},
    ]

    decompile_all(
        binary_path=bin_path,
        output_directory=out_dir,
        functions_provider=lambda p: funcs_run2,
        decompiler_fn=tracking_decompiler,
        resume=True,
    )
    # fn1 was already completed, so only unvisited fn2 was decompiled
    assert visited_order == ["0x2000"]
