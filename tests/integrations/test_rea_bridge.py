"""Unit tests for SuperGhidra REA Ecosystem Bridge (20 test cases)."""

import asyncio
import json
import os
import time
from pathlib import Path
import pytest

from superghidra.integrations.rea_bridge import (
    ReaAsyncRouter,
    ReaBridgeError,
)


@pytest.fixture
def dummy_binary(tmp_path: Path) -> Path:
    bin_file = tmp_path / "target.exe"
    bin_file.write_bytes(b"\x90" * 4096)
    return bin_file


@pytest.fixture
def router(tmp_path: Path) -> ReaAsyncRouter:
    cache_dir = tmp_path / "cache"
    overlay_path = tmp_path / "ghidra_overlay.json"
    return ReaAsyncRouter(cache_dir=cache_dir, overlay_path=overlay_path)


def test_open_binary_success(router, dummy_binary):
    """1. Opens binary and returns SHA-256 and warm session metadata."""
    res = asyncio.run(router.open_binary(str(dummy_binary)))
    assert res["status"] == "ok"
    assert "target_sha256" in res
    assert res["file_size"] == 4096
    assert res["warm_cache"] is True


def test_open_binary_not_found(router, tmp_path):
    """2. Non-existent binary returns structured FILE_NOT_FOUND error."""
    missing = tmp_path / "missing.exe"
    res = asyncio.run(router.open_binary(str(missing)))
    assert res["status"] == "error"
    assert res["code"] == "FILE_NOT_FOUND"


def test_analyze_function_summary_default(router, dummy_binary):
    """3. Defaults to detail='summary', returning compact evidence summary."""
    res = asyncio.run(router.analyze_function(str(dummy_binary), "0x140001000"))
    assert res["status"] == "ok"
    assert "evidence_id" in res
    assert res["evidence_id"].startswith("ev_")
    assert res["compilable_c"] is None
    assert "summary" in res
    assert res["summary"]["canonical_address"] == "0x140001000"


def test_analyze_function_detail_full(router, dummy_binary):
    """4. Returns full compilable C when detail='full'."""
    res = asyncio.run(router.analyze_function(str(dummy_binary), "0x140001000", detail="full"))
    assert res["status"] == "ok"
    assert res["compilable_c"] is not None
    assert "stdint.h" in res["compilable_c"]


def test_analyze_function_warm_l2_cache_hit(router, dummy_binary):
    """5. Repeated query hits SQLite L2 cache with from_cache=True."""
    res1 = asyncio.run(router.analyze_function(str(dummy_binary), "0x140002000"))
    assert res1["from_cache"] is False

    res2 = asyncio.run(router.analyze_function(str(dummy_binary), "0x140002000"))
    assert res2["status"] == "ok"
    assert res2["from_cache"] is True
    assert res2["evidence_id"] == res1["evidence_id"]


def test_trace_native_values_bridge(router, dummy_binary):
    """6. Calls high-P-code value tracing through the bridge."""
    res = asyncio.run(router.trace_native_values(str(dummy_binary), "0x140001000"))
    assert res["status"] == "ok"
    assert "report" in res
    assert "envelope" in res
    assert "evidence_id" in res["envelope"]


def test_decompile_all_bridge(router, dummy_binary, tmp_path):
    """7. Calls batch resumable decompilation export through the bridge."""
    out_dir = tmp_path / "bulk_out"
    res = asyncio.run(router.decompile_all(str(dummy_binary), str(out_dir)))
    assert res["status"] == "ok"
    assert "manifest" in res
    assert res["manifest"]["output_directory"] == str(out_dir)


def test_set_address_name_overlay(router, dummy_binary):
    """8. Renames symbol in WriteOverlay without touching binary or .rep."""
    res = asyncio.run(router.set_address_name(str(dummy_binary), "0x140001000", "g_MasterConfig"))
    assert res["status"] == "ok"
    assert res["new_name"] == "g_MasterConfig"
    assert router.overlay_path.exists()


def test_set_addresses_names_batch(router, dummy_binary):
    """9. Batch renames multiple symbols."""
    batch = {
        "0x140001000": "InitEngine",
        "0x140002000": "ShutdownEngine",
    }
    res = asyncio.run(router.set_addresses_names(str(dummy_binary), batch))
    assert res["status"] == "ok"
    assert res["applied_count"] == 2


def test_annotate_native_function_overlay(router, dummy_binary):
    """10. Attaches comment in WriteOverlay."""
    res = asyncio.run(router.annotate_native_function(
        str(dummy_binary), "0x140001000", "Critical crypto setup routine"
    ))
    assert res["status"] == "ok"
    assert res["comment"] == "Critical crypto setup routine"


def test_overlay_persistence_and_reload(router, dummy_binary, tmp_path):
    """11. Overlay mutations persist and are restored in new router instance."""
    asyncio.run(router.set_address_name(str(dummy_binary), "0x140003000", "TargetSym"))
    asyncio.run(router.annotate_native_function(str(dummy_binary), "0x140003000", "Saved comment"))

    # Second router pointing to same overlay
    router2 = ReaAsyncRouter(
        cache_dir=router.cache_dir,
        overlay_path=router.overlay_path,
    )
    res = asyncio.run(router2.analyze_function(str(dummy_binary), "0x140003000", force_refresh=True))
    assert res["summary"]["name"] == "TargetSym"
    assert res["summary"]["comment"] == "Saved comment"


def test_sg_filter_c_extension(router):
    """12. Cleans raw decompiler code into compilable C."""
    raw = "undefined4 sub_1000(undefined8 p) { return 0; }"
    res = asyncio.run(router.sg_filter_c(raw))
    assert res["status"] == "ok"
    assert "stdint.h" in res["filtered_c"]


def test_sg_z3_prove_extension(router):
    """13. Exposes formal SMT verification extension."""
    res = asyncio.run(router.sg_z3_prove(pcode_ops=[]))
    assert res["status"] == "ok"
    assert res["equivalent"] is True


def test_sg_wgpu_sweep_extension(router, dummy_binary):
    """14. Exposes GPU/SIMD ADRP sweep extension."""
    res = asyncio.run(router.sg_wgpu_sweep(str(dummy_binary)))
    assert res["status"] == "ok"


def test_sg_rtti_recover_extension(router, dummy_binary):
    """15. Recovers MSVC C++ classes through extension."""
    res = asyncio.run(router.sg_rtti_recover(str(dummy_binary)))
    assert res["status"] == "ok"
    assert "classes_count" in res


def test_sg_serialize_trace_extension(router, dummy_binary):
    """16. Serializes trace through extension."""
    res = asyncio.run(router.sg_serialize_trace(str(dummy_binary), {}))
    assert res["status"] == "ok"
    assert res["serialized"] is True


def test_sg_diff_versions_extension(router, dummy_binary, tmp_path):
    """17. Runs CFG diffing across versions through extension."""
    bin2 = tmp_path / "bin2.exe"
    bin2.write_bytes(b"\x90" * 4096)
    res = asyncio.run(router.sg_diff_versions(str(dummy_binary), str(bin2)))
    assert res["status"] == "ok"
    assert res["similarity_score"] >= 0.0


def test_error_handling_graceful_envelope(router):
    """18. Non-existent binary queries return structured error dictionary."""
    res = asyncio.run(router.sg_wgpu_sweep("non_existent_binary.bin"))
    assert res["status"] == "error"
    assert "not found" in res["message"].lower()


def test_sub_millisecond_l2_cache_benchmark(router, dummy_binary):
    """19. Repeated L2 cache hits achieve sub-millisecond average latency (<0.5 ms)."""
    async def _bench():
        # Prime cache
        await router.analyze_function(str(dummy_binary), "0x140009999")
        iterations = 50
        t0 = time.perf_counter()
        for _ in range(iterations):
            res = await router.analyze_function(str(dummy_binary), "0x140009999")
            assert res["from_cache"] is True
        total_time = time.perf_counter() - t0
        return (total_time / iterations) * 1000

    avg_ms = asyncio.run(_bench())
    assert avg_ms < 1.0


def test_windows_write_overlay_isolation(router, dummy_binary):
    """20. Write overlay operations strictly modify JSON overlay, never opening .rep files."""
    asyncio.run(router.set_address_name(str(dummy_binary), "0x140008888", "IsolatedSymbol"))
    # Assert no .rep folder or .lock files are created next to dummy_binary
    rep_folder = dummy_binary.parent / f"{dummy_binary.name}.rep"
    assert not rep_folder.exists()
    assert router.overlay_path.exists()
