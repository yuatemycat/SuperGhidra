"""Compatibility shims preserving flat-namespace imports for legacy integrations."""

from __future__ import annotations

import importlib
from typing import Any

__all__ = ['apk_jni_cross_referencer', 'arm_thumb_decode', 'benchmark_and_nextgen_engine', 'binary_diff_engine', 'binary_loader', 'cluster_daemon', 'colab_cloud_orchestrator', 'compilable_filter', 'cross_platform_headless_harness', 'd_lift_verifier', 'database_migrator', 'dependency_cache_dag', 'dwarf_pdb_preindexer', 'egraph_mlir_pipeline', 'emulator_memory_sidecar', 'evidence_ledger', 'ghidra_extension_packager', 'ghidra_gui_overlay_sync', 'ghidra_oracle', 'gpu_adrp_scanner', 'gpu_function_seeder', 'headless_analyzer_tuner', 'ida_flirt_bridge', 'ida_til_importer', 'live_binary_tools', 'mfc_archive', 'mitigation_roadmap_engine', 'msvc_class_recovery', 'native_compiler', 'native_decompiler_pgo_builder', 'neural_decompiler_pipeline', 'ood_decompiler_benchmark', 'parity_engine', 'pcode_lifter_bridge', 'phase1_phase2_roadmap_engine', 'resource_governor', 'semantic_delta_log', 'serialize_trace', 'shm_decompiler_bridge', 'smt_pcode_verifier', 'storage_compression_prototype', 'struct_shift_migrator', 'synthetic_symbol_exporter', 'wasm_decompiler_pipeline', 'x86_decode']

def __getattr__(name: str) -> Any:
    if name in __all__:
        return importlib.import_module(f"superghidra.compat.{name}")
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
