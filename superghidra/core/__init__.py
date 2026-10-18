"""SuperGhidra Core Domain: Daemon, Oracle, Resource Governor, SHM IPC, Dependency DAG & Headless Harness."""

from __future__ import annotations

import importlib
from typing import Any

_EXPORTS: dict[str, tuple[str, str]] = {
    "GhidraOracleSession": ("superghidra.core.ghidra_oracle", "GhidraOracleSession"),
    "GhidraDaemonServer": ("superghidra.core.ghidra_oracle", "GhidraDaemonServer"),
    "L2SQLiteCache": ("superghidra.core.ghidra_oracle", "L2SQLiteCache"),
    "WriteOverlay": ("superghidra.core.ghidra_oracle", "WriteOverlay"),
    "client_send_request": ("superghidra.core.ghidra_oracle", "client_send_request"),
    "ResourceMode": ("superghidra.core.resource_governor", "ResourceMode"),
    "FunctionComplexityTier": ("superghidra.core.resource_governor", "FunctionComplexityTier"),
    "ModePolicy": ("superghidra.core.resource_governor", "ModePolicy"),
    "get_default_mode_policy": ("superghidra.core.resource_governor", "get_default_mode_policy"),
    "DecompilerComplexityGovernor": ("superghidra.core.resource_governor", "DecompilerComplexityGovernor"),
    "JVMResourceConfigurator": ("superghidra.core.resource_governor", "JVMResourceConfigurator"),
    "DecompileProcessPoolReaper": ("superghidra.core.resource_governor", "DecompileProcessPoolReaper"),
    "PersistentDecompilerDBCache": ("superghidra.core.resource_governor", "PersistentDecompilerDBCache"),
    "TelemetryResourceGovernor": ("superghidra.core.resource_governor", "TelemetryResourceGovernor"),
    "ShmBinaryView": ("superghidra.core.shm_decompiler_bridge", "ShmBinaryView"),
    "ShmRingBuffer": ("superghidra.core.shm_decompiler_bridge", "ShmRingBuffer"),
    "ShmChannel": ("superghidra.core.shm_decompiler_bridge", "ShmChannel"),
    "ShmMessage": ("superghidra.core.shm_decompiler_bridge", "ShmMessage"),
    "SectionInfo": ("superghidra.core.shm_decompiler_bridge", "SectionInfo"),
    "benchmark_shm_bridge": ("superghidra.core.shm_decompiler_bridge", "benchmark_shm_bridge"),
    "DependencyCacheDAG": ("superghidra.core.dependency_cache_dag", "DependencyCacheDAG"),
    "DecompilationLRUCache": ("superghidra.core.dependency_cache_dag", "DecompilationLRUCache"),
    "InvalidationImpactReport": ("superghidra.core.dependency_cache_dag", "InvalidationImpactReport"),
    "AnalyzerConfiguration": ("superghidra.core.headless_analyzer_tuner", "AnalyzerConfiguration"),
    "AnalyzerProfileName": ("superghidra.core.headless_analyzer_tuner", "AnalyzerProfileName"),
    "HeadlessCommandBuilder": ("superghidra.core.headless_analyzer_tuner", "HeadlessCommandBuilder"),
    "ScriptGenerator": ("superghidra.core.headless_analyzer_tuner", "ScriptGenerator"),
    "get_profile_config": ("superghidra.core.headless_analyzer_tuner", "get_profile_config"),
    "HeadlessProfile": ("superghidra.core.cross_platform_headless_harness", "HeadlessProfile"),
    "HeadlessEnvironmentConfigurator": ("superghidra.core.cross_platform_headless_harness", "HeadlessEnvironmentConfigurator"),
    "DecompilerBuildConfig": ("superghidra.core.native_decompiler_pgo_builder", "DecompilerBuildConfig"),
    "NativeDecompilerPGOBuilder": ("superghidra.core.native_decompiler_pgo_builder", "NativeDecompilerPGOBuilder"),
    "ReconstructionObligationLedger": ("superghidra.diff.evidence_ledger", "ReconstructionObligationLedger"),
    "ProofObligation": ("superghidra.diff.evidence_ledger", "ProofObligation"),
    "VTableSlotVerifier": ("superghidra.diff.evidence_ledger", "VTableSlotVerifier"),
    "FieldDisplacementVerifier": ("superghidra.diff.evidence_ledger", "FieldDisplacementVerifier"),
    "AllocationSizeVerifier": ("superghidra.diff.evidence_ledger", "AllocationSizeVerifier"),
    "CheckResult": ("superghidra.diff.evidence_ledger", "CheckResult"),
}

__all__ = list(_EXPORTS.keys())


def __getattr__(name: str) -> Any:
    if name in _EXPORTS:
        mod_path, attr_name = _EXPORTS[name]
        mod = importlib.import_module(mod_path)
        val = getattr(mod, attr_name)
        globals()[name] = val
        return val
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
