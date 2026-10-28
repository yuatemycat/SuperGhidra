"""SuperGhidra: High-Performance Binary Analysis, C++ Recovery, and Daemon Automation.

Stable Public Core (API Frozen in v0.4.0):
- Loader: load_binary, BinaryImage, Section, Symbol, Import, Relocation
- RTTI & MFC Recovery: recover_classes, ClassRecoveryReport, RTTIClass, MFCArchiveDecoder, CRuntimeClassInfo
- Overlay: WriteOverlay
- Daemon Client: query_oracle, is_daemon_online, start_daemon, stop_daemon, client_send_request
- C Filter: CompilableDecompilerFilter, filter_c_code
- Exporters: DWARF5Exporter, PDBExporter, SymFileExporter, MapFileExporter, export_from_ledger

All other subsystems are designated experimental and reside under `superghidra.experimental.*`.
"""

from __future__ import annotations

import importlib
from typing import Any

__version__ = "0.5.0"

# ==============================================================================
# Supported Stable Core API
# ==============================================================================

_SUPPORTED_CORE: dict[str, tuple[str, str]] = {
    # 1. Binary Loader
    "load_binary": ("superghidra.formats.binary_loader", "load_binary"),
    "BinaryImage": ("superghidra.formats.binary_loader", "BinaryImage"),
    "Section": ("superghidra.formats.binary_loader", "Section"),
    "Symbol": ("superghidra.formats.binary_loader", "Symbol"),
    "Import": ("superghidra.formats.binary_loader", "Import"),
    "Relocation": ("superghidra.formats.binary_loader", "Relocation"),
    # 2. MSVC RTTI & MFC Recovery
    "recover_classes": ("superghidra.formats.msvc_class_recovery", "recover_classes"),
    "ClassRecoveryReport": ("superghidra.formats.msvc_class_recovery", "ClassRecoveryReport"),
    "RTTIClass": ("superghidra.formats.msvc_class_recovery", "RTTIClass"),
    "RTTIBaseClass": ("superghidra.formats.msvc_class_recovery", "RTTIBaseClass"),
    "MemberVariable": ("superghidra.formats.msvc_class_recovery", "MemberVariable"),
    "MFCArchiveDecoder": ("superghidra.formats.mfc_archive", "MFCArchiveDecoder"),
    "CRuntimeClassInfo": ("superghidra.formats.mfc_archive", "CRuntimeClassInfo"),
    "MFCClassSchema": ("superghidra.formats.mfc_archive", "MFCClassSchema"),
    # 3. Write Overlay
    "WriteOverlay": ("superghidra.core.ghidra_oracle", "WriteOverlay"),
    # 4. Daemon Client
    "query_oracle": ("superghidra.core.ghidra_oracle", "query_oracle"),
    "is_daemon_online": ("superghidra.core.ghidra_oracle", "is_daemon_online"),
    "start_daemon": ("superghidra.core.ghidra_oracle", "start_daemon"),
    "stop_daemon": ("superghidra.core.ghidra_oracle", "stop_daemon"),
    "client_send_request": ("superghidra.core.ghidra_oracle", "client_send_request"),
    "is_loopback_host": ("superghidra.core.ghidra_oracle", "is_loopback_host"),
    "save_session_token": ("superghidra.core.ghidra_oracle", "save_session_token"),
    "load_session_token": ("superghidra.core.ghidra_oracle", "load_session_token"),
    # 5. Compilable C Filter
    "CompilableDecompilerFilter": ("superghidra.core.compilable_filter", "CompilableDecompilerFilter"),
    "filter_c_code": ("superghidra.core.compilable_filter", "filter_c_code"),
    # 7. Formats & Dispatch (1.0.0)
    "dispatch_apple_binary": ("superghidra.formats.apple_dispatch", "dispatch_apple_binary"),
    "AppleDispatchReport": ("superghidra.formats.apple_dispatch", "AppleDispatchReport"),
    "recover_il2cpp_metadata": ("superghidra.formats.il2cpp_metadata", "recover_il2cpp_metadata"),
    "IL2CPPMetadataReport": ("superghidra.formats.il2cpp_metadata", "IL2CPPMetadataReport"),
    "audit_rust_go_binary": ("superghidra.formats.rust_go_metadata", "audit_rust_go_binary"),
    "RustGoAuditReport": ("superghidra.formats.rust_go_metadata", "RustGoAuditReport"),
    # 8. Evidence Ledger & Paging (1.0.0)
    "EvidenceEnvelope": ("superghidra.core.evidence_ledger", "EvidenceEnvelope"),
    "EpistemicStatus": ("superghidra.core.evidence_ledger", "EpistemicStatus"),
    "ReferenceProvenance": ("superghidra.core.evidence_ledger", "ReferenceProvenance"),
    "CoverageBoundary": ("superghidra.core.evidence_ledger", "CoverageBoundary"),
    "inspect_analysis_view": ("superghidra.core.views", "inspect_analysis_view"),
    # 9. Value Tracing & Jump Table Recovery (1.0.0)
    "trace_native_values": ("superghidra.lifters.trace_values", "trace_native_values"),
    "HighPCodeValueTracer": ("superghidra.lifters.trace_values", "HighPCodeValueTracer"),
    "ValueTraceReport": ("superghidra.lifters.trace_values", "ValueTraceReport"),
    "ARM64JumpTableProver": ("superghidra.acceleration.jump_table_prover", "ARM64JumpTableProver"),
    "RecoveredJumpTable": ("superghidra.acceleration.jump_table_prover", "RecoveredJumpTable"),
    # 10. Resumable Bulk Decompilation (1.0.0)
    "decompile_all": ("superghidra.core.bulk_decompile", "decompile_all"),
    "BulkDecompileRunner": ("superghidra.core.bulk_decompile", "BulkDecompileRunner"),
    "BulkDecompileManifest": ("superghidra.core.bulk_decompile", "BulkDecompileManifest"),
    # 11. REA Ecosystem Bridge (1.0.0)
    "ReaAsyncRouter": ("superghidra.integrations.rea_bridge", "ReaAsyncRouter"),
    "ReaBridgeError": ("superghidra.integrations.rea_bridge", "ReaBridgeError"),
    # 6. Exporters
    "DWARF5Exporter": ("superghidra.formats.synthetic_symbol_exporter", "DWARF5Exporter"),
    "PDBExporter": ("superghidra.formats.synthetic_symbol_exporter", "PDBExporter"),
    "SymFileExporter": ("superghidra.formats.synthetic_symbol_exporter", "SymFileExporter"),
    "MapFileExporter": ("superghidra.formats.synthetic_symbol_exporter", "MapFileExporter"),
    "export_from_ledger": ("superghidra.formats.synthetic_symbol_exporter", "export_from_ledger"),
}

__all__ = [
    "__version__",
    "experimental",
    "compat",
    *sorted(_SUPPORTED_CORE.keys()),
]

# Legacy / experimental symbols preserved for seamless backward-compatibility
_LEGACY_EXPORTS: dict[str, tuple[str, str]] = {
    "GhidraOracleSession": ("superghidra.core.ghidra_oracle", "GhidraOracleSession"),
    "GhidraDaemonServer": ("superghidra.core.ghidra_oracle", "GhidraDaemonServer"),
    "L2SQLiteCache": ("superghidra.core.ghidra_oracle", "L2SQLiteCache"),
    "MAX_REQUEST_SIZE": ("superghidra.core.ghidra_oracle", "MAX_REQUEST_SIZE"),
    "get_default_token_path": ("superghidra.core.ghidra_oracle", "get_default_token_path"),
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
    "DataBuffer": ("superghidra.storage.storage_compression_prototype", "DataBuffer"),
    "SlotDirectory": ("superghidra.storage.storage_compression_prototype", "SlotDirectory"),
    "SlotDirectoryEntry": ("superghidra.storage.storage_compression_prototype", "SlotDirectoryEntry"),
    "CompressedLocalManagedBufferFile": ("superghidra.storage.storage_compression_prototype", "CompressedLocalManagedBufferFile"),
    "StorageCompressionBenchmark": ("superghidra.storage.storage_compression_prototype", "StorageCompressionBenchmark"),
    "GhidraExtensionPackager": ("superghidra.storage.ghidra_extension_packager", "GhidraExtensionPackager"),
    "ExtensionValidationError": ("superghidra.storage.ghidra_extension_packager", "ExtensionValidationError"),
    "GPUAdrpScanner": ("superghidra.acceleration.gpu_adrp_scanner", "GPUAdrpScanner"),
    "ADRPMatch": ("superghidra.acceleration.gpu_adrp_scanner", "ADRPMatch"),
    "scan_adrp_add_pairs": ("superghidra.acceleration.gpu_adrp_scanner", "scan_adrp_add_pairs"),
    "GPUFunctionSeeder": ("superghidra.acceleration.gpu_function_seeder", "GPUFunctionSeeder"),
    "FunctionSeed": ("superghidra.acceleration.gpu_function_seeder", "FunctionSeed"),
    "SeedClassification": ("superghidra.acceleration.gpu_function_seeder", "SeedClassification"),
    "BinaryDiffEngine": ("superghidra.diff.binary_diff_engine", "BinaryDiffEngine"),
    "FunctionMatch": ("superghidra.diff.binary_diff_engine", "FunctionMatch"),
    "StructShiftMigrator": ("superghidra.diff.struct_shift_migrator", "StructShiftMigrator"),
    "StructShiftReport": ("superghidra.diff.struct_shift_migrator", "StructShiftReport"),
    "migrate_struct_shifts": ("superghidra.diff.struct_shift_migrator", "migrate_struct_shifts"),
    "ReconstructionObligationLedger": ("superghidra.diff.evidence_ledger", "ReconstructionObligationLedger"),
    "ProofObligation": ("superghidra.diff.evidence_ledger", "ProofObligation"),
    "ObligationType": ("superghidra.diff.evidence_ledger", "ObligationType"),
    "ObligationStatus": ("superghidra.diff.evidence_ledger", "ObligationStatus"),
    "SemanticDeltaLog": ("superghidra.diff.semantic_delta_log", "SemanticDeltaLog"),
    "SemanticEvent": ("superghidra.diff.semantic_delta_log", "SemanticEvent"),
    "DeltaEventType": ("superghidra.diff.semantic_delta_log", "DeltaEventType"),
    "PCodeLifter": ("superghidra.lifters.pcode_lifter_bridge", "PCodeLifter"),
    "PCodeFunction": ("superghidra.lifters.pcode_lifter_bridge", "PCodeFunction"),
    "PCodeBasicBlock": ("superghidra.lifters.pcode_lifter_bridge", "PCodeBasicBlock"),
    "PCodeOp": ("superghidra.lifters.pcode_lifter_bridge", "PCodeOp"),
    "PCodeOpCode": ("superghidra.lifters.pcode_lifter_bridge", "PCodeOpCode"),
    "Varnode": ("superghidra.lifters.pcode_lifter_bridge", "Varnode"),
    "AddressSpace": ("superghidra.lifters.pcode_lifter_bridge", "AddressSpace"),
    "SMTPcodeVerifier": ("superghidra.lifters.smt_pcode_verifier", "SMTPcodeVerifier"),
    "CIntrinsic": ("superghidra.lifters.smt_pcode_verifier", "CIntrinsic"),
    "VerificationResult": ("superghidra.lifters.smt_pcode_verifier", "VerificationResult"),
    "VerificationStatus": ("superghidra.lifters.smt_pcode_verifier", "VerificationStatus"),
    "EGraphPipeline": ("superghidra.lifters.egraph_mlir_pipeline", "EGraphPipeline"),
    "X86Insn": ("superghidra.lifters.x86_decode", "X86Insn"),
    "iter_decode": ("superghidra.lifters.x86_decode", "iter_decode"),
    "ThumbInsn": ("superghidra.lifters.arm_thumb_decode", "ThumbInsn"),
    "iter_thumb_decode": ("superghidra.lifters.arm_thumb_decode", "iter_thumb_decode"),
    "WasmViewerServer": ("superghidra.lifters.wasm_decompiler_pipeline", "WasmViewerServer"),
    "export_wasm_decompiler_package": ("superghidra.lifters.wasm_decompiler_pipeline", "export_wasm_decompiler_package"),
    "ApkJniCrossReferencer": ("superghidra.integrations.apk_jni_cross_referencer", "ApkJniCrossReferencer"),
    "EmulatorMemorySidecar": ("superghidra.integrations.emulator_memory_sidecar", "EmulatorMemorySidecar"),
    "EmulatorFleetGuard": ("superghidra.integrations.emulator_memory_sidecar", "EmulatorFleetGuard"),
    "ColabCloudOrchestrator": ("superghidra.integrations.colab_cloud_orchestrator", "ColabCloudOrchestrator"),
    "DLiftVerifier": ("superghidra.integrations.d_lift_verifier", "DLiftVerifier"),
    "NeuralDecompilerPipeline": ("superghidra.integrations.neural_decompiler_pipeline", "NeuralDecompilerPipeline"),
    "GhidraGuiOverlaySync": ("superghidra.integrations.ghidra_gui_overlay_sync", "GhidraGuiOverlaySync"),
}


def __getattr__(name: str) -> Any:
    if name == "experimental":
        return importlib.import_module("superghidra.experimental")
    if name == "compat":
        return importlib.import_module("superghidra.compat")

    # 1. Resolve from supported core
    if name in _SUPPORTED_CORE:
        mod_name, attr_name = _SUPPORTED_CORE[name]
        mod = importlib.import_module(mod_name)
        return getattr(mod, attr_name)

    # 2. Resolve from legacy/experimental exports for compatibility
    if name in _LEGACY_EXPORTS:
        mod_name, attr_name = _LEGACY_EXPORTS[name]
        mod = importlib.import_module(mod_name)
        return getattr(mod, attr_name)

    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
