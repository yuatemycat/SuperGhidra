"""SuperGhidra Integrations Domain: APK JNI Cross-Referencer, Android Emulator Sidecar, Cloud Colab Orchestrator & Neural Pipeline."""

from __future__ import annotations

import importlib
from typing import Any

_EXPORTS: dict[str, tuple[str, str]] = {
    "APKJNICrossReferencer": ("superghidra.integrations.apk_jni_cross_referencer", "APKJNICrossReferencer"),
    "JavaNativeMethod": ("superghidra.integrations.apk_jni_cross_referencer", "JavaNativeMethod"),
    "JNIRegisteredNative": ("superghidra.integrations.apk_jni_cross_referencer", "JNIRegisteredNative"),
    "JNICrossReferenceMatch": ("superghidra.integrations.apk_jni_cross_referencer", "JNICrossReferenceMatch"),
    "FleetSafetyViolationError": ("superghidra.integrations.emulator_memory_sidecar", "FleetSafetyViolationError"),
    "EmulatorDeviceInfo": ("superghidra.integrations.emulator_memory_sidecar", "EmulatorDeviceInfo"),
    "EmulatorFleetGuard": ("superghidra.integrations.emulator_memory_sidecar", "EmulatorFleetGuard"),
    "MemoryRegion": ("superghidra.integrations.emulator_memory_sidecar", "MemoryRegion"),
    "BaseMemoryReader": ("superghidra.integrations.emulator_memory_sidecar", "BaseMemoryReader"),
    "Win32ProcessMemoryReader": ("superghidra.integrations.emulator_memory_sidecar", "Win32ProcessMemoryReader"),
    "FridaMemoryReader": ("superghidra.integrations.emulator_memory_sidecar", "FridaMemoryReader"),
    "MockMemoryReader": ("superghidra.integrations.emulator_memory_sidecar", "MockMemoryReader"),
    "ModuleBaseResolver": ("superghidra.integrations.emulator_memory_sidecar", "ModuleBaseResolver"),
    "VTableSlot": ("superghidra.integrations.emulator_memory_sidecar", "VTableSlot"),
    "VTableVerificationResult": ("superghidra.integrations.emulator_memory_sidecar", "VTableVerificationResult"),
    "StructFieldVerificationResult": ("superghidra.integrations.emulator_memory_sidecar", "StructFieldVerificationResult"),
    "DynamicKeyResult": ("superghidra.integrations.emulator_memory_sidecar", "DynamicKeyResult"),
    "verify_vtable_pointer": ("superghidra.integrations.emulator_memory_sidecar", "verify_vtable_pointer"),
    "verify_struct_field": ("superghidra.integrations.emulator_memory_sidecar", "verify_struct_field"),
    "extract_dynamic_encryption_keys": ("superghidra.integrations.emulator_memory_sidecar", "extract_dynamic_encryption_keys"),
    "EmulatorSidecarShmServer": ("superghidra.integrations.emulator_memory_sidecar", "EmulatorSidecarShmServer"),
    "EmulatorSidecarShmClient": ("superghidra.integrations.emulator_memory_sidecar", "EmulatorSidecarShmClient"),
    "CloudRuntimeTier": ("superghidra.integrations.colab_cloud_orchestrator", "CloudRuntimeTier"),
    "CloudConfig": ("superghidra.integrations.colab_cloud_orchestrator", "CloudConfig"),
    "ColabCloudOrchestrator": ("superghidra.integrations.colab_cloud_orchestrator", "ColabCloudOrchestrator"),
    "NeuralDecompilerPipeline": ("superghidra.integrations.neural_decompiler_pipeline", "NeuralDecompilerPipeline"),
    "LLMDecompilerClient": ("superghidra.integrations.neural_decompiler_pipeline", "LLMDecompilerClient"),
    "SkeletonExtractor": ("superghidra.integrations.neural_decompiler_pipeline", "SkeletonExtractor"),
    "DecompiledSkeleton": ("superghidra.integrations.neural_decompiler_pipeline", "DecompiledSkeleton"),
    "NeuralPrediction": ("superghidra.integrations.neural_decompiler_pipeline", "NeuralPrediction"),
    "VerifiedNeuralCommit": ("superghidra.integrations.neural_decompiler_pipeline", "VerifiedNeuralCommit"),
    "DLiftRewardEngine": ("superghidra.integrations.d_lift_verifier", "DLiftRewardEngine"),
    "DLiFTPipeline": ("superghidra.integrations.d_lift_verifier", "DLiFTPipeline"),
    "InMemClangSyntaxGate": ("superghidra.integrations.d_lift_verifier", "InMemClangSyntaxGate"),
    "ClangSyntaxGate": ("superghidra.integrations.d_lift_verifier", "ClangSyntaxGate"),
    "Z3SemanticEquivalenceGate": ("superghidra.integrations.d_lift_verifier", "Z3SemanticEquivalenceGate"),
    "SemanticEquivalenceGate": ("superghidra.integrations.d_lift_verifier", "SemanticEquivalenceGate"),
    "ReadabilityGate": ("superghidra.integrations.d_lift_verifier", "ReadabilityGate"),
    "GRPORewardManager": ("superghidra.integrations.d_lift_verifier", "GRPORewardManager"),
    "DScoreResult": ("superghidra.integrations.d_lift_verifier", "DScoreResult"),
    "DScoreReport": ("superghidra.integrations.d_lift_verifier", "DScoreReport"),
    "SyntaxCheckResult": ("superghidra.integrations.d_lift_verifier", "SyntaxCheckResult"),
    "SemanticCheckResult": ("superghidra.integrations.d_lift_verifier", "SemanticCheckResult"),
    "ReadabilityMetrics": ("superghidra.integrations.d_lift_verifier", "ReadabilityMetrics"),
    "CFunctionSymbolicLifter": ("superghidra.integrations.d_lift_verifier", "CFunctionSymbolicLifter"),
    "build_dlift_benchmark_candidates": ("superghidra.integrations.d_lift_verifier", "build_dlift_benchmark_candidates"),
    "symbolic_write_retry_oracle": ("superghidra.integrations.d_lift_verifier", "symbolic_write_retry_oracle"),
    "run_dlift_verification_suite": ("superghidra.integrations.d_lift_verifier", "run_dlift_verification_suite"),
}

__all__ = list(_EXPORTS.keys()) + ["build_synthetic_dex_bytes", "build_synthetic_jni_elf_bytes"]


def __getattr__(name: str) -> Any:
    if name in _EXPORTS:
        mod_path, attr_name = _EXPORTS[name]
        mod = importlib.import_module(mod_path)
        val = getattr(mod, attr_name)
        globals()[name] = val
        return val
    if name in ("build_synthetic_dex_bytes", "build_synthetic_jni_elf_bytes"):
        mod = importlib.import_module("superghidra.integrations.apk_jni_cross_referencer")
        val = getattr(mod.APKJNICrossReferencer, name)
        globals()[name] = val
        return val
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
