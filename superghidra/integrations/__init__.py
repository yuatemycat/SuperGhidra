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
