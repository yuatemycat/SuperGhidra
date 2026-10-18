# `superghidra.integrations` — APK JNI Cross-Referencer, Android Emulator Sidecar, Colab Orchestrator & Neural Pipeline

> **Progressive Discovery Index:** Read this before inspecting files in `superghidra/integrations/`.

## 1. Domain Modules & Primary Exports

| Module | Primary Exports | Purpose |
| :--- | :--- | :--- |
| [`apk_jni_cross_referencer.py`](apk_jni_cross_referencer.py) | `APKJNICrossReferencer`, `JavaNativeMethod`, `JNIRegisteredNative`, `JNICrossReferenceMatch` | Correlates Android DEX `native` method declarations with ELF `.so` static JNI exports (`Java_<pkg>_<cls>_<method>`) and dynamic `RegisterNatives` (`JNINativeMethod`) tables. |
| [`emulator_memory_sidecar.py`](emulator_memory_sidecar.py) | `EmulatorFleetGuard`, `FleetSafetyViolationError`, `BaseMemoryReader`, `Win32ProcessMemoryReader`, `FridaMemoryReader`, `MockMemoryReader`, `verify_vtable_pointer`, `verify_struct_field`, `extract_dynamic_encryption_keys`, `EmulatorSidecarShmServer`, `EmulatorSidecarShmClient` | Live/mock process memory introspection sidecar with strict fleet isolation, VTable/struct pointer verification, Shannon entropy key extraction, and SHM streaming. |
| [`colab_cloud_orchestrator.py`](colab_cloud_orchestrator.py) | `ColabCloudOrchestrator`, `CloudConfig`, `CloudRuntimeTier` | Google Colab Cloud TPU v5e / NVIDIA T4 pipeline orchestrator with ELF64 `.text` slicing (`extract_elf_executable_slice`), boundary-aware seeding, and HuggingFace Hub streaming. |
| [`neural_decompiler_pipeline.py`](neural_decompiler_pipeline.py) | `NeuralDecompilerPipeline`, `LLMDecompilerClient`, `SkeletonExtractor`, `DecompiledSkeleton`, `NeuralPrediction`, `VerifiedNeuralCommit` | Two-phase Skeleton-to-Skin neural decompiler normalizing raw C skeletons, querying OpenAI/vLLM/Ollama/Gemini HTTP endpoints, and gating commits via `EvidenceLedger`. |

## 2. Key Data Structures & Invariants
- **`EmulatorFleetGuard` Safety Invariant:**
  - Protected farm serials (`emulator-5564`, `127.0.0.1:5565`, `MEmu_0`, `127.0.0.1:21503`) are unconditionally blocked.
  - Unknown serials default to `authorized_for_experiments=False` and are denied.
  - `FridaMemoryReader` classifies process attachment as a mutation (`is_mutation=True`), permitting attachment **only** on allow-listed sandbox targets (`emulator-5580`, `127.0.0.1:21513`).
- **Honest Neural Fallback Invariant:** When no live LLM endpoint is configured or an HTTP error occurs, `LLMDecompilerClient` emits neutral heuristic names (`sub_<addr>`, `field_0x<offset>`) with `model_identifier="heuristic-fallback"`, `source="heuristic"`, and `confidence <= 0.3`.
- **Colab Upload Safety:** `ColabCloudOrchestrator` defaults to `upload=False`, honors `dry_run=True`, and restricts HuggingFace uploads strictly to `<workspace>/results` with explicit `allow_patterns`.

## 3. Quick-Test Command
```powershell
python -m pytest tests/integrations -q
```
