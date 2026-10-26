# `superghidra.integrations` — APK JNI Cross-Referencer, Android Emulator Sidecar, Colab Orchestrator & Neural Pipeline

> **Progressive Discovery Index:** Read this before inspecting files in `superghidra/integrations/`.

## 1. Domain Modules & Primary Exports

| Module | Primary Exports | Purpose |
| :--- | :--- | :--- |
| [`apk_jni_cross_referencer.py`](apk_jni_cross_referencer.py) | `APKJNICrossReferencer`, `JavaNativeMethod`, `JNIRegisteredNative`, `JNICrossReferenceMatch` | Correlates Android DEX `native` method declarations with ELF `.so` static JNI exports (`Java_<pkg>_<cls>_<method>`) and dynamic `RegisterNatives` (`JNINativeMethod`) tables. |
| [`emulator_memory_sidecar.py`](emulator_memory_sidecar.py) | `EmulatorFleetGuard`, `FleetSafetyViolationError`, `BaseMemoryReader`, `Win32ProcessMemoryReader`, `FridaMemoryReader`, `MockMemoryReader`, `verify_vtable_pointer`, `verify_struct_field`, `extract_dynamic_encryption_keys`, `EmulatorSidecarShmServer`, `EmulatorSidecarShmClient` | Live/mock process memory introspection sidecar with strict fleet isolation, VTable/struct pointer verification, Shannon entropy key extraction, and SHM streaming. |
| [`colab_cloud_orchestrator.py`](colab_cloud_orchestrator.py) | `ColabCloudOrchestrator`, `CloudConfig`, `CloudRuntimeTier` | Google Colab Cloud TPU v5e / NVIDIA T4 pipeline orchestrator with ELF64 `.text` slicing (`extract_elf_executable_slice`), boundary-aware seeding, and HuggingFace Hub streaming. |
| [`neural_decompiler_pipeline.py`](neural_decompiler_pipeline.py) | `NeuralDecompilerPipeline`, `LLMDecompilerClient`, `SkeletonExtractor`, `DecompiledSkeleton`, `NeuralPrediction`, `VerifiedNeuralCommit` | Two-phase Skeleton-to-Skin neural decompiler normalizing raw C skeletons, querying OpenAI/vLLM/Ollama/Gemini HTTP endpoints, and gating commits via `EvidenceLedger`. |
| [`d_lift_verifier.py`](d_lift_verifier.py) | `DLiftRewardEngine`, `InMemClangSyntaxGate`, `Z3SemanticEquivalenceGate`, `ReadabilityGate`, `GRPORewardManager`, `DScoreResult` | D-LiFT + Z3 self-verifying neural decompiler backend with 3-gate hierarchical reward (`max(R_syn) < min(R_sem) < min(R_read)`), constant-drift counterexamples, and GRPO advantage normalization. |
| [`ghidra_gui_overlay_sync.py`](ghidra_gui_overlay_sync.py) | `OverlaySyncBridge`, `generate_ghidra_python_script`, `generate_ghidra_watcher_script`, `generate_diff_report`, `sync_to_script` | Synchronizes write-overlay mutations and `.ghidra-delta.jsonl` streams into one-shot or live `--watch` Ghidra GUI Python scripts with incremental delta calculation, `before`/`after` conflict checking, and atomic FlatProgramAPI transactions. |


## 2. Key Data Structures & Invariants
- **`EmulatorFleetGuard` Safety Invariant:**
  - Protected serials (`emulator-5564`, `127.0.0.1:5565`, `MEmu_0`, `127.0.0.1:21503`) are unconditionally blocked.
  - Unknown serials default to `authorized_for_experiments=False` and are denied.
  - `FridaMemoryReader` classifies process attachment as a mutation (`is_mutation=True`), permitting attachment **only** on allow-listed sandbox targets (`emulator-5580`, `127.0.0.1:21513`).
- **Honest Neural Fallback Invariant:** When no live LLM endpoint is configured or an HTTP error occurs, `LLMDecompilerClient` emits neutral heuristic names (`sub_<addr>`, `field_0x<offset>`) with `model_identifier="heuristic-fallback"`, `source="heuristic"`, and `confidence <= 0.3`.
- **Colab Upload Safety:** `ColabCloudOrchestrator` defaults to `upload=False`, honors `dry_run=True`, and restricts HuggingFace uploads strictly to `<workspace>/results` with explicit `allow_patterns`.
- **`OverlaySyncBridge` Live Watcher & Conflict Checking:** `OverlaySyncBridge` ingests optional `before` / `expected_before` values from `ghidra_overlay.json`, `.ghidra-delta.jsonl`, and `merge_fork` journals. `compute_incremental_delta` returns only added or modified entries compared to a prior snapshot, and `verify_conflicts` checks proposed changes against the live `currentProgram` state (or default `FUN_<addr>` / `sub_<addr>` prefixes), skipping any address where the analyst modified the symbol in CodeBrowser. Passing `--watch` (`--poll-ms <int>`) emits a background daemon script (`generate_ghidra_watcher_script`) that checks `(mtime_ns, size, sha256)` on each poll tick and applies accepted incremental diffs inside `currentProgram.startTransaction("SuperGhidra Live Overlay Sync")`.

## 3. Quick-Test Command
```powershell
python -m pytest tests/integrations -q
```
