## Summary

SuperGhidra 0.3.1 delivers empirical benchmark methodology improvements, interactive GUI overlay continuous synchronization, theme-aware architectural documentation, and launch kit tooling.

---

## What's New in v0.3.1

### 1. Empirical Benchmark Generalization (70/30 Split & IDA defs.h Baselines)
- Added function-disjoint 70% train (912 evaluable functions) and 30% held-out test (388 evaluable functions) evaluation splits to the HumanEval-Decompile benchmark (`CompilableDecompilerFilter`) across the 1,300 evaluable corpus.
- Evaluated on Windows AMD64 under `gcc.EXE 16.2.0 (MinGW-W64)`: confirmed filter achieves 22.62% (294/1,300) full-corpus pass rate (vs raw Ghidra 8.23% / 107/1,300) and generalizes out-of-sample on the held-out 30% test split with 25.26% (98/388 vs raw Ghidra 11.08% / 43/388, +55 gains).
- Symmetrically normalized IDA Pro baselines with Hex-Rays `defs.h` compatibility macros (`__int64`, `LODWORD`, `HIDWORD`, `BYTEn`), yielding 19.00% (247/1,300) filtered vs 18.69% (243/1,300) raw IDA (11.86% / 46/388 on the held-out test split).

### 2. Interactive GUI Overlay Continuous Watcher (`superghidra overlay-sync`)
- Enhanced `superghidra overlay-sync` with `--watch` and `--poll-ms` flags.
- Reverse engineers working in Ghidra CodeBrowser can now run a background watcher script that automatically polls `ghidra_overlay.json` and `.ghidra-delta.jsonl` every 1,000 ms, committing external agent mutations into the active GUI session via atomic transactions.

### 3. Theme-Aware Vector Architecture Diagrams
- Replaced ASCII diagrams in `README.md` with responsive vector graphics (`docs/assets/architecture-dark.svg` and `docs/assets/architecture-light.svg`).
- Graph visualizes the 3-tier boundary: Tier 1 Read Path (`readOnly=True` daemon RPC), Tier 2 Z3 Obligation Gate (sound SMT verification on lifted IR), and Tier 3 Write Path (non-destructive JSON write overlays and GUI sync replay).

### 4. CLI Launch Kit & Walkthrough Demonstrations
- Added `superghidra launch-kit` CLI command (`11be364`) to inspect and output ready-to-run configurations and submission kits.
- Repaired `rtti-recover` CLI and added a walkthrough demonstration with real `Serialize()` layout output.

---

## Assets Included

- `superghidra-0.3.1-py3-none-any.whl`: Pre-built pure-Python distribution wheel.
- `superghidra-0.3.1.tar.gz`: Source distribution archive.
- `SuperGhidraCodec-1.0.0.zip`: Ghidra extension skeleton containing the Java BufferFile LZ4/Zstd codec.
