# Contributing to SuperGhidra

Thank you for your interest in contributing to **SuperGhidra**! SuperGhidra is an open-source, high-performance Ghidra architecture and GPU acceleration suite designed to overcome JVM decompiler bottlenecks, lock contention, and storage bloat.

We welcome contributions from reverse engineers, compiler enthusiasts, and GPU systems developers.

---

## 🏛️ Code Architecture & Safety Invariants

Before submitting code, please review [`AGENTS.md`](AGENTS.md) and [`ARCHITECTURE.md`](ARCHITECTURE.md). All contributions must strictly preserve our core safety invariants:

1. **Storage Layer Safety:**
   - In-engine BufferFile frame writes must remain append-only.
   - Sync order is inviolable: **directory first + fsync**, then **header pointer + fsync**.
   - Working buffers use LZ4 (~4 GB/s); snapshot backups use Zstandard.
2. **Oracle Lock Safety:**
   - `ghidra_oracle.py` must open target programs **read-only** (`readOnly=True`).
   - Mutations (renames, comments, bookmarks) belong in the JSON write-overlay, never directly in the `.rep` database files.
   - Never automatically delete active `.lock` files.
3. **EvidenceLedger Invariant Proofs:**
   - No automated or neural symbol commit may bypass the `ReconstructionObligationLedger` gate (`VTableSlotVerifier`, `FieldDisplacementVerifier`, `AllocationSizeVerifier`).
4. **Android Emulator Fleet Guard:**
   - Introspection sidecars must protect real hardware and primary emulator instances (`emulator-5564`, `127.0.0.1:21503`). Mutations are restricted to authorized sandboxes (`emulator-5580`, `127.0.0.1:21513`).
5. **Formal Verification Soundness:**
   - Unhandled instructions, floating-point operations, or unroll overflows in the Z3 SMT lifter must return `UNKNOWN` (`is_equivalent=False`), never false `UNSAT`.

---

## 🛠️ Development Setup

### 1. Requirements
- **Python:** 3.10 or newer (MSVC 64-bit on Windows, GCC/Clang on Linux/macOS)
- **Java:** OpenJDK 21 LTS
- **Ghidra:** Ghidra 11.x or 12.x-DEV
- **Optional Accelerators:**
  - `z3-solver` (SMT formal equivalence verification)
  - `wgpu` (GPU compute shaders via Vulkan, DirectX 12, Metal)
  - `lz4`, `zstandard` (High-speed compression codecs)
  - `frida` (Runtime memory introspection)

### 2. Environment Installation
```bash
# Clone the repository
git clone https://github.com/yuatemycat/SuperGhidra.git
cd SuperGhidra

# Install editable package with all development dependencies
pip install -e .[all]
```

### 3. Running the Test Suite
All PRs must maintain 100% test pass rate across the domain suites:
```bash
# Run entire test suite
pytest tests -v

# Run targeted subsystem suite
pytest tests/core -v
pytest tests/acceleration -v
pytest tests/lifters -v
```

---

## 📋 Pull Request Workflow

1. **Fork & Branch:** Create a feature branch off `master` with a descriptive name (e.g. `feat/arm64-vector-lift` or `fix/lz4-slot-dir`).
2. **Atomic Commits:** Follow conventional commit formatting:
   - `feat(...)`: New feature or capability
   - `fix(...)`: Bug fix or invariant safeguard
   - `perf(...)`: Benchmark-proven speed or memory optimization
   - `docs(...)`: Documentation or architectural specifications
   - `test(...)`: Unit, regression, or integration test cases
3. **No Working Tree Artifacts:** Do not commit temporary test databases, `__pycache__`, or local `.lock` files. Test runs must write only to temporary directories or `SUPERGHIDRA_DATA_DIR`.
4. **SMT Equivalence Verification:** If adding or changing P-Code lifters or instruction decoders, include Z3 equivalence proof tests.
5. **Submit PR:** Open a Pull Request against `master`. Complete the PR template checklist.

---

## 🐞 Reporting Issues & Requesting Features

- Use the provided [Bug Report](.github/ISSUE_TEMPLATE/bug_report.yml) or [Feature Request](.github/ISSUE_TEMPLATE/feature_request.yml) templates.
- For crash or decompiler hang reports, include:
  - Architecture (`x86_64`, `arm64`, `arm32`, `thumb2`)
  - Function body size (bytes) & basic block count
  - Resource governor mode (`eco`, `balanced`, `turbo`, `auto`)
  - Minimal reproducing binary slice or disassembly dump

---

## ⚖️ License & Copyright

SuperGhidra is open source under the **Apache License 2.0**. By contributing to this project, you agree that your contributions will be licensed under the Apache License 2.0.
