## Description

Briefly describe the change, feature, or bug fix introduced by this pull request.

---

## Type of Change

- [ ] New feature (non-breaking change which adds capability)
- [ ] Bug fix (non-breaking change which fixes an issue)
- [ ] Performance optimization (reduces latency or memory overhead)
- [ ] Invariant / Security reinforcement
- [ ] Documentation & Specifications
- [ ] Tests / Benchmarks

---

## Subsystem Impacted

- [ ] `superghidra/core` (Daemon, Oracle, Resource Governor, SHM Bridge)
- [ ] `superghidra/storage` (BufferFile Codec, Slot Directory, Packager)
- [ ] `superghidra/acceleration` (WGPU Scanners, Prologue Seeder)
- [ ] `superghidra/diff` (Binary Diffing, Struct Migrator, Evidence Ledger)
- [ ] `superghidra/lifters` (P-Code Lifter, Z3 SMT Equivalence Verifier, Disassemblers)
- [ ] `superghidra/formats` (Synthetic DWARF5/PDB, MFC Archive, Binary Loader)
- [ ] `superghidra/integrations` (APK JNI, Emulator Sidecar, Colab Cloud, Neural Pipeline)

---

## Architectural Checklist

- [ ] My code adheres to the project coding conventions and safety invariants in [`AGENTS.md`](AGENTS.md).
- [ ] I have executed the test suite (`pytest tests/`) and all domain test suites pass cleanly.
- [ ] If modifying instruction lifting or AST translation, I have included Z3 SMT equivalence proofs.
- [ ] No temporary files, `.lock` files, or test outputs were created in the source tree.
- [ ] I have updated relevant documentation / docstrings.
- [ ] I agree to the [SuperGhidra Contributor License Agreement](CLA.md) (authorizing distribution under GNU AGPL-3.0 and the commercial license).
- [ ] My commits include a Developer Certificate of Origin (DCO) sign-off (`git commit -s`).
