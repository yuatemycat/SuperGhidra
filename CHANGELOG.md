# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.4.0] - 2026-10-26

### Fixed
- **Canonical Package Imports & Zero Shims**: Replaced all internal and test imports with canonical package paths (`superghidra.<domain>.<module>`), removed the 33 root backward-compatibility shims, and purged `.` from `pytest.ini`'s `pythonpath`.
- **Public API Resolution**: Resolved 10 broken `AttributeError` exports in `superghidra.__all__` (`Relocation`, `RTTIClass`, `RTTIBaseClass`, `CRuntimeClassInfo`, `MemberVariable`, `MFCArchiveDecoder`, `MFCClassSchema`, `start_daemon`, `stop_daemon`, `filter_c_code`).
- **MFC Class Recovery Validation**: Added MFC linkage check and `CObject` hierarchy reachability validation in `msvc_class_recovery._scan_mfc`, pruning 18 false-positive candidate classes in pure C binaries like `libcrypto-3.dll`.
- **Cross-Platform Type Lattice CI**: Regenerated `tests/fixtures/binaries/sample_x64.dll` with memory displacement instructions, fixing type lattice test failures on non-Windows CI platforms.
- **Decompiler Daemon Routing (#25)**: Connected `superghidra decompile` to route through active Ghidra background daemon on default port 5073 with automatic multi-function response parsing and compilable C filter normalization (`filter_c_code`), while adding `--raw` bypass flag and local ALU fallback lifter.
- **Linux Socket Reset Handling**: Handled `ConnectionResetError` during oversized TCP payload test termination across POSIX environments.
- **CI Wheel Isolation & DCO Verification**: Added `test-wheel` isolated verification job installing into clean virtualenv outside repository, and added per-commit DCO sign-off check for PRs.

### Added
- **API Freeze & Supported Core**: Standardized `superghidra` public surface around a frozen, documented core:
  - Binary Loader (`load_binary`, `BinaryImage`, `Section`, `Symbol`, `Import`, `Relocation`)
  - MSVC RTTI & MFC Recovery (`recover_classes`, `ClassRecoveryReport`, `RTTIClass`, `MFCArchiveDecoder`, `CRuntimeClassInfo`)
  - Write Overlay (`WriteOverlay`)
  - Persistent Daemon Client (`query_oracle`, `is_daemon_online`, `start_daemon`, `stop_daemon`, `client_send_request`)
  - Compilable C Filter (`CompilableDecompilerFilter`, `filter_c_code`)
  - Synthetic Exporters (`DWARF5Exporter`, `PDBExporter`, `SymFileExporter`, `MapFileExporter`, `export_from_ledger`)
- **Experimental Domain**: Relocated non-core subsystems under `superghidra.experimental.*` (GPU acceleration, binary diffing, zero-JVM lifters, emulator sidecar, storage codecs, dynamic resource governor, and SHM IPC).
- **Packaging Compatibility Subpackage**: Added `superghidra.compat` preserving legacy module namespaces without polluting the top-level site-packages directory.
- **Daemon Security Hardening**:
  - Loopback Binding Invariant: Daemon strictly binds to loopback addresses (`127.0.0.1`, `::1`); refuses non-loopback addresses unless `--allow-remote` is explicitly specified.
  - Session Token Verification: Mutating and control commands (`stop`, `rename`, `comment`, `clear`, `register_struct`, `mode`, `hibernate`) require a verified session token passed via `--token`, `SUPERGHIDRA_SESSION_TOKEN`, or local `~/.superghidra/daemon.token` with 0600 permissions.
  - Bounded Request Payloads: Enforces a 2 MB maximum payload limit per request to prevent buffer exhaustion and memory denial-of-service.
- **Versioned JSON Schemas**: Added Draft 2020-12 schemas and local validator in `superghidra.schemas`:
  - `overlay.schema.v1.json` (WriteOverlay / `ghidra_overlay.json`)
  - `delta_log.schema.v1.json` (SemanticDeltaLog / `.ghidra-delta.jsonl`)
  - `evidence_ledger.schema.v1.json` (ReconstructionObligationLedger)
  - `struct_shift.schema.v1.json` (StructShiftMigrator)
- **Redistributable Sample Binaries**: Generated standalone, self-contained binary fixtures in `tests/fixtures/binaries/`:
  - `sample_arm64.so`: 64-bit ELF ARM64 shared library with real ADRP+LDR/ADD instruction sequences.
  - `sample_x64.dll`: PE32+ (x86_64) DLL with real x86_64 instructions, section headers, and export directories.
  Real-binary and integration tests now run deterministically across all environments in CI without relying on host system libraries.
- **Python 3.13 & macOS CI**: Added Python 3.13 and `macos-latest` runners to GitHub Actions test matrix.
- **Release Automation Gate**: Tagged releases only trigger and publish to PyPI after all matrix CI tests pass.
- **Typing & Linting**: Added PEP 561 `py.typed` marker file, strict `mypy` configuration, and `ruff` lint rules in `pyproject.toml`.

### Changed
- **Packaging Directory Layout**: Migrated from flat root layout to canonical `src/` layout (`src/superghidra/`).
- **Package Distribution Boundary**: Moved Jupyter notebooks (`colab_cloud_orchestrator.ipynb` to `notebooks/`), `.docx` specifications, and launch marketing kits out of the distributed package via `MANIFEST.in`.
- **Test Suite Hygiene**: Moved workstation-specific video rendering tests out of the standard pytest suite into `tests_manual/`.
- **Documentation Alignment**: Reconciled HumanEval benchmark figures across `README.md`, `PLAN.md`, `SECURITY.md`, and release notes to match authoritative summary data (1,300 evaluable functions, 22.62% full corpus pass rate, 25.26% held-out 30% test split).

## [0.3.1] - 2026-10-25
### Added
- Cross-platform headless analysis tuner and Google Colab hardware matrix (CPU, T4, TPU v5e).
- Function-disjoint 70% train and 30% held-out test evaluation splits for compilable C filter.
- Standalone synthetic DWARF 5 and experimental PDB symbol exporters.
- Automated struct shift migration tool with C++ header patch generation.

## [0.3.0] - 2026-10-22
### Added
- SMT P-code verification backend with Z3 symbolic state simulator.
- MSVC RTTI and MFC `CRuntimeClass` class layout recovery.
- LiquidWork MFC `CArchive` pure-Python and Rust stream deserializers.

## [0.2.0] - 2026-10-18
### Added
- WGPU compute shader and NumPy SIMD ARM64 `ADRP+ADD/LDR` reference pair scanner.
- High-throughput GPU parallel function prologue seeder.
- Zero-copy shared memory IPC ring buffer (`shm_decompiler_bridge.py`).
- Dynamic speed-vs-resource governor and multi-tier resource modes (`eco`, `balanced`, `turbo`, `auto`).

## [0.1.0] - 2026-10-10
### Added
- Initial implementation of transparent LZ4 and Zstandard 16 KB buffer compression codecs.
- Persistent lock-free Ghidra Oracle daemon with L2 SQLite WAL query cache.
- In-memory and JSON symbol write-overlay (`ghidra_overlay.json`).
- Append-only semantic delta event log (`.ghidra-delta.jsonl`) with cryptographic SHA-256 proofs.
