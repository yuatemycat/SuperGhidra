# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.5.0-dev] - Unreleased

### Added
- **Deprecation Policy**: Authored `DEPRECATION.md` codifying the SemVer stability contract, 3-tier API classification (Tier 1 Frozen Core, Tier 2 Experimental, Tier 3 Legacy Compatibility), deprecation notice timelines (`DeprecationWarning`), and versioned JSON schema evolution rules.
- **CI Quality Gates (Ruff & Mypy)**: Added dedicated `lint-and-typecheck` job to GitHub Actions running `ruff check src tests` and `mypy` against the public core API surface.
- **Push-Level DCO Verification**: Extended DCO sign-off validation in CI to verify commits on push as well as pull requests.
- **SHA-256 Binary Hash Validation**: Extended daemon server binary mismatch protection to compare file SHA-256 hashes against Ghidra project metadata.
- **ARM64 Bitfield & CSEL Verification (#26)**: Added ARM64 bitfield moves (`UBFM`, `SBFM`, `LSL`, `LSR`, `ASR`, `UXTB`, `UXTH`, `UBFX`, `UBFIZ`) and conditional selection (`CSEL`, `CSINC`, `CSINV`, `CSNEG`) lowering with Z3 SMT equivalence verification in `tests/lifters/test_arm64_bitfield_csel.py`.
- **Mach-O Objective-C Metadata Recovery (#28)**: Added pure-Python 64-bit Mach-O Objective-C runtime recovery engine (`superghidra.formats.macho_objc_recovery`) extracting classes, superclasses, instance methods, class methods, and ivar displacements, with CLI subcommand `superghidra objc-recover`, synthetic fixture `sample_objc_arm64.dylib`, and unit test suite `tests/formats/test_macho_objc_recovery.py`.
- **Standalone Decompiler Memory Lowering & Register Declarations**: Added function prologue/epilogue decoding, memory displacement operand support, and automatic hardware register typing (`uint64_t <reg> = 0;`) in decompiled C output.
- **MFC Public Sample & CI Precision/Recall Suite**: Added synthetic redistributable binary `sample_mfc_x64.dll` and test suite `TestMFCPrecisionRecall` verifying precision=1.0 and recall=1.0 on MFC class hierarchies and 0 false positives on non-MFC binaries.
- **Synthetic Decompiler Idiom Benchmark (#27)**: Added 200-sample synthetic regression suite across 17 decompiler idiom templates in `benchmarks/data/held_out_200.jsonl` with evaluation runner `benchmarks/eval_held_out.py`. Evaluates type and macro normalization against synthetic Ghidra and Hex-Rays idioms, with fair IDA baseline (`defs.h` via `IDA_COMPAT_DEFS_H`) showing compilability rises from 24.50% to 93.50% (matching SuperGhidra's 93.50%). Documented in `docs/benchmarks/SYNTHETIC_IDIOM_BENCHMARK.md` and verified by `tests/benchmarks/test_held_out_eval.py`.

### Fixed
- **Undefined Name Elimination**: Resolved 5 `F821` runtime name errors across `compilable_filter.py`, `cross_platform_headless_harness.py`, `parity_engine.py`, `arm_thumb_decode.py`, and `egraph_mlir_pipeline.py`.
- **Ruff Lint Modernization**: Cleared over 1,130 lint warnings and formatting issues across `src/` and `tests/`, enforcing automated `ruff` and `isort` rules.
- **Core Public Type Safety**: Brought all public core modules (`__init__.py`, `__main__.py`, `binary_loader.py`, `msvc_class_recovery.py`, `synthetic_symbol_exporter.py`, `compilable_filter.py`, `validator.py`) to zero mypy errors.

## [0.4.0] - 2026-10-26

### Fixed
- **Canonical Package Imports & Zero Shims**: Replaced all internal and test imports with canonical package paths (`superghidra.<domain>.<module>`), removed the 33 root backward-compatibility shims, and purged `.` from `pytest.ini`'s `pythonpath`.
- **Public API Resolution**: Resolved 10 broken `AttributeError` exports in `superghidra.__all__` (`Relocation`, `RTTIClass`, `RTTIBaseClass`, `CRuntimeClassInfo`, `MemberVariable`, `MFCArchiveDecoder`, `MFCClassSchema`, `start_daemon`, `stop_daemon`, `filter_c_code`).
- **MFC Class Recovery Validation**: Added MFC linkage check and `CObject` hierarchy reachability validation in `msvc_class_recovery._scan_mfc`, pruning 18 false-positive candidate classes in pure C binaries like `libcrypto-3.dll`.
- **Cross-Platform Type Lattice CI**: Regenerated `tests/fixtures/binaries/sample_x64.dll` with memory displacement instructions, fixing type lattice test failures on non-Windows CI platforms.
- **Decompiler Daemon Routing & Binary Validation (#25)**: Connected `superghidra decompile` with opt-in `--daemon` routing to active Ghidra background daemons (default port 5073) with automatic multi-function response parsing and compilable C filter normalization (`filter_c_code`). Added binary validation to the daemon server refusing cross-binary decompilation (HTTP 409) if the requested file mismatches the loaded project.
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
- **Typing & Linting**: Added PEP 561 `py.typed` marker file for public core types and `ruff` lint rules in `pyproject.toml`.

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
