# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.3] - 2026-10-29

### Fixed
- **ARM64 Jump Table Destination Register Preservation**: Fixed candidate scanner in `ARM64JumpTableProver.scan_candidates` to prevent the table load instruction itself (`LDRSW`, `LDRB`, `LDRH`, `LDR`) from being flagged as a compare register clobber when the compiler emits the table entry into the same register as the index operand (`Rt == cmp_reg`, e.g. `ldrsw x8, [x9, x8, lsl #2]`).

## [1.0.2] - 2026-10-29

### Fixed
- **ARM64 Jump Table Prover Register Clobber Detection**: Corrected instruction bitmask in `ARM64JumpTableProver.scan_candidates` to detect data-processing register instructions (`MOV x1, x2`, `ADD x1, x1, x2`), data-processing immediate instructions (`MOVZ x1, #7`), and load operations clobbering the compare register between `CMP` and the jump table index calculation.
- **Evidence Gatekeeper Natural Alignment**: Enforced that struct rewrites must verify natural alignment of old field offsets (`offset % width == 0`) before permitting cross-version offset migrations.

## [1.0.1] - 2026-10-29

### Fixed
- **Directory Locking Race Condition**: Replaced file deletion/recreation loop with kernel-enforced non-blocking advisory locking (`msvcrt.locking` on Windows, `fcntl.flock` on POSIX). Completely eliminates multi-process acquisition races on stale locks (0 violations in 20 stress runs).
- **Dyld Chained Fixups ADDEND64 Name Offset**: Corrected import symbol name offset unpacking from bits 32..63 (the upper 32 bits of the first 64-bit word) per `<mach-o/fixup-chains.h>`, resolving symbol name shifts (e.g. `_bar`).
- **Jump Table Prover Register Parity & Soundness**: Enforced register parity between `CMP` operand and table load index register (`cmp_reg == index_reg`), verified dispatch register dataflow (`table_target_reg == dispatch_reg`), and formulated non-vacuous Z3 bounds and default-escape proofs.
- **Evidence Gatekeeper Hardening**: Rejected `+inf`/`-inf` similarity scores (enforcing finite reals in `[0.0, 1.0]`), and added explicit cross-version memory access width preservation check (`new_access_width != access_width`).
- **Documentation Parity**: Aligned README.md with PyPI package availability for `superghidra-mcp` and documented standalone Mach-O dyld chained fixups support.

## [1.0.0] - 2026-10-28

### Added
- **Persistent Evidence Ledger & View Paging (Milestone 1 & 2)**: Added SQLite L2 `retained_evidence` table with 30-day LRU eviction quota (`enforce_cache_quota`), structured `EvidenceEnvelope`, and 9-facet pagination (`inspect_analysis_view`) returning summary-first views under 2,048 UTF-8 bytes for MCP agents.
- **Reconstruction Obligation Ledger & Gatekeeper**: Formal verification gatekeeper (`ReconstructionObligationLedger`) validating struct layout alignments, non-negative field offsets, vtable slot bounds, CFG cosine similarity gates, and cross-version struct rewrite memory access width preservation.
- **Inter-procedural High-P-Code Value Tracing (Milestone 3)**: Forward and backward dataflow tracing (`trace_native_values`) across High-P-Code def-use chains, tracking parameter origins, constants, and taint sets across up to 32 call frames.
- **Bounds-Proven ARM64 Jump Table Recovery**: Recovers multi-target switch dispatch tables from AArch64 `CMP`, `B.cond`, and `BR` indirect branches. Includes shift decoding (`lsl #12`), indirect branch verification, and formal Z3 bounds proof (`ARM64JumpTableProver`).
- **Crash-Resumable Whole-Binary Decompilation (Milestone 4)**: Added `decompile_all` with append-only JSONL progress journaling, PID & inode directory locking with automatic stale lock recovery, 64 KB chunked SHA-256 integrity verification, external import filtering, and a 5-consecutive-error circuit breaker.
- **Ghidra-Free Standalone Parsers (Milestone 5)**:
  - Mach-O Dyld Chained Fixups (`superghidra.formats.apple_dispatch`): Complete standalone chained fixup rebasing (including ARM64e PAC strip), Swift 5 type metadata, and 64-bit Objective-C class hierarchy extraction.
  - Unity IL2CPP Metadata (`superghidra.formats.il2cpp_metadata`): Standalone parser for `global-metadata.dat` across versions 24 through 39 with bounded parameter counts and native ELF/PE RVA correlation.
  - Rust & Go Metadata (`superghidra.formats.rust_go_metadata`): Standalone parser for Rust Cargo dependency trees (`.dep-v0`) and Go `pclntab` runtime function tables and build information.
- **REA Ecosystem Provider Bridge (Milestone 6)**: Added `ReaAsyncRouter` and `superghidra[rea]` extra providing in-process async integration with the Reverse Engineering Assistant (REA) ecosystem.

### Fixed
- **Stale Lock Recovery & Atomic Acquisition**: Resolved high-severity directory lock contention bug in `bulk_decompile.py` where dead process PIDs returned alive on POSIX platforms; implemented atomic `os.open` lockfile creation.
- **Public Export Parity**: Resolved star-import crashes (`from superghidra import *`) by mapping canonical `Il2CppMetadataReport` and `CrateAuditReport` with backward-compatibility aliases.
- **Dyld Chained Fixups Hardening**: Corrected 16-byte struct unpack and symbol name offset derivation in `DYLD_CHAINED_IMPORT_ADDEND64`; added upper admission limit (65,536 entries) to prevent DoS on truncated payloads.
- **Jump Table Immediate & Branch Decoding**: Decoded optional `lsl #12` shift amounts on ARM64 `CMP` immediate instructions and enforced presence of indirect branch (`BR`) instructions for jump table candidates.
- **Evidence Gatekeeper Tightening**: Enforced non-negative struct offsets, rejected NaN similarity scores, and added memory access width and natural alignment checks to cross-version rewrites.
- **Mypy Cleanliness**: Resolved 13 type errors in `ghidra_oracle.py`, achieving 0 mypy errors across all 76 source modules.

## [0.5.0] - 2026-10-27

### Added
- **Deprecation Policy**: Authored `DEPRECATION.md` codifying the SemVer stability contract, 3-tier API classification (Tier 1 Frozen Core, Tier 2 Experimental, Tier 3 Legacy Compatibility), deprecation notice timelines (`DeprecationWarning`), and versioned JSON schema evolution rules.
- **CI Quality Gates (Ruff & Mypy)**: Added dedicated `lint-and-typecheck` job to GitHub Actions running `ruff check src tests` and `mypy` against the public core API surface.
- **Push-Level DCO Verification**: Extended DCO sign-off validation in CI to verify commits on push as well as pull requests.
- **SHA-256 Binary Hash Validation**: Extended daemon server binary mismatch protection to compare file SHA-256 hashes against Ghidra project metadata.
- **ARM64 Bitfield & CSEL Verification (#26)**: Added ARM64 bitfield moves (`UBFM`, `SBFM`, `LSL`, `LSR`, `ASR`, `UXTB`, `UXTH`, `UBFX`, `UBFIZ`) and conditional selection (`CSEL`, `CSINC`, `CSINV`, `CSNEG`) lowering with Z3 SMT equivalence verification in `tests/lifters/test_arm64_bitfield_csel.py`.
- **Mach-O Objective-C Recovery Prototype (#28)**: Added experimental prototype for 64-bit Mach-O Objective-C runtime metadata parsing (`superghidra.formats.macho_objc_recovery`) with CLI subcommand `superghidra objc-recover` and unit tests (`tests/formats/test_macho_objc_recovery.py`). Designated as an early prototype (currently recovers 0 classes on real-world frameworks such as Sparkle); full production Objective-C class and Swift 5 nominal type recovery is planned for the 1.x roadmap.
- **Standalone Decompiler Memory Lowering & Register Declarations**: Added function prologue/epilogue decoding, memory displacement operand support, and automatic hardware register typing (`uint64_t <reg> = 0;`) in decompiled C output.
- **MFC Public Sample & CI Precision/Recall Suite**: Added synthetic redistributable binary `sample_mfc_x64.dll` and test suite `TestMFCPrecisionRecall` verifying precision=1.0 and recall=1.0 on MFC class hierarchies and 0 false positives on non-MFC binaries.
- **Synthetic Decompiler Idiom Benchmark (#27)**: Added 200-sample synthetic regression suite across 17 decompiler idiom templates in `benchmarks/data/held_out_200.jsonl` with evaluation runner `benchmarks/eval_held_out.py`. Evaluates type and macro normalization against synthetic Ghidra and Hex-Rays idioms, with fair IDA baseline (`defs.h` via `IDA_COMPAT_DEFS_H`) showing compilability rises from 24.50% to 93.50% (matching SuperGhidra's 93.50%). Documented in `docs/benchmarks/SYNTHETIC_IDIOM_BENCHMARK.md` and verified by `tests/benchmarks/test_held_out_eval.py`.
- **Release Verification & Tag Guard**: Enforced tag-to-version equality check in `release.yml` preventing accidental out-of-sync package publishing; verified 787 unit and integration tests passing across all domains.

### Fixed
- **Undefined Name Elimination**: Resolved 5 `F821` runtime name errors across `compilable_filter.py`, `cross_platform_headless_harness.py`, `parity_engine.py`, `arm_thumb_decode.py`, and `egraph_mlir_pipeline.py`.
- **Ruff Lint Modernization**: Cleared over 1,130 lint warnings and formatting issues across `src/` and `tests/`, enforcing automated `ruff` and `isort` rules.
- **Core Public Type Safety & Daemon Type-Checking**: Resolved 86 type errors in `ghidra_oracle.py` and brought public core modules (`__init__.py`, `__main__.py`, `binary_loader.py`, `msvc_class_recovery.py`, `synthetic_symbol_exporter.py`, `compilable_filter.py`, `validator.py`, `ghidra_oracle.py`, and lifters/acceleration/storage/compat suites - 74 modules total) to zero mypy errors.

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
