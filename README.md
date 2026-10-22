# SuperGhidra

[![License: AGPL-3.0-or-later](https://img.shields.io/badge/License-AGPL_3.0--or--later-blue.svg)](LICENSE)
[![PyPI version](https://img.shields.io/pypi/v/superghidra.svg)](https://pypi.org/project/superghidra/)
[![Python 3.10+](https://img.shields.io/badge/Python-3.10+-3776AB.svg)](https://www.python.org/)
[![CI](https://github.com/yuatemycat/SuperGhidra/actions/workflows/ci.yml/badge.svg)](https://github.com/yuatemycat/SuperGhidra/actions/workflows/ci.yml)

Python tools that make Ghidra faster to script against, plus a few analyses it doesn't do out of the box: MFC/C++ class recovery, `Serialize()` layout tracing, cross-version function matching, and a Z3 equivalence checker for P-code.

## Why

Ghidra's analysis is excellent, but driving it from scripts is slow. Each headless run pays 5–15 seconds of JVM startup. A project lock stops a second process from reading. Bulk jobs such as sweeping a 20 MB ARM64 `.text` section or matching 45,000 functions between two builds run on a single CPU thread.

SuperGhidra keeps one read-only Ghidra project loaded in a background daemon and caches its answers. Bulk work moves into plain Python, NumPy or GPU compute shaders. Much of the format and class-recovery work doesn't need Ghidra at all.

## What's inside

| Package | What it does |
| :--- | :--- |
| `core` | Daemon on `127.0.0.1:5073` with a SQLite cache. Renames and comments go to a JSON overlay, never into the `.rep`. Also includes a resource governor (`eco` / `balanced` / `turbo` / `auto`) and shared-memory IPC. |
| `formats` | ELF / PE / Mach-O loader, MSVC RTTI and MFC `CRuntimeClass` recovery, `Serialize()` tracing, a CArchive decoder, and DWARF 5 / Breakpad / map export. None of these need Ghidra. |
| `lifters` | ARM64 → P-code lifter (integer, exclusive memory, SIMD vector arithmetic and bitwise, atomic CAS/SWP/LDADD), x86 and ARM/Thumb decoders, and a Z3 checker that proves two snippets equivalent or answers `UNKNOWN`. |
| `diff` | Matches functions across versions with CFG feature vectors, then finds struct fields whose offsets moved and rewrites the accesses. |
| `acceleration` | WGPU compute shaders (DirectX 12 / Vulkan / Metal) that scan ARM64 for `ADRP+ADD/LDR` pairs and function prologues, with graceful CPU/SIMD fallback. |
| `storage` | LZ4 / Zstd codec for Ghidra's 16 KB buffer pages, plus a standalone Java `BufferFile` codec. |
| `integrations` | APK ↔ JNI cross-referencer, Android emulator memory reader with a device allow-list, and an LLM naming pipeline. |

Each package has its own README under [`superghidra/`](superghidra/).

## Results so far

All benchmarks are measured on physical hardware (Intel Core i9-12950HX, 64 GB DDR5, NVIDIA RTX A5500 Laptop GPU) and across the multi-platform CI matrix. Full empirical data and logs are in [`docs/benchmarks/`](docs/benchmarks/).

### Hardware & Throughput Matrix

| Workload / Benchmark | Input Size / Target | Engine / Backend | Measured Time | Measured Throughput / Result | Status |
| :--- | :--- | :--- | :---: | :---: | :--- |
| **ARM64 ADRP + ADD/LDR Sweep** | 4.0 MB ARM64 block (1,048,576 insns) | NumPy SIMD | **7.28 ms** | **143.95 M insn/s** | 1,049 pairs identified |
| **ARM64 Function Seeder** | 4.0 MB ARM64 block (1,048,576 insns) | NumPy SIMD | **8.31 ms** | **126.19 M insn/s** | 1,049 prologues identified |
| **Large-scale GPU ADRP Sweep** | 20.0 MB ARM64 block (5,242,880 insns) | WGPU DirectX 12 | **41.20 ms** | **127.25 M insn/s** | Bit-exact match with CPU |
| **Buffer File Compression (LZ4)** | 1,000 synthetic 16 KB pages (16.0 MB) | LZ4 `block` | **36.12 ms** | **442.9 MB/s** (4.84x ratio) | 79.32% disk savings |
| **Buffer File Compression (Zstd)** | 1,000 synthetic 16 KB pages (16.0 MB) | Zstd Level 3 | **77.48 ms** | **206.5 MB/s** (7.39x ratio) | 86.47% disk savings |
| **Decompilation Query Cache** | Live Ghidra Daemon RPC | SQLite L2 Cache | **< 0.01 ms** | **> 100,000 req/s** | In-memory overlay match |
| **SHM Channel IPC Roundtrip** | 64 KB memory-mapped ring buffer | Windows SHM IPC | **5.12 µs** | **195,300 msg/s** | Zero-copy shared memory |

### Out-of-Distribution Systems Matrix (Uncontaminated Decompilation Verification)

Addresses the dataset contamination problem in neural decompiler benchmarks (such as HumanEval-Decompile) where models recall memorized pretraining code. Evaluated under MSVC 14.44 `cl.exe` / MinGW GCC 16.2.0 via differential co-execution:

| Workload ID | Systems Role & Target Kernel | Raw Ghidra Semantics | LLM Raw Syntax ($R_{syn}$) | LLM Semantic Pass ($R_{sem}$) | Gate 2 Hallucination Catch | SuperGhidra Verified Pass |
| :--- | :--- | :---: | :---: | :---: | :---: | :---: |
| `SHA256_ROUND` | Crypto compression quarter-step (Ch, Maj, 32-bit rotations) | PASS | 100% | **0% (FAIL)** | **REJECTED (100%)** | **PASS (100%)** |
| `CHACHA20_QR` | ChaCha20 quarter-round permutation (rotation invariants) | PASS | 100% | **0% (FAIL)** | **REJECTED (100%)** | **PASS (100%)** |
| `RFC1071_CHECKSUM` | 16-bit 1's complement folded Internet checksum | PASS | 100% | **0% (FAIL)** | **REJECTED (100%)** | **PASS (100%)** |
| `LEB128_DECODE` | DWARF/WASM unsigned LEB128 variable-length integer parsing | PASS | 100% | **0% (FAIL)** | **REJECTED (100%)** | **PASS (100%)** |
| `SPSC_RING_BUFFER` | Lock-free SPSC ring buffer (64-bit pointer alignment padding) | PASS | 100% | **0% (FAIL)** | **REJECTED (100%)** | **PASS (100%)** |
| `SLAB_ALLOC_HEADER` | Slab chunk header bitflag extraction (`size & ~0x7`) | PASS | 100% | **0% (FAIL)** | **REJECTED (100%)** | **PASS (100%)** |

- **Finding:** Raw LLM predictions achieved a 100% compilation rate but a 0.0% semantic pass rate due to subtle binary logic hallucinations. SuperGhidra's D-LiFT / CoExec gate rejected 100% of hallucinated candidates prior to commit.

### Reference Puzzle Baseline: HumanEval-Decompile (1,296 Evaluated Functions)

<!-- humaneval:begin -->
| Metric | IDA raw | IDA + filter | Ghidra raw | Ghidra + filter |
| :--- | :---: | :---: | :---: | :---: |
| **Pass Rate** | 243/1300 (18.69%) | 247/1300 (19.0%) | 107/1300 (8.23%) | 294/1300 (22.62%) |
| **Filter Gains** | — | +4 | — | +187 |
| **Filter Regressions** | — | -0 | — | -0 |

- **Dataset:** `LLM4Binary/decompile-eval@b9271fae3c556e46948559f4176ffa6f8b4f9491` (1300 evaluable functions from binaries compiled at `O0`–`O3`).
- **Compiler:** Evaluated by recompiling recovered C/C++ with `gcc.EXE (MinGW-W64 x86_64-ucrt-posix-seh, built by Brecht Sanders, r3) 16.2.0` under `gcc -O0 -lm`.
<!-- humaneval:end -->

### Dual-OS Test Matrix (GitHub Actions CI)

Full 6-job matrix evaluated with `pytest tests -v -rs -rx --strict-markers` (all integration tests run; skipped reasons reported):

| Operating System | Python 3.10 | Python 3.11 | Python 3.12 | Pytest Test Count | Pass Rate (passed / active) |
| :--- | :---: | :---: | :---: | :---: | :---: |
| **Ubuntu Linux** (`ubuntu-latest`) | 32s | 26s | 25s | 636 collected (594 passed, 42 skipped) | 100% |
| **Windows Server** (`windows-latest`) | 1m 25s | 1m 06s | 53s | 636 collected (604 passed, 32 skipped) | 100% |

Detailed logs and measurement methodology are documented in [`docs/benchmarks/EMPIRICAL_TEST_BENCHMARK_MATRIX.md`](docs/benchmarks/EMPIRICAL_TEST_BENCHMARK_MATRIX.md).

## Installation

**From PyPI:**

```bash
pip install superghidra
```

Optional acceleration and integration extras:

```bash
pip install "superghidra[all]"       # all optional backends
pip install "superghidra[smt]"       # Z3 P-code equivalence checker
pip install "superghidra[gpu]"       # WGPU compute shaders (ADRP/prologue sweeps)
pip install "superghidra[storage]"   # LZ4 & Zstandard 16 KB page compression
pip install "superghidra[ghidra]"    # PyGhidra bridge & JVM headless bindings
pip install "superghidra[frida]"     # Live emulator runtime inspection
```

**From source (development):**

```bash
git clone https://github.com/yuatemycat/SuperGhidra
cd SuperGhidra
pip install -e ".[all]"
python -m pytest -q
```

**Unified CLI:**

SuperGhidra ships with an integrated standalone command-line executable `superghidra`:

```bash
# Display version and hardware acceleration telemetry
superghidra version

# Staged P-code decompiler (handles register-to-register mov/add/xor and ret on x86-64; any other instruction exits non-zero)
superghidra decompile target.dll --va 0x140001000 --arch x86_64 -o decompiled.c

# Import IDA Pro .til type library and dump schema catalog
superghidra til-import mssdk64.til -o catalog.json

# Match binary bytes against IDA FLIRT signature database
superghidra flirt-match vc32rtf.sig target.exe --rva 0x1000

# Recover MSVC / MFC C++ class hierarchies, RTTI structures, and virtual call tables
superghidra rtti-recover app.dll -o classes.json

# Filter raw decompiler output into clean, compilable C
superghidra filter raw_decompile.c -o clean.c
```

**Inspect a Windows binary (no Ghidra needed):**

```bash
python -m superghidra.formats.binary_loader app.dll          # sections, imports, exports
python -m superghidra.formats.msvc_class_recovery app.dll    # RTTI + MFC classes
python -m superghidra.formats.serialize_trace app.dll CMyDoc # Serialize() field layout
```

**From Python:**

```python
from superghidra.formats.binary_loader import load_binary
from superghidra.formats.msvc_class_recovery import recover_classes
import superghidra as sg

img = load_binary("app.dll")
print(img.format, img.arch, len(img.sections))

report = recover_classes("app.dll")
print(len(report.mfc_classes), "MFC classes")

# Lift one ARM64 instruction and check it against itself with Z3
ops = sg.ARM64PcodeLifter().lift_instruction(0x1000, 0x91008041)  # add x1, x2, #0x20
print(sg.SMTPcodeVerifier().verify_equivalence(ops, ops).equivalent)
```

**Query a Ghidra project through the daemon** (needs JDK 21, Ghidra 11+ and `pyghidra`):

```bash
export GHIDRA_INSTALL_DIR=/path/to/ghidra
python ghidra_oracle.py --project-dir ~/re/proj --project-name game --program-name libgame.so status
python ghidra_oracle.py decompile 0x00CF2D84   # first call boots Ghidra, later calls hit the cache
python ghidra_oracle.py rename 0x00CF2D84 World_tick
python ghidra_oracle.py mode eco               # throttle CPU use
python ghidra_oracle.py stop
```

Run `python ghidra_oracle.py --help` to list every command.

**Configuration** is read from environment variables, and nothing is tied to a particular machine:

| Variable | Used for |
| :--- | :--- |
| `GHIDRA_INSTALL_DIR`, `JAVA_HOME` | Ghidra and JDK locations (daemon, headless runs, Java codec build) |
| `SUPERGHIDRA_PROJECTS` | Default projects for the daemon: `dir,name[,program]` entries joined by `;` |
| `SUPERGHIDRA_MSVC_ROOT` | Portable MSVC folder, used when gcc/clang aren't on `PATH` |
| `SUPERGHIDRA_TEST_ARM64_ELF`, `SUPERGHIDRA_TEST_SWDM`, `SUPERGHIDRA_TEST_SW_ROOT` | Optional real binaries / a SOLIDWORKS install for the integration tests. Those tests skip when unset. |

## MCP

SuperGhidra tools are exposed as Model Context Protocol (MCP) tools through [SuperghidraMCP](https://github.com/yuatemycat/SuperghidraMCP) (an Apache-2.0 MCP server built on [pyghidra-mcp](https://github.com/clearbluejar/pyghidra-mcp)). It provides 38 tools to Claude, Antigravity, and Codex, including `recover_cpp_classes`, `trace_serialize`, `decode_carchive`, `diff_binaries`, `verify_smt_equivalence`, and `gpu_adrp_scan`. This lets an AI agent drive analysis workflows directly without manually orchestrating headless Ghidra scripts.

## Known limitations

- The Java codec doesn't compress Ghidra projects transparently. Ghidra hardcodes `LocalManagedBufferFile` with no storage hook, so the SuperGhidra codec operates on external `.sgdb` files or requires patching Ghidra's core jar.
- PDB export implements CodeView 7.0 MSF structures with a Global Symbol Index (GSI) 4096-bucket hash table; MSVC and LLVM toolchains can read symbols, while complex type streams remain under active expansion.
- The SMT checker is sound but incomplete. Floats, calls, unhandled ops and long loops return `UNKNOWN` by design to prevent false equivalence.
- The ARM64 lifter covers core integer, exclusive memory, SIMD vector math/bitwise, and ARMv8.1-A atomics. Advanced cryptographic and complex floating-point vector ops remain unimplemented.
- The LLM naming stage needs a real endpoint. Without one, it falls back to neutral names such as `sub_<addr>`, labelled `heuristic-fallback`.
- Detailed audit analysis, cross-backend telemetry, and resolution plans are documented in [`docs/specs/AUDIT_RECONCILIATION_REPORT.md`](docs/specs/AUDIT_RECONCILIATION_REPORT.md).

More detail is in [PLAN.md](PLAN.md).

## Repository layout

```
superghidra/   the package, split into the seven areas above
tests/         pytest suites, one folder per area
docs/          benchmark reports and design notes
ghidra_extension_skeleton/   Java BufferFile codec
*.py           thin shims so `import binary_loader` etc. keep working for older callers
```

If you're an AI agent, start with [AGENTS.md](AGENTS.md).

## Contributing

Issues and PRs are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md) for the test workflow and the safety rules: read-only projects, verified symbol commits and the emulator allow-list. Report security issues as described in [SECURITY.md](SECURITY.md).

## License

SuperGhidra is licensed under the [GNU AGPL-3.0-or-later](LICENSE). If you modify it and let other people use it over a network, for example as a hosted MCP server, you have to offer them your modified source.

If the AGPL doesn't fit your use, a commercial license is available. See [COMMERCIAL-LICENSE.md](COMMERCIAL-LICENSE.md).

Releases up to and including 0.2.0, and commits before the license change, were published under Apache-2.0. Those versions stay under Apache-2.0 and the text is kept in [`LICENSES/Apache-2.0.txt`](LICENSES/Apache-2.0.txt).

© 2026 yuatemycat and contributors.
