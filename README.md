# SuperGhidra

[![License: Apache-2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
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
| `lifters` | ARM64 → P-code lifter (integer subset), x86 and ARM/Thumb decoders, and a Z3 checker that proves two snippets equivalent or answers `UNKNOWN`. |
| `diff` | Matches functions across versions with CFG feature vectors, then finds struct fields whose offsets moved and rewrites the accesses. |
| `acceleration` | WGPU shaders that scan ARM64 for `ADRP+ADD/LDR` pairs and function prologues, with a SIMD CPU fallback. |
| `storage` | LZ4 / Zstd codec for Ghidra's 16 KB buffer pages, plus a standalone Java `BufferFile` codec. |
| `integrations` | APK ↔ JNI cross-referencer, Android emulator memory reader with a device allow-list, and an LLM naming pipeline. |

Each package has its own README under [`superghidra/`](superghidra/).

## Results so far

- **MFC class recovery:** 52 of 52 serializable classes in `mfc140u.dll` are linked to their `Serialize()`. The same holds for 118 of 118 in SOLIDWORKS' `swdocumentmgr.dll`.
- **`Serialize()` tracing:** 115 classes in `swdocumentmgr.dll` are traced in about 2 seconds. 83 of them have matching load and store paths.
- **CArchive decoding:** the layouts recovered from that DLL alone decode the model history in a real SOLIDWORKS part file: feature names, IDs, timestamps and configurations. The file uses a newer format than the DLL, so the end of the stream is still undecoded.
- **x86 decoder:** instruction lengths match Capstone on about 6.7M instructions of Windows code, including AVX-512.
- **Storage:** pages shrink by 79% with LZ4 and by 86% with Zstd. These figures come from synthetic Ghidra-like pages, not real projects.
- **Throughput:** function seeding runs at 12M instructions/s on WGPU and 50M/s with SIMD. A shared-memory round trip takes about 5 µs.

All numbers come from one Windows development machine. The full reports are in [`docs/benchmarks/`](docs/benchmarks/).

## Quick start

```bash
git clone https://github.com/yuatemycat/SuperGhidra
cd SuperGhidra
pip install -e ".[all]"      # or pick extras: smt, gpu, storage, ghidra, frida
python -m pytest -q
```

**Unified CLI:**

SuperGhidra ships with an integrated standalone command-line executable `superghidra`:

```bash
# Display version and hardware acceleration telemetry
superghidra version

# Staged P-code decompiler (MBA simplification, opaque branch pruning, goto-free C)
superghidra decompile target.dll --rva 0x140001000 --arch x86_64 -o decompiled.c

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

Most modules are also exposed as MCP tools through a [pyghidra-mcp](https://github.com/clearbluejar/pyghidra-mcp) fork, including `recover_cpp_classes`, `trace_serialize`, `decode_carchive`, `diff_binaries`, `verify_smt_equivalence` and `gpu_adrp_scan`. This lets an AI agent drive them directly.

## Known limitations

- The Java codec doesn't compress Ghidra projects transparently. Ghidra has no hook for replacing its buffer file, so you have to call the codec explicitly.
- PDB export is experimental, and MSVC/LLVM tools may not load the output. Use DWARF export instead.
- The SMT checker is sound but incomplete. Floats, calls, unhandled ops and long loops return `UNKNOWN`.
- The ARM64 lifter covers integer instructions only. Atomics lift as `UNIMPLEMENTED`.
- The LLM naming stage needs a real endpoint. Without one, it falls back to neutral names such as `sub_<addr>`, labelled `heuristic-fallback`.

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

[Apache 2.0](LICENSE) © 2026 yuatemycat and contributors.
