# SuperGhidra: Seeded "Good First Issue" Templates

These 5 issues provide clear entry points for open-source contributors, tagged with `good first issue` and `help wanted`.

---

## Issue 1: `feat(cli): route 'superghidra decompile' to live daemon when running`

* **Labels:** `enhancement`, `good first issue`
* **Title:** `feat(cli): route 'superghidra decompile' to live daemon when running`
* **Issue Body:**
```markdown
### Summary
Currently, `superghidra decompile <binary> --rva <addr>` routes directly to the experimental standalone P-code lifter in `superghidra.core.live_binary_tools`. This lifter only supports a small integer-arithmetic subset of x86-64 instructions and exits non-zero on real-world functions containing branches, floats, or calls.

When the SuperGhidra oracle daemon (`127.0.0.1:5073`) is already running with an open project, `superghidra decompile` should automatically probe the daemon socket, fetch the full Ghidra decompiler output, and run it through `compilable_filter.py`.

### Proposed Behavior
1. In `cmd_decompile()` in `superghidra/__main__.py`:
   - Attempt a quick TCP probe to `127.0.0.1:5073` (timeout 50ms).
   - If daemon is responding, issue a `decompile` query for the function at RVA/VA.
   - Run the result through `CompilableDecompilerFilter.filter()`.
   - If daemon is not running, fall back to the existing staged standalone lifter (with a note that the daemon is offline).
2. Add a `--no-daemon` flag to force the offline lifter.

### Acceptance Criteria
- [ ] Probes `127.0.0.1:5073` cleanly without crashing if connection is refused.
- [ ] When daemon is up, prints compilable C decompiler output.
- [ ] When daemon is down, gracefully falls back to standalone lifter.
- [ ] Unit test added in `tests/core/test_cli_decompile.py`.
```

---

## Issue 2: `feat(lifters): add ARM64 UBFM/SBFM and CSEL instructions to P-code lifter`

* **Labels:** `lifters`, `good first issue`, `help wanted`
* **Title:** `feat(lifters): add ARM64 UBFM/SBFM and CSEL instructions to P-code lifter`
* **Issue Body:**
```markdown
### Summary
The zero-JVM ARM64 lifter in `superghidra/lifters/pcode_lifter_bridge.py` covers basic arithmetic, memory loads/stores, and register moves, but lacks bitfield moves (`UBFM`, `SBFM` / aliases `LSR`, `LSL`, `ASR`, `UBFIZ`, `UXTW`) and conditional selection (`CSEL`, `CSINC`, `CSET`).

### Proposed Implementation
1. Add instruction decoders for:
   - `UBFM` (Unsigned Bitfield Move) -> P-code `INT_RIGHT`, `INT_LEFT`, `INT_AND`.
   - `SBFM` (Signed Bitfield Move) -> P-code `INT_SRIGHT`, `INT_SEXT`.
   - `CSEL` (Conditional Select) -> P-code conditional assignment (or multiplexer formula).
2. Wire up the corresponding semantics in `smt_pcode_verifier.py` so symbolic execution verifies them against equivalent C ternary expressions (`cond ? a : b`).

### Acceptance Criteria
- [ ] Correctly lifts `UBFM`/`SBFM` and `CSEL` machine code bytes into `PcodeOp` sequences.
- [ ] Z3 equivalence test in `tests/lifters/test_arm64_bitfield_csel.py` passes.
- [ ] No regression on existing lifter test suite (`pytest tests/lifters`).
```

---

## Issue 3: `feat(benchmarks): add held-out C/C++ evaluation split & IDA cleanup baseline`

* **Labels:** `benchmarks`, `help wanted`
* **Title:** `feat(benchmarks): add held-out C/C++ evaluation split & IDA cleanup baseline`
* **Issue Body:**
```markdown
### Summary
SuperGhidra's compilability benchmarks evaluate `compilable_filter.py` on the 1,300-function GCC HumanEval-Decompile corpus (achieving 22.62% full corpus pass rate, and 25.26% on the function-disjoint held-out 30% test split, vs 8.23% stock Ghidra and 18.69% raw IDA Pro / 19.00% IDA + defs.h).

To extend benchmark generalizability beyond synthetic puzzles, we want:
1. A held-out evaluation dataset of real-world compiled functions from open-source libraries (e.g. SQLite, zlib, or Coreutils).
2. Extended comparative evaluation against additional architectures and compiler optimization levels.

### Acceptance Criteria
- [ ] Script in `benchmarks/eval_held_out.py` evaluating compilation pass rates on the held-out split.
- [ ] Documented methodology in `docs/benchmarks/SYNTHETIC_IDIOM_BENCHMARK.md`.
- [ ] Both raw and filtered pass rates recorded for both Ghidra and IDA.
```

---

## Issue 4: `feat(formats): add Mach-O Objective-C class & selector metadata recovery`

* **Labels:** `formats`, `good first issue`, `help wanted`
* **Title:** `feat(formats): add Mach-O Objective-C class & selector metadata recovery`
* **Issue Body:**
```markdown
### Summary
`superghidra/formats/msvc_class_recovery.py` recovers MSVC RTTI and MFC classes from PE files in pure Python without launching the JVM. We want equivalent capability for ARM64 macOS / iOS Mach-O binaries containing Objective-C runtime metadata.

### Proposed Implementation
1. In `superghidra/formats/binary_loader.py` (or a dedicated `superghidra/formats/macho_objc_recovery.py`):
   - Parse Mach-O sections `__objc_classlist`, `__objc_classrefs`, `__objc_methname`, `__objc_methtype`, and `__objc_const`.
   - Recover class names, superclasses, instance methods, class methods, and ivar offsets.
2. Export the recovered class hierarchy to JSON conforming to the existing format schema used by `rtti-recover`.

### Acceptance Criteria
- [ ] Recovers ObjC classes and method selectors from a sample Mach-O binary without JVM.
- [ ] CLI command `superghidra objc-recover <macho-binary> -o classes.json`.
- [ ] Unit tests in `tests/formats/test_macho_objc_recovery.py`.
```

---

## Issue 5: `ci(release): build and attach Ghidra GUI overlay sync extension .zip on tag push`

* **Labels:** `ci`, `good first issue`
* **Title:** `ci(release): build and attach Ghidra GUI overlay sync extension .zip on tag push`
* **Issue Body:**
```markdown
### Summary
SuperGhidra provides `ghidra_extension_skeleton/` and `ghidra_gui_overlay_sync.py` to sync JSON write-overlay modifications live into an open Ghidra CodeBrowser window.

We need a GitHub Actions release workflow that automatically packages this extension into `SuperGhidra-GUI-Sync-Extension.zip` and attaches it to GitHub Releases whenever a `v*` tag is pushed.

### Acceptance Criteria
- [ ] Workflow `.github/workflows/release.yml` triggered on tags `v*`.
- [ ] Packages extension files into a zip following Ghidra's extension layout convention.
- [ ] Attaches the artifact to the GitHub release draft/published asset list.
- [ ] Passes YAML linter and runs cleanly on GitHub Actions runner.
```
