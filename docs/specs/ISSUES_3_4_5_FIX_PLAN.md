# Fix plan for issues #3, #4, #5

Status: draft, 2026-10-22. Nothing in this plan has been implemented yet.

All three issues have the same root cause. A test or a published number checks that
something ran, not that its result is correct. Each section fixes one bug and adds the
check that would have caught it. The last section changes the project rules so the same
kind of bug is harder to merge again.

Order of work: #3, then #4, then #5, then the P1 prevention checks, then P2 and P3. The
P1 canary and skip budget can start in parallel with #4, since they touch
`tests/conftest.py` and CI anyway. #3 comes first because the
CLI currently returns made-up output with exit 0. #4 depends on nothing else but will
surface any integration failures #3 introduces. #5 is the most work and needs gcc plus
network access to the dataset.

Work directly on `master` in small commits, one per step, each referencing its issue
(`Fixes #3`). Do not touch the files that were already modified or untracked before this
work started (`superghidra/diff/README.md`, the OOD benchmark files).

---

## Issue #3: `superghidra decompile` returns made-up output

### What is wrong

| Location | Problem |
| :--- | :--- |
| `superghidra/__main__.py:108` | `offset = min(args.rva, len(data))` uses the RVA as a file offset and clamps it to the end of the file. An out-of-range RVA produces an empty buffer instead of an error. |
| `superghidra/__main__.py:145` | Same clamp in `cmd_flirt_match`. |
| `superghidra/core/live_binary_tools.py:901-916` | Only `mov`/`add`/`xor`/`ret` are lifted. Every other instruction, including invalid decodes, is skipped with no error. |
| `superghidra/core/live_binary_tools.py:907` | `src_vn = rbx if insn.rm == 3 else rcx`. Source and destination are not decoded from ModRM, so `mov rax, rbx` becomes `rax = rcx`. The destination is always `rax` and `add` is always `rax + rbx`. |
| `superghidra/core/live_binary_tools.py:918-921` | When nothing was lifted, it emits `rax = 0x42; return rax;`. |
| `superghidra/core/live_binary_tools.py:903` | `arch="arm64"` is passed to the x86 decoder in 32-bit mode. ARM64 bytes are decoded as x86. Not in the issue, same class of bug. |
| `README.md:107` | The example `--rva 0x140001000` is a VA (default x64 DLL image base plus 0x1000), not an RVA. |

Two existing tests decompile the exact bytes from the issue (`48 89 d8 48 01 d8 c3`) and
check neither the body nor the register:
`tests/core/test_parity_benchmark_scorecard.py:79-89` and
`tests/lifters/test_staged_pcode_pipeline.py:53-66`. Both would pass with the `0x42` stub.

### Changes

1. **Add `LiftError(ValueError)` to `live_binary_tools.py`.** It carries
   `unhandled: list[tuple[int, str]]` (address, hex bytes) and a message.
2. **Remove the `0x42` fallback.** `staged_decompile_function` raises `LiftError` when:
   - `code_bytes` is empty;
   - `arch` is not `x86_64` (the lifter only handles x86-64 today; `x86` and `arm64`
     raise "not supported by this lifter" until someone implements them);
   - any decoded instruction is invalid or not handled (list every one, not just the first);
   - the buffer ends before a `ret`.
3. **Decode registers from ModRM.** Add a 16-entry GPR table in encoding order
   (`rax, rcx, rdx, rbx, rsp, rbp, rsi, rdi, r8..r15`). `X86Insn.reg` and `X86Insn.rm`
   already include REX.R/REX.B.
   - `0x89`, `0x01`, `0x31` (`op r/m, r`): dst = `rm`, src = `reg`.
   - `0x8B`, `0x03`, `0x33` (`op r, r/m`): dst = `reg`, src = `rm`.
   - Only register forms with REX.W are handled (`insn.mem is None` and REX.W set).
     Memory operands and 32-bit forms raise `LiftError`. 32-bit ops zero-extend and
     need their own handling, which is out of scope here.
   - `xor r, r` with the same register stays `INT_XOR` so the emitted code matches the input.
4. **CLI address mapping.** Add a helper `_function_bytes(path, arch, rva=None, va=None, length)`
   in `__main__.py`, used by both `decompile` and `flirt-match`:
   - `img = load_binary(str(path), raw_arch=arch)`. Raw files load as one section at base 0,
     so for a raw blob the RVA equals the file offset, which is what the issue's `toy.bin`
     case expects.
   - If the file is ELF/PE/Mach-O and `img.arch != arch`, exit 2 and print both.
   - `va = img.rva_to_va(rva)` unless `--va` is given. Add `--va` as an option mutually
     exclusive with `--rva`.
   - `img.va_to_offset(va)` returns `None` → exit 2 with "address 0x… is not backed by file
     bytes". A section that is not executable → exit 2.
   - Read with `img.read_va(va, length)`. A short read is fine; the lifter decides whether
     the bytes contain a `ret`.
5. **CLI error handling.** Catch `LiftError` in `cmd_decompile`, print the message and the
   unhandled list to stderr, write nothing to stdout or `--output`, and exit 3.
6. **README.** Change the example to `--va 0x140001000` (or `--rva 0x1000`) and state that
   the lifter only handles register-to-register `mov`/`add`/`xor` and `ret` on x86-64. Any
   other instruction exits non-zero.

### Tests

Unit tests in `tests/lifters/test_staged_pcode_pipeline.py`. Each one checks exact
statements in `c_code`, not just that a field exists:

| Input bytes | Expected |
| :--- | :--- |
| `48 89 d8 48 01 d8 c3` | contains `rax = rbx;` and `rax = rax + rbx;`, does not contain `rcx` in the body |
| `48 89 c3 c3` (`mov rbx, rax`) | `rbx = rax;` |
| `48 8b c3 c3` (`mov rax, rbx`, 8B form) | `rax = rbx;` |
| `4c 89 c0 c3` (`mov rax, r8`) | `rax = r8;` |
| `48 31 c0 c3` | `rax = rax ^ rax;` (or the emitter's equivalent; pin the exact string) |
| `48 8d 0d 00 00 00 00 c3` (`lea`) | `LiftError`, `unhandled[0][0] == func_rva` |
| `b8 01 00 00 00 c3` (32-bit `mov eax, imm`) | `LiftError` |
| `48 89 d8` (no `ret`) | `LiftError` |
| `b""` | `LiftError` |
| any bytes with `arch="arm64"` | `LiftError` |

Fix the two existing weak tests to assert `rax = rbx;`.

New CLI tests in `tests/core/test_cli_decompile.py`. They run `python -m superghidra` in a
subprocess, so argument parsing and exit codes are covered:

- Raw blob with the code at file offset 0x1000, `--rva 0x1000` → exit 0, stdout has
  `rax = rbx;`.
- Same file, `--rva 0x140001000` → exit 2, empty stdout, stderr names the address.
- Raw blob with a `lea` at the target → exit 3, stderr lists the address, `-o` file not created.
- Synthetic PE whose `.text` RVA differs from its file offset (for example RVA 0x1000 at
  file offset 0x400). Reuse a PE builder from `tests/formats` if one exists, otherwise add a
  minimal one. `--rva 0x1000` must lift the bytes at offset 0x400.
- `--arch arm64` on an x86-64 PE → exit 2 (arch mismatch).

Integration (marked `integration`, skip with a reason if the file is missing):
`kernel32.dll` on Windows and `/bin/ls` on Linux at a real function → non-zero exit and
`0x42` not in stdout.

### Done when

`python -m pytest tests/lifters tests/core -q` passes, and `rg -n "0x42" superghidra/core/live_binary_tools.py`
finds nothing in the lift path.

---

## Issue #4: CI skips integration tests; deflatten test fails on gcc/clang

### What is wrong

- `.github/workflows/ci.yml` runs `pytest tests -v -m "not integration"`, so the 11
  integration tests never run in CI. The README CI table (`README.md:65-66`) reports this
  as "11 deselected" next to "100%".
- `tests/integration/test_live_binary_upgrade.py:146-154` compiles `_FLAT_SOURCE` with
  `native_compiler.c_compiler()`. That function prefers gcc, then clang, then cl.exe
  (`superghidra/core/native_compiler.py:72-73`), and gcc builds with `-O0`
  (`native_compiler.py:112`). `_find_cmp_chain` (`live_binary_tools.py:348`) only accepts
  `cmp mem, imm8` (`_is_cmp_imm8`, line 295), which is the MSVC `/Od` shape. The test
  therefore fails wherever gcc or clang is on PATH, including a Windows machine that has
  both MinGW and MSVC installed.

### Changes

Step A, so CI can run the full suite without hiding a known failure:

1. Have `_compile_flattened` return the compiler path it used.
2. In the deflatten test, if the compiler is not cl.exe, call
   `pytest.xfail(...)`, or use a `strict=True` xfail marker, with the reason "dispatcher
   scan only recognises MSVC /Od; see #4". Use strict xfail rather than skip. Once gcc
   support lands, the test starts passing, strict xfail turns that into a failure, and
   someone has to remove the marker.
3. Change CI to `python -m pytest tests -v -rs -rx --strict-markers`. `-rs`/`-rx` print
   every skip and xfail reason in the log. Check `pyproject.toml` for `addopts` that
   re-add the marker filter (none found on 2026-10-22).
4. Check what the Windows runner actually has. `kernel32.dll` exists there, so the
   kernel32 integration tests will now run. Find out whether MinGW gcc is on PATH; if so,
   the deflatten test takes the xfail path on Windows too. `SUPERGHIDRA_TEST_ARM64_ELF`
   is unset in CI, so the libg tests skip with a reason. That is expected; it should
   appear in the `-rs` output.
5. Update the CI table in `README.md:59-66` from the first green run after this change,
   including the new skip and xfail counts and the run link. Remove "100%" unless the
   column is defined as passed / (collected − skipped − xfailed).

Step B, so the scanner handles gcc/clang:

1. Compile `_FLAT_SOURCE` with `gcc -O0` and `clang -O0`, disassemble
   `flattened_score`, and save the disassembly as a text fixture under
   `tests/fixtures/deflatten/`. Do not write the recogniser from memory. gcc at `-O0`
   usually loads the state into a register (`mov eax, [rbp-x]`) and then compares the
   register (`cmp eax, imm` / `test eax, eax`). Confirm this, and check whether clang
   emits a jump table instead.
2. Extend `_find_cmp_chain` to also accept a chain of `cmp reg, imm` / `test reg, reg`
   where `reg` was loaded from one stack slot and is not written in between. That slot is
   the state variable. Case bodies already write it with `mov dword [slot], imm`, which
   `_is_mov_imm` matches. `_deflatten_chain` builds `cases` from `cmp_insn.imm`;
   `test reg, reg` must map to state 0.
3. Duplicate compares such as `cmp eax, 2; je` followed by `cmp eax, 2; jg` (a gcc
   range split) must not add a second case for the same value. Add a test for this with
   the gcc fixture bytes.
4. If clang emits a jump table, keep a strict xfail for clang with that reason and open a
   separate issue. Do not widen the recogniser to guess.
5. Add a unit test in `tests/core` that runs the recogniser on the fixture bytes, so the
   gcc path is covered without a compiler. Leave the integration test as the end-to-end
   check.

### Done when

CI on both OSes runs the whole suite with no `-m` filter, the log lists every skip and
xfail with a reason, and on Linux the deflatten test either passes (after Step B) or is a
strict xfail (after Step A only).

---

## Issue #5: HumanEval table is asymmetric, "0 regressions" is wrong, pin is gone

### What is wrong

| Location | Problem |
| :--- | :--- |
| `README.md:46-57`, `docs/benchmarks/EMPIRICAL_TEST_BENCHMARK_MATRIX.md:74-80`, `docs/benchmarks/EMPIRICAL_BENCHMARK_MATRIX_v0.2.0.md:46-49`, `docs/SUPERGHIDRA_ARCHITECTURE_AND_IDA_PRO_GAP_ANALYSIS.md:572` | Filtered Ghidra is compared against raw IDA. The filter is never applied to IDA. The tables claim 0 regressions. The reporter measured 36. |
| README numbers | 107 / 219 / 294 of 1,296. `gcc_compare.py` on today's corpus gives Ghidra 279, IDA 243, filtered 350 of 1,300. The README numbers do not come from `gcc_compare.py` as it stands, and the plan has to find out which script and revision produced them. |
| `benchmarks/humaneval_decompile/harness.py:180-220` | If the pinned revision is missing, it falls back to the live revision. The fallback is recorded only in `cache/REVISION.txt`, which is gitignored. |
| `benchmarks/humaneval_decompile/harness.py:228-234` | A cached `humaneval.jsonl` is reused without checking which revision it came from. |
| `.gitignore:22-32` | Score logs and summaries are ignored, so no published number can be checked from the repository. |

### Changes

1. **Make the comparison symmetric.** In `gcc_compare.score_gcc_sample`, also score
   `ida_filtered_pass` (IDA body through `CompilableDecompilerFilter.filter` with the same
   arguments as the Ghidra side). Add the matching fields to `averages_from_gcc_log`:
   - `ida_filtered_avg`, `ida_filtered_pass_count`;
   - `filter_gained_ghidra` / `filter_broken_ghidra` (raw Ghidra vs filtered Ghidra);
   - `filter_gained_ida` / `filter_broken_ida`;
   - rename the overlap fields so they say which two columns they compare.
2. **Pin hard.** Look up the commits of `LLM4Binary/decompile-eval`
   (`HfApi().list_repo_commits`) and set `PINNED_REVISION` to a commit that exists,
   probably `b9271fae3c556e46948559f4176ffa6f8b4f9491` (the one the reporter scored).
   Confirm it before using it. A missing pin then fails the run. The live-revision
   fallback runs only with an explicit `--allow-unpinned` flag, and in that case the
   summary records `"pinned": false`.
3. **Check the cache.** `load_humaneval_rows` reads `cache/REVISION.txt` and re-downloads
   when it does not match `PINNED_REVISION`.
4. **Put provenance in the summary.** `gcc_score_summary.json` gets `dataset_id`,
   `dataset_revision`, `pinned`, `row_count`, `evaluable_denominator`, the compiler path
   and `--version` output, the OS, and the git commit of this repo.
5. **Look at the 36 regressions before publishing anything.** List the sample ids where
   `ghidra_pass and not filtered_pass`. For each one, find which rewrite breaks it by
   toggling the filter's options (`emit_compilable`, `strip_canary`, `include_headers`,
   `collapse_strides`) and then the individual rewrites. Fix the rewrites that are wrong.
   Add the minimal failing body for each fixed case to `tests/core/test_compilable_filter.py`.
   Do not aim for 0 if that would mean reverting useful rewrites. Publish the measured
   count, whatever it is.
6. **Commit the evidence.** Keep the full logs ignored. Commit a slim per-sample log
   (sample id, the four pass booleans, evaluable flag; no source bodies) and the summary
   under `docs/benchmarks/humaneval/`. Check the size first; 1,312 rows of booleans should
   be well under 1 MB.
7. **Generate the published table.** Add `scripts/render_humaneval_table.py`. It reads the
   committed summary and rewrites the block between `<!-- humaneval:begin -->` and
   `<!-- humaneval:end -->` in `README.md` and in the benchmark matrix doc. Columns: IDA
   raw, IDA + filter, Ghidra raw, Ghidra + filter, each as count / denominator and percent.
   Then filter gains and filter regressions for both decompilers, and the dataset revision
   and compiler under the table.
8. **Fix the prose.** Remove "+5.79% over commercial IDA Pro" and "0 regressions" from all
   four documents listed above. The gap-analysis line 572 ("249 with 0 regressions") is
   another unverified number; either regenerate it or mark it unverified. Reword "Evaluated
   under `gcc -O0 -lm` across optimization levels `O0`–`O3`" to say plainly that the
   dataset binaries were built at O0–O3 and the recovered C is recompiled with gcc.

### Tests

In `tests/benchmarks/` (no network, no dataset):

- `score_gcc_sample` on a hand-made row with an IDA body that contains a Ghidra-only token
  sets `ida_filtered_pass` independently of `ida_pass`.
- `averages_from_gcc_log` on a small synthetic log returns the right gained/broken counts
  for both decompilers.
- `_download_split` with a mocked `load_dataset` that raises a revision error fails
  without `--allow-unpinned` and records `pinned: false` with it.
- A stale `REVISION.txt` triggers a re-download (mock the download).
- `test_published_numbers.py`: the README block is byte-identical to
  `render_humaneval_table` output for the committed summary, and the committed summary's
  `dataset_revision` equals `PINNED_REVISION`. This test is what keeps the README from
  drifting again.

### Running it

The harness refuses cl.exe, so the full run needs gcc and network access. Run it on Linux
or WSL with `python -m benchmarks.humaneval_decompile.gcc_compare --workers 8`. The
reporter's numbers came from CachyOS with gcc. Record which machine produced the committed
summary.

### Done when

`python -m pytest tests/benchmarks -q` passes, the README table comes from the committed
summary, and someone else running the harness at the pinned revision gets the same counts.
A different gcc version may change a few samples; say so under the table.

---

## Prevention

The fixes above close these three bugs. This section is about the next bug of the same
kind, in code nobody has written a targeted test for yet.

Written rules alone do not prevent it. `AGENTS.md` invariant 5 already said "return
UNKNOWN, never a false result" for the SMT verifier, and the `0x42` stub was written
anyway. So every rule below is enforced by a check that runs in CI and fails the change.
`AGENTS.md` and `CONTRIBUTING.md` only name the check and the local command, so an agent
or contributor can run it before pushing (see "Documentation" at the end of this section).

Priority order. P1 checks are cheap, need no new dependencies, and together would have
caught all three issues. Do them before the P2 and P3 checks.

| # | Check | Pri | Would have caught | Runs |
| :--- | :--- | :---: | :--- | :--- |
| 1 | Stub canary | P1 | #3 | every PR |
| 2 | Skip budget | P1 | #4 | every PR |
| 3 | Docs tests and number linter | P1 | #3 (README example), #5 | every PR |
| 4 | Provenance check in the lifter | P1 | #3 | always, in the code path |
| 5 | Symmetric benchmark grid | P1 | #5 | benchmark runs |
| 6 | Compiler matrix | P2 | #4 | every PR, integration job only |
| 7 | Weekly external pin and reproduction check | P2 | #5 | weekly cron |
| 8 | Comparison against reference tools | P2 | #3 | every PR |
| 9 | Mutation testing on changed files | P3 | #3 | PR, Linux only |

### 1. Stub canary

Checks that the tests can tell a real implementation from a fake one.

- `tests/canary/targets.toml` lists public tools and a fake for each. A fake returns
  output with the right shape and meaningless content. First entries:
  - `superghidra.core.live_binary_tools:staged_decompile_function`: returns the old
    `rax = 0x42; return rax;` result, whatever the input.
  - `superghidra.core.live_binary_tools:deflatten_control_flow`: returns
    `{"deflattened": True, "gotos_eliminated": 1, "back_edges_removed": 1, ...}`.
  - `superghidra.core.live_binary_tools:query_binary_dataflow`,
    `solve_global_type_lattice`, `match_flirt_signatures`: constant results with the
    same keys.
  - `superghidra.core.compilable_filter:CompilableDecompilerFilter.filter`: returns its
    input unchanged.
- `scripts/stub_canary.py` runs pytest once per target, in a subprocess with
  `SUPERGHIDRA_STUB=<module:function>`, against the test paths listed for that target.
  The canary passes only if that pytest run **fails**. A target whose tests still pass
  with the fake is reported as having blind tests.
- Patching has to happen before test modules import the name, because tests use
  `from superghidra.core.live_binary_tools import staged_decompile_function`. Do it in a
  `pytest_configure` hook in `tests/conftest.py` that runs only when `SUPERGHIDRA_STUB`
  is set. CLI tests run `python -m superghidra` in a child process. For those, the canary
  puts `tests/canary/` on `PYTHONPATH`, and a `sitecustomize.py` there applies the same
  patch in the child. No test hook goes into package code.
- CI: a separate job runs `python scripts/stub_canary.py`. New public tools in a canonical
  file from the `AGENTS.md` decision matrix need an entry. Enforce that with a test that
  compares the public functions of those files against `targets.toml`, plus an explicit
  `exempt` list with a reason for each exemption.

### 2. Skip budget

Makes every skipped, deselected or expected-to-fail test a reviewed decision.

- `tests/skip_budget.toml` holds one entry per allowed skip or xfail: node id pattern,
  platforms, reason, issue link. Example: libg tests skip when
  `SUPERGHIDRA_TEST_ARM64_ELF` is unset; the deflatten test is xfail on gcc/clang (#4).
- `tests/conftest.py` collects skip, xfail and deselect outcomes in `pytest_runtest_logreport`
  and `pytest_deselected`. When `SUPERGHIDRA_ENFORCE_SKIP_BUDGET=1` (set in CI), it fails
  the session in `pytest_sessionfinish` if:
  - any outcome has no matching entry; or
  - an entry matched nothing on a platform it lists, meaning it is stale and should be
    removed.
- CI does not pass `-m`. If a marker filter is ever reintroduced, every deselected test
  fails the budget.

### 3. Docs tests and number linter

Treats the README's commands and numbers as things that can be wrong.

- **Commands.** Put `<!-- run -->` before each README code block that a user is meant to
  run. `tests/docs/test_readme_commands.py` extracts those blocks and runs them from the repo
  root. To make that possible, the examples point at small committed fixtures (for example
  `tests/fixtures/cli/sample.dll`, a synthetic PE) instead of `target.dll`. Each block may
  declare an expected exit code (`<!-- run exit=2 -->`). Blocks that need Ghidra or network
  access are tagged `<!-- run integration -->` and are covered by the skip budget.
- **Numbers.** `scripts/check_published_numbers.py` scans `README.md` and new files in
  `docs/benchmarks/` for measurements: percentages, `N / M` counts, times, throughput.
  Each one must sit inside a `<!-- generated:<name> begin -->` … `end` block written by a
  render script from a committed summary file. Version strings and dates are ignored by
  pattern. It runs as a test in `tests/docs/`.
- **Older reports.** `docs/benchmarks/` already has many hand-written numbers. Do not
  convert all of them in this work. Move the ones that are not regenerated under
  `docs/benchmarks/archive/` with a first line saying "Not regenerated; numbers
  unverified", and exclude that folder from the linter. The README CI table
  (`README.md:59-66`) is generated as well, from the CI run's JUnit XML.

### 4. Provenance check in the lifter

Makes made-up output fail inside the code, not just in tests.

- After lifting, `staged_decompile_function` calls `_check_provenance(ops, insns)`:
  - every op's address must be the address of an instruction decoded from `code_bytes`;
  - every decoded instruction up to and including the `ret` must produce at least one op.
- A violation is a bug in the lifter, not bad input, so it raises `AssertionError` rather
  than `LiftError`. The check is a set comparison over a few dozen addresses, so leave it
  on in production.
- The result dict gets `"source_addresses"`, so tests and callers can check provenance too.
- The same idea applies to every tool that returns addresses. The integration tests already
  check `_inside_image`. Move that check into a shared helper in `live_binary_tools.py`
  and call it before returning, so the check is not test-only.

### 5. Symmetric benchmark grid

Makes a one-sided comparison impossible to produce.

- In `gcc_compare.py`, define `DECOMPILERS = ("ida", "ghidra")` and
  `TRANSFORMS = {"raw": identity, "filtered": CompilableDecompilerFilter.filter}`, and
  score every pair. This replaces step 1 of the #5 fix with a general version.
- The render script only takes columns from that grid. A test asserts the summary has
  every pair, and that the gained/broken counts exist for every transform other than `raw`.
- Adding a transform later automatically applies it to both decompilers.

### 6. Compiler matrix

- Add `SUPERGHIDRA_CC` to `native_compiler.c_compiler()`/`cxx_compiler()` to force a
  compiler (`gcc`, `clang`, `cl`). `cl` means "the `cl.exe` on PATH with the current
  environment". Today only the portable `SUPERGHIDRA_MSVC_ROOT` layout is supported, and
  the CI MSVC setup action provides the vcvars layout instead.
- CI integration job: Linux with `gcc` and `clang` (install clang via apt), Windows with
  `cl` (via `ilammy/msvc-dev-cmd`) and MinGW `gcc` if the runner has it. Keep the unit job
  on one compiler per OS to save CI minutes.

### 7. Weekly external pin and reproduction check

- `.github/workflows/weekly.yml`, on a cron schedule plus manual dispatch:
  - `python -m benchmarks.humaneval_decompile.check_pins` checks that `PINNED_REVISION`
    exists via `HfApi().dataset_info(DATASET_ID, revision=PINNED_REVISION)`, and that the
    hashes in `tests/fixtures/external_pins.toml` still match. Put every external file a
    test or benchmark depends on there.
  - Run the full `gcc_compare` at the pin and compare the counts to the committed summary.
    Any difference fails the job. A gcc version change can move a few samples, so the job
    prints the per-sample diff from the slim log so it can be investigated.
- A failed scheduled run notifies the maintainers through GitHub's usual workflow failure
  email. Optionally open an issue with `gh issue create` using the workflow token.

### 8. Comparison against reference tools

Tests on generated inputs, checked against an independent implementation. New dev-only
dependencies: `hypothesis`, `capstone`, `unicorn`, `pefile`, `pyelftools`. Add them to a
`test` extra in `pyproject.toml`, not to `all`.

- `tests/lifters/test_x86_decode_vs_capstone.py`: `hypothesis` generates REX.W prefixes
  (`48`, `49`, `4C`, `4D`), opcodes `01 03 31 33 89 8B` and register-form ModRM bytes. It
  checks that the lifted op's source and destination registers match Capstone's operands.
  That covers every register pair, including the one #3 got wrong.
- `tests/lifters/test_lift_vs_unicorn.py`: generates short sequences of supported
  instructions ending in `ret` and random initial register values. It runs the bytes in
  Unicorn and the lifted P-code in a small evaluator (`COPY`, `INT_ADD`, `INT_XOR`), and
  compares the registers afterwards. No compiler is needed, so it runs on every OS. A
  second, integration-marked variant compiles the emitted C with gcc and compares results.
- `tests/formats/test_address_map_vs_reference.py`: on `kernel32.dll` and a system ELF
  (each skipped with a budget entry when missing), it compares `va_to_offset` with
  `pefile`'s `get_offset_from_rva` and with segment math from `pyelftools` for a sample of
  RVAs, including addresses past the end of the file and in `.bss`.
- No reference tool exists for the deflattener. It relies on the compiler fixtures from #4.

### 9. Mutation testing on changed files

- Configure `mutmut` in `pyproject.toml`. A PR job on the Linux runner (mutmut 3 needs
  `fork()`; check before relying on that) mutates only the `superghidra/` files changed in
  the PR and runs that domain's test suite.
- Start it as a report-only job that posts surviving mutants in the job summary. After a
  few weeks, decide whether to make surviving mutants on changed lines fail the job, with
  a `# pragma: no mutate` escape for equivalent mutants.

### Documentation

Add each line in the same commit as the check it describes. Do not document a command
that does not exist yet.

`AGENTS.md`, section 4, new invariant 6:

> 6. **No placeholder results.** When a tool cannot produce a result from its input, it
>    raises or exits non-zero. It never returns output that looks real but was not derived
>    from the input. Enforced by the stub canary and the lifter provenance check.

`AGENTS.md`, new section 6, "Checks that will fail your change". Keep it short, since the
file is meant to stay small:

| Check | Run locally | Fails when |
| :--- | :--- | :--- |
| Stub canary | `python scripts/stub_canary.py --target <module:function>` | tests still pass with the tool replaced by a fake |
| Skip budget | `SUPERGHIDRA_ENFORCE_SKIP_BUDGET=1 python -m pytest tests` | a skip, xfail or deselect has no entry in `tests/skip_budget.toml` |
| Published numbers | `python -m pytest tests/docs -q` | a README command fails, or a number is not in a generated block |

`AGENTS.md`, section 5, item 2: add "and comes from a committed summary file through a
render script".

`CONTRIBUTING.md`: the same table, for people.

`templates/TEST_CASE_TEMPLATE.py`: add two required sections, "exact output for a known
input" and "error path for unsupported input", with one example of each.

---

## Decisions needed

Defaults are listed first. Change them before starting if they are wrong.

1. **`--va` flag on `decompile` and `flirt-match`.** Default: add it, keep `--rva`
   meaning a real RVA. Alternative: accept a VA in `--rva` when it is at or above the
   image base. That is less typing, but ambiguous for ELF PIE images where the base is 0.
2. **Committing benchmark logs.** Default: commit the slim boolean log and the summary.
   Alternative: publish them as a release asset and link them.
3. **README HumanEval table while #5 is in progress.** Default: remove the current table
   in the same commit as the #3 fix and replace it with a one-line note that the numbers
   are being regenerated (see #5). The current numbers are known to be wrong.

## Commits

```
fix(core): raise LiftError instead of emitting a placeholder body        (#3)
fix(core): decode x86-64 mov/add/xor registers from ModRM                (#3)
fix(cli): map --rva/--va through the binary loader                       (#3)
test(core): assert exact decompile output and CLI exit codes             (#3)
ci: run the integration suite and print skip reasons                     (#4)
test(integration): mark the gcc/clang deflatten case as strict xfail     (#4)
feat(core): recognise the gcc -O0 register-compare dispatcher            (#4)
fix(benchmarks): fail on a missing dataset pin and check the cache       (#5)
feat(benchmarks): score IDA through the filter and count filter regressions (#5)
fix(core): <one commit per filter regression fixed>                      (#5)
docs(benchmarks): regenerate the HumanEval table from the committed summary (#5)
test: add the stub canary and its first targets                          (P1)
test: enforce a skip budget in CI                                         (P1)
test(docs): run README commands and lint published numbers                (P1)
feat(core): check lifted op provenance before returning                   (P1)
refactor(benchmarks): score every decompiler x transform pair             (P1)
docs(agents): add the no-placeholder-results invariant and check table    (P1, with the checks)
ci: add the gcc/clang/cl compiler matrix to the integration job           (P2)
ci: add the weekly pin and benchmark reproduction job                     (P2)
test(lifters): compare decode and lift against capstone and unicorn       (P2)
ci: add a report-only mutation testing job                                (P3)
```

Before each push, run the domain suite named in `AGENTS.md` and the prose check in
`AGENTS.md` section 5, item 7.
