# Contributing to SuperGhidra

Contributions are welcome, whether it's a bug report, a failing binary, a test, or a patch. This page covers the rules that matter before you open a PR.

## Invariants to keep

These five are enforced by tests. [`AGENTS.md`](AGENTS.md) lists them too, and [`ARCHITECTURE.md`](ARCHITECTURE.md) shows where each piece lives.

1. **Storage writes are append-only.** Sync order is fixed: write the directory and `fsync`, then write the header pointer and `fsync`. Working buffers use LZ4. Snapshot backups use Zstandard.
2. **The oracle never writes to a Ghidra project.** `ghidra_oracle.py` opens programs with `readOnly=True`. Renames, comments and bookmarks go to the JSON write overlay, not the `.rep` files. Never delete a fresh `.lock` file.
3. **Automated and neural symbol commits go through the ledger.** Nothing may bypass `ReconstructionObligationLedger` (`VTableSlotVerifier`, `FieldDisplacementVerifier`, `AllocationSizeVerifier`).
4. **The emulator sidecar protects real devices.** Don't touch `emulator-5564` or `127.0.0.1:21503`. Writes are only allowed on the authorized sandboxes `emulator-5580` and `127.0.0.1:21513`.
5. **The Z3 checker doesn't guess.** An unhandled instruction, a floating-point operation, or a loop past the unroll bound must return `UNKNOWN` (`is_equivalent=False`), never a false `UNSAT`.
6. **No placeholder results.** When a tool cannot produce a result from its input, it raises or exits non-zero. It never returns output that looks real but was not derived from the input.

## Setup

You need Python 3.10 or newer. For the Ghidra-backed parts you also need JDK 21 and Ghidra 11.x or 12.x-DEV.

```bash
git clone https://github.com/yuatemycat/SuperGhidra.git
cd SuperGhidra
pip install -e ".[all]"
```

The extras are optional. `smt` installs `z3-solver`, `gpu` installs `wgpu`, `storage` installs `lz4` and `zstandard`, and `frida` installs `frida`. Tests that need a missing package skip themselves.

## Running tests

```bash
pytest tests -v                # everything
pytest tests/core -v           # one domain: core, storage, acceleration, diff, lifters, formats, integrations
```

All tests should pass before you open a PR. Tests that need real binaries read their paths from environment variables (see the README) and skip when those are unset.

## Pull requests

1. Branch off `master` with a short descriptive name, such as `feat/arm64-vector-lift` or `fix/lz4-slot-dir`.
2. Keep commits small and use a conventional prefix: `feat`, `fix`, `perf`, `docs` or `test`, for example `fix(storage): reject truncated slot directory`. Put the reason in the body if it isn't obvious.
3. Don't commit test databases, `__pycache__` or `.lock` files. Tests should write only to temporary directories or `SUPERGHIDRA_DATA_DIR`.
4. If you change a P-code lifter or an instruction decoder, add a Z3 equivalence test for it.
5. Open the PR against `master` and fill in the template.

## Reporting issues

Use the [bug report](.github/ISSUE_TEMPLATE/bug_report.yml) or [feature request](.github/ISSUE_TEMPLATE/feature_request.yml) template. For a crash or a decompiler hang, include:

- the architecture (`x86_64`, `arm64`, `arm32` or `thumb2`)
- the function size in bytes and its basic block count
- the resource governor mode (`eco`, `balanced`, `turbo` or `auto`)
- a minimal binary slice or disassembly dump that reproduces it

## License

SuperGhidra is released under the GNU AGPL-3.0-or-later and is also offered under a separate commercial license (see [COMMERCIAL-LICENSE.md](COMMERCIAL-LICENSE.md)). By opening a pull request you agree that your contribution may be distributed under both. You keep the copyright on your work. If you can't agree to the second part, say so in the PR before it is merged.

Code from before the license change was released under Apache-2.0, and that version of the text is in `LICENSES/Apache-2.0.txt`.
