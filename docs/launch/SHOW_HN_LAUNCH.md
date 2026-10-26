# SuperGhidra: Hacker News (`Show HN`) Launch Post & Opener Kit

This document contains copy-paste ready material for submitting **SuperGhidra** and **SuperGhidraMCP** to Hacker News.

- **Primary URL to Submit:** `https://github.com/yuatemycat/SuperGhidra`

---

## 1. Submission Title Options

Choose one of the following two titles depending on launch focus:

### Option 1 (Systems & Multi-Agent Focus — Recommended)
```text
Show HN: SuperGhidra – Lock-free Ghidra daemon, Z3 P-code verifier, and C++ recovery
```

### Option 2 (Performance & Decompilation Focus)
```text
Show HN: SuperGhidra – Persistent Ghidra daemon, compilable C filter, and WGPU ARM64 scanner
```

---

## 2. Author's Opening Comment (Post Immediately After Submitting)

```markdown
Hi HN, I built **[SuperGhidra](https://github.com/yuatemycat/SuperGhidra)** (`pip install superghidra`) and its companion MCP server **[SuperGhidraMCP](https://github.com/yuatemycat/SuperGhidraMCP)** to solve three bottlenecks I kept hitting when scripting Ghidra and running multiple AI agents against large stripped binaries (especially 20 MB+ ARM64 Android `.so` libraries and legacy MSVC/MFC Windows targets):

1. **JVM Cold Starts & `.rep` Lock Contention:** Every `analyzeHeadless` invocation pays 5–15 seconds of JVM startup, and an open Ghidra GUI locks the `.rep` project so background scripts or agents hit `LockException`. SuperGhidra keeps a single read-only Ghidra project loaded in a persistent background daemon (`127.0.0.1:5073`) backed by a 64 KB zero-copy shared-memory ring buffer (`5.12 µs` roundtrip, ~195k msg/s) and an L2 SQLite query cache (`< 0.01 ms` hits). All renames, comments, and struct recoveries go into a non-destructive JSON write overlay (`ghidra_overlay.json`). Multiple agents work on isolated forks, and `merge_fork` replays the journal while rejecting stale-base conflicts before syncing back to the live Ghidra GUI.

2. **Gated Agent Commits & Z3 P-Code Equivalence:** Letting LLMs directly rename symbols or rewrite structs in an RE database quickly pollutes the project. SuperGhidra puts an Obligation Ledger Gate in front of overlay commits: candidate structs and symbols must pass deterministic checks on vtable slot counts, field offsets, and allocation sizes. A pure-Python P-code lifter + Z3 prover checks whether a simplified C statement is semantically equivalent to the lifted IR (returning `UNKNOWN` rather than guessing on floats, unhandled instructions, or unbounded loops).

3. **Zero-JVM Fast Paths (SIMD, WGPU, and MSVC/MFC Recovery):** A surprising amount of reverse engineering doesn't need the JVM at all. SuperGhidra includes standalone pure-Python loaders for PE/ELF/Mach-O that recover MSVC RTTI (`CompleteObjectLocator`, vtables, class hierarchies), MFC `CRuntimeClass` tables, and `CArchive::Serialize()` field layouts in milliseconds, exporting to JSON, DWARF 5, Breakpad, or `.map`. For bulk ARM64 analysis, a NumPy SIMD scanner sweeps 4 MB (1M instructions) for `ADRP + ADD/LDR` pairs in `7.28 ms` (`143.95 M insn/s`), and a WGPU compute shader sweeps 20 MB (5.24M instructions) in `41.20 ms` (`127.25 M insn/s` on an RTX A5500 Laptop GPU) with bit-exact parity.

**A note on the `HumanEval-Decompile` benchmark numbers in the repo:**
Across 1,300 evaluable functions compiled with GCC (`O0`–`O3`) and tested against unit suites, stock NSA Ghidra output compiled and passed on `8.23%` (107/1,300), raw IDA Pro passed on `18.69%` (243/1,300; `19.00%` / 247/1,300 with Hex-Rays `defs.h`), and Ghidra output run through SuperGhidra's `compilable_filter.py` passed on `22.62%` (294/1,300 full corpus, and `25.26%` / 98/388 on the function-disjoint held-out 30% test split). Important caveat: `compilable_filter.py` is a deterministic AST and token rewriter that strips stack canaries and normalizes Ghidra pseudo-types (`undefined8`, `CONCAT44`, `SUB84`, etc.) into standard C rather than a neural model.

Everything is open source ([SuperGhidra](https://github.com/yuatemycat/SuperGhidra) and [SuperGhidraMCP](https://github.com/yuatemycat/SuperGhidraMCP)). I'd love feedback on the overlay conflict model, the P-code lifter coverage, and any edge cases you hit on real binaries!
```
