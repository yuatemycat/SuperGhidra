# SuperGhidra: Multi-Platform Social Media Launch Kit

Copy-paste ready launch copy tailored for technical communities across X/Twitter, Reddit, Discord, and LinkedIn.

- **Primary Repository:** `https://github.com/yuatemycat/SuperGhidra`
- **Companion MCP Server:** `https://github.com/yuatemycat/SuperGhidraMCP`
- **PyPI:** `pip install superghidra`
- **Key Media Assets to Attach:**
  - Demo GIF: `docs/assets/demo.gif` (RTTI & MFC recovery in ~1s)
  - Architecture SVG/PNG: `docs/assets/architecture-dark.svg`

---

## 1. X / Twitter (Launch Thread)

### Tweet 1 (Hook + Summary)
I open-sourced SuperGhidra (`pip install superghidra`): a persistent, lock-free Ghidra daemon with MCP support, a Z3 P-code verifier, and zero-JVM MSVC/MFC C++ class recovery.

Solves the two biggest headaches with Ghidra scripting: 5–15s JVM startup overhead and `.rep` lock collisions while the GUI is open.

🧵👇
[Attach: docs/assets/demo.gif]

### Tweet 2 (Daemon & Overlay Architecture)
Every headless run normally pays JVM boot latency. And if your CodeBrowser GUI is open, scripts crash with `LockException`.

SuperGhidra keeps a `readOnly=True` Ghidra instance warm in a local daemon (`127.0.0.1:5073`) backed by an L2 SQLite cache (<0.01ms hits) and 64 KB shared-memory ring buffer (5.12 µs roundtrip).

All agent writes go to a JSON overlay (`ghidra_overlay.json`), syncing live into GUI sessions without corrupting `.rep` files.

### Tweet 3 (Zero-JVM MSVC & MFC Recovery)
A lot of binary analysis doesn't need the JVM at all.

SuperGhidra includes pure-Python PE/ELF/Mach-O loaders that recover MSVC RTTI hierarchies, MFC `CRuntimeClass` descriptors, and `CArchive::Serialize()` field layouts.

On Microsoft's `mfc140u.dll`, it recovers 755 RTTI classes and 391 MFC classes in ~1 second with zero Ghidra dependency.

### Tweet 4 (Z3 Gate & HumanEval Caveat)
Letting LLMs directly commit renames quickly pollutes your RE database.

SuperGhidra puts an Obligation Ledger Gate in front of overlay commits: candidate structs and symbols must pass deterministic checks on vtable slot counts, field offsets, and allocation sizes. A pure-Python P-code lifter + Z3 solver proves equivalence (and returns `UNKNOWN` on floats/loops rather than guessing).

Benchmark note: The 22.69% HumanEval-Decompile pass rate measures our deterministic C rewriter (`compilable_filter.py`), not neural model weights.

### Tweet 5 (Links & CTA)
Everything is open source under AGPL-3.0 with dual-OS CI (747 tests on Linux & Windows):

- Core repo: https://github.com/yuatemycat/SuperGhidra
- MCP Server (38 tools for Claude Desktop, Cursor, Antigravity): https://github.com/yuatemycat/SuperGhidraMCP
- v0.3.1 Release: https://github.com/yuatemycat/SuperGhidra/releases/tag/v0.3.1

Feedback welcome on the overlay conflict model and P-code lifter coverage!

---

## 2. Reddit

### Post A: `r/ReverseEngineering` & `r/ghidra`

**Title:** SuperGhidra: Warm lock-free Ghidra daemon, non-destructive JSON write overlays, and standalone MSVC/MFC class recovery

**Body:**
```markdown
Hi r/ReverseEngineering,

I wrote and open-sourced **SuperGhidra** (https://github.com/yuatemycat/SuperGhidra) to solve two practical bottlenecks when scripting Ghidra and integrating external tools or agents:

1. **JVM Cold-Starts & `.rep` Lock Contention:**
   Every `analyzeHeadless` invocation costs 5–15 seconds of JVM startup. More painfully, opening a `.rep` project in Ghidra CodeBrowser acquires an exclusive OS lock, causing background scripts or AI agents to fail with `LockException`.
   SuperGhidra keeps a single `readOnly=True` Ghidra session warm in a local daemon (`127.0.0.1:5073`) backed by a 64 KB shared-memory ring buffer (5.12 µs roundtrip) and SQLite L2 cache. All renames, comments, and recovered types are routed to a non-destructive `ghidra_overlay.json` journal. You sync them into your active GUI session using a generated FlatProgramAPI script (`superghidra overlay-sync --watch`), so your GUI and background scripts never fight over locks.

2. **Standalone MSVC RTTI & MFC `Serialize()` Tracing (No JVM):**
   Ghidra lacks built-in MFC `CRuntimeClass` recovery and `CArchive` serialization layout tracing. SuperGhidra includes pure-Python PE/ELF/Mach-O parsers that extract MSVC RTTI structures (`CompleteObjectLocator`, class hierarchy descriptors, vtables) and trace MFC dynamic class declarations. On Microsoft's `mfc140u.dll`, it extracts 755 RTTI classes and 391 MFC classes in ~1 second without running Ghidra or Java. It can export these directly to DWARF 5, Breakpad symbols, or JSON.

3. **P-Code Lifter & Z3 Equivalence Prover:**
   Includes a zero-JVM ARM64 and x86 P-code lifter with a Z3 solver backend. When simplifying decompiled basic blocks or validating variable renamings, it tests whether the candidate C expression mathematically matches the lifted IR. To ensure soundness, floating-point instructions, unsupported opcodes, or loops past unroll limits strictly return `UNKNOWN` rather than false positives.

**Benchmark Caveat:**
In our `HumanEval-Decompile` benchmarks (1,296 functions compiled with GCC `O0`–`O3`), stock Ghidra pseudo-C compiled and passed 8.26%, raw IDA passed 16.90%, and Ghidra output passed through SuperGhidra's `compilable_filter.py` passed 22.69% (with zero regressions on functions that already passed in raw Ghidra). Note that `compilable_filter.py` is a deterministic AST/token rewriter for Ghidra's pseudo-types (`undefined8`, `CONCAT44`, `SUB168`), not an LLM.

**Links:**
- GitHub: https://github.com/yuatemycat/SuperGhidra
- MCP Server: https://github.com/yuatemycat/SuperGhidraMCP
- PyPI: `pip install superghidra`

I'd appreciate feedback on the overlay synchronization workflow and any odd MSVC/MFC binaries you test against it!
```

---

### Post B: `r/LocalLLaMA` & `r/ClaudeAI`

**Title:** SuperGhidra + SuperGhidraMCP: Guardrailed multi-agent Ghidra reverse engineering with Z3 formal verification

**Body:**
```markdown
Hi everyone,

If you've tried using AI coding agents (Claude Desktop, Cursor, Antigravity, Claude Code) to reverse-engineer binaries with Ghidra, you've likely hit two problems:
1. Connecting multiple agents to Ghidra's headless API or Python bridge either causes `.rep` lock collisions or corrupts the project database.
2. Unchecked LLMs hallucinate structure definitions, rename incorrect functions, and invent nonexistent struct fields.

We built **SuperGhidra** and its companion MCP server **SuperGhidraMCP** (38 tools) to provide safe, concurrent multi-agent reverse engineering:

- **Isolated Session Forks:** Agents operate on isolated forks against a warm, read-only Ghidra oracle daemon (`127.0.0.1:5073`). Reads hit a 5 µs shared-memory ring buffer or SQLite cache; writes go to a private delta journal.
- **Obligation Ledger Gate:** Candidate struct commits and symbol renames are gated through deterministic verification (`VTableSlotVerifier`, `FieldDisplacementVerifier`, `AllocationSizeVerifier`). If an agent hallucinates a 3-slot vtable when the binary shows 7 dereferences, the commit is rejected.
- **Z3 P-Code Verification:** Basic block simplifications are checked for mathematical equivalence against pure-Python lifted P-code using Z3 SMT solving. If an instruction contains floats or unsupported behavior, the gate returns `UNKNOWN` and rejects the speculative rewrite.
- **Live GUI Watcher:** All approved mutations can be watched and synced live into an open Ghidra CodeBrowser window (`superghidra overlay-sync --watch`) via atomic transactions.

**Setup (Claude Desktop / Cursor / Antigravity):**
```json
{
  "mcpServers": {
    "superghidra": {
      "command": "superghidra-mcp",
      "args": ["-t", "stdio", "--project-path", "<path_to_gpr_or_binary>"],
      "env": {
        "GHIDRA_INSTALL_DIR": "E:\\03_Devops\\ghidra",
        "JAVA_HOME": "E:\\03_Devops\\jdk-21"
      }
    }
  }
}
```

- SuperGhidra (Core Engine): https://github.com/yuatemycat/SuperGhidra
- SuperGhidraMCP (MCP Server): https://github.com/yuatemycat/SuperGhidraMCP
```

---

## 3. Discord (Community & Server Announcements)

**Channels:** `#tools`, `#reverse-engineering`, `#mcp`, `#announcements`

```text
Hey everyone! Just released **SuperGhidra 0.3.1** — high-performance Python tooling and a lock-free daemon for Ghidra:

- 🚀 **Zero `.rep` Lock Contention:** Keeps a read-only Ghidra instance warm on `127.0.0.1:5073` (5.12 µs IPC, SQLite L2 cache). Writes go to `ghidra_overlay.json` and sync live into an open Ghidra GUI window with `superghidra overlay-sync --watch`.
- ⚡ **Pure-Python MSVC & MFC Recovery:** Recovers MSVC RTTI class trees, MFC `CRuntimeClass` descriptors, and `CArchive::Serialize()` field layouts directly from PE binaries without touching the JVM or launching Ghidra (~1s on 750+ classes).
- 🛡️ **Formal Z3 Equivalence Gate:** Verifies rewritten C logic against lifted ARM64/x86 P-code via Z3, rejecting hallucinated agent mutations.
- 🔌 **38-Tool MCP Server:** Built-in multi-agent session forks for Claude Desktop, Cursor, Antigravity, and Claude Code.

GitHub: https://github.com/yuatemycat/SuperGhidra
Release v0.3.1: https://github.com/yuatemycat/SuperGhidra/releases/tag/v0.3.1
Install: `pip install superghidra`
```

---

## 4. LinkedIn (Technical / Engineering Network)

```text
Reverse engineering stripped enterprise binaries with Ghidra often runs into two operational bottlenecks: 5–15 second JVM startup latency per headless script invocation, and exclusive file lock collisions on .rep projects whenever the interactive Ghidra GUI is open.

To solve this, I've open-sourced SuperGhidra (v0.3.1) and its companion Model Context Protocol (MCP) server:

Architecture highlights:
1. Lock-Free Oracle Daemon: Decouples binary read operations from write mutations. A persistent background daemon serves queries across an L1 shared-memory ring buffer (5.12 µs roundtrip) and an L2 SQLite cache (>100k req/s).
2. Non-Destructive Write Overlays: Mutations are recorded in append-only JSON journals (ghidra_overlay.json) and synced live into active Ghidra CodeBrowser sessions via atomic transactions, preventing database corruption when multiple agents or scripts run concurrently.
3. Zero-JVM C++ Recovery: Standalone PE/ELF parsers recover MSVC RTTI hierarchies and MFC CRuntimeClass / CArchive field layouts in pure Python without launching a JVM.
4. Formal SMT Verification: Includes a pure-Python P-code lifter coupled with a Z3 solver to verify semantic equivalence before committing speculative code restructurings.

The repository includes a 6-job CI matrix across Ubuntu and Windows Server with 747 automated tests.

Source Code: https://github.com/yuatemycat/SuperGhidra
Release Notes: https://github.com/yuatemycat/SuperGhidra/releases/tag/v0.3.1

#ReverseEngineering #Cybersecurity #SoftwareEngineering #Ghidra #Python #Compilers #BinaryAnalysis
```
