# CLAUDE.md — SuperGhidra Agent Operating Guide

Use this instruction file when operating as an autonomous reverse-engineering agent (Claude Code, Cursor, Antigravity, or custom MCP client) inside a SuperGhidra workspace.

## 1. Golden Rules for Tool Selection

1. **NEVER use `superghidra decompile` on real functions:**
   - `superghidra decompile` is an experimental zero-JVM integer-only P-code lifter. It handles function prologues, direct calls, integer register operations, and ARM64 lowering (11 of 154 exports decompiled on test DLLs). Calling it on production functions with complex branches, memory dereferences, or floats will exit non-zero.
   - **For real decompilation, use `python -m superghidra.core.ghidra_oracle decompile <addr>`** (or the `decompile_function` / `oracle_decompile` MCP tool).
   - **To filter raw decompiler output into clean compilable C, use `superghidra filter <raw.c> -o <clean.c>`.** This strips stack canaries, simplifies stride calculations, replaces Ghidra pseudo-types (`undefined8`, `CONCAT44`, `SUB84`) with `<stdint.h>` types, and injects required standard headers.

2. **Use standalone zero-JVM tools before spinning up Ghidra:**
   - Do not pay JVM startup costs for tasks solvable with direct binary parsing.
   - For PE/COFF header analysis, MSVC RTTI class hierarchy extraction, MFC `CRuntimeClass` table recovery, and `CArchive::Serialize()` field tracing, run standalone tools:
     - `superghidra rtti-recover <binary> -o classes.json`
     - `python -m superghidra.formats.msvc_class_recovery <binary>`
     - `python -m superghidra.formats.serialize_trace <binary> <ClassName>`
   - These tools run in plain Python and require no JVM, no headless analyzer, and no `.rep` project locks.

3. **Never write directly to a locked `.rep` database:**
   - Ghidra locks its project directory against concurrent writers.
   - All symbol renames, comments, and struct definitions route to the **JSON write-overlay** (`ghidra_overlay.json`) and CRDT fork journals.
   - The persistent daemon serves read queries from its SQLite cache and overlays pending edits in memory.
   - To apply agent mutations into an active Ghidra GUI session without restarting Ghidra, generate an overlay script:
     - `superghidra overlay-sync --overlay ghidra_overlay.json --out ghidra_gui_overlay_sync.py`
     - The human analyst executes this script in Ghidra's Script Manager inside an atomic transaction.

## 2. Decision Matrix: Task -> Exact Tool Call

| Agent Goal | Correct Command / Tool | Do NOT Use |
| :--- | :--- | :--- |
| Check if daemon is alive | `python -m superghidra.core.ghidra_oracle status` | Spawning a new headless JVM per query |
| Decompile a function | `python -m superghidra.core.ghidra_oracle decompile <addr>` (pass through `superghidra filter <raw.c> -o <clean.c>` for clean C) | `superghidra decompile` on production functions |
| Recover MSVC RTTI / MFC classes | `superghidra rtti-recover <binary> -o classes.json` or `python -m superghidra.formats.msvc_class_recovery <binary>` | Manual vtable walking in headless Ghidra |
| Scan ARM64 binary for `ADRP+ADD/LDR` | `python -m superghidra.acceleration.gpu_adrp_scanner <binary>` (auto-routes NumPy SIMD < 10 MB, WGPU >= 10 MB) | Single-threaded Python byte loops |
| Seed ARM64 function entrypoints | `python -m superghidra.acceleration.gpu_function_seeder <binary>` or MCP `gpu_seed_functions` | Full linear sweep disassembler |
| Verify equivalence of rewritten logic | `python -m superghidra.lifters.smt_pcode_verifier ...` or MCP `verify_smt_equivalence` | Guessing semantic equivalence without Z3 proof |
| Rename a function or symbol | `python -m superghidra.core.ghidra_oracle rename <addr> <name>` or MCP `rename_function` | Direct `.rep` file modification |
| Add a comment to an address | `python -m superghidra.core.ghidra_oracle comment <addr> <text>` or MCP `set_comment` | Direct `.rep` file modification |
| Query incoming cross-references | `python -m superghidra.core.ghidra_oracle refs <addr>` or MCP `list_xrefs` | Ad-hoc text search over binary files |
| Inspect virtual function tables | `python -m superghidra.core.ghidra_oracle vtable <addr> [count]` | Manual pointer math in hex editors |
| Disassemble raw instructions | `python -m superghidra.core.ghidra_oracle disassemble <addr> [count]` or MCP `disassemble` | Spawning fresh headless instances per block |
| Translate VA <-> RVA | `python -m superghidra.core.ghidra_oracle rva <addr>` or MCP `rva_translate` | Manual image base arithmetic |
| Push overlay edits to Ghidra GUI | `superghidra overlay-sync --overlay ghidra_overlay.json --out ghidra_gui_overlay_sync.py` | Telling user to restart Ghidra |
| Manage multi-agent session forks | MCP `list_forks`, `merge_fork(auto_discard=True)`, `discard_fork` | Concurrent uncoordinated writes to main state |

## 3. Standard 5-Step Autonomous RE Workflow

Follow this 5-step sequence when analyzing a target binary:

### Step 1: Fast Zero-JVM Triage
Extract static metadata, exports, imports, and class hierarchies before starting Ghidra:

1. **PE / MSVC / MFC Targets:**
   ```bash
   # Recover MSVC RTTI structures and MFC CRuntimeClass tables
   superghidra rtti-recover <target_binary> -o triage_classes.json

   # Or run via Python module:
   python -m superghidra.formats.msvc_class_recovery <target_binary>

   # Trace CArchive serialization field layouts:
   python -m superghidra.formats.serialize_trace <target_binary> <ClassName>
   ```

2. **ARM64 Targets:**
   ```bash
   # Sweep ADRP+ADD/LDR pairs (auto-routes NumPy SIMD < 10 MB, WGPU >= 10 MB):
   python -m superghidra.acceleration.gpu_adrp_scanner <target_binary>

   # Fast prologue function candidate discovery:
   python -m superghidra.acceleration.gpu_function_seeder <target_binary>
   ```

3. **Binary Structure Inspection:**
   ```bash
   python -m superghidra.formats.binary_loader <target_binary>
   ```

### Step 2: Ensure the Lock-Free Daemon is Running
Verify the persistent TCP daemon on `127.0.0.1:5073`:

```bash
python -m superghidra.core.ghidra_oracle status
```

- If the daemon is active, it responds with uptime, function count, and L2 cache hit rate.
- If offline, `ghidra_oracle.py` client commands auto-spawn the background daemon. You can also start it manually:
  ```bash
  python -m superghidra.core.ghidra_oracle serve --project-dir <path_to_projects> --project-name <name> --program-name <binary> --mode balanced
  ```
- Keep the project in read-only mode so the human analyst can keep their Ghidra GUI open simultaneously.
- Set the governor mode (`eco`, `balanced`, `turbo`, `auto`) based on system load:
  ```bash
  python -m superghidra.core.ghidra_oracle mode balanced
  ```

### Step 3: Iterative Decompilation & Cross-Reference Analysis
Query the warm daemon. Queries are served from the SQLite L2 cache in `< 0.01 ms` for repeat lookups:

1. **Cross-References and VTables:**
   ```bash
   # Inspect cross-references
   python -m superghidra.core.ghidra_oracle refs 0x140001000

   # Inspect virtual method table entries
   python -m superghidra.core.ghidra_oracle vtable 0x140005000 16
   ```

2. **Decompile Function:**
   ```bash
   python -m superghidra.core.ghidra_oracle decompile 0x140001000 > raw_decompile.c
   ```

3. **Filter to Compilable C:**
   ```bash
   superghidra filter raw_decompile.c -o clean_decompile.c
   ```
   Inspect `clean_decompile.c` for simplified types, cleaned control flow, and standardized integer definitions.

### Step 4: Guarded Mutation & Z3 Equivalence Verification
Before proposing a logic simplification, struct definition, or symbol rename, validate the change through formal and structural guards:

1. **Z3 Equivalence Verification:**
   - Run the SMT equivalence verifier on proposed integer logic or expressions:
     ```bash
     python -m superghidra.lifters.smt_pcode_verifier ...
     ```
     Or invoke MCP `verify_smt_equivalence`.
   - Interpretation rules:
     - `UNSAT`: Formal equivalence proven. No input exists where decompiled C diverges from native P-code. Proceed with commit.
     - `SAT`: Counterexample found. Outputs diverge. Reject the proposed rewrite.
     - `UNKNOWN`: Solver reached timeout, floating point operations, unhandled instructions, or unbounded loops. **Do not claim formal equivalence.** Document the change as heuristic in comments.

2. **EvidenceLedger Structural Invariants:**
   All struct layouts, field renames, and vtable assignments must satisfy three physical constraints:
   - **VTable Slot Index:** Slot offset must satisfy natural pointer alignment (`offset % pointer_size == 0`). Slot index must fit within known hierarchy bounds.
   - **Allocation Size:** Allocation sources (`malloc`, `operator new`, pool allocators) set strict size limits. Struct size must satisfy `struct_size <= allocation_size`.
   - **Struct Field Displacement:** Field accesses must follow natural alignment (`offset % access_size == 0`). Access must stay within bounds (`offset + access_size <= total_struct_size`). Disjoint fields must not collide.
   - If EvidenceLedger rejects an edit, inspect the offset mismatch. Do not force the mutation.

3. **Stage Mutations to Write-Overlay:**
   ```bash
   # Rename function
   python -m superghidra.core.ghidra_oracle rename 0x140001000 ProcessPacket

   # Add comment
   python -m superghidra.core.ghidra_oracle comment 0x140001000 "Validated against packet header schema"
   ```
   Edits write to `ghidra_overlay.json` without touching `.rep` project files.

### Step 5: Close the Loop with the Human Analyst
Provide the human analyst with a clean path to integrate your mutations:

1. **If the Ghidra GUI is Open:**
   Generate the synchronization script:
   ```bash
   superghidra overlay-sync --overlay ghidra_overlay.json --out ghidra_gui_overlay_sync.py
   ```
   Instruct the analyst:
   > Run `ghidra_gui_overlay_sync.py` in Ghidra's **Script Manager**.
   > Mutations will commit in an atomic `currentProgram.startTransaction(...)` block without requiring a project restart.

2. **If Inspecting Changes Before Sync:**
   Print a summary diff of all staged mutations:
   ```bash
   superghidra overlay-sync --overlay ghidra_overlay.json --diff
   ```

3. **Multi-Agent Collaborative Sessions & Auto-Discard:**
   When running multiple agents on parallel tasks, isolate each agent in a session fork (`create_fork`). Merge into main via MCP `merge_fork(fork_id, auto_discard=True)` after verification.
   - **Auto-Discard:** Always pass `auto_discard=True` on `merge_fork`. Once all operations merge cleanly with zero pending conflicts (`pending_ops == 0`), SuperGhidra automatically deletes the fork's workspace directory and transaction journal to prevent storage leaks.
   - **Manual Cleanup:** Call `discard_fork(fork_id)` to explicitly drop abandoned or unneeded session forks.
   - The CRDT semilattice resolves conflicting field types using type confidence tiers and hardware instruction evidence.
