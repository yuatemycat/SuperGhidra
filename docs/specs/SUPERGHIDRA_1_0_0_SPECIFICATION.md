# SuperGhidra 1.0.0 — Agent-First Architecture & REA Integration Specification

**Version:** `1.0.0`  
**Target Repository:** [yuatemycat/SuperGhidra](https://github.com/yuatemycat/SuperGhidra)  
**Reference Architecture:** [morluto/rea (Reverse Engineer Anything)](https://github.com/morluto/rea)  
**License:** Apache-2.0  

---

## 1. Executive Summary: Performance with Evidence-Gated Agent Contracts

SuperGhidra solves the systems bottlenecks that make scripting and running AI agents against stock NSA Ghidra slow:
- Persistent read-only daemon (`127.0.0.1:5073`) eliminating 5–15 second headless JVM startup overhead and `.rep` project lock contention.
- Sub-millisecond SQLite L2 query cache with 1-hop invalidation DAG.
- 5.12 µs zero-copy shared-memory (SHM) ring buffer.
- WGPU / SIMD ARM64 instruction scanner (127.25M–143.95M insn/s).
- Z3 SMT P-code equivalence checker.
- Compilable C cleanup filter lifting HumanEval-Decompile pass rates from 8.26% (stock Ghidra) to 22.69% (294 / 1,296 functions) with zero regressions.

Meanwhile, [morluto/rea](https://github.com/morluto/rea) has established an agent-investigation protocol across Claude Code, Cursor, Codex, and Gemini CLI by introducing:
- Summary-first Model Context Protocol (MCP) pagination.
- Explicit epistemic tagging (`observed`, `inferred`, `unknown`).
- Cross-call high-P-code value tracing.
- Crash-resumable bulk exports.
- Ghidra-free Mach-O/Swift/IL2CPP/Rust static readers.

**SuperGhidra `1.0.0`** merges both designs: keeping SuperGhidra's lock-free daemon, `merge_fork` overlay concurrency, WGPU shaders, and Z3/C-filter pipeline while upgrading its agent-facing RPC/MCP layer, static format parsers, and cross-call P-code tracer—and shipping a drop-in `superghidra[rea]` provider bridge.

| Architectural Pillar | Pre-1.0 SuperGhidra Baseline | SuperGhidra `1.0.0` Scope | Target Package |
| :--- | :--- | :--- | :--- |
| **MCP & Daemon Pagination** | Full JSON RPC/SHM payloads from SQLite L2 cache (`127.0.0.1:5073`) | Summary-first responses with retained `parent_evidence_id`, facet paging via `inspect_analysis_view`, and compact/full MCP schema profiles | `superghidra.core` / `superghidra.mcp` |
| **Epistemic & Obligation Ledger** | Z3 returns `UNKNOWN` on floats/loops; LLM naming gates commits on vtable/offset checks | Universal `EvidenceEnvelope` (`observed` / `inferred` / `unknown`), reference provenance tags, truncation counters, and `ReconstructionObligationLedger` | `superghidra.core.ledger` |
| **P-Code Value Tracing & Jump Tables** | Intra-snippet ARM64 integer P-code lifter + Z3 equivalence checker | Inter-procedural high-P-code def-use graphs (`trace_native_values`), AST `block_membership` vs. `is_dead` separation, and WGPU + bounds-proven AArch64 jump tables | `superghidra.lifters` / `superghidra.acceleration` |
| **Bulk Compilable Export** | Single-target CLI `superghidra decompile` and `superghidra filter` | Crash-resumable `superghidra decompile-all --resume` with inode locking, `decompile-index.json` manifest, and batched compilable C filtering | `superghidra.cli` / `superghidra.core` |
| **Ghidra-Free Static Formats** | ELF/PE/Mach-O loader, MSVC RTTI, MFC `CRuntimeClass`, `Serialize()`, `CArchive`, DWARF 5 | Mach-O `LC_DYLD_CHAINED_FIXUPS` (`arm64e`), Obj-C & `__swift5_types` vtables, Unity IL2CPP `global-metadata.dat`, and Rust `.dep-v0` / Go build metadata | `superghidra.formats` |
| **REA Ecosystem Bridge** | Standalone CLI and Python SDK (`import superghidra as sg`) | `superghidra[rea]` bridge replacing REA's cold headless Ghidra runner and read-only Windows P0 with SuperGhidra's warm daemon and `merge_fork` overlays | `superghidra.integrations.rea_bridge` |

---

## 2. Pillar 1: Summary-First MCP & Daemon Pagination

When an AI coding agent inspects a large binary, returning full decompiled dossiers, call graphs, or large structs inline rapidly exhausts the context window. SuperGhidra `1.0.0` introduces retained evidence paging directly inside the `127.0.0.1:5073` SQLite L2 cache.

### 2.1 Schema Profiles & Read/Mutate Boundary Descriptors

The integrated MCP server is controlled by two configuration options:
- **Input Schema Profile (`SUPERGHIDRA_MCP_INPUT_SCHEMA_PROFILE=compact|full`):** Defaults to `compact` to minimize token overhead during `tools/list` registration while maintaining full canonical validation on the daemon.
- **Output Schema Profile (`SUPERGHIDRA_MCP_OUTPUT_SCHEMA_PROFILE=compact|full|off`):** Defaults to `compact` for clients that cap `tools/list` frames.
- **Explicit Read vs. Mutate Surface (`mcp.superghidra.json`):** Declares a strict boundary separating pure read-only queries (`open_binary`, `analyze_function`, `inspect_analysis_view`, `trace_native_values`, `prove_equivalence`) from gated state mutations (`commit_overlay_rename`, `commit_struct_layout`, `merge_fork`). Read queries never acquire locks or touch `.rep`; mutations write exclusively to fork journals and require passing structural/Z3 checks before `merge_fork` replay.

### 2.2 SQLite L2 Retained Evidence Schema (`parent_evidence_id`)

Every daemon query computes a deterministic `evidence_id` (`ev_<sha256_prefix>`) keyed by `(target_sha256, overlay_revision, analysis_profile_digest, operation, canonical_selector)`.

```sql
-- Added to superghidra/core/cache.py schema in 1.0.0
CREATE TABLE IF NOT EXISTS retained_evidence (
    evidence_id TEXT PRIMARY KEY,
    target_sha256 TEXT NOT NULL,
    overlay_revision INTEGER NOT NULL DEFAULT 0,
    analysis_profile_digest TEXT NOT NULL,
    operation TEXT NOT NULL,
    canonical_address TEXT,
    retention_mode TEXT NOT NULL DEFAULT 'complete-record',
    summary_json BLOB NOT NULL,          -- LZ4/Zstd compressed summary payload
    facets_json BLOB NOT NULL,           -- LZ4/Zstd compressed full dossier facets
    created_at_ms INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_evidence_lookup 
ON retained_evidence(target_sha256, overlay_revision, operation, canonical_address);
```

### 2.3 Two-Stage Dossier Retrieval (`analyze_function` → `inspect_analysis_view`)

Over MCP, `analyze_function` is summary-first by default (`detail="summary"`). It returns the compilable C signature, basic block/instruction counts, top-level caller/callee counts, Z3 verification status, and `parent_evidence_id`:

```json
{
  "evidence_id": "ev_9f8a2b1c4d5e",
  "parent_evidence_id": "ev_9f8a2b1c4d5e",
  "retention": "complete-record",
  "target_sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
  "overlay_revision": 4,
  "procedure": {
    "canonical_address": "0x140001000",
    "observed_name": "CMyDoc::Serialize",
    "name_provenance": "overlay_pending",
    "signature_compilable_c": "void CMyDoc_Serialize(CMyDoc *this, CArchive *ar);",
    "compilable_filter_status": "passed_gcc_syntax"
  },
  "facet_counts": {
    "compilable_c_lines": 48,
    "raw_ghidra_c_lines": 62,
    "pcode_ops": 312,
    "def_use_edges": 840,
    "incoming_xrefs": 14,
    "outgoing_calls": 6,
    "recovered_struct_fields": 9
  },
  "limitations": []
}
```

When an agent needs specific details, it calls `inspect_analysis_view` using `parent_evidence_id` without re-running Ghidra or re-lifting P-code:

```python
# superghidra/core/views.py
from typing import Literal, Optional
from pydantic import BaseModel, Field

class InspectAnalysisViewRequest(BaseModel):
    parent_evidence_id: str = Field(..., description="Retained Evidence ID from a prior summary call")
    facet: Literal[
        "compilable_c",
        "raw_c",
        "assembly",
        "pcode_ops",
        "def_use_edges",
        "incoming_xrefs",
        "outgoing_calls",
        "struct_fields",
        "jump_tables"
    ]
    offset: int = Field(0, ge=0)
    limit: int = Field(64, ge=1, le=500)
    filter_expr: Optional[str] = None
```

If a client requests `detail="complete"` and the serialized payload exceeds the transport frame limit (default 8 MiB), SuperGhidra returns a structured `resource_constraint` with `details.resource = "transport"` and the retained `parent_evidence_id`, allowing the agent to page via `inspect_analysis_view` or stream to disk via `export_evidence_bundle`.

---

## 3. Pillar 2: Epistemic Tagging & Reconstruction Obligation Ledger

SuperGhidra enforces formal soundness: its Z3 prover returns `UNKNOWN` rather than guessing on floating-point ops, unhandled instructions, or unbounded loops, and its LLM naming pipeline refuses to commit symbols or structs until vtable slots, field offsets, and allocation sizes pass structural validation.

SuperGhidra `1.0.0` generalizes this into a repository-wide epistemic contract.

### 3.1 The Universal `EvidenceEnvelope`

Every tool response from `superghidra.core`, `superghidra.formats`, `superghidra.lifters`, and `superghidra.diff` wraps findings in an `EvidenceEnvelope` separating observed static/runtime facts from inferred heuristics and unknown boundaries:

```python
# superghidra/core/evidence_ledger.py
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional

class EpistemicStatus(str, Enum):
    OBSERVED = "observed"     # Direct binary bytes, symbol table entries, or Frida runtime reads
    INFERRED = "inferred"     # Heuristics: CFG feature matches, candidate names, decompiler types
    UNKNOWN = "unknown"       # Unresolved indirect calls, Z3 float/loop bailouts, uninitialized memory

class ReferenceProvenance(str, Enum):
    ANALYSIS = "analysis"                 # Ghidra auto-analyzer or SuperGhidra static pass
    DEFAULT = "default"                   # Default platform/loader assumption
    IMPORTED = "imported"                 # DWARF 5, PDB, IDA .til, or FLIRT .sig match
    USER_DEFINED = "user_defined"         # Committed JSON overlay or human annotation
    SMT_PROVEN = "smt_proven"             # Verified equivalent by SuperGhidra's Z3 P-code prover
    OVERLAY_PENDING = "overlay_pending"   # Staged in an unmerged agent fork journal

@dataclass
class CoverageBoundary:
    facet: str
    examined_count: int
    decoded_count: int
    omitted_count: int
    truncated: bool
    reason: Optional[str] = None

@dataclass
class EvidenceEnvelope:
    evidence_id: str
    target_sha256: str
    overlay_revision: int
    epistemic_status: EpistemicStatus
    provenance: ReferenceProvenance
    data: Dict[str, Any]
    coverage: List[CoverageBoundary] = field(default_factory=list)
    limitations: List[str] = field(default_factory=list)
```

### 3.2 The Reconstruction Obligation Ledger (`merge_fork` Gatekeeper)

When multiple agents work in parallel forks to rename symbols, recover structs, or rewrite functions into standard C, SuperGhidra `1.0.0` tracks a **Reconstruction Obligation Ledger** inside the JSON overlay journal before `merge_fork` commits changes to the main session:

| Obligation Type | Verification Gate Before `merge_fork` Commit | Outcome on Failure / Conflict |
| :--- | :--- | :--- |
| **Struct & Class Layout (`rtti-recover`, `serialize_trace`)** | Checks vtable slot count, `CRuntimeClass` inheritance chain, field offsets against `LDR`/`STR` displacements, and heap allocation size (`operator new` / `malloc` args) | Rejects struct commit; records offset collision in `limitations` |
| **Decompiled C Cleanup (`superghidra filter`)** | Compiles filtered C under `gcc -fsyntax-only -Wall` and runs `superghidra.lifters.z3_checker` on integer basic blocks against lifted P-code | If Z3 returns `SAT` (counterexample found), reverts to conservative C cast; if `UNKNOWN` (floats/loops), tags block `epistemic_status: "inferred"` |
| **Cross-Version Struct Rewrite (`superghidra.diff`)** | Verifies CFG feature cosine similarity threshold and proves via Z3 that rewritten struct field offsets preserve memory access width and sign extension | Refuses automatic rewrite on ambiguous matches; emits candidate addresses as `input_ambiguity` |
| **Concurrent Agent Edits (`merge_fork`)** | Compares `before_value` in the agent's fork journal against current `main_overlay` state | Discards stale-base edit (`conflict_stale_base`) and assigns an open obligation for the agent to re-evaluate against the updated overlay |

---

## 4. Pillar 3: Inter-Procedural High-P-Code Value Tracing & WGPU Jump Tables

SuperGhidra's `lifters` package includes a pure-Python ARM64 integer P-code lifter, x86/ARM/Thumb decoders, and a Z3 equivalence prover, while `acceleration` scans 20 MB ARM64 blocks in under 1 second via WGPU DirectX 12 / Vulkan compute shaders. SuperGhidra `1.0.0` extends these with two static analysis primitives:

### 4.1 Cross-Call High-P-Code Def-Use Graphs (`trace_native_values`)

`superghidra trace-values` composes **high-P-code def-use graphs across statically resolved calls** directly inside the daemon:

1. **Inter-Procedural Parameter & Return Binding:** Logical `CALL` input varnodes at the call site bind to the callee's recovered parameter ordinals (`param_0..param_n`), and callee decoded `RETURN` P-code operations bind back to the caller's `CALL` output varnode.
2. **AST Block Membership vs. Stale `is_dead` Flags:** Ghidra's raw `PcodeBlockBasic.isDead()` flag can remain set even after the decompiler decodes a live block. SuperGhidra `1.0.0` inspects the decompiler C syntax tree (`ClangTokenGroup`) to report `block_membership: "ast_live" | "ast_elided"` alongside raw `pcode_is_dead`.
3. **Strict Resource & Pagination Budgets:** Each function dossier retains up to `3,000` P-code operations, `64` inputs per operation, and `12,000` def-use edges (8 MiB node payload cap, 32 MiB serialized trace cap), with explicit `omitted_ops` and `omitted_edges` counters and cycle-safe single-attempt memoization per procedure selector.
4. **Explicit Unknowns on Aliasing & State:** Stack `STORE` operations are labeled `stack_local_store` rather than assumed persistent global state; pointer aliasing, variadic bindings, and unresolved indirect calls are tagged `epistemic_status: "unknown"`.

```bash
# CLI usage in SuperGhidra 1.0.0
superghidra trace-values target.dll --procedure 0x140001000 --max-depth 3 --max-nodes 2500 -o value_graph.json
```

### 4.2 Hybrid WGPU + Bounds-Proven AArch64 Jump-Table Recovery

Stock disassemblers frequently misclassify optimized ARM64 byte (`LDRB`) and halfword (`LDRH`) relative switch tables. SuperGhidra `1.0.0` pairs its WGPU scanner with formal jump-table verification:

- **Stage 1 (WGPU / NumPy SIMD Sweep):** Sweeps `.text` to locate candidate `CMP` + `B.HI`/`B.HS` bounds checks paired with `ADR`/`ADRP` table base loads, `LDRB`/`LDRH`/`LDRSW` indexed loads, and scaled `ADD` + `BR` indirect dispatches.
- **Stage 2 (Z3 & Unsigned Bounds Verification):** Proves the exact case count $N$ from the dominating unsigned bounds check, reads exactly $N$ entries from the backing `.rodata`/`.text` table, separates proven numeric `mappings` from the explicit `default_target` and `data_sources`, and marks any non-literal or out-of-bounds entry as `null` (`unresolved_case`) rather than zipping mismatched label/destination arrays.

---

## 5. Pillar 4: Crash-Resumable Whole-Binary Compilable Export (`superghidra decompile-all`)

While SuperGhidra's SQLite L2 cache serves single functions in under 0.05 ms, agents rebuilding entire modules or performing cross-binary audits need a fault-tolerant bulk exporter. Combining journaled exports with SuperGhidra's compilable C filter (22.69% HumanEval-Decompile pass rate) and Z3 prover yields `superghidra decompile-all`:

```bash
# Export all internal functions through SuperGhidra's compilable C filter and Z3 checker
superghidra decompile-all target.exe \
  --output ./decomp_out \
  --filter-compilable \
  --verify-z3 \
  --arch x86_64 \
  --resume
```

### 5.1 Execution & Fault-Tolerance Contract

1. **Inode & PID Directory Locking:** An active run acquires an exclusive lock on `--output` identified by `(st_dev, st_ino, holder_pid)`. Concurrent runs against the same directory are refused immediately with the holder's PID; if a prior holder crashed, the next `--resume` run verifies process termination and recovers the lock.
2. **Append-Only Journal & `--resume` Integrity:** Every completed function appends a committed record to `.superghidra-export.journal.jsonl` containing `(canonical_address, file_relpath, file_sha256, status, z3_equivalence, filter_applied)`. On `--resume`, SuperGhidra verifies that `(target_sha256, analysis_profile_digest, overlay_revision)` match the original run, hashes existing `.c` files in bounded chunks to skip intact writes, ignores any torn final journal line from a power loss/crash, and attempts unvisited procedures before retrying prior timeouts.
3. **External Import Skipping & Circuit Breaker:** Procedures classified as `external` (such as PLT/IAT imports) are recorded in `decompile-index.json` with `status: "external"` without invoking the decompiler or writing empty `.c` files. If 5 consecutive functions fail to write or read (e.g., disk full), the export halts cleanly while preserving `decompile-index.json` for a later `--resume`.
4. **Manifest-Only Agent Return:** When called via MCP (`decompile_all`), the tool writes `.c` files to disk and returns only the compact manifest (`counts`, `output_directory`, `analysis_profile_digest`, and capped failure diagnostics up to 2,048 UTF-8 bytes) so zero pseudocode tokens flood the agent's context window.

---

## 6. Pillar 5: Expanded Ghidra-Free Static Parsers (`superghidra.formats`)

`superghidra.formats` already provides Ghidra-free Windows/C++ recovery (`msvc_class_recovery`, `serialize_trace`, `CArchive`, `.til`, and FLIRT `.sig`). SuperGhidra `1.0.0` adds three static format modules:

| Module in `superghidra.formats` | Target Artifacts | What It Recovers Without Starting Ghidra | Epistemic & Safety Boundaries |
| :--- | :--- | :--- | :--- |
| **`apple_dispatch.py`** | macOS/iOS Mach-O (`x86_64`, `arm64`, `arm64e` universal/thin slices) | Decodes `LC_DYLD_CHAINED_FIXUPS` (including authenticated `arm64e` pointer rebases/binds) and legacy `LC_DYLD_INFO`; extracts 64-bit Objective-C classes, metaclasses, ivar offsets, protocols, and `__objc_catlist` categories; decodes `__swift5_types` nominal descriptors (`class`, `struct`, `enum`, `actor`), protocol conformances, and non-resilient Swift class vtable slots | Enforces default 64 MiB admission budget (configurable via `--max-input-bytes` up to 1 GiB); preserves raw `type_binding` when a Swift conformance targets an external dylib symbol rather than guessing display names |
| **`il2cpp_metadata.py`** | Unity `global-metadata.dat` (versions 24, 27, 29, 31, and 39) + optional native `.so`/`.dll` | Extracts assembly images, namespaces, type/method/field/property definitions, parameter lists (indexed by `method_indices`), and string literals; optionally joins metadata indices to static native method RVAs | Rejects unrecognized/encrypted headers cleanly; marks byte-pattern address joins as `epistemic_status: "inferred"` |
| **`rust_go_metadata.py`** | Compiled Rust and Go ELF/PE/Mach-O binaries | Parses `.dep-v0` (`cargo-auditable`) zlib-compressed JSON to recover exact Rust crate names, versions, and dependency DAG edges plus inferred `/rustc/<40-hex>/` commit hashes; parses Go `.go.buildinfo` and `pclntab` headers for compiler version, module replacements, and build flags | Reports a missing `.dep-v0` section as `observed_absence` (`null` metadata), never as proof that the binary has zero dependencies |

```bash
# Static CLI commands in SuperGhidra 1.0.0 (no JVM or Ghidra installation required)
superghidra apple-dispatch TargetApp.macho --arch arm64e -o swift_objc_vtables.json
superghidra il2cpp-recover global-metadata.dat --binary libil2cpp.so -o unity_types.json
superghidra crate-audit target_rust.exe -o rust_deps.json
```

---

## 7. Pillar 6: The `superghidra[rea]` Provider Bridge

REA has an active agent user base, but its built-in Ghidra provider starts cold headless JVM processes (with a 330s timeout) and restricts Windows x64 to experimental read-only sessions. SuperGhidra `1.0.0` adds an optional `rea` extra (`pip install "superghidra[rea]"`) that exposes SuperGhidra's `127.0.0.1:5073` daemon and 5.12 µs SHM ring buffer as a backend for REA and any MCP client.

### 7.1 Bridge Routing & Execution Layers (`superghidra.integrations.rea_bridge`)

| Layer | Component | Transport / Latency | Handled Operations |
| :--- | :--- | :--- | :--- |
| **1. Agent Client** | Claude Code, Cursor, Codex, Gemini CLI | MCP `stdio` / SSE (`compact` schema profile) | Issues standard REA native calls or SuperGhidra extension calls |
| **2. Adapter Shim** | `superghidra.integrations.rea_bridge` | In-process Python async router | Maps REA contracts (`open_binary`, `analyze_function`, `trace_native_values`, `decompile_all`, `set_address_name`, `annotate_native_function`) and exposes `sg_filter_c`, `sg_z3_prove`, `sg_wgpu_sweep`, `sg_rtti_recover`, `sg_serialize_trace`, and `sg_diff_versions` |
| **3. Warm Ghidra Core** | `superghidra.core` Daemon (`127.0.0.1:5073`) | 5.12 µs SHM ring buffer & <0.01 ms SQLite L2 cache | Serves cached decompilation, xrefs, P-code value graphs, and lock-free JSON overlay / `merge_fork` mutations |
| **4. Fast Bypass Engines** | `formats`, `lifters`, `acceleration`, `storage` | Direct NumPy SIMD / WGPU DirectX 12 / Z3 | Runs ARM64 `ADRP` sweeps, Z3 equivalence proofs, compilable C filtering, and Ghidra-free PE/ELF/Mach-O/IL2CPP/Rust parsing without touching the JVM |

### 7.2 Capabilities Enabled by the Bridge

- **Eliminates Cold Start Latency:** Once a binary is loaded in the `127.0.0.1:5073` daemon, repeated `function`, `decompile`, and `xrefs` calls hit SuperGhidra's SQLite L2 cache in <0.01 ms instead of spawning headless JVM scripts.
- **Read/Write Annotations on Windows x64:** Routes `annotate_native_function`, `set_address_name`, and `set_addresses_names` into SuperGhidra's lock-free JSON overlay and `merge_fork` journal—giving Windows users conflict-checked renames and comments without touching `.rep`.
- **Compilable C & Z3 Verification:** When an agent calls `analyze_function` or `decompile_all` through the bridge, SuperGhidra attaches `compilable_c` (filtered through `superghidra filter`) and `z3_verification` metadata alongside raw Ghidra pseudocode.

---

## 8. Package Layout & Phased Rollout Checklist

### 8.1 Updated `pyproject.toml` Extras

```toml
[project]
name = "superghidra"
version = "1.0.0"
requires-python = ">=3.10"

[project.optional-dependencies]
smt = ["z3-solver>=4.13.0"]
gpu = ["wgpu>=0.15.0", "numpy>=1.26.0"]
storage = ["lz4>=4.3.3", "zstandard>=0.22.0"]
ghidra = ["pyghidra>=1.0.0"]
frida = ["frida>=16.2.0"]
rea = ["mcp>=1.2.0", "pydantic>=2.7.0"]
all = ["superghidra[smt,gpu,storage,ghidra,frida,rea]"]
```

### 8.2 Phased Implementation Milestones

1. **Milestone 1 — Core Ledger & Summary-First Cache (`superghidra/core`):**
   - Add `retained_evidence` and `obligation_ledger` tables to the `127.0.0.1:5073` SQLite L2 cache ([`cache.py`](../src/superghidra/core/cache.py)).
   - Implement `EvidenceEnvelope` (`observed` / `inferred` / `unknown` + `ReferenceProvenance`) and `inspect_analysis_view` facet paging.
   - Publish `contributions/mcp-servers/mcp.superghidra.json` declaring read-only vs. `merge_fork` mutation boundaries.
2. **Milestone 2 — Inter-Procedural P-Code & Jump-Table Verifier (`superghidra/lifters` & `acceleration`):**
   - Implement `trace_native_values` across statically resolved calls with 3,000-op / 12,000-edge dossier caps and `ast_live` vs. `pcode_is_dead` reporting.
   - Wire WGPU/SIMD `ADRP` sweep outputs into the unsigned-bounds AArch64 relative jump-table prover.
3. **Milestone 3 — Crash-Resumable `decompile-all` & Expanded `formats` (`superghidra/cli` & `formats`):**
   - Build `superghidra decompile-all --resume --filter-compilable --verify-z3` with `(st_dev, st_ino)` locking and `decompile-index.json`.
   - Add `apple_dispatch.py` (`LC_DYLD_CHAINED_FIXUPS`, Obj-C, `__swift5_types`), `il2cpp_metadata.py`, and `rust_go_metadata.py` with unit tests in the Ubuntu/Windows Python 3.10–3.12 CI matrix.
4. **Milestone 4 — `superghidra[rea]` MCP & CLI Bridge (`superghidra/integrations/rea_bridge.py`):**
   - Implement the MCP server and REA CLI provider shim over the 5.12 µs SHM ring buffer and `127.0.0.1:5073` daemon.
   - Run full regression benchmarks against the 1,296-function HumanEval-Decompile suite to verify zero refinement regressions.
