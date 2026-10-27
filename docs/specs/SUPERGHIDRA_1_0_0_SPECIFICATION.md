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
| **Epistemic & Obligation Ledger** | Z3 returns `UNKNOWN` on floats/loops; LLM naming gates commits on vtable/offset checks | Universal `EvidenceEnvelope` (`observed` / `inferred` / `unknown`), reference provenance tags, truncation counters, and `ReconstructionObligationLedger` | `superghidra.core.evidence_ledger` |
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
-- Added to superghidra/core/ghidra_oracle.py SQLite L2 cache schema in 1.0.0
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
superghidra decompile-all target.exe   --output ./decomp_out   --filter-compilable   --verify-z3   --arch x86_64   --resume
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

### 8.2 Detailed Phased Implementation Milestones

#### Milestone 1 — Core Retained Evidence & Summary-First Protocol
- **Target Modules:** `src/superghidra/core/ghidra_oracle.py`, `src/superghidra/core/views.py`, `src/superghidra/core/evidence_ledger.py`
- **MCP Configuration:** `contributions/mcp-servers/mcp.superghidra.json`
- **Key Tasks:**
  1. Add `retained_evidence` table to SQLite L2 cache with LZ4 / Zstandard compressed BLOB columns (`summary_json`, `facets_json`).
  2. Implement composite index on `(target_sha256, overlay_revision, operation, canonical_address)`.
  3. Add 30-day eviction policy and 2 GB configurable maximum cache size quota.
  4. Implement `evidence_id` generator using `ev_<sha256[:12]>` over normalized query tuples.
  5. Default `analyze_function` responses to `detail="summary"`.
  6. Implement `inspect_analysis_view` facet paging router across 9 facets (`compilable_c`, `raw_c`, `assembly`, `pcode_ops`, `def_use_edges`, `incoming_xrefs`, `outgoing_calls`, `struct_fields`, `jump_tables`).
  7. Implement input and output schema profile negotiation (`SUPERGHIDRA_MCP_INPUT_SCHEMA_PROFILE`, `SUPERGHIDRA_MCP_OUTPUT_SCHEMA_PROFILE`).
  8. Publish `mcp.superghidra.json` defining strict read-only vs. gated mutation surfaces.
- **Verification Suite:** `tests/core/test_evidence_paging.py` (24 test cases covering cache hits, misses, facet pagination, LRU eviction, and schema profile downshifting).

#### Milestone 2 — Universal Epistemic Tagging & Reconstruction Obligation Gatekeeper
- **Target Modules:** `src/superghidra/core/evidence_ledger.py`, `src/superghidra/diff/evidence_ledger.py`
- **Key Tasks:**
  1. Implement `EvidenceEnvelope` wrapper across all tool responses with `EpistemicStatus` (`observed`, `inferred`, `unknown`), `ReferenceProvenance` (`analysis`, `default`, `imported`, `user_defined`, `smt_proven`, `overlay_pending`), and `CoverageBoundary`.
  2. Wrap analysis returns in `ghidra_oracle.py`, `binary_diff_engine.py`, `msvc_class_recovery.py`, and `smt_pcode_verifier.py`.
  3. Wire `ReconstructionObligationLedger` into `merge_fork` pipeline:
     - Class/struct layout gate: vtable slot count, `CRuntimeClass` hierarchy, field displacement checks against `LDR`/`STR`, allocation size verifier.
     - Compilable C gate: syntax validation via `CompilableDecompilerFilter` and integer basic block Z3 proof.
     - Cross-version struct rewrite gate: CFG cosine similarity check, access width, and sign extension preservation.
     - Fork conflict resolution: detect `before_value` divergence against `main_overlay` and flag `conflict_stale_base` without corrupting state.
  4. Enforce truncation counters and coverage boundaries on all serialized collections.
- **Verification Suite:** `tests/core/test_evidence_ledger_obligations.py` (18 test cases covering envelope validation, gate failures, stale-base detection, and conflict isolation).

#### Milestone 3 — Inter-Procedural High-P-Code Value Tracing & Jump-Table Prover
- **Target Modules:** `src/superghidra/lifters/trace_values.py`, `src/superghidra/lifters/pcode_lifter_bridge.py`, `src/superghidra/acceleration/gpu_adrp_scanner.py`
- **Key Tasks:**
  1. Construct cross-call high-P-code def-use graphs (`trace_native_values`).
  2. Map call site logical `CALL` input varnodes to formal parameter ordinals (`param_0..param_n`).
  3. Map callee decoded `RETURN` P-code operations back to caller `CALL` output varnode.
  4. Parse decompiler `ClangTokenGroup` C syntax trees to distinguish `ast_live` from `ast_elided` blocks regardless of stale `PcodeBlockBasic.isDead()` flags.
  5. Enforce traversal limits: 3,000 P-code operations, 64 inputs/op, 12,000 def-use edges; 8 MiB node cap, 32 MiB trace cap; cycle-safe single-attempt recursion memoization.
  6. Implement hybrid WGPU / SIMD ARM64 sweep + Z3 formal unsigned bounds proof for relative jump tables (`CMP` + `B.HI`/`B.HS` + `ADR`/`ADRP` + `LDRB`/`LDRH`/`LDRSW`). Prove upper bound $N$, extract exactly $N$ entries, identify explicit `default_target`, and flag out-of-bounds or non-literal cases as `null` (`unresolved_case`).
- **Verification Suite:** `tests/lifters/test_trace_native_values.py` (16 test cases), `tests/acceleration/test_jump_table_prover.py` (12 test cases).

#### Milestone 4 — Crash-Resumable Bulk Compilable Export
- **Target Modules:** `src/superghidra/core/bulk_decompile.py`, `src/superghidra/__main__.py`
- **Key Tasks:**
  1. Implement cross-platform directory locking with `(st_dev, st_ino, holder_pid)`. Win32 `LockFileEx` / named mutexes on Windows, `fcntl.flock` on Linux. Stale lock dead-process detection and recovery.
  2. Implement append-only `.superghidra-export.journal.jsonl` recording `(canonical_address, file_relpath, file_sha256, status, z3_equivalence, filter_applied)`.
  3. Implement `--resume` reconciliation engine: target SHA-256 match, analysis profile digest match, chunked 64 KB SHA-256 validation of written `.c` files, torn-line discard, unvisited procedure priority.
  4. Implement external import filtering: record PLT/IAT imports in `decompile-index.json` with `status: "external"` without decompiler invocation.
  5. Implement 5-consecutive-error circuit breaker.
  6. Limit MCP `decompile_all` return payload to compact manifest (<2,048 UTF-8 bytes).
- **Verification Suite:** `tests/core/test_decompile_all_resumable.py` (15 test cases covering lock contention, crash resumption, torn journal recovery, and external import filtering).

#### Milestone 5 — Expanded Ghidra-Free Static Binary Parsers
- **Target Modules:** `src/superghidra/formats/apple_dispatch.py`, `src/superghidra/formats/il2cpp_metadata.py`, `src/superghidra/formats/rust_go_metadata.py`
- **Key Tasks:**
  1. `apple_dispatch.py`: Mach-O thin/universal parser, 64-bit dyld chained fixups (`LC_DYLD_CHAINED_FIXUPS`) with pointer authentication (`arm64e`), legacy `LC_DYLD_INFO`, Objective-C class hierarchy/categories/ivars, `__swift5_types` nominal type descriptors, protocol conformances, and Swift class vtables. Admission budget 64 MiB default (up to 1 GiB).
  2. `il2cpp_metadata.py`: Unity `global-metadata.dat` (versions 24, 27, 29, 31, 39) type, field, method, and string recovery; native ELF/PE/Mach-O method pointer joining.
  3. `rust_go_metadata.py`: Cargo `.dep-v0` zlib JSON dependency DAG and `/rustc/<hash>/` extraction; Go `.go.buildinfo` and `pclntab` runtime metadata extraction.
- **Verification Suite:** `tests/formats/test_apple_dispatch.py` (14 test cases), `tests/formats/test_il2cpp_metadata.py` (12 test cases), `tests/formats/test_rust_go_metadata.py` (10 test cases).

#### Milestone 6 — The `superghidra[rea]` Provider Bridge
- **Target Modules:** `src/superghidra/integrations/rea_bridge.py`
- **Key Tasks:**
  1. Implement in-process async Python router in `superghidra.integrations.rea_bridge`.
  2. Implement REA tool protocol adapter (`open_binary`, `analyze_function`, `trace_native_values`, `decompile_all`, `set_address_name`, `annotate_native_function`).
  3. Implement fast daemon/SHM bypass: sub-millisecond cached responses, zero-copy shared memory IPC, write overlay for Windows read/write capability.
  4. Inject compilable C filtering and Z3 verification into standard REA queries.
  5. Expose SuperGhidra extension tools (`sg_filter_c`, `sg_z3_prove`, `sg_wgpu_sweep`, `sg_rtti_recover`, `sg_serialize_trace`, `sg_diff_versions`).
- **Verification Suite:** `tests/integrations/test_rea_bridge.py` (20 test cases covering REA contract fidelity, error propagation, and performance benchmarks).

---

## 9. MCP Tool Schemas & CLI Interface Specifications

### 9.1 Unified CLI Commands & Argument Contracts

```bash
# 1. Cross-call High-P-Code value tracing
superghidra trace-values <binary_path>   --procedure <canonical_address_or_name>   [--max-depth 3]   [--max-nodes 2500]   [--output value_graph.json]

# 2. Crash-resumable bulk export with compilable C filtering and Z3 verification
superghidra decompile-all <binary_path>   --output <output_directory>   [--filter-compilable]   [--verify-z3]   [--arch <x86_64|arm64|arm|x86>]   [--concurrency 4]   [--resume]

# 3. Mach-O dyld fixups, Objective-C, and Swift metadata recovery (Zero JVM)
superghidra apple-dispatch <binary_path>   [--arch <x86_64|arm64|arm64e>]   [--max-input-bytes 67108864]   [--output swift_objc_vtables.json]

# 4. Unity IL2CPP metadata recovery (Zero JVM)
superghidra il2cpp-recover <global_metadata_dat_path>   [--binary <native_binary_path>]   [--output unity_types.json]

# 5. Rust cargo-auditable and Go build metadata recovery (Zero JVM)
superghidra crate-audit <binary_path>   [--output rust_go_deps.json]

# 6. Integrated MCP server daemon
superghidra mcp-serve   [--port 5073]   [--profile <compact|full>]   [--transport <stdio|sse>]
```

### 9.2 Complete MCP Tool JSON Schemas

#### Tool: `inspect_analysis_view`
```json
{
  "name": "inspect_analysis_view",
  "description": "Pages retained facets of a completed analysis dossier using parent_evidence_id without re-running decompilation or analysis passes.",
  "parameters": {
    "type": "object",
    "properties": {
      "parent_evidence_id": {
        "type": "string",
        "description": "Retained Evidence ID returned by a prior summary-first analysis call (e.g. ev_9f8a2b1c4d5e)."
      },
      "facet": {
        "type": "string",
        "enum": [
          "compilable_c",
          "raw_c",
          "assembly",
          "pcode_ops",
          "def_use_edges",
          "incoming_xrefs",
          "outgoing_calls",
          "struct_fields",
          "jump_tables"
        ],
        "description": "The specific facet to page or inspect."
      },
      "offset": {
        "type": "integer",
        "default": 0,
        "minimum": 0,
        "description": "Zero-based item or line offset into the facet."
      },
      "limit": {
        "type": "integer",
        "default": 64,
        "minimum": 1,
        "maximum": 500,
        "description": "Maximum number of items or lines to return in this page."
      },
      "filter_expr": {
        "type": "string",
        "description": "Optional substring or regex filter to narrow facet elements."
      }
    },
    "required": ["parent_evidence_id", "facet"]
  }
}
```

#### Tool: `trace_native_values`
```json
{
  "name": "trace_native_values",
  "description": "Constructs an inter-procedural high-P-code def-use graph across statically resolved calls starting from a designated procedure.",
  "parameters": {
    "type": "object",
    "properties": {
      "binary_path": {
        "type": "string",
        "description": "Path to the target binary file."
      },
      "procedure": {
        "type": "string",
        "description": "Canonical hex address (e.g. 0x140001000) or symbol name to begin tracing from."
      },
      "max_depth": {
        "type": "integer",
        "default": 3,
        "minimum": 1,
        "maximum": 8,
        "description": "Maximum call depth to traverse across inter-procedural call sites."
      },
      "max_nodes": {
        "type": "integer",
        "default": 2500,
        "minimum": 100,
        "maximum": 12000,
        "description": "Hard cap on total def-use nodes retained in the trace."
      }
    },
    "required": ["binary_path", "procedure"]
  }
}
```

#### Tool: `decompile_all`
```json
{
  "name": "decompile_all",
  "description": "Executes a crash-resumable batch decompilation export across all internal functions of a binary, writing filtered compilable C and returning only a compact status manifest.",
  "parameters": {
    "type": "object",
    "properties": {
      "binary_path": {
        "type": "string",
        "description": "Path to the binary to decompile."
      },
      "output_directory": {
        "type": "string",
        "description": "Destination directory for exported .c source files, journal, and index."
      },
      "filter_compilable": {
        "type": "boolean",
        "default": true,
        "description": "Apply SuperGhidra compilable C syntax filter to eliminate undefined types and macros."
      },
      "verify_z3": {
        "type": "boolean",
        "default": false,
        "description": "Execute Z3 formal P-code equivalence check on reconstructed basic blocks."
      },
      "resume": {
        "type": "boolean",
        "default": true,
        "description": "Resume from existing .superghidra-export.journal.jsonl if present."
      }
    },
    "required": ["binary_path", "output_directory"]
  }
}
```

#### Tool: `apple_dispatch`
```json
{
  "name": "apple_dispatch",
  "description": "Extracts dyld chained fixups, Objective-C classes/protocols/categories, and Swift 5 nominal types/vtables from a Mach-O binary without running Ghidra.",
  "parameters": {
    "type": "object",
    "properties": {
      "binary_path": {
        "type": "string",
        "description": "Path to the Mach-O binary or FAT archive."
      },
      "arch": {
        "type": "string",
        "enum": ["x86_64", "arm64", "arm64e"],
        "description": "Architecture slice to select when parsing a universal FAT binary."
      },
      "max_input_bytes": {
        "type": "integer",
        "default": 67108864,
        "description": "Maximum byte admission budget to prevent memory exhaustion on untrusted files."
      }
    },
    "required": ["binary_path"]
  }
}
```

#### Tool: `il2cpp_recover`
```json
{
  "name": "il2cpp_recover",
  "description": "Parses Unity global-metadata.dat to extract type definitions, fields, methods, and string literals, optionally joining method pointers to native shared library RVAs.",
  "parameters": {
    "type": "object",
    "properties": {
      "metadata_path": {
        "type": "string",
        "description": "Path to global-metadata.dat file."
      },
      "binary_path": {
        "type": "string",
        "description": "Optional path to the compiled native binary (libil2cpp.so, GameAssembly.dll) for RVA correlation."
      }
    },
    "required": ["metadata_path"]
  }
}
```

#### Tool: `crate_audit`
```json
{
  "name": "crate_audit",
  "description": "Audits compiled Rust binaries (.dep-v0 section) and Go binaries (.go.buildinfo and pclntab) to recover exact crate dependencies, compiler hashes, and module paths.",
  "parameters": {
    "type": "object",
    "properties": {
      "binary_path": {
        "type": "string",
        "description": "Path to the compiled Rust or Go ELF/PE/Mach-O binary."
      }
    },
    "required": ["binary_path"]
  }
}
```

### 9.3 Declarative Read/Mutate Surface Descriptor (`mcp.superghidra.json`)

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "server": {
    "name": "superghidra",
    "version": "1.0.0",
    "vendor": "SuperGhidra Authors",
    "default_input_profile": "compact",
    "default_output_profile": "compact"
  },
  "capabilities": {
    "tools": true,
    "resources": true,
    "prompts": false,
    "logging": true
  },
  "security_boundaries": {
    "read_surface": [
      "open_binary",
      "analyze_function",
      "inspect_analysis_view",
      "trace_native_values",
      "decompile_all",
      "prove_equivalence",
      "apple_dispatch",
      "il2cpp_recover",
      "crate_audit",
      "inspect_binary",
      "rva_translate",
      "gpu_adrp_scan",
      "gpu_seed_functions",
      "diff_functions",
      "migrate_struct_shifts"
    ],
    "mutate_surface": [
      "commit_overlay_rename",
      "commit_struct_layout",
      "annotate_native_function",
      "set_address_name",
      "merge_fork",
      "set_governor_mode",
      "hibernate",
      "clear_cache"
    ],
    "mutation_policy": {
      "direct_rep_write": false,
      "journal_backing": true,
      "gate_enforcement": "ReconstructionObligationLedger",
      "stale_base_resolution": "reject_stale_assign_obligation"
    }
  }
}
```

---

## 10. Quantitative Verification Suite & Acceptance Matrix

### 10.1 Empirical Verification Targets & Latency Budgets

| Metric / Subsystem | Verification Target | Measurement Context | Failure Action |
| :--- | :--- | :--- | :--- |
| **Retained Evidence L2 Cache Hit** | < 0.01 ms | Repeat `analyze_function` or `inspect_analysis_view` on warm SQLite WAL | Re-evaluate query planner and index selectivity |
| **Retained Evidence L2 Cache Store** | < 0.20 ms | Compress and persist 50 KB dossier via LZ4 to `retained_evidence` | Profile serialization and compression thresholds |
| **Zero-Copy SHM Ring Buffer** | < 10.0 µs roundtrip | In-process 64 KB shared memory ring buffer IPC | Fallback to TCP loopback with alert |
| **WGPU ARM64 ADRP Scanner** | > 125,000,000 insn/s | 20 MB stripped ARM64 ELF library sweep | Downshift to NumPy SIMD scanner |
| **Bulk Decompile Throughput** | > 40 functions/s | Warm daemon decompilation through compilable C filter | Thread pool starvation check |
| **HumanEval-Decompile Pass Rate** | ≥ 22.69% (294/1,296) | Zero regressions against baseline corpus (GCC 16.2 `-O0 -lm`) | Halt release; bisect AST rewriter rules |
| **Z3 Formal Prover Soundness** | 0 false UNSAT | Zero false equivalence proofs on modified semantics | Immediate patch; revert unhandled opcode to UNKNOWN |
| **Directory Inode Locking** | 100% mutual exclusion | Concurrent multi-process `decompile_all` race tests | Re-acquire lock verification via Win32 / POSIX APIs |

### 10.2 Domain Test Suite Mapping

| Test File | Test Count | Domain / Focus | Key Invariant Assertions |
| :--- | :--- | :--- | :--- |
| `tests/core/test_evidence_paging.py` | 24 | Retained evidence L2 cache & pagination | `parent_evidence_id` persistence, facet offsets, LRU quota eviction |
| `tests/core/test_evidence_ledger_obligations.py` | 18 | `EvidenceEnvelope` & obligation gates | Vtable slot bounds, C filter syntax, `conflict_stale_base` isolation |
| `tests/lifters/test_trace_native_values.py` | 16 | Inter-procedural High-P-Code tracing | Parameter ordinal binding, cycle termination, 3,000-op cap |
| `tests/acceleration/test_jump_table_prover.py` | 12 | ARM64 jump-table recovery | Bounds $N$ verification, table extraction, non-literal `null` entry |
| `tests/core/test_decompile_all_resumable.py` | 15 | Batch compilable export & `--resume` | `(st_dev, st_ino)` locking, torn journal recovery, circuit breaker |
| `tests/formats/test_apple_dispatch.py` | 14 | Mach-O chained fixups, Obj-C, Swift 5 | Chained pointer rebases, nominal type descriptors, 64 MiB budget |
| `tests/formats/test_il2cpp_metadata.py` | 12 | Unity `global-metadata.dat` v24–39 | Header version parsing, method definition indexing, native RVA join |
| `tests/formats/test_rust_go_metadata.py` | 10 | Rust `.dep-v0` & Go `.go.buildinfo` | Zlib JSON DAG parsing, commit hash extraction, missing section null |
| `tests/integrations/test_rea_bridge.py` | 20 | `superghidra[rea]` provider bridge | REA tool mapping, overlay routing on Windows, compilable C injection |

### 10.3 Cross-Platform Continuous Integration Matrix

- **Operating Systems:**
  - Ubuntu 22.04 LTS & Ubuntu 24.04 LTS (Linux x86_64)
  - Windows Server 2022 & Windows 11 (Windows x86_64)
  - macOS 14 Sonoma (ARM64 Apple Silicon)
- **Python Runtimes:** 3.10, 3.11, 3.12
- **Required Build Dependencies:** OpenJDK 21, GCC / Clang, Z3 Solver, CMake, Ninja
- **Optional Accelerators (Marked Skip on Absence):** WGPU DirectX 12 / Vulkan, CUDA

---

## 11. Security Architecture & Daemon Sandboxing Invariants

### 11.1 Daemon Network Isolation & Authentication

1. **Loopback Binding Invariant:** The daemon strictly binds to loopback interfaces (`127.0.0.1`, `::1`). Attempts to bind to `0.0.0.0` or external network adapters are refused with an explicit error unless `--allow-remote` is passed.
2. **Port-Scoped Session Tokens:** Every daemon startup generates or verifies a cryptographic token stored in `~/.superghidra/daemon.<port>.token`. All mutating operations (`commit_overlay_rename`, `commit_struct_layout`, `merge_fork`, `set_governor_mode`, `hibernate`, `clear_cache`) require a matching token in the authorization header or command payload.
3. **Payload Frame Bounds:** JSON RPC request frames are strictly capped at 2 MB. MCP transport payloads default to an 8 MiB frame cap (configurable up to 32 MiB). Oversized frames are rejected with HTTP 413 / RPC frame limit error before deserialization.

### 11.2 Memory Admission & Untrusted Binary Parser Hardening

1. **Admission Budget:** The static format parsers (`apple_dispatch.py`, `il2cpp_metadata.py`, `rust_go_metadata.py`) enforce a default 64 MiB admission budget per binary slice (configurable via `--max-input-bytes` up to 1 GiB).
2. **Offset Arithmetic Guardrails:** All internal offset calculations (e.g. Mach-O load command offsets, Unity string table indices, zlib stream lengths) are validated against total file bounds before slicing to prevent out-of-bounds reads and memory exhaustion.
3. **Encrypted or Corrupt Headers:** Unrecognized metadata versions, encrypted Unity metadata headers, or truncated chained fixup tables exit cleanly with `epistemic_status: "unknown"` and structured diagnostic reports, never raising unhandled exceptions or terminating the parent daemon.

### 11.3 Database Immutability & Safe Mutation Overlays

1. **Immutable Ghidra Projects:** Ghidra `.rep` project files are opened exclusively in read-only mode (`openProgram(..., readOnly=True)`). The underlying project files on disk are never locked or written to by background agents.
2. **Append-Only Journals:** All user and agent modifications (renames, comments, type assignments) are appended to `.ghidra-delta.jsonl` and mirrored in the memory overlay `ghidra_overlay.json`.
3. **Formal Ledger Gates:** No neural or automated commit may bypass `ReconstructionObligationLedger` checks. Offsets, vtable slot indices, and allocation bounds must be verified before changes can be promoted to `main_overlay`.

---

## 12. Backward Compatibility, Migration Path & Release Checklist

### 12.1 Canonical Package Import Invariants

- All internal modules and consumer tools must use canonical package imports:
  `from superghidra.<domain>.<module> import ...`
- The `superghidra.compat` package provides shims for external tools and older scripts, issuing a `DeprecationWarning` while directing callers to canonical domain paths.
- Loose root `.py` shims have been retired in v0.4.0.

### 12.2 Existing SuperghidraMCP & CLI Compatibility

- All 38 existing MCP tools registered in `SuperghidraMCP` maintain identical parameter schemas and return contracts.
- Existing CLI commands (`superghidra scan-arm64`, `superghidra smt-check`, `superghidra decompile`, `superghidra filter`, `python ghidra_oracle.py ...`) remain functional without breaking changes.
- The new 1.0.0 tools (`inspect_analysis_view`, `trace_native_values`, `decompile_all`, `apple_dispatch`, `il2cpp_recover`, `crate_audit`) are registered alongside existing tools under their canonical names.

### 12.3 REA Ecosystem Compatibility Matrix

| REA Version / Client | Bridge Support | Required Extras | Transport |
| :--- | :--- | :--- | :--- |
| `morluto/rea >= 0.8.0` | Drop-in backend | `pip install "superghidra[rea]"` | In-process Python async router / CLI provider |
| Claude Code CLI | First-class MCP | `superghidra mcp-serve` | `stdio` with `compact` schema profile |
| Cursor / Windsurf | First-class MCP | `superghidra mcp-serve` | `stdio` / SSE with `compact` schema profile |
| Antigravity CLI / AGY | First-class MCP | `superghidra mcp-serve` | MCP loopback client with warm L2 query cache |

### 12.4 Definition of Done (DoD) for SuperGhidra 1.0.0 Tag

- [ ] All 6 Phased Implementation Milestones implemented with code living in canonical domain packages.
- [ ] 100% of unit and integration test suites passing in CI (all 787 baseline tests + new 1.0.0 milestone tests).
- [ ] Zero HumanEval-Decompile regressions against baseline corpus (minimum 22.69% pass rate preserved).
- [ ] Clean prose audit: zero prohibited marketing terms per AGENTS.md rule 7.
- [ ] Declarative security surface descriptor `mcp.superghidra.json` published and verified by schema validator.
- [ ] Cross-platform CI passing on Ubuntu 22.04/24.04 and Windows Server 2022 across Python 3.10, 3.11, and 3.12.
- [ ] `pyproject.toml` version bumped to `1.0.0` with `[rea]` extra documented in `README.md`.
