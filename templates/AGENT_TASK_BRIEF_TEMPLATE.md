# Agent Sub-Task Brief: `<Short Task Title>`

> **Context Budget Target:** `< 1,500 tokens` of repository context. Do **not** scan unrelated domains.

## 1. Objective
<2–3 sentences stating the exact problem to solve, feature to implement, or bug to fix.>

## 2. Bounded Scope & Progressive Discovery

- **Target Domain:** `superghidra/<domain>/`
- **Subsystem Index (Read First):** [`superghidra/<domain>/README.md`](../superghidra/<domain>/README.md)
- **Allowed Files to Inspect / Edit:**
  1. `superghidra/<domain>/<target_module>.py` (Lines `<start>–<end>`)
  2. `tests/<domain>/test_<target_module>.py`
  3. *(Optional)* `<target_module>.py` (root backward-compatibility shim, only if adding a new module)
- **Out-of-Scope Domains (Do NOT Read):**
  - All other subdirectories under `superghidra/` and `tests/` unless discovered via `get_impact_radius_tool`.

## 3. Graph-First Discovery Commands (`code-review-graph`)
Run these MCP queries before viewing full source files:
1. `get_minimal_context_tool(task="<Short Task Title>")`
2. `semantic_search_nodes_tool(query="<TargetClassOrFunction>")`
3. `get_impact_radius_tool(target="superghidra/<domain>/<target_module>.py")`

## 4. Critical Invariants to Preserve
- [ ] **Root Backward Compatibility:** Top-level `import <target_module>` must continue to work and alias `superghidra.<domain>.<target_module>` in `sys.modules`.
- [ ] **Domain Invariant:** <e.g., `EvidenceLedger` proof check / `EmulatorFleetGuard` sandbox check / Z3 `UNKNOWN` on unhandled ops / read-only `.rep` database>.
- [ ] **Zero Unintended Side Effects:** All temporary test artifacts must use `tempfile.TemporaryDirectory()`.

## 5. Acceptance Criteria & Verification Commands
1. **Domain Test Suite Passes:**
   ```powershell
   python -m pytest tests/<domain>/test_<target_module>.py -q
   ```
2. **Shim Import Check Passes:**
   ```powershell
   python -c "import <target_module>; from superghidra.<domain> import <target_module> as m; assert <target_module> is m; print('OK')"
   ```
3. **Update Code Review Graph:**
   Call `build_or_update_graph_tool` (or `code-review-graph update`) after edits complete.
