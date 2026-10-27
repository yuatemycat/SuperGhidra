# Awesome Lists PR Submission Kit

This kit provides ready-to-submit pull request copy and target specifications for 5 major curated GitHub lists.

---

## Target 1: [AllsafeCyberSecurity/awesome-ghidra](https://github.com/AllsafeCyberSecurity/awesome-ghidra)

* **Repository:** `AllsafeCyberSecurity/awesome-ghidra`
* **Target File:** `README.md` under `## Ghidra Scripts/Plugins/Extension` section
* **PR Title:** `Add SuperGhidra to Ghidra Scripts/Plugins/Extension`
* **Exact Line to Add:**
  ```markdown
  * [SuperGhidra](https://github.com/yuatemycat/SuperGhidra) - Persistent lock-free Ghidra daemon (SQLite/SHM cache + non-destructive JSON write overlays), WGPU/SIMD ARM64 scanner, Z3 P-code equivalence checker, compilable C rewriter, and standalone MSVC RTTI / MFC class recovery suite.
  ```
* **PR Description:**
  ```markdown
  Adds **[SuperGhidra](https://github.com/yuatemycat/SuperGhidra)** (and its companion MCP server **[SuperGhidraMCP](https://github.com/yuatemycat/SuperGhidraMCP)**) to the `Ghidra Scripts/Plugins/Extension` section.

  **Why it's useful for Ghidra users:**
  - Eliminates the 5–15s JVM cold-start penalty in headless scripting by keeping a `readOnly=True` Ghidra daemon on `127.0.0.1:5073` with L1 shared-memory (`< 50 µs`) and L2 SQLite caching.
  - Prevents `LockException` when the Ghidra GUI is open by writing renames, comments, and recovered types to a non-destructive `ghidra_overlay.json` journal that syncs live into the GUI via `ghidra_gui_overlay_sync.py`.
  - Ships with `pip install superghidra`, a 6-job Windows/Linux CI matrix, and standalone MSVC RTTI / MFC `CArchive::Serialize()` recovery, LZ4/Zstd 16 KB `BufferFile` codecs, and NumPy SIMD / WGPU ARM64 `ADRP` scanners.
  ```

---

## Target 2: [punkpeye/awesome-mcp-servers](https://github.com/punkpeye/awesome-mcp-servers)

* **Repository:** `punkpeye/awesome-mcp-servers`
* **Target File:** `README.md` under `### 🔒 Security` section (alphabetical order by owner/repo)
* **PR Title:** `Add yuatemycat/SuperGhidraMCP to Security`
* **Exact Line to Add:**
  ```markdown
  - [yuatemycat/SuperGhidraMCP](https://github.com/yuatemycat/SuperGhidraMCP) 🐍 🏠 🍎 🪟 🐧 - Guardrailed Ghidra reverse engineering MCP server featuring isolated multi-agent session forks, a persistent lock-free daemon cache ([SuperGhidra](https://github.com/yuatemycat/SuperGhidra)), Z3 P-code equivalence verification, and zero-JVM MSVC/MFC class recovery.
  ```
* **PR Description:**
  ```markdown
  Adds **[yuatemycat/SuperGhidraMCP](https://github.com/yuatemycat/SuperGhidraMCP)** (powered by **[SuperGhidra](https://github.com/yuatemycat/SuperGhidra)**) to the Security section in alphabetical order with standard language/platform badges (`🐍 Python`, `🏠 Local`, `🍎 macOS`, `🪟 Windows`, `🐧 Linux`).

  Unlike single-session Ghidra MCP wrappers that mutate a live `.rep` project in place, SuperGhidraMCP isolates concurrent AI agents into private session forks backed by a read-only daemon cache and gates symbol/struct commits through deterministic vtable/offset checks (`merge_fork`).
  ```

---

## Target 3: [wong2/awesome-mcp-servers](https://github.com/wong2/awesome-mcp-servers) & [gmh5225/awesome-ai-security](https://github.com/gmh5225/awesome-ai-security)

* **Target File:** `README.md` under MCP / AI Security tooling
* **PR Title:** `Add SuperGhidra and SuperGhidraMCP`
* **Exact Line to Add:**
  ```markdown
  - **[SuperGhidra](https://github.com/yuatemycat/SuperGhidra) / [SuperGhidraMCP](https://github.com/yuatemycat/SuperGhidraMCP)** - Lock-free Ghidra oracle daemon, guardrailed multi-agent MCP server with `merge_fork` conflict detection, Z3 P-code verifier, WGPU ARM64 scanner, and compilable C filter.
  ```
* **PR Description:**
  ```markdown
  Adds [SuperGhidra](https://github.com/yuatemycat/SuperGhidra) (`pip install superghidra`) and [SuperGhidraMCP](https://github.com/yuatemycat/SuperGhidraMCP) for AI-assisted binary reverse engineering, static analysis, and formal P-code verification.
  ```

---

## Target 4: [fr0gger/awesome-ida-x64-olly-plugin](https://github.com/fr0gger/awesome-ida-x64-olly-plugin)

* **Repository:** `fr0gger/awesome-ida-x64-olly-plugin`
* **Target File:** `README.md` under `## Ghidra` section
* **PR Title:** `Add SuperGhidra to Ghidra plugins/tools`
* **Exact Line to Add:**
  ```markdown
  * [SuperGhidra](https://github.com/yuatemycat/SuperGhidra) - High-performance lock-free Ghidra daemon, IDA `.til` / FLIRT `.sig` bridge, MSVC RTTI & MFC `Serialize()` recovery, Z3 P-code verifier, and WGPU ARM64 scanner.
  ```
* **PR Description:**
  ```markdown
  Adds **[SuperGhidra](https://github.com/yuatemycat/SuperGhidra)** (`pip install superghidra`) to the Ghidra section. Provides lock-free Ghidra daemon caching, IDA `.til` import and FLIRT `.sig` matching without IDA licenses, MSVC RTTI/MFC recovery, and Z3 P-code verification.
  ```
