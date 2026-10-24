#!/usr/bin/env python3
"""Generates the SuperGhidra architecture vector graph (docs/assets/architecture.svg).

Pixel-perfect SVG generator tailored for GitHub dark & light themes.
"""

from pathlib import Path

def generate_svg() -> str:
    width = 1040
    height = 690

    svg = f"""<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {width} {height}" width="100%" height="100%" style="background-color: #0d1117; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif;">
  <defs>
    <!-- Gradients -->
    <linearGradient id="readGrad" x1="0%" y1="0%" x2="100%" y2="100%">
      <stop offset="0%" stop-color="#0f172a" />
      <stop offset="100%" stop-color="#1e293b" />
    </linearGradient>
    <linearGradient id="gateGrad" x1="0%" y1="0%" x2="100%" y2="100%">
      <stop offset="0%" stop-color="#1e1b4b" />
      <stop offset="100%" stop-color="#2e1065" />
    </linearGradient>
    <linearGradient id="syncAGrad" x1="0%" y1="0%" x2="100%" y2="100%">
      <stop offset="0%" stop-color="#064e3b" />
      <stop offset="100%" stop-color="#065f46" />
    </linearGradient>
    <linearGradient id="syncBGrad" x1="0%" y1="0%" x2="100%" y2="100%">
      <stop offset="0%" stop-color="#451a03" />
      <stop offset="100%" stop-color="#7c2d12" />
    </linearGradient>
    
    <!-- Arrow Markers -->
    <marker id="arrow-cyan" viewBox="0 0 10 10" refX="6" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
      <path d="M 0 1 L 8 5 L 0 9 z" fill="#38bdf8" />
    </marker>
    <marker id="arrow-slate" viewBox="0 0 10 10" refX="6" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
      <path d="M 0 1 L 8 5 L 0 9 z" fill="#94a3b8" />
    </marker>
    <marker id="arrow-purple" viewBox="0 0 10 10" refX="6" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
      <path d="M 0 1 L 8 5 L 0 9 z" fill="#a78bfa" />
    </marker>
    <marker id="arrow-amber" viewBox="0 0 10 10" refX="6" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
      <path d="M 0 1 L 8 5 L 0 9 z" fill="#fbbf24" />
    </marker>
    <marker id="arrow-emerald" viewBox="0 0 10 10" refX="6" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
      <path d="M 0 1 L 8 5 L 0 9 z" fill="#34d399" />
    </marker>
    <marker id="arrow-orange" viewBox="0 0 10 10" refX="6" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
      <path d="M 0 1 L 8 5 L 0 9 z" fill="#fb923c" />
    </marker>
    
    <!-- Filter Shadow -->
    <filter id="cardShadow" x="-5%" y="-5%" width="110%" height="115%" filterUnits="userSpaceOnUse">
      <feDropShadow dx="0" dy="4" stdDeviation="6" flood-color="#000000" flood-opacity="0.4" />
    </filter>
  </defs>

  <!-- ==================== HEADER ==================== -->
  <text x="520" y="38" text-anchor="middle" fill="#f0f6fc" font-size="19" font-weight="700" letter-spacing="0.5">SuperGhidra Architecture &amp; Zero Lock Contention</text>
  <text x="520" y="58" text-anchor="middle" fill="#8b949e" font-size="13">Read/Write Separation · Shared-Memory IPC · SQLite L2 Cache · Non-Destructive Overlays</text>

  <!-- ==================== TIER 1: READ PATH ==================== -->
  <!-- Container Box -->
  <rect x="30" y="80" width="980" height="150" rx="10" fill="#161b22" stroke="#30363d" stroke-width="1.5" filter="url(#cardShadow)" />
  <rect x="30" y="80" width="980" height="32" rx="10" fill="#1f2937" />
  <rect x="30" y="102" width="980" height="10" fill="#1f2937" />
  <circle cx="48" cy="96" r="4.5" fill="#38bdf8" />
  <text x="60" y="101" fill="#38bdf8" font-size="13" font-weight="700" letter-spacing="0.5">1. READ PATH (Zero Lock Contention)</text>
  <text x="990" y="100" text-anchor="end" fill="#8b949e" font-size="11">Concurrent with active Ghidra GUI CodeBrowser</text>

  <!-- Box 1A: Ghidra .rep Fork -->
  <g transform="translate(50, 122)">
    <rect width="250" height="92" rx="8" fill="url(#readGrad)" stroke="#38bdf8" stroke-width="1.5" />
    <text x="15" y="24" fill="#f0f6fc" font-size="13" font-weight="600">Ghidra .rep Fork / Session</text>
    <text x="15" y="44" fill="#94a3b8" font-size="11.5">• Opens target with readOnly=True</text>
    <text x="15" y="62" fill="#94a3b8" font-size="11.5">• Immune to GUI .lock collisions</text>
    <text x="15" y="80" fill="#38bdf8" font-size="11" font-weight="500">Zero project lock contention</text>
  </g>

  <!-- Arrow: 1A -> Daemon -->
  <path d="M 300 168 L 348 168" stroke="#38bdf8" stroke-width="2" marker-end="url(#arrow-cyan)" />

  <!-- Box 1B: SuperGhidra Daemon -->
  <g transform="translate(355, 122)">
    <rect width="635" height="92" rx="8" fill="#0f172a" stroke="#0284c7" stroke-width="1.5" />
    <text x="18" y="24" fill="#f0f6fc" font-size="13" font-weight="600">SuperGhidra Background Daemon</text>
    <rect x="238" y="11" width="105" height="18" rx="4" fill="#0369a1" />
    <text x="290" y="24" text-anchor="middle" fill="#e0f2fe" font-size="10.5" font-family="ui-monospace, monospace" font-weight="600">127.0.0.1:5073</text>
    <text x="18" y="44" fill="#94a3b8" font-size="11.5">Single JVM warm instance · JSON-RPC · Headless worker bridge</text>

    <!-- Sub-badge 1: L1 SHM -->
    <g transform="translate(18, 52)">
      <rect width="285" height="30" rx="6" fill="#1e293b" stroke="#38bdf8" stroke-width="1" />
      <text x="10" y="20" fill="#38bdf8" font-size="11" font-weight="600">L1 SHM Ring Buffer:</text>
      <text x="135" y="20" fill="#f0f6fc" font-size="11" font-family="ui-monospace, monospace">64 KB · ~5.12 µs IPC</text>
    </g>

    <!-- Sub-badge 2: L2 SQLite Cache -->
    <g transform="translate(320, 52)">
      <rect width="298" height="30" rx="6" fill="#1e293b" stroke="#38bdf8" stroke-width="1" />
      <text x="10" y="20" fill="#38bdf8" font-size="11" font-weight="600">L2 SQLite Query Cache:</text>
      <text x="155" y="20" fill="#f0f6fc" font-size="11" font-family="ui-monospace, monospace">&gt;100k req/s (&lt;0.01ms)</text>
    </g>
  </g>

  <!-- ==================== TIER 2: VALIDATION & OVERLAY ==================== -->
  <!-- Container Box -->
  <rect x="30" y="250" width="980" height="190" rx="10" fill="#161b22" stroke="#30363d" stroke-width="1.5" filter="url(#cardShadow)" />
  <rect x="30" y="250" width="980" height="32" rx="10" fill="#1f2937" />
  <rect x="30" y="272" width="980" height="10" fill="#1f2937" />
  <circle cx="48" cy="266" r="4.5" fill="#a78bfa" />
  <text x="60" y="271" fill="#a78bfa" font-size="13" font-weight="700" letter-spacing="0.5">2. INTERACTIVE QUERIES, VALIDATION GATE &amp; WRITE OVERLAY</text>
  <text x="990" y="270" text-anchor="end" fill="#8b949e" font-size="11">Non-destructive mutations · Automated structural gates</text>

  <!-- Box 2A: Coding Agents & Callers -->
  <g transform="translate(50, 292)">
    <rect width="250" height="132" rx="8" fill="#1e293b" stroke="#64748b" stroke-width="1.5" />
    <text x="15" y="24" fill="#f0f6fc" font-size="13" font-weight="600">AI Agents &amp; CLI Callers</text>
    <text x="15" y="46" fill="#cbd5e1" font-size="11.5">• Claude Desktop / Claude Code</text>
    <text x="15" y="65" fill="#cbd5e1" font-size="11.5">• Cursor / Antigravity IDE</text>
    <text x="15" y="84" fill="#cbd5e1" font-size="11.5">• SuperGhidra MCP (38 Tools)</text>
    <text x="15" y="103" fill="#cbd5e1" font-size="11.5">• Unified CLI / Python Scripts</text>
    <text x="15" y="121" fill="#38bdf8" font-size="10.5" font-family="ui-monospace, monospace">read: cached / write: gated</text>
  </g>

  <!-- Bi-directional Flow: Daemon <-> Agents -->
  <path d="M 430 214 L 430 236 L 175 236 L 175 284" stroke="#38bdf8" stroke-width="1.8" stroke-dasharray="4,3" fill="none" marker-end="url(#arrow-cyan)" />
  <rect x="230" y="226" width="160" height="18" rx="4" fill="#0b0f19" stroke="#38bdf8" stroke-width="0.8" />
  <text x="310" y="239" text-anchor="middle" fill="#38bdf8" font-size="10.5" font-weight="500">Cached Decompilations &amp; Xrefs</text>

  <!-- Arrow: Agents -> Gate -->
  <path d="M 300 358 L 348 358" stroke="#a78bfa" stroke-width="2" marker-end="url(#arrow-purple)" />
  <text x="325" y="348" text-anchor="middle" fill="#a78bfa" font-size="9.5" font-weight="600">Mutations</text>

  <!-- Box 2B: Validation Gate -->
  <g transform="translate(355, 292)">
    <rect width="285" height="132" rx="8" fill="url(#gateGrad)" stroke="#818cf8" stroke-width="1.5" />
    <text x="15" y="24" fill="#f0f6fc" font-size="13" font-weight="600">Naming &amp; Struct Pipeline Gate</text>
    <rect x="15" y="33" width="170" height="16" rx="3" fill="#312e81" />
    <text x="100" y="45" text-anchor="middle" fill="#c7d2fe" font-size="9.5" font-family="ui-monospace, monospace">EvidenceLedger Obligation Gate</text>
    
    <text x="15" y="66" fill="#e0e7ff" font-size="11.5">✓ VTableSlotVerifier</text>
    <text x="15" y="84" fill="#e0e7ff" font-size="11.5">✓ FieldDisplacementVerifier</text>
    <text x="15" y="102" fill="#e0e7ff" font-size="11.5">✓ AllocationSizeVerifier</text>
    <text x="15" y="121" fill="#f43f5e" font-size="10.5" font-weight="500">Rejects hallucinated structs &amp; slots</text>
  </g>

  <!-- Arrow: Gate -> Overlay -->
  <path d="M 640 358 L 688 358" stroke="#a78bfa" stroke-width="2" marker-end="url(#arrow-purple)" />
  <text x="664" y="348" text-anchor="middle" fill="#a78bfa" font-size="9.5" font-weight="600">Verified</text>

  <!-- Box 2C: JSON Write Overlay -->
  <g transform="translate(695, 292)">
    <rect width="295" height="132" rx="8" fill="#1e1b4b" stroke="#fbbf24" stroke-width="1.5" />
    <text x="15" y="24" fill="#f0f6fc" font-size="13" font-weight="600">JSON Write Overlay &amp; Delta Log</text>
    <text x="15" y="44" fill="#fcd34d" font-size="11" font-family="ui-monospace, monospace">ghidra_overlay.json &amp; .ghidra-delta.jsonl</text>
    <text x="15" y="65" fill="#cbd5e1" font-size="11.5">• Renames, comments &amp; struct types</text>
    <text x="15" y="84" fill="#cbd5e1" font-size="11.5">• Zero writes touch the main .rep</text>
    <text x="15" y="103" fill="#cbd5e1" font-size="11.5">• Conflict-aware transaction journal</text>
    <text x="15" y="121" fill="#34d399" font-size="10.5" font-weight="500">Safe, non-destructive persistence</text>
  </g>

  <!-- ==================== TIER 3: SYNCHRONIZATION ==================== -->
  <!-- Container Box -->
  <rect x="30" y="460" width="980" height="205" rx="10" fill="#161b22" stroke="#30363d" stroke-width="1.5" filter="url(#cardShadow)" />
  <rect x="30" y="460" width="980" height="32" rx="10" fill="#1f2937" />
  <rect x="30" y="482" width="980" height="10" fill="#1f2937" />
  <circle cx="48" cy="476" r="4.5" fill="#34d399" />
  <text x="60" y="481" fill="#34d399" font-size="13" font-weight="700" letter-spacing="0.5">3. SYNCHRONIZATION BACK TO MAIN PROJECT (TWO OPTIONS)</text>
  <text x="990" y="480" text-anchor="end" fill="#8b949e" font-size="11">Atomic GUI sync or automated headless merge</text>

  <!-- Forking Arrows: Overlay -> Sync Options -->
  <path d="M 842 424 L 842 445 L 285 445 L 285 502" stroke="#fbbf24" stroke-width="1.8" fill="none" marker-end="url(#arrow-amber)" />
  <path d="M 842 424 L 842 445 L 755 445 L 755 502" stroke="#fbbf24" stroke-width="1.8" fill="none" marker-end="url(#arrow-amber)" />

  <!-- Box 3A: Live Ghidra GUI Sync -->
  <g transform="translate(50, 510)">
    <rect width="445" height="138" rx="8" fill="url(#syncAGrad)" stroke="#34d399" stroke-width="1.5" />
    <text x="16" y="24" fill="#f0f6fc" font-size="13" font-weight="600">Option 3A: Live Ghidra GUI Sync</text>
    <rect x="235" y="11" width="195" height="18" rx="4" fill="#047857" />
    <text x="332" y="24" text-anchor="middle" fill="#d1fae5" font-size="10.5" font-family="ui-monospace, monospace" font-weight="600">superghidra overlay-sync</text>
    
    <text x="16" y="48" fill="#e2e8f0" font-size="11.5">• <tspan font-weight="600" fill="#34d399">Ghidra Script Manager:</tspan> Run <tspan font-family="ui-monospace, monospace">ghidra_gui_overlay_sync.py</tspan></text>
    <text x="16" y="68" fill="#e2e8f0" font-size="11.5">• <tspan font-weight="600" fill="#34d399">Live Watcher:</tspan> Pass <tspan font-family="ui-monospace, monospace">--watch</tspan> to continuously poll (default 1000 ms)</text>
    <text x="16" y="88" fill="#e2e8f0" font-size="11.5">• Applies renames, comments &amp; struct types atomically</text>
    <text x="16" y="108" fill="#e2e8f0" font-size="11.5">• Refreshes active CodeBrowser / Listing view without restart</text>
    <text x="16" y="127" fill="#6ee7b7" font-size="11" font-weight="500">Perfect while interactively reverse engineering in the GUI</text>
  </g>

  <!-- Box 3B: Headless Journal Replay -->
  <g transform="translate(525, 510)">
    <rect width="465" height="138" rx="8" fill="url(#syncBGrad)" stroke="#fb923c" stroke-width="1.5" />
    <text x="16" y="24" fill="#f0f6fc" font-size="13" font-weight="600">Option 3B: Headless Journal Replay &amp; Auto-Discard</text>
    <rect x="335" y="11" width="115" height="18" rx="4" fill="#9a3412" />
    <text x="392" y="24" text-anchor="middle" fill="#ffedd5" font-size="10.5" font-family="ui-monospace, monospace" font-weight="600">merge_fork</text>
    
    <text x="16" y="48" fill="#e2e8f0" font-size="11.5">• Close GUI to release project lock, then replay journal into <tspan font-family="ui-monospace, monospace">.rep</tspan></text>
    <text x="16" y="68" fill="#e2e8f0" font-size="11.5">• <tspan font-weight="600" fill="#fb923c">Auto-Discard:</tspan> With <tspan font-family="ui-monospace, monospace">auto_discard=True</tspan>, cleans up fork on 0 conflicts</text>
    <text x="16" y="88" fill="#e2e8f0" font-size="11.5">• Deletes private fork directory &amp; journal to reclaim disk space</text>
    <text x="16" y="108" fill="#e2e8f0" font-size="11.5">• Stale or unneeded forks can also be pruned via <tspan font-family="ui-monospace, monospace">discard_fork</tspan></text>
    <text x="16" y="127" fill="#fdba74" font-size="11" font-weight="500">Ideal for batch processing, automated pipelines &amp; CI/CD</text>
  </g>
</svg>
"""
    return svg

def main():
    target = Path("docs/assets/architecture.svg")
    target.parent.mkdir(parents=True, exist_ok=True)
    svg_content = generate_svg()
    target.write_text(svg_content, encoding="utf-8")
    print(f"Generated {len(svg_content)} bytes to {target}")

if __name__ == "__main__":
    main()
