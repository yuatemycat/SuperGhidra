#!/usr/bin/env python3
"""Generates the SuperGhidra architecture diagram using the cathrynlavery/diagram-design specification.

Builds docs/assets/architecture.html (full editorial page) and exports
docs/assets/architecture.svg (standalone, inline-safe SVG with embedded styles).
"""

from pathlib import Path
import re
import xml.etree.ElementTree as ET

HTML_CONTENT = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>SuperGhidra · Architecture &amp; Zero Lock Contention</title>
  <link href="https://fonts.googleapis.com/css2?family=Instrument+Serif:ital@0;1&amp;family=Geist:wght@400;500;600&amp;family=Geist+Mono:wght@400;500;600&amp;display=swap" rel="stylesheet">
  <style>
    *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
    :root {
      --color-paper:   #2d3142;
      --color-ink:     #f5f5f5;
      --color-muted:   #bfc0c0;
      --color-accent:  #f08a59;
      --font-sans:     'Geist', system-ui, -apple-system, sans-serif;
      --font-serif:    'Instrument Serif', Georgia, serif;
      --font-mono:     'Geist Mono', ui-monospace, monospace;
    }

    body {
      font-family: var(--font-sans);
      background: var(--color-paper);
      color: var(--color-ink);
      min-height: 100vh;
      display: flex;
      align-items: center;
      justify-content: center;
      padding: 2.5rem 1.5rem;
    }

    .frame { max-width: 1100px; width: 100%; }

    .eyebrow {
      font-family: var(--font-mono);
      font-size: 0.68rem;
      font-weight: 500;
      letter-spacing: 0.18em;
      text-transform: uppercase;
      color: var(--color-muted);
      margin-bottom: 0.4rem;
    }

    h1 {
      font-family: var(--font-serif);
      font-size: clamp(1.6rem, 2.4vw + 0.8rem, 2.2rem);
      font-weight: 400;
      letter-spacing: -0.01em;
      line-height: 1.15;
      color: var(--color-ink);
      margin-bottom: 1.25rem;
    }

    svg { width: 100%; min-width: 900px; display: block; }
  </style>
</head>
<body>
  <div class="frame">
    <p class="eyebrow">Architecture · Diagram Design</p>
    <h1>SuperGhidra: Zero Lock Contention &amp; Non-Destructive Mutations</h1>

    <svg viewBox="0 0 1000 500" xmlns="http://www.w3.org/2000/svg" role="img" aria-labelledby="sg-arch-title sg-arch-desc">
      <title id="sg-arch-title">SuperGhidra Architecture &amp; Zero Lock Contention</title>
      <desc id="sg-arch-desc">Read/write separation via warm Ghidra background daemon, SQLite L2 query cache, shared-memory IPC, and non-destructive JSON write overlays.</desc>

      <defs>
        <pattern id="dots" width="22" height="22" patternUnits="userSpaceOnUse">
          <circle cx="1" cy="1" r="0.9" fill="rgba(245,245,245,0.08)"/>
        </pattern>
        <marker id="arrow" markerWidth="8" markerHeight="6" refX="7" refY="3" orient="auto"><polygon points="0 0, 8 3, 0 6" fill="#bfc0c0"/></marker>
        <marker id="arrow-accent" markerWidth="8" markerHeight="6" refX="7" refY="3" orient="auto"><polygon points="0 0, 8 3, 0 6" fill="#f08a59"/></marker>
        <marker id="arrow-link" markerWidth="8" markerHeight="6" refX="7" refY="3" orient="auto"><polygon points="0 0, 8 3, 0 6" fill="#739fdf"/></marker>
      </defs>

      <!-- Background with subtle editorial dotted grid -->
      <rect width="100%" height="100%" fill="#2d3142"/>
      <rect width="100%" height="100%" fill="url(#dots)" opacity="0.65"/>

      <!-- ==================== ZONES (Drawn before arrows and nodes) ==================== -->
      <!-- Zone 1: Read Path -->
      <rect x="40" y="68" width="920" height="96" rx="8"
            fill="rgba(245,245,245,0.02)" stroke="rgba(245,245,245,0.08)" stroke-width="0.8"/>
      <rect x="64" y="62" width="232" height="12" rx="2" fill="#2d3142"/>
      <text x="180" y="71" fill="#949eb2" font-size="7" font-family="'Geist Mono', monospace"
            text-anchor="middle" letter-spacing="0.14em">1 · READ PATH (ZERO LOCK CONTENTION)</text>

      <!-- Zone 2: Validation & Write Overlay -->
      <rect x="40" y="196" width="920" height="96" rx="8"
            fill="rgba(245,245,245,0.02)" stroke="rgba(245,245,245,0.08)" stroke-width="0.8"/>
      <rect x="64" y="190" width="272" height="12" rx="2" fill="#2d3142"/>
      <text x="200" y="199" fill="#949eb2" font-size="7" font-family="'Geist Mono', monospace"
            text-anchor="middle" letter-spacing="0.14em">2 · INTERACTIVE QUERIES &amp; VALIDATION GATE</text>

      <!-- Zone 3: Synchronization -->
      <rect x="40" y="324" width="920" height="96" rx="8"
            fill="rgba(245,245,245,0.02)" stroke="rgba(245,245,245,0.08)" stroke-width="0.8"/>
      <rect x="64" y="318" width="272" height="12" rx="2" fill="#2d3142"/>
      <text x="200" y="327" fill="#949eb2" font-size="7" font-family="'Geist Mono', monospace"
            text-anchor="middle" letter-spacing="0.14em">3 · SYNCHRONIZATION BACK TO MAIN PROJECT</text>

      <!-- ==================== ARROWS (Drawn before node boxes) ==================== -->
      <!-- Conn 1: Fork -> Daemon (H) -->
      <line x1="288" y1="116" x2="368" y2="116" stroke="#bfc0c0" stroke-width="1.2" marker-end="url(#arrow)"/>

      <!-- Conn 2: Daemon -> Cache (H) -->
      <line x1="632" y1="116" x2="712" y2="116" stroke="#bfc0c0" stroke-width="1.2" marker-end="url(#arrow)"/>

      <!-- Conn 3: Daemon -> Agents (Cached Xrefs) L-path with r=8 -->
      <path d="M 436,148 V 168 Q 436,176 428,176 H 184 Q 176,176 176,184 V 212"
            fill="none" stroke="#739fdf" stroke-width="1.2" marker-end="url(#arrow-link)"/>

      <!-- Conn 4: Agents -> Gate (H) -->
      <line x1="288" y1="244" x2="368" y2="244" stroke="#f08a59" stroke-width="1.4" marker-end="url(#arrow-accent)"/>

      <!-- Conn 5: Gate -> Overlay (H) -->
      <line x1="632" y1="244" x2="712" y2="244" stroke="#bfc0c0" stroke-width="1.2" marker-end="url(#arrow)"/>

      <!-- Conn 6: Overlay -> Live GUI Sync L-path with r=8 -->
      <path d="M 770,276 V 296 Q 770,304 762,304 H 338 Q 330,304 330,312 V 340"
            fill="none" stroke="#bfc0c0" stroke-width="1.2" marker-end="url(#arrow)"/>

      <!-- Conn 7: Overlay -> Headless Replay L-path with r=8 (offset 12px lower to prevent overlap) -->
      <path d="M 822,276 V 308 Q 822,316 814,316 H 678 Q 670,316 670,324 V 340"
            fill="none" stroke="#bfc0c0" stroke-width="1.2" marker-end="url(#arrow)"/>

      <!-- ==================== ARROW LABELS (Masked on paper rects) ==================== -->
      <!-- Label 1: SYNC READ -->
      <rect x="296" y="106" width="64" height="12" rx="2" fill="#2d3142"/>
      <text x="328" y="115" fill="#bfc0c0" font-size="8" font-family="'Geist Mono', monospace" text-anchor="middle" letter-spacing="0.08em">READ-ONLY</text>

      <!-- Label 2: L1/L2 LOOKUP -->
      <rect x="640" y="106" width="64" height="12" rx="2" fill="#2d3142"/>
      <text x="672" y="115" fill="#bfc0c0" font-size="8" font-family="'Geist Mono', monospace" text-anchor="middle" letter-spacing="0.08em">L1 / L2 IPC</text>

      <!-- Label 3: CACHED XREFS -->
      <rect x="246" y="170" width="88" height="12" rx="2" fill="#2d3142"/>
      <text x="290" y="179" fill="#739fdf" font-size="8" font-family="'Geist Mono', monospace" text-anchor="middle" letter-spacing="0.08em">CACHED XREFS</text>

      <!-- Label 4: MUTATIONS -->
      <rect x="296" y="234" width="64" height="12" rx="2" fill="#2d3142"/>
      <text x="328" y="243" fill="#f08a59" font-size="8" font-family="'Geist Mono', monospace" text-anchor="middle" letter-spacing="0.08em">PROPOSED</text>

      <!-- Label 5: VERIFIED -->
      <rect x="644" y="234" width="56" height="12" rx="2" fill="#2d3142"/>
      <text x="672" y="243" fill="#bfc0c0" font-size="8" font-family="'Geist Mono', monospace" text-anchor="middle" letter-spacing="0.08em">VERIFIED</text>

      <!-- Label 6: ATOMIC GUI SYNC -->
      <rect x="472" y="298" width="104" height="12" rx="2" fill="#2d3142"/>
      <text x="524" y="307" fill="#bfc0c0" font-size="8" font-family="'Geist Mono', monospace" text-anchor="middle" letter-spacing="0.08em">LIVE GUI SYNC</text>

      <!-- Label 7: BATCH MERGE -->
      <rect x="716" y="310" width="84" height="12" rx="2" fill="#2d3142"/>
      <text x="758" y="319" fill="#bfc0c0" font-size="8" font-family="'Geist Mono', monospace" text-anchor="middle" letter-spacing="0.08em">BATCH MERGE</text>

      <!-- ==================== NODES (Opaque mask + styled box) ==================== -->
      <!-- Node 1: Ghidra .rep Session -->
      <g>
        <rect x="64" y="84" width="224" height="64" rx="6" fill="#2d3142"/>
        <rect x="64" y="84" width="224" height="64" rx="6" fill="rgba(191,192,192,0.08)" stroke="#949eb2" stroke-width="1"/>
        <rect x="72" y="92" width="28" height="12" rx="2" fill="transparent" stroke="rgba(148,158,178,0.4)" stroke-width="0.8"/>
        <text x="86" y="101" fill="#949eb2" font-size="7" font-family="'Geist Mono', monospace" text-anchor="middle" letter-spacing="0.08em">REP</text>
        <text x="276" y="142" fill="rgba(245,245,245,0.06)" font-size="28" font-weight="600" font-family="'Geist Mono', monospace" text-anchor="end">01</text>
        <text x="176" y="118" fill="#f5f5f5" font-size="12" font-weight="600" font-family="'Geist', sans-serif" text-anchor="middle">Ghidra .rep Session</text>
        <text x="176" y="134" fill="#bfc0c0" font-size="9" font-family="'Geist Mono', monospace" text-anchor="middle">readOnly=True · zero lock collisions</text>
      </g>

      <!-- Node 2: SuperGhidra Daemon (Focal coral #f08a59) -->
      <g>
        <rect x="368" y="84" width="264" height="64" rx="6" fill="#2d3142"/>
        <rect x="368" y="84" width="264" height="64" rx="6" fill="rgba(240,138,89,0.08)" stroke="#f08a59" stroke-width="1"/>
        <rect x="376" y="92" width="44" height="12" rx="2" fill="transparent" stroke="rgba(240,138,89,0.5)" stroke-width="0.8"/>
        <text x="398" y="101" fill="#f08a59" font-size="7" font-family="'Geist Mono', monospace" text-anchor="middle" letter-spacing="0.08em">DAEMON</text>
        <text x="620" y="142" fill="rgba(240,138,89,0.10)" font-size="28" font-weight="600" font-family="'Geist Mono', monospace" text-anchor="end">02</text>
        <text x="500" y="118" fill="#f5f5f5" font-size="12" font-weight="600" font-family="'Geist', sans-serif" text-anchor="middle">SuperGhidra Background Daemon</text>
        <text x="500" y="134" fill="#bfc0c0" font-size="9" font-family="'Geist Mono', monospace" text-anchor="middle">127.0.0.1:5073 · warm JVM instance</text>
      </g>

      <!-- Node 3: L1 SHM & L2 Cache -->
      <g>
        <rect x="712" y="84" width="224" height="64" rx="6" fill="#2d3142"/>
        <rect x="712" y="84" width="224" height="64" rx="6" fill="#393e53" stroke="#f5f5f5" stroke-width="1"/>
        <rect x="720" y="92" width="36" height="12" rx="2" fill="transparent" stroke="rgba(245,245,245,0.4)" stroke-width="0.8"/>
        <text x="738" y="101" fill="#f5f5f5" font-size="7" font-family="'Geist Mono', monospace" text-anchor="middle" letter-spacing="0.08em">CACHE</text>
        <text x="924" y="142" fill="rgba(245,245,245,0.06)" font-size="28" font-weight="600" font-family="'Geist Mono', monospace" text-anchor="end">03</text>
        <text x="824" y="118" fill="#f5f5f5" font-size="12" font-weight="600" font-family="'Geist', sans-serif" text-anchor="middle">L1 SHM &amp; L2 SQLite Cache</text>
        <text x="824" y="134" fill="#bfc0c0" font-size="9" font-family="'Geist Mono', monospace" text-anchor="middle">64 KB SHM (&lt;50 µs) · &gt;100k req/s</text>
      </g>

      <!-- Node 4: Agents & CLI -->
      <g>
        <rect x="64" y="212" width="224" height="64" rx="6" fill="#2d3142"/>
        <rect x="64" y="212" width="224" height="64" rx="6" fill="rgba(191,192,192,0.08)" stroke="#949eb2" stroke-width="1"/>
        <rect x="72" y="220" width="40" height="12" rx="2" fill="transparent" stroke="rgba(148,158,178,0.4)" stroke-width="0.8"/>
        <text x="92" y="229" fill="#949eb2" font-size="7" font-family="'Geist Mono', monospace" text-anchor="middle" letter-spacing="0.08em">CLIENT</text>
        <text x="276" y="270" fill="rgba(245,245,245,0.06)" font-size="28" font-weight="600" font-family="'Geist Mono', monospace" text-anchor="end">04</text>
        <text x="176" y="246" fill="#f5f5f5" font-size="12" font-weight="600" font-family="'Geist', sans-serif" text-anchor="middle">AI Agents &amp; CLI Callers</text>
        <text x="176" y="262" fill="#bfc0c0" font-size="9" font-family="'Geist Mono', monospace" text-anchor="middle">Claude · Cursor · Antigravity · MCP</text>
      </g>

      <!-- Node 5: Pipeline Gate (Focal coral #f08a59) -->
      <g>
        <rect x="368" y="212" width="264" height="64" rx="6" fill="#2d3142"/>
        <rect x="368" y="212" width="264" height="64" rx="6" fill="rgba(240,138,89,0.08)" stroke="#f08a59" stroke-width="1"/>
        <rect x="376" y="220" width="32" height="12" rx="2" fill="transparent" stroke="rgba(240,138,89,0.5)" stroke-width="0.8"/>
        <text x="392" y="229" fill="#f08a59" font-size="7" font-family="'Geist Mono', monospace" text-anchor="middle" letter-spacing="0.08em">GATE</text>
        <text x="620" y="270" fill="rgba(240,138,89,0.10)" font-size="28" font-weight="600" font-family="'Geist Mono', monospace" text-anchor="end">05</text>
        <text x="500" y="246" fill="#f5f5f5" font-size="12" font-weight="600" font-family="'Geist', sans-serif" text-anchor="middle">Obligation Ledger Gate</text>
        <text x="500" y="262" fill="#bfc0c0" font-size="9" font-family="'Geist Mono', monospace" text-anchor="middle">vtables · displacements · sizes</text>
      </g>

      <!-- Node 6: JSON Write Overlay -->
      <g>
        <rect x="712" y="212" width="224" height="64" rx="6" fill="#2d3142"/>
        <rect x="712" y="212" width="224" height="64" rx="6" fill="#393e53" stroke="#f5f5f5" stroke-width="1"/>
        <rect x="720" y="220" width="48" height="12" rx="2" fill="transparent" stroke="rgba(245,245,245,0.4)" stroke-width="0.8"/>
        <text x="744" y="229" fill="#f5f5f5" font-size="7" font-family="'Geist Mono', monospace" text-anchor="middle" letter-spacing="0.08em">OVERLAY</text>
        <text x="924" y="270" fill="rgba(245,245,245,0.06)" font-size="28" font-weight="600" font-family="'Geist Mono', monospace" text-anchor="end">06</text>
        <text x="824" y="246" fill="#f5f5f5" font-size="12" font-weight="600" font-family="'Geist', sans-serif" text-anchor="middle">JSON Write Overlay</text>
        <text x="824" y="262" fill="#bfc0c0" font-size="9" font-family="'Geist Mono', monospace" text-anchor="middle">ghidra_overlay.json · delta log</text>
      </g>

      <!-- Node 7: Live GUI Sync -->
      <g>
        <rect x="180" y="340" width="300" height="64" rx="6" fill="#2d3142"/>
        <rect x="180" y="340" width="300" height="64" rx="6" fill="rgba(245,245,245,0.05)" stroke="#bfc0c0" stroke-width="1"/>
        <rect x="188" y="348" width="32" height="12" rx="2" fill="transparent" stroke="rgba(191,192,192,0.5)" stroke-width="0.8"/>
        <text x="204" y="357" fill="#bfc0c0" font-size="7" font-family="'Geist Mono', monospace" text-anchor="middle" letter-spacing="0.08em">SYNC</text>
        <text x="468" y="398" fill="rgba(245,245,245,0.06)" font-size="28" font-weight="600" font-family="'Geist Mono', monospace" text-anchor="end">3A</text>
        <text x="330" y="374" fill="#f5f5f5" font-size="12" font-weight="600" font-family="'Geist', sans-serif" text-anchor="middle">Option 3A · Live Ghidra GUI Sync</text>
        <text x="330" y="390" fill="#bfc0c0" font-size="9" font-family="'Geist Mono', monospace" text-anchor="middle">superghidra overlay-sync --watch</text>
      </g>

      <!-- Node 8: Headless Replay & Discard -->
      <g>
        <rect x="520" y="340" width="300" height="64" rx="6" fill="#2d3142"/>
        <rect x="520" y="340" width="300" height="64" rx="6" fill="rgba(245,245,245,0.05)" stroke="#bfc0c0" stroke-width="1"/>
        <rect x="528" y="348" width="36" height="12" rx="2" fill="transparent" stroke="rgba(191,192,192,0.5)" stroke-width="0.8"/>
        <text x="546" y="357" fill="#bfc0c0" font-size="7" font-family="'Geist Mono', monospace" text-anchor="middle" letter-spacing="0.08em">MERGE</text>
        <text x="808" y="398" fill="rgba(245,245,245,0.06)" font-size="28" font-weight="600" font-family="'Geist Mono', monospace" text-anchor="end">3B</text>
        <text x="670" y="374" fill="#f5f5f5" font-size="12" font-weight="600" font-family="'Geist', sans-serif" text-anchor="middle">Option 3B · Headless Replay &amp; Discard</text>
        <text x="670" y="390" fill="#bfc0c0" font-size="9" font-family="'Geist Mono', monospace" text-anchor="middle">merge_fork(auto_discard=True) · disk cleanup</text>
      </g>

      <!-- ==================== LEGEND STRIP ==================== -->
      <line x1="40" y1="448" x2="960" y2="448" stroke="rgba(245,245,245,0.10)" stroke-width="0.8"/>
      <text x="40" y="472" fill="#bfc0c0" font-size="8" font-family="'Geist Mono', monospace" letter-spacing="0.18em">LEGEND</text>

      <rect x="100" y="464" width="14" height="10" rx="2" fill="rgba(240,138,89,0.08)" stroke="#f08a59" stroke-width="1"/>
      <text x="120" y="472" fill="#bfc0c0" font-size="8.5" font-family="'Geist', sans-serif">Focal / daemon &amp; gate</text>

      <rect x="290" y="464" width="14" height="10" rx="2" fill="#393e53" stroke="#f5f5f5" stroke-width="1"/>
      <text x="310" y="472" fill="#bfc0c0" font-size="8.5" font-family="'Geist', sans-serif">In-memory / overlay store</text>

      <rect x="500" y="464" width="14" height="10" rx="2" fill="rgba(245,245,245,0.05)" stroke="#bfc0c0" stroke-width="1"/>
      <text x="520" y="472" fill="#bfc0c0" font-size="8.5" font-family="'Geist', sans-serif">Sync target (GUI or headless)</text>

      <line x1="720" y1="469" x2="742" y2="469" stroke="#739fdf" stroke-width="1.2" marker-end="url(#arrow-link)"/>
      <text x="750" y="472" fill="#bfc0c0" font-size="8.5" font-family="'Geist', sans-serif">Cached query</text>
    </svg>
  </div>
</body>
</html>
"""

def export_standalone_svg(html_str: str) -> str:
    # Extract svg element
    match = re.search(r"(<svg\b[^>]*>.*?</svg>)", html_str, re.DOTALL)
    if not match:
        raise ValueError("No <svg> block found in HTML")
    raw_svg = match.group(1)

    # Prefix IDs to avoid collisions
    slug = "architecture"
    id_re = re.compile(r'\bid=["\']([^"\']+)["\']')
    found_ids = set(id_re.findall(raw_svg))
    renames = {old: f"{slug}-{old}" for old in found_ids if old not in {"sg-arch-title", "sg-arch-desc"}}

    out_svg = raw_svg
    for old, new in renames.items():
        out_svg = re.sub(rf'\bid=["\']{re.escape(old)}["\']', f'id="{new}"', out_svg)
        out_svg = re.sub(rf'url\(#{re.escape(old)}\)', f'url(#{new})', out_svg)
        out_svg = re.sub(rf'href=["\']#{re.escape(old)}["\']', f'href="#{new}"', out_svg)

    # Embed typography and CSS variables inside <defs><style>
    font_import = (
        "@import url('https://fonts.googleapis.com/css2?family=Instrument+Serif:ital@0;1"
        "&amp;family=Geist:wght@400;500;600&amp;family=Geist+Mono:wght@400;500;600&amp;display=swap');"
    )
    style_block = f"""
      <style>
        {font_import}
        #{slug}-root {{
          --color-paper:   #2d3142;
          --color-ink:     #f5f5f5;
          --color-muted:   #bfc0c0;
          --color-accent:  #f08a59;
          --font-sans:     'Geist', system-ui, -apple-system, sans-serif;
          --font-serif:    'Instrument Serif', Georgia, serif;
          --font-mono:     'Geist Mono', ui-monospace, monospace;
          font-family: var(--font-sans);
          color: var(--color-ink);
        }}
      </style>
    """
    out_svg = out_svg.replace("<svg ", f'<svg id="{slug}-root" ', 1)
    out_svg = out_svg.replace("<defs>", f"<defs>{style_block}", 1)

    return f'<?xml version="1.0" encoding="UTF-8"?>\n{out_svg}\n'

def main():
    assets_dir = Path("docs/assets")
    assets_dir.mkdir(parents=True, exist_ok=True)

    html_path = assets_dir / "architecture.html"
    html_path.write_text(HTML_CONTENT, encoding="utf-8")
    print(f"Generated {html_path}")

    svg_content = export_standalone_svg(HTML_CONTENT)
    svg_path = assets_dir / "architecture.svg"
    svg_path.write_text(svg_content, encoding="utf-8")
    print(f"Generated {svg_path}")

if __name__ == "__main__":
    main()
