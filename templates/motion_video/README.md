# Motion Video Toolkit & Production Templates

Standardized toolchain, generators, and starter templates for authoring deterministic motion graphics and technical product videos using HyperFrames, HTML5, CSS, and GSAP.

Curated from production session `cf067101-7ae1-43bd-b0d2-84405d4a8fbe`.

---

## Subsystem Layout

```
templates/motion_video/
├── data_terminal_animator.mjs       # Data-driven CLI & code surface animator
├── font_longhand_sanitizer.mjs      # CSS font shorthand -> longhand converter
├── audio_onset_aligner.py           # Audio transient onset & lead-in alignment tool
├── README.md                        # Documentation and architecture guide
└── starter_vertical_project/        # 9:16 portrait (1080x1920) boilerplate
    ├── index.html                   # Main composition with safe zone markers
    ├── hyperframes.json             # 1080x1920 30fps canvas config
    ├── meta.json                    # Project metadata
    ├── package.json                 # Scripts (dev, check, render, snapshot)
    ├── SPEC.md                      # Creative constraints & timing spec
    ├── README.md                    # Starter project instructions
    ├── compositions/
    │   ├── s-hook.html              # Opening hook scene (0 - 5s)
    │   ├── s-terminal.html          # Data-driven terminal scene (5 - 25s)
    │   └── s-end.html               # CTA & held poster card (25 - 30s)
    └── assets/sfx/
        ├── impact.mp3               # Hard strike landing (0.047s onset lead-in)
        ├── whoosh.mp3               # Scene transition sweep (0.165s peak lead-in)
        ├── pop.mp3                  # Marker swipe highlight (0.113s onset lead-in)
        ├── typing.mp3               # Typewriter run (0.452s onset lead-in)
        ├── ping.mp3                 # Success notification (0.318s onset lead-in)
        ├── error.mp3                # Tension alert (0.604s onset lead-in)
        └── README.md                # Audio timing tables & alignment formulas
```

---

## 1. Data Terminal Animator (`data_terminal_animator.mjs`)

Generates complete, seekable HyperFrames/GSAP HTML compositions directly from captured terminal logs (`assets/real_output.txt`) or structured JSON manifests.

### Why It Matters
Technical audiences immediately spot fake terminal animations. This tool enforces realism:
1. **Per-character typewriter cadence** on commands and prompts (`stagger: 0.018s`).
2. **Whole-chunk stdout reveals**: Output lines appear instantly or in realistic micro-bursts, matching actual stdout execution rather than typing character-by-character.
3. **Animated marker swipes**: Highlights key numbers, statistics, or metrics via CSS gradient background fills (`0% -> 100%`).
4. **Transform-only motion**: Animates strictly via `x`, `y`, `scale`, and `opacity`. Avoids GSAP layout snapping (`top`/`left`) that causes micro-stuttering during headless frame capture.
5. **Ligature suppression**: Enforces `font-variant-ligatures: none; font-feature-settings: "liga" 0, "calt" 0;` so arrows (`->`) and comparison operators (`!=`) remain stable monospaced glyphs.

### CLI Usage

```powershell
# Generate from raw text log (blocks separated by double newlines)
node templates/motion_video/data_terminal_animator.mjs `
  --input "assets/real_output.txt" `
  --output "compositions/s-terminal.html" `
  --title "SuperGhidra Engine" `
  --hl "755,391"

# Generate from structured JSON config
node templates/motion_video/data_terminal_animator.mjs `
  --config "terminal_scene.json" `
  --output "compositions/s-terminal.html"
```

### Programmatic API

```javascript
import { generateTerminalComposition, parseRawOutputText } from "./data_terminal_animator.mjs";

const blocks = parseRawOutputText(rawStdoutString);
const html = generateTerminalComposition({
  compositionId: "terminal_proof",
  width: 1080,
  height: 1920,
  terminal: {
    x: 70,
    y: 200,
    width: 940,
    height: 1100,
    title: "Analysis Demo"
  },
  highlights: [{ pattern: "100%", duration: 0.35 }],
  blocks
});
```

---

## 2. Font Longhand Sanitizer (`font_longhand_sanitizer.mjs`)

Automated utility that expands CSS shorthand `font:` declarations into explicit longhand properties (`font-family`, `font-size`, `font-weight`, `line-height`, `font-style`).

### Why It Matters
In headless Chromium (HyperFrames, Puppeteer, Playwright), CSS shorthand like:
```css
font: 700 54px/1 'Inter', sans-serif;
```
frequently fails to load or match custom `@font-face` descriptors during seek-by-frame screenshot captures, causing silent drops to Times New Roman or Arial. Expanding shorthand to:
```css
font-family: 'Inter', sans-serif; font-weight: 700; font-size: 54px; line-height: 1;
```
guarantees deterministic, pixel-perfect font rendering on all platforms.

### CLI Usage

```powershell
# Scan and rewrite a directory
node templates/motion_video/font_longhand_sanitizer.mjs --dir ./compositions

# CI Check mode (exits with code 1 if unexpanded shorthands exist)
node templates/motion_video/font_longhand_sanitizer.mjs --check --dir .

# Dry-run preview
node templates/motion_video/font_longhand_sanitizer.mjs --dry-run index.html
```

---

## 3. Audio Onset Aligner (`audio_onset_aligner.py`)

Analyzes audio sound effects (transient onsets, peak energy timestamps, lead-in delays) and calculates the exact `data-start` timeline offset to synchronize auditory impacts with visual motion frames.

### Why It Matters
Sound effects rarely begin with their peak transient at sample 0. For example:
- `whoosh.mp3` has a **0.165s** lead-in before the peak wind rush.
- `impact.mp3` has a **0.047s** lead-in before the strike transient.
- `pop.mp3` has a **0.113s** lead-in before the click.

If a visual impact occurs at second `27.200` and `<audio data-start="27.200">` is used, the audio strike arrives at `27.247s` (47ms late), destroying the illusion of physical collision.

### The Alignment Formula

$$\text{data-start} = T_{\text{visual\_target}} - \Delta t_{\text{lead\_in}}$$

### CLI Usage

```powershell
# Calculate placement for an impact hitting at 25.9s
python templates/motion_video/audio_onset_aligner.py `
  --audio "templates/motion_video/starter_vertical_project/assets/sfx/impact.mp3" `
  --visual-hit 25.9 `
  --id "sfx-impact"

# Align a whoosh transition so its peak lands at 4.6s
python templates/motion_video/audio_onset_aligner.py `
  --audio "templates/motion_video/starter_vertical_project/assets/sfx/whoosh.mp3" `
  --visual-hit 4.6 `
  --align-to peak

# Output machine-readable JSON
python templates/motion_video/audio_onset_aligner.py --audio pop.mp3 --visual-hit 8.9 --json

# Print only the formatted HTML tag
python templates/motion_video/audio_onset_aligner.py --audio ping.mp3 --visual-hit 14.2 --tag-only
```

---

## 4. Starter Vertical Project (`starter_vertical_project/`)

A production-ready boilerplate for 9:16 vertical video compositions (1080x1920 @ 30fps).

### Key Features
1. **Interactive Safe Zone Guide**: Shows TikTok/Reels overlay boundaries (top search 168px, right-side interaction rail 140px, bottom caption shelf 590px). Toggle in browser with `?safezone=1`.
2. **Transform-Safe GSAP Structure**: Sub-pixel motion interpolation with zero layout-snapping stutter.
3. **Three-Act Composition**:
   - `compositions/s-hook.html`: Strong hook statement on frame 0 with progress fill bar.
   - `compositions/s-terminal.html`: Real terminal demonstration with typewriter and marker effects.
   - `compositions/s-end.html`: Punchy call-to-action held dead still for $\ge 1.5$ seconds.
4. **Pre-calibrated Free SFX**: Complete set of 6 UI sound effects with verified onset lead-in tables.

### Development Workflow

```powershell
cd templates/motion_video/starter_vertical_project

# 1. Preview locally in browser
npm run dev

# 2. Audit against safe zones
# Open: http://localhost:PORT/?safezone=1

# 3. Check for layout, motion, contrast, and font issues
npm run check

# 4. Render final MP4
npm run render
```

---

## Environment & Dependency Requirements

- **Node.js**: `v22.0.0+` (native ESM modules).
- **Python**: `3.12+` with `numpy` (and standard library `wave`).
- **FFmpeg & FFprobe**: Installed at `E:\03_Devops\hermes\tools\ffmpeg-9.0.1-win32-x64\bin` and permanently registered in User `PATH`.
- **HyperFrames CLI**: `hyperframes@0.8.195` (executed via `npx --yes hyperframes@0.8.195` or `package.json` scripts).
