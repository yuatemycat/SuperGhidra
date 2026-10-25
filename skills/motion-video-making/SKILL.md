---
name: motion-video-making
description: Master motion graphic and launch video production using HyperFrames (HTML/CSS + GSAP to MP4). Codifies technical invariants (font longhand parsing, ligature neutralization, GSAP transform-only motion, audio onset lead-in compensation, vertical safe-zones, Frame 0 hook, real stdout-to-DOM piping, telemetry suppression).
---

# Motion Video Making (HyperFrames Engine)

This skill codifies the complete pipeline and hard-won invariants for producing deterministic motion graphics, product launch clips, and technical terminal animations using the HyperFrames rendering engine (HTML/CSS + GSAP frame-by-frame seeking).

## 1. Core Operating Environment & Toolchain

- **Node.js Runtime:** Node.js 22+ (v24.21.0 on this workstation).
- **FFmpeg Requirement:** Dedicated binary at `E:\03_Devops\hermes\tools\ffmpeg-9.0.1-win32-x64\bin\ffmpeg.exe`. Prepend to `$env:Path` before running render or audio verification commands:
  ```powershell
  $env:Path = "E:\03_Devops\hermes\tools\ffmpeg-9.0.1-win32-x64\bin;" + $env:Path
  ```
- **Telemetry Suppression (Mandatory):** Pass telemetry denial environment flags on every `npx hyperframes` execution:
  ```powershell
  $env:DO_NOT_TRACK = "1"
  $env:HYPERFRAMES_NO_TELEMETRY = "1"
  $env:HYPERFRAMES_SKIP_SKILLS = "1"
  ```
- **CLI Invariant:** Use pinned package version `npx hyperframes@0.8.195 <command>` or local project dependencies.

---

## 2. Hard-Won Technical Invariants

### Invariant 1: Font Loading Longhand Requirement
- **Problem:** Headless Chrome running inside HyperFrames fails to parse or trigger font loading when using the CSS `font:` shorthand (e.g. `font: 400 34px/1.4 'JetBrains Mono', monospace;`). Elements fall back silently to default system sans-serif (Helvetica/Arial), destroying layout alignment.
- **Rule:** **Never** use `font:` shorthand. Always write explicit longhand CSS properties:
  ```css
  font-family: 'JetBrains Mono', monospace;
  font-weight: 400;
  font-size: 34px;
  line-height: 1.4;
  ```
- Use `scripts/font_longhand_sanitizer.mjs` to automatically verify and rewrite all stylesheets.

### Invariant 2: Code Terminal Ligature Neutralization
- **Problem:** Developer fonts (JetBrains Mono, Fira Code, Cascadia Code) feature stylistic ligatures that collapse ASCII character sequences like `->`, `<-`, `!=`, `==`, `//` into single symbolic glyphs (e.g. arrows, unequal signs). In terminal capture animations and disassembly traces, this creates visual artifacts and misaligns monospaced columns.
- **Rule:** On any container hosting terminal, code, or disassembled output, explicitly neutralize ligatures and contextual alternates:
  ```css
  #terminal-body, .code-container {
    font-variant-ligatures: none;
    font-feature-settings: "liga" 0, "calt" 0;
  }
  ```

### Invariant 3: GSAP Transform-Only Motion
- **Problem:** Tweening CSS layout properties (`left`, `top`, `width`, `height`, `margin`, `padding`) triggers layout reflows, causes frame rendering jank in headless browser passes, and fails `npx hyperframes check --json` with `gsap_non_transform_motion`.
- **Rule:** Animate exclusively via GPU-accelerated compositing properties (`x`, `y`, `scale`, `scaleX`, `scaleY`, `rotation`, `opacity`, `clipPath`, `filter`).
- **Initial State Invariant:** Always use `gsap.fromTo()`, never `gsap.from()`. Scrubbing or seeking a timeline that uses `.from()` leads to stale initial values and visual glitches.
- **Width/Height Transitions:** For progress bars, terminal expansions, or morphing pills:
  - Use `scaleX` or `scaleY` with `transform-origin: left center;` instead of tweening `width` or `height`.
  - Or tween `clip-path: inset(...)` for reveal wipes.

### Invariant 4: Audio Onset Lead-In Compensation
- **Problem:** Standard bundled sound effect files (`error.mp3`, `ping.mp3`, `impact.mp3`) often contain a brief lead-in period of silence or ambient pre-attack transient before the perceptual peak onset (e.g. `error.mp3` has ~0.60s lead-in; `ping.mp3` has ~0.30s lead-in). If the `<audio>` tag's `data-start` is set to the visual beat timestamp, the sound hits visibly late.
- **Rule:** Measure audio onset latency using `python scripts/audio_onset_aligner.py` and apply negative offset to `data-start`:
  $$\text{data-start} = T_{\text{visual\_beat}} - T_{\text{audio\_lead\_in}}$$
  Example: For a visual error punch landing at `t = 3.83s`, set `data-start="3.23"` for a file with 0.60s lead-in.
- **Audio Tag Contract:** Every `<audio>` element MUST have a unique `id` attribute, or HyperFrames will omit it from the final render mix.

### Invariant 5: Vertical Safe Zones (TikTok, Reels, Shorts)
- **Dimensions:** 1080 × 1920 px (9:16 portrait) at 30 fps.
- **Top Bar Exclusion:** `y < 168 px` (covered by system status bar, search icon, tabs).
- **Bottom Bar Exclusion:** `y > 1330 px` (covered by creator username, caption, sound marquee, platform action pills). Only flat background color or non-critical texture allowed below 1330 px.
- **Right Rail Exclusion:** `x > 940 px` (covered by avatar, like, comment, bookmark, share icons).
- **Safe Action Zone:** `x: [0, 940]`, `y: [168, 1330]`. All readable text, terminal frames, and key graphics must sit entirely within this rectangle.
- **Minimum Font Floor:** 28 px. Any body or terminal text below 28 px becomes unreadable when scaled to a mobile screen.

### Invariant 6: Frame 0 Hook Rule
- **Problem:** Social platforms use Frame 0 as the instant preview thumbnail. If Frame 0 is black, shows a generic splash, or fades in from opacity 0, viewers swipe away within 200 ms.
- **Rule:** Frame 0 must already be fully painted with high-contrast, visceral tension (e.g. bold claim, massive quantified problem, or real failure state). No black frames. No logo splash screens. The text or visual must be legible on Frame 0 before any timeline progression occurs.

### Invariant 7: Data-Driven Stdout-to-Animation Pipeline
- **Problem:** Manually typing mock terminal output creates synthetic, unconvincing demonstrations and introduces typos.
- **Rule:** Capture real command execution stdout using `capture_real_stdout.py`. Parse the exact stdout into JSON/HTML spans via `data_terminal_animator.mjs`.
- **Typing Mechanics:**
  - Wrap each character in `<span class="c">char</span>`.
  - Animate typing using `gsap.fromTo(".c", { opacity: 0 }, { opacity: 1, duration: 0.001, stagger: 0.018, ease: "none" })`.
  - Apply `white-space: pre-wrap;` on individual line containers (`.ln`), never on the outer terminal wrapper (prevents phantom empty lines).
  - Target key numbers for marker swipe highlights:
    `background: linear-gradient(#B8F433, #B8F433) no-repeat left center; background-size: 0% 100%;` tweened to `background-size: 100% 100%`.

### Invariant 8: Banned Visual Defaults
Avoid generic synthetic AI video tropes:
- No dark void with floating particle dust or glow/bloom neon.
- No generic glassmorphism cards with multi-colored radial gradients.
- No three-cards-in-a-row KPI layout.
- No floating 3D mockups of phones or laptops.
- No AI avatars, fake human presenters, or synthetic synthesized voices unless explicitly mandated.
- Grounding: Use solid, flat color-block poster grounds (e.g. `#FF4B1F` orange, `#B8F433` acid green, `#FFFFFF` crisp white, `#0A0A0A` obsidian ink) contrasted with one authentic product surface.

---

## 3. Production Workflow

1. **Capture:** Capture real tool output with `python scripts/capture_real_stdout.py`.
2. **Spec:** Author quantified specification `SPEC.md` using `templates/SPEC_TEMPLATE.md`.
3. **Scaffold:** Set up `index.html` and compositions using `templates/root_index.html` and `templates/scene_template.html`.
4. **Animate:** Generate terminal typing with `node scripts/data_terminal_animator.mjs`.
5. **Sanitize:** Sanitize CSS with `node scripts/font_longhand_sanitizer.mjs`.
6. **Align Audio:** Calculate audio lead-in offsets with `python scripts/audio_onset_aligner.py`.
7. **Audit:** Run `npx hyperframes check --json` (must report 0 errors).
8. **Render:** Render with `npx hyperframes render --quality looks --output out/film.mp4`.
9. **Verify:** Check loudness with `npx hyperframes audio` and duration with `ffprobe`.
