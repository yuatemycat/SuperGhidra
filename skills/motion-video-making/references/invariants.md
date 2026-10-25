# Technical Invariants for HyperFrames Motion Graphics

This document provides in-depth technical analysis and solutions for the 8 core invariants discovered during production runs on Windows 11.

---

## 1. Font Loading Longhand Bug in Headless Chrome

### Root Cause
HyperFrames uses Puppeteer/Playwright to drive a headless Chromium instance that navigates through the local DOM timeline frame-by-frame. When CSS uses the shorthand `font:` property:
```css
/* BROKEN IN HEADLESS CHROME */
font: 700 48px/1.2 'Inter', sans-serif;
```
Chromium's CSS font loader fails to resolve web fonts or bundled fonts (`Archivo Black`, `JetBrains Mono`, `Inter`) referenced by shorthand in certain inline `<style>` contexts inside `<template>` shadow DOMs. As a result, text silently defaults to `Times New Roman` or `Helvetica/Arial`.

### Remediation
Always write out explicit CSS longhand declarations:
```css
/* RELIABLE IN HEADLESS CHROME */
font-family: 'Inter', sans-serif;
font-weight: 700;
font-size: 48px;
line-height: 1.2;
```

---

## 2. Code Terminal Ligature Neutralization

### Root Cause
Monospaced developer typefaces such as `JetBrains Mono`, `Fira Code`, and `Cascadia Code` bundle OpenType ligature tables designed for programming readability. When rendering command prompts, assembly instructions, disassembly traces, or C code:
- `->` becomes an elongated Unicode right arrow (`\u2192`).
- `<-` becomes an elongated Unicode left arrow (`\u2190`).
- `!=` becomes an unequal mathematical symbol (`\u2260`).
- `==` becomes an elongated double equals bar.
- `//` or `/*` collapse into joined symbols.

In technical demonstrations, this disrupts monospaced column alignment and renders commands incorrectly.

### Remediation
Apply OpenType ligature neutralization to all code blocks:
```css
.terminal-text, pre, code, .code-body {
  font-variant-ligatures: none;
  font-feature-settings: "liga" 0, "calt" 0;
}
```

---

## 3. GSAP Transform-Only Rule (`gsap_non_transform_motion`)

### Root Cause
HyperFrames runs an automated AST validator (`npx hyperframes check`) that inspects GSAP animation scripts. If a timeline animates layout-triggering properties (`left`, `top`, `width`, `height`, `margin`, `padding`), the check rejects the build with:
```
Error: gsap_non_transform_motion on selector '#terminal'
Fix: animate x, y, scale, or clipPath instead of layout properties.
```
In browser compositing pipelines, layout recalculation degrades headless frame-capture framerates by up to 5x.

### Remediation
1. **Positioning & Movement:** Use `x` and `y` transforms.
2. **Expansion & Scaling:** Use `scaleX` and `scaleY` with an explicit `transform-origin` (e.g. `transform-origin: left center;`).
3. **Wipes & Crops:** Use `clipPath: "inset(0% 0% 0% 0%)"` or CSS clip-paths.
4. **State Machine Invariant:** Always use `gsap.fromTo()`. Avoid `gsap.from()` because seeking back to frame 0 can leave DOM elements frozen in dirty intermediate states.

---

## 4. Audio Onset Lead-In Compensation

### Root Cause
Many stock and bundled sound effect files (.mp3, .wav) contain an initial silent buffer or low-frequency transient swell before the primary acoustic attack. For example:
- `error.mp3`: Contains ~600 ms of pre-rumble before the abrasive error buzz.
- `ping.mp3`: Contains ~300 ms of ambient resonance before the bell chime.
- `impact.mp3`: Contains ~30 ms of sub-bass sweep before the primary hit.

If timed at the visual event time $T_{event}$, the auditory impact arrives noticeably out of sync.

### Formula
$$\text{data-start} = T_{event} - T_{lead\_in}$$

### Verification
Run `npx hyperframes audio` to produce the onset manifest:
```json
{
  "onsets": [
    { "file": "assets/sfx/whoosh.mp3", "time": 6.57 },
    { "file": "assets/sfx/typing.mp3", "time": 10.45 },
    { "file": "assets/sfx/pop.mp3", "time": 11.56 },
    { "file": "assets/sfx/ping.mp3", "time": 24.98 }
  ]
}
```
Align each onset with visual frame timestamps.

---

## 5. Vertical Safe-Zones for 9:16 Video

### Coordinate Breakdown (1080 × 1920 px)
```
+------------------------------------+ (0,0)
| Top Exclusion Zone (y: 0 - 168)     | Status bar, search bar, tabs
+------------------------------------+ (y = 168)
|                                    |
|                                    |
|         ACTION SAFE ZONE           |
|                                    | Right Rail Exclusion
|       (x: 0 - 940 px)              | (x: 940 - 1080 px)
|       (y: 168 - 1330 px)           | Avatar, likes, comments,
|                                    | share button icons
|                                    |
|                                    |
+------------------------------------+ (y = 1330)
| Bottom Exclusion Zone              | Captions, music title,
| (y: 1330 - 1920)                   | profile handle, navigation bar
+------------------------------------+ (1080, 1920)
```
- Keep all interactive typography, code terminals, and diagram nodes inside `y: 168` to `1330 px` and `x <= 940 px`.
- Use the bottom region (`y > 1330 px`) only for solid background extensions.

---

## 6. Frame 0 Hook Rule

### Principle
Mobile video discovery is governed by instant swipe interactions. The first frame rendered by the player is Frame 0.
- **Banned:** Black canvas, white flash, fading in from opacity 0, static logos, or spinning loaders.
- **Required:** High-contrast statement, quantified benchmark disparity, or visceral pain point already rendered at full opacity at $t = 0.00s$.
- Motion during the hook should be constrained to subtle emphasis (e.g. a loading bar filling up or a single word blur-in) rather than a slow reveal.

---

## 7. Data-Driven Stdout-to-Animation Pipeline

### Principle
Never invent or hand-craft terminal output. Real reverse engineering and systems tools produce idiosyncratic formatting, table alignments, and error structures that convey authenticity.
- Capture stdout directly from live tool execution.
- Programmatically generate individual character spans for typing sequences.
- Keep `white-space: pre-wrap;` strictly scoped to individual line elements (`.ln`), preventing empty vertical gaps.
- Apply highlight marker sweeps using CSS background gradients rather than adding extra DOM overlays.

---

## 8. Telemetry Suppression Invariant

### Principle
Automated agent toolchains must operate deterministically without transmitting telemetry, prompts, or feedback ratings to external servers.
Always inject the following environment variables:
```powershell
$env:DO_NOT_TRACK = "1"
$env:HYPERFRAMES_NO_TELEMETRY = "1"
$env:HYPERFRAMES_SKIP_SKILLS = "1"
```
Do not run `npx hyperframes feedback` or `npx hyperframes events`.
