# SPEC: Starter Vertical Video (9:16 Portrait)

## 1. Project Objective & Constraints
- **Platform**: TikTok, Instagram Reels, YouTube Shorts
- **Format**: 1080 x 1920 px, 30 fps, Progressive Scan
- **Duration**: 30.0s (900 frames)
- **Audio Strategy**: Muted-first by design. Motion graphics and high-contrast typography communicate the thesis with zero audio. Auditory SFX provide tactile weight when unmuted.

## 2. Visual Language & Anti-Patterns
- **Ground Colors**: Flat solid color blocks. No gradients, no dark void backgrounds, no synthetic floating particles, no bloom/glow.
  - Scene 1 (Hook / Tension): High-tension warm ground (`#FF4B1F` or similar)
  - Scene 2 (Proof / Product): High-contrast tech ground (`#B8F433` or `#FFFFFF`) with real terminal (`#16171C`)
  - Scene 3 (End Card): Clean deep ground (`#0A0A0A`) with accent wordmark
- **Typography**:
  - Display / Hero Words: `Archivo Black` 400 (tracking -2%, line-height 0.90 - 0.95, 150px - 400px)
  - Body & UI Labels: `Inter` 700/800 (44px - 72px)
  - Terminal & CLI Code: `JetBrains Mono` 500/700 (34px body, 50px - 56px CTA)
  - **Rule**: Explicit longhand CSS properties only (`font-family`, `font-size`, `font-weight`, `line-height`). Never shorthand `font:`.
  - **Rule**: Disable ligatures on code elements (`font-variant-ligatures: none; font-feature-settings: "liga" 0, "calt" 0;`).

## 3. TikTok / Shorts Safe Zones
```
+-------------------------------------------------------+ y = 0
|  TOP UI MARGIN (y: 0..168px)                          | (Header, Search, Following)
+-------------------------------------------------------+ y = 168px
|                                                       |
|                                                       |
|   VERIFIED CONTENT RECT                               |
|   x: 70px -> 940px                                    |
|   y: 168px -> 1330px                                  |
|                                                       |
|   (All copy, titles, terminals, CTAs must sit here)   |
|                                                       |
|                                                       |
+-------------------------------------------------------+ y = 1330px
|  BOTTOM CAPTION & INTERACTION SHELF (y: 1330..1920px) | (Captions, CTA, Profile)
+-------------------------------------------------------+ y = 1920px
```
- Safe rect: `x: 70px -> 940px`, `y: 168px -> 1330px`.
- No critical text right of `x = 940px` (covered by vertical action rail: like, comment, share, bookmark).
- Diagnostic: Run with `?safezone=1` in browser to visually audit elements against the red overlay.

## 4. Motion Guidelines & GSAP Invariants
- **Transform-only tweening**: Always animate `x`, `y`, `scale`, `opacity`, `clipPath`.
  - **NEVER** animate `left`, `top`, `margin`, or `padding` in GSAP. Non-transform layout properties snap to device pixels and stutter under frame-by-frame headless capture.
- **Entrances**: `expo.out` (0.45s) or `power2.out` (0.2 - 0.4s).
- **Scene flood transitions**: `clip-path: inset(...)` 0.4s with `power2.inOut`.
- **Exits**: 40-50% faster than entrances (`power3.in` 0.15 - 0.25s).
- **Stillness**: Once a title or statistic lands, it holds dead still. Do not add continuous floating drift.
- **Held poster finish**: Final end card must hold completely motionless for $\ge 1.5$ seconds before video end.

## 5. Timeline Shot Breakdown
| Scene | Seconds | Frames | Beat / Description |
| :--- | :--- | :--- | :--- |
| **S1: Hook** | `0.0 - 5.0` | 0 - 150 | Frame 0 shows initial statement immediately. Progress bar fills. Rapid tension beats. |
| **S2: Terminal** | `4.6 - 25.0` | 138 - 750 | Up-wipe green flood. Real terminal surface reveals. Command typed char-by-char. Output appears whole. Marker swipe on statistics. |
| **S3: End Card** | `25.0 - 30.0` | 750 - 900 | Up-wipe to deep ink. Brand wordmark wipes in. CTA terminal pill lands with impact hit. Holds static to end. |
