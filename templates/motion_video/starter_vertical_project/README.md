# Starter Vertical Motion Video (HyperFrames & GSAP)

Production starter project for authoring 9:16 vertical motion videos (TikTok, Instagram Reels, YouTube Shorts) using HTML, CSS, and GSAP timelines.

## Features
- **Deterministic 1080x1920 @ 30fps**: Configured in `hyperframes.json` and `index.html`.
- **Pre-configured Safe Zone Overlay**: Visual bounds for top search headers, right-side social action icons, and bottom caption shelves. Toggleable via `?safezone=1`.
- **Transform-Safe GSAP Animations**: Strictly avoids layout snapping on `left`/`top`; uses sub-pixel `x`/`y`/`scale`/`opacity`/`clipPath`.
- **Pre-Calibrated SFX**: Free UI sound effects with exact onset lead-in compensations so audio hits match visual frames.
- **Headless Chrome Webfont Protection**: Fully sanitized with longhand CSS properties (`font-family`, `font-size`, `font-weight`, `line-height`).

## Quick Start

```powershell
# 1. Preview composition in browser studio
npm run dev

# 2. Preview with Safe Zone overlay active
# Open browser to: http://localhost:PORT/?safezone=1

# 3. Audit and lint compositions
npm run check

# 4. Render to final MP4
npm run render
```

## Directory Structure

```
starter_vertical_project/
├── index.html                 # Main composition root timeline and SFX tracks
├── hyperframes.json           # 1080x1920 30fps canvas configuration
├── meta.json                  # Composition title and metadata
├── package.json               # Scripts for dev, check, render, and snapshot
├── SPEC.md                    # Creative constraints and timeline spec
├── compositions/
│   ├── s-hook.html            # Opening hook & friction statement (0-5s)
│   ├── s-terminal.html        # Real code/CLI surface with typewriter & marker highlights (5-25s)
│   └── s-end.html             # Call to action & held poster card (25-30s)
└── assets/sfx/
    ├── impact.mp3             # Hard transient landing hit (0.047s onset lead-in)
    ├── whoosh.mp3             # Transition scene wipe (0.165s peak lead-in)
    ├── pop.mp3                # Marker highlight swipe (0.113s onset lead-in)
    ├── typing.mp3             # CLI typewriter run (0.452s onset lead-in)
    ├── ping.mp3               # Success alert (0.318s onset lead-in)
    ├── error.mp3              # Failure/friction alert (0.604s onset lead-in)
    └── README.md              # Audio timing tables and alignment formulas
```

## Re-generating Terminal Scenes

To re-generate `compositions/s-terminal.html` directly from real CLI command output:

```powershell
node ../data_terminal_animator.mjs --input real_output.txt --output compositions/s-terminal.html --title "Engine Demo" --hl "755,391"
```

## Aligning New Sound Effects

When adding an audio file, calculate the exact `data-start` offset needed to match a visual hit at second `T`:

```powershell
python ../audio_onset_aligner.py --audio assets/sfx/custom_hit.wav --visual-hit 12.5 --id "sfx-custom"
```
