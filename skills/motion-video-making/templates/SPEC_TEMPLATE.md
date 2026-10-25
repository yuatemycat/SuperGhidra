# SPEC: [Project Title] (TikTok / Vertical 9:16)

GOAL:    A developer who scrolls past sees one quantified result ([Key Win]) and leaves knowing the exact command to type: `[Install Command]`.
OUTPUT:  HyperFrames, 1080 x 1920, 30 fps.
TIME:    [Duration, e.g. 30.0] s x 30 fps = [Total Frames, e.g. 900] frames. Muted-first design. No voiceover, no synthetic captions. Every word is high-contrast on-screen typography. No human avatars, faces, or hands.

LOOK:    Medium = flat colour-block poster plus one authenticated product surface.
         Grounds (flat, no gradient, no grain): old way #[Hex1], new way #[Hex2], explainer #[Hex3], end card #[Hex4].
         Ink #[DarkHex] on light grounds; white on #[DarkHex]. Accent = #[AccentHex], reserved strictly for counted metrics and chips.
         Display Typography: Archivo Black 400, tracking -2%, line-height 0.92, sizes 130-400 px.
         Body/Labels: Inter 700/800, sizes 44-72 px.
         Terminal & Commands: JetBrains Mono 400/500/700, 34 px in terminal, 52-56 px for CTA.
         Product Surface: Authenticated terminal window, title bar 64 px with three window dots (#FF5F57 #FEBC2E #28C840). Text captured from real CLI execution (`assets/real_output.txt`), never retyped.
         Shadow: none. Vignette: none. Corner radius: 18 px on terminal/pill only.

OBJECTS: Terminal window (above). Diagram nodes are 4-6 px ink-outlined rectangles with real labels. Arrows drawn via clip-path. No generic icons, no padlocks, no fake logos.

MOTION:  Entrance = expo.out 0.45 s; move/camera = power2.inOut 0.4-0.6 s; exit/flood = power3.in 0.3 s.
         Wipe-flood between scenes: clip-path inset, 12 frames, power2.inOut.
         Landed typography is dead still.
         Terminal typing: 1 char per frame (0.018s stagger), linear.
         Exits are 40-50% shorter than entrances.

SHOTS:
  S1  f0-75    HOOK. Frame 0 is already fully painted (no black frame). High-contrast problem statement.
  S2  f75-195  TENSION. Rapid 3-beat rhythm (40 frames each). Per-word blur entrances. Hands off via wipe-flood.
  S3  f195-255 REVEAL. Hero brand / solution name reveals per-letter. Ink pill lands with key claim.
  S4  f255-540 PROOF (held 9.5 s). Terminal window morphs from pill (x/y/scale). Real CLI command types out; stdout appears; key quantitative metric highlighted with fluorescent marker swipe.
  S5  f540-700 HOW IT WORKS. Clean white ground. Beat A: READS architecture path. Beat B: WRITES guarantee.
  S6  f700-810 AGENTS / ECOSYSTEM. Slot machine reel rolling through agent tools, landing on target integration.
  S7  f810-900 END CARD. Minimal obsidian background. Large product wordmark wipes in. Terminal CTA pill lands with `$ [install command]`. Final state holds dead still for >= 2.0 s.

BANNED DEFAULTS: Dark void with floating dust, glow/bloom/neon, particles, radial gradients, glassmorphism cards, 3 KPI cards in a row, fake logos, simulated avatars, synthesized voices, placeholder mockup results.

SAFE ZONE (TikTok/Reels): Nothing above y=168. All text and product inside y 168-1330. Below 1330 only flat background color. No text right of x=940.

QA GATES:
- `npx hyperframes check --json` reports 0 errors.
- Frame 0 hook readable and non-black.
- Every `<audio>` element has an `id`.
- Audio onsets compensated for lead-ins.
- Audio loudness between -14 and -16 LUFS (or -11 to -12 LUFS for sparse SFX), 0 clipped samples.
