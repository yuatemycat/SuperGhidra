# Audio Onset Lead-In & Loudness Calibration

Guidelines and measured offset parameters for sound design in HyperFrames videos.

---

## 1. Measured SFX Lead-In Offset Table

The following measurements reflect the standard offline SFX library bundled in HyperFrames:

| SFX Name | File | Measured Acoustic Attack Onset | Recommended Negative Offset | Usage Scenario |
| :--- | :--- | :--- | :--- | :--- |
| **Error / Alarm** | `error.mp3` | ~0.60 s | `-0.60 s` | Visual failure, lock contention, red screen |
| **Ping / Bell** | `ping.mp3` | ~0.32 s | `-0.32 s` | Milestone achieved, recovery, successful check |
| **Whoosh / Wipe** | `whoosh.mp3` | ~0.00 s | `0.00 s` | Scene wipe, ground flood, slide transitions |
| **Pop / Bubble** | `pop.mp3` | ~0.00 s | `0.00 s` | Chip reveal, badge appearance |
| **Typing** | `typing.mp3` | ~0.00 s | `0.00 s` | Active terminal command entry |
| **Impact / Thud** | `impact.mp3` | ~0.03 s | `-0.03 s` | End-card slam, heavy hero arrival |

---

## 2. Timing Calculation Example

Suppose Scene 2 has three visual beats:
- Beat 1: "GUI OPEN?" at `t = 2.50s`
- Beat 2: "PROJECT LOCKED." at `t = 3.83s` (triggers error buzzer)
- Beat 3: "SCRIPTS FAIL." at `t = 5.17s`

To align the peak audible buzz of `error.mp3` with Beat 2:
$$\text{data-start} = 3.83\text{s} - 0.60\text{s} = 3.23\text{s}$$

In `index.html`:
```html
<audio id="sfx-error" src="assets/sfx/error.mp3" data-start="3.23" data-duration="1.4" data-volume="0.45" data-track-index="11"></audio>
```

---

## 3. Loudness & Dynamic Range Calibration

HyperFrames provides an automated EBU R128 loudness metering tool:
```powershell
npx hyperframes audio
```

### Loudness Targets:
1. **Full Mix (Dialogue + Background Music + SFX):**
   - Integrated Loudness: **-14.0 to -16.0 LUFS**
   - True Peak: **< -1.5 dBTP**
   - Loudness Range (LRA): **< 7 LU**
2. **Sparse Sound Design (SFX Only, No Music):**
   - Integrated Loudness: **-11.0 to -12.5 LUFS** (slightly hotter due to long silence between transients)
   - True Peak: **< -1.5 dBTP**
   - Clipped Samples: **0** (strictly enforced; any clipping fails QA)

### Headroom Safeguard:
Always set individual `<audio>` tag `data-volume` between `0.45` and `0.80` rather than `1.0` to avoid sum-distortion when multiple tracks overlap.
