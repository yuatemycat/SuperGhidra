# Bundled Free Sound Effects Reference

These audio assets are royalty-free sound effects pre-calibrated for UI transitions, typography hits, and real product interactions in HyperFrames video compositions.

## Measured Lead-In and Onset Metrics

Measured using `templates/motion_video/audio_onset_aligner.py` (RMS threshold ratio = 0.20, frame = 10ms, hop = 2ms):

| File | Duration (s) | Peak RMS (dBFS) | Peak Time (s) | Onset Lead-In (s) | Recommended Mix Volume | Primary Visual Use Case |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| `impact.mp3` | 2.116 | -2.7 | 0.077 | **0.047** | `0.80 - 0.85` | Hero wordmark landing, CTA lock-in, hard collision |
| `whoosh.mp3` | 0.575 | -7.5 | **0.165** (peak) | **0.121** (onset) | `0.65 - 0.80` | Scene flood/wipes, terminal slides, drawer reveals |
| `pop.mp3` | 0.720 | -9.9 | 0.123 | **0.113** | `0.75 - 0.80` | Marker swipes, chip highlights, badge appearances |
| `typing.mp3` | 1.500 | -20.6 | 0.460 | **0.452** | `0.45 - 0.55` | Code typing runs, terminal command entry |
| `ping.mp3` | 1.320 | -20.8 | 0.326 | **0.318** | `0.65 - 0.70` | Success toasts, checkmarks, slot reel completion |
| `error.mp3` | 1.620 | -26.7 | 0.741 | **0.604** | `0.45 - 0.50` | Tension beats, script failures, lockup alerts |

## Alignment Rule

To align an auditory hit with a visual event occurring at second `T_visual`:

```
data-start = T_visual - LeadIn
```

- For **hard strikes** (`impact.mp3`, `pop.mp3`), subtract the **Onset Lead-In**.
- For **kinetic sweeps** (`whoosh.mp3`), subtract the **Peak Time** (0.165s) so the peak rush of wind hits right at the visual seam.
