# Motion Video Toolchain & HyperFrames QA Verification Report

**Date:** 2026-10-25  
**Workstation Environment:** Windows 11 Pro, NVIDIA RTX A5500 Laptop GPU  
**Node.js Runtime:** v24.21.0  
**FFmpeg Version:** n9.0.1-11-ge47273f4d9-20260831 (`E:\03_Devops\hermes\tools\ffmpeg-9.0.1-win32-x64\bin\ffmpeg.exe`)  
**HyperFrames Package Version:** `0.8.195`  
**Test Suite Status:** 8 passed in 5.54s ([`tests/integrations/test_motion_video_toolchain.py`](file:///E:/02_Projects/SuperGhidra/tests/integrations/test_motion_video_toolchain.py))  

---

## 1. Workstation Toolchain Audit

### 1.1 Node.js Runtime
- Command: `node -v`
- Result: `v24.21.0` (exceeds the minimum Node.js 22+ requirement for ES module loaders and headless Chrome orchestration).

### 1.2 FFmpeg & FFprobe
- Binaries verified:
  - `E:\03_Devops\hermes\tools\ffmpeg-9.0.1-win32-x64\bin\ffmpeg.exe`
  - `E:\03_Devops\hermes\tools\ffmpeg-9.0.1-win32-x64\bin\ffprobe.exe`
- Version output: `ffmpeg version n9.0.1-11-ge47273f4d9-20260831`, built with gcc 15.2.0, supporting `libx264`, `libx265`, `libvmaf`, `libebur128`.

### 1.3 Telemetry & Isolation Helper Scripts
To ensure reproducible execution without telemetry leakage, interactive prompts, or PATH shadowing, helper wrappers were created and verified:
1. **Repository PowerShell Runner:** [`scripts/run_hyperframes.ps1`](file:///E:/02_Projects/SuperGhidra/scripts/run_hyperframes.ps1)
2. **DevOps Global CMD Wrapper:** [`E:\03_Devops\bin\hyperframes.cmd`](file:///E:/03_Devops/bin/hyperframes.cmd)
3. **DevOps Global PowerShell Wrapper:** [`E:\03_Devops\bin\hyperframes.ps1`](file:///E:/03_Devops/bin/hyperframes.ps1)
4. **Project Launch Wrapper:** [`E:\02_Projects\superghidra-launch\film\run-hyperframes.ps1`](file:///E:/02_Projects/superghidra-launch/film/run-hyperframes.ps1)

Each wrapper injects:
```powershell
$env:DO_NOT_TRACK = "1"
$env:HYPERFRAMES_NO_TELEMETRY = "1"
$env:HYPERFRAMES_SKIP_SKILLS = "1"
$env:Path = "E:\03_Devops\hermes\tools\ffmpeg-9.0.1-win32-x64\bin;$env:Path"
```
Verification test: `& scripts/run_hyperframes.ps1 --version` returns `0.8.195` with exit code 0.

---

## 2. Validation of Existing Launch Video (`superghidra-launch/film`)

### 2.1 HyperFrames Static and Runtime Check
- Command: `& ./run-hyperframes.ps1 check --json` in `E:\02_Projects\superghidra-launch\film`
- Report location: `.hyperframes/artifacts/checks/fbbaf30f-6b93-48a5-a51e-20810d975c4a.json`
- Results:
  - `lint.ok`: `true` (`errorCount: 0`, `warningCount: 0`)
  - `runtime.ok`: `true` (`errorCount: 0`, `warningCount: 0`)
  - `layout.ok`: `true` (`errorCount: 0`, `warningCount: 0`, `totalIssueCount: 0`)
  - `motion.ok`: `true` (`errorCount: 0`)
  - `contrast.ok`: `true` (`errorCount: 0`, 234/234 checks passed)
  - `craft.errorCount`: `0` (13 intentional `line_unread` warnings for slot-machine ticker rolls and character-by-character typing animations, documented in `REVIEW.md`)

### 2.2 Rendered Artifact Inspection (`superghidra-tiktok.mp4`)
- Target: `E:\02_Projects\superghidra-launch\film\out\superghidra-tiktok.mp4`
- File size: 1,535,132 bytes (~1.46 MB)
- FFprobe stream properties:
  - **Video Stream:** H.264 High Profile (`avc1`), 1080x1920 (9:16 vertical portrait), 30.0 fps progressive, 900 total frames, duration 30.000 s, bitrate 342.8 kb/s.
  - **Audio Stream:** AAC LC (`mp4a.40.2`), stereo, 48000 Hz, duration 30.000 s, bitrate 59.2 kb/s.
  - **Metadata Tags:** `hyperframes_version=0.8.195`, `hyperframes_renderer=hyperframes`, `encoder=Lavf63.1.101`.

---

## 3. Template Verification (`templates/motion_video/`)

All newly curated motion video assets were tested programmatically:

| Component | Path | Verification Command | Status | Notes |
| :--- | :--- | :--- | :--- | :--- |
| **Font Longhand Sanitizer** | [`font_longhand_sanitizer.mjs`](file:///E:/02_Projects/SuperGhidra/templates/motion_video/font_longhand_sanitizer.mjs) | `node templates/motion_video/font_longhand_sanitizer.mjs --check --dir templates/motion_video` | PASS | Scanned 6 files; found 0 shorthand violations; prevents headless font drop. |
| **Data Terminal Animator** | [`data_terminal_animator.mjs`](file:///E:/02_Projects/SuperGhidra/templates/motion_video/data_terminal_animator.mjs) | `node templates/motion_video/data_terminal_animator.mjs --input <txt> --output <html\>` | PASS | Generates GSAP timeline, typewriter syntax spans, marker highlights, no ligatures. |
| **Audio Onset Aligner** | [`audio_onset_aligner.py`](file:///E:/02_Projects/SuperGhidra/templates/motion_video/audio_onset_aligner.py) | `python templates/motion_video/audio_onset_aligner.py --audio error.mp3 --visual-hit 3.83 --json` | PASS | Detected attack lead-in of 0.604s; computed exact `data-start="3.226"` for hit at 3.83s. |
| **Starter Vertical Project** | [`starter_vertical_project/`](file:///E:/02_Projects/SuperGhidra/templates/motion_video/starter_vertical_project/) | `& run_hyperframes.ps1 check --json` inside starter project | PASS | `ok: true`, 0 errors across lint, runtime, layout, motion, contrast. |

---

## 4. Pytest Automated Test Suite

A dedicated integration test module was added:
[`tests/integrations/test_motion_video_toolchain.py`](file:///E:/02_Projects/SuperGhidra/tests/integrations/test_motion_video_toolchain.py)

```
============================== 8 passed in 5.54s ==============================
tests/integrations/test_motion_video_toolchain.py::test_node_environment PASSED
tests/integrations/test_motion_video_toolchain.py::test_ffmpeg_availability PASSED
tests/integrations/test_motion_video_toolchain.py::test_hyperframes_runner_scripts PASSED
tests/integrations/test_motion_video_toolchain.py::test_launch_video_artifact_metadata PASSED
tests/integrations/test_motion_video_toolchain.py::test_motion_video_templates_font_sanitizer PASSED
tests/integrations/test_motion_video_toolchain.py::test_motion_video_templates_terminal_animator PASSED
tests/integrations/test_motion_video_toolchain.py::test_motion_video_templates_audio_aligner PASSED
tests/integrations/test_motion_video_toolchain.py::test_starter_vertical_project_structure PASSED
```

Existing core and lifter suites continue to pass cleanly without regressions (`161 passed, 1 skipped, 32 subtests passed in 9.10s`).
