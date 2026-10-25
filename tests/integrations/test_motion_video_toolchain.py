"""Integration test suite for the Motion Video Toolchain & HyperFrames Engine.

Validates:
1. Workstation environment (Node.js 22+, FFmpeg 9.0.1+ at E:\\03_Devops).
2. HyperFrames runner scripts and environment variable enforcement.
3. Existing rendered artifact verification (superghidra-tiktok.mp4 metadata and streams).
4. Motion video production templates in templates/motion_video/ (font sanitizer, terminal animator, audio onset aligner).
"""

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path
import pytest

WORKSPACE_ROOT = Path(__file__).resolve().parents[2]
DEV_OPS_ROOT = Path("E:/03_Devops")
FFMPEG_EXE = DEV_OPS_ROOT / "hermes/tools/ffmpeg-9.0.1-win32-x64/bin/ffmpeg.exe"
FFPROBE_EXE = DEV_OPS_ROOT / "hermes/tools/ffmpeg-9.0.1-win32-x64/bin/ffprobe.exe"
LAUNCH_FILM_DIR = Path("E:/02_Projects/superghidra-launch/film")
LAUNCH_MP4 = LAUNCH_FILM_DIR / "out/superghidra-tiktok.mp4"
TEMPLATES_DIR = WORKSPACE_ROOT / "templates/motion_video"


def test_node_environment():
    """Verify Node.js is installed and version is >= 22.0.0."""
    result = subprocess.run(["node", "-v"], capture_output=True, text=True, check=True)
    version_str = result.stdout.strip()
    assert version_str.startswith("v"), f"Unexpected node version format: {version_str}"
    major = int(version_str.lstrip("v").split(".")[0])
    assert major >= 22, f"Node.js major version must be >= 22, found {major} ({version_str})"


def test_ffmpeg_availability():
    """Verify FFmpeg and FFprobe exist in E:\\03_Devops and execute cleanly."""
    assert FFMPEG_EXE.exists(), f"FFmpeg not found at {FFMPEG_EXE}"
    assert FFPROBE_EXE.exists(), f"FFprobe not found at {FFPROBE_EXE}"

    result = subprocess.run([str(FFMPEG_EXE), "-version"], capture_output=True, text=True, check=True)
    assert "ffmpeg version" in result.stdout
    assert "libavcodec" in result.stdout

    result_probe = subprocess.run([str(FFPROBE_EXE), "-version"], capture_output=True, text=True, check=True)
    assert "ffprobe version" in result_probe.stdout


def test_hyperframes_runner_scripts():
    """Verify helper runner scripts exist and execute hyperframes --version cleanly."""
    cmd_script = DEV_OPS_ROOT / "bin/hyperframes.cmd"
    ps1_script = WORKSPACE_ROOT / "scripts/run_hyperframes.ps1"

    assert cmd_script.exists(), f"Runner script missing at {cmd_script}"
    assert ps1_script.exists(), f"Runner script missing at {ps1_script}"

    # Test powershell wrapper
    proc = subprocess.run(
        ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", str(ps1_script), "--version"],
        capture_output=True,
        text=True,
        check=True,
    )
    assert "0.8.195" in proc.stdout.strip(), f"Expected version 0.8.195, got: {proc.stdout}"


def test_launch_video_artifact_metadata():
    """Verify the rendered launch video artifact exists, has size > 1MB, and matches 9:16 H.264/AAC specs."""
    assert LAUNCH_MP4.exists(), f"Artifact missing: {LAUNCH_MP4}"
    file_size = LAUNCH_MP4.stat().st_size
    assert file_size > 1_000_000, f"File size too small: {file_size} bytes"

    # Inspect streams via ffprobe
    probe_cmd = [
        str(FFPROBE_EXE),
        "-v", "error",
        "-print_format", "json",
        "-show_format",
        "-show_streams",
        str(LAUNCH_MP4),
    ]
    proc = subprocess.run(probe_cmd, capture_output=True, text=True, check=True)
    meta = json.loads(proc.stdout)

    streams = meta.get("streams", [])
    video_stream = next((s for s in streams if s.get("codec_type") == "video"), None)
    audio_stream = next((s for s in streams if s.get("codec_type") == "audio"), None)

    assert video_stream is not None, "Missing video stream"
    assert video_stream["codec_name"] == "h264"
    assert int(video_stream["width"]) == 1080
    assert int(video_stream["height"]) == 1920
    assert float(video_stream["duration"]) == pytest.approx(30.0, abs=0.1)

    assert audio_stream is not None, "Missing audio stream"
    assert audio_stream["codec_name"] == "aac"
    assert int(audio_stream["sample_rate"]) == 48000
    assert int(audio_stream["channels"]) == 2


def test_motion_video_templates_font_sanitizer():
    """Verify font_longhand_sanitizer.mjs expands shorthands and checks clean trees."""
    sanitizer_path = TEMPLATES_DIR / "font_longhand_sanitizer.mjs"
    assert sanitizer_path.exists(), f"Missing template: {sanitizer_path}"

    proc = subprocess.run(["node", str(sanitizer_path), "--help"], capture_output=True, text=True)
    assert proc.returncode == 0
    assert "HyperFrames Font Longhand Sanitizer" in proc.stdout

    # Check against launch film compositions
    proc_check = subprocess.run(
        ["node", str(sanitizer_path), "--check", "--dir", str(LAUNCH_FILM_DIR)],
        capture_output=True,
        text=True,
    )
    assert proc_check.returncode == 0
    assert "Found 0 shorthand declarations" in proc_check.stdout


def test_motion_video_templates_terminal_animator(tmp_path):
    """Verify data_terminal_animator.mjs synthesizes valid GSAP terminal compositions."""
    animator_path = TEMPLATES_DIR / "data_terminal_animator.mjs"
    assert animator_path.exists(), f"Missing template: {animator_path}"

    sample_input = tmp_path / "sample.txt"
    sample_input.write_text(
        "$ superghidra scan target.dll\n[OK] Recovered 42 RTTI classes\n[OK] Analysis completed in 0.4s\n",
        encoding="utf-8"
    )
    output_html = tmp_path / "terminal.html"

    proc = subprocess.run(
        [
            "node",
            str(animator_path),
            "--input", str(sample_input),
            "--output", str(output_html),
            "--title", "Test Scan",
            "--hl", "42,0.4s",
        ],
        capture_output=True,
        text=True,
        check=True,
    )
    assert output_html.exists()
    content = output_html.read_text(encoding="utf-8")
    assert "gsap" in content
    assert "JetBrains Mono" in content
    assert "font-family:" in content
    assert "Test Scan" in content


def test_motion_video_templates_audio_aligner():
    """Verify audio_onset_aligner.py correctly calculates acoustic attack lead-in offset."""
    aligner_path = TEMPLATES_DIR / "audio_onset_aligner.py"
    assert aligner_path.exists(), f"Missing template: {aligner_path}"

    sfx_file = LAUNCH_FILM_DIR / "assets/sfx/error.mp3"
    assert sfx_file.exists(), f"Test sfx file missing: {sfx_file}"

    proc = subprocess.run(
        [
            sys.executable,
            str(aligner_path),
            "--audio", str(sfx_file),
            "--visual-hit", "3.83",
            "--json",
        ],
        capture_output=True,
        text=True,
        check=True,
    )
    res = json.loads(proc.stdout)
    assert 0.50 <= res["lead_in"] <= 0.70, f"Unexpected lead-in for error.mp3: {res['lead_in']}"
    assert pytest.approx(res["calculated_data_start"], abs=0.05) == 3.23
    assert "<audio id=\"sfx-error\"" in res["html_tag"]


def test_starter_vertical_project_structure():
    """Verify starter_vertical_project contains all necessary assets, configs, and compositions."""
    starter_dir = TEMPLATES_DIR / "starter_vertical_project"
    assert starter_dir.exists(), f"Starter project directory missing: {starter_dir}"

    assert (starter_dir / "index.html").exists()
    assert (starter_dir / "hyperframes.json").exists()
    assert (starter_dir / "package.json").exists()
    assert (starter_dir / "meta.json").exists()
    assert (starter_dir / "SPEC.md").exists()
    assert (starter_dir / "README.md").exists()

    sfx_dir = starter_dir / "assets/sfx"
    assert sfx_dir.exists()
    assert (sfx_dir / "README.md").exists()
    required_sfx = ["error.mp3", "impact.mp3", "ping.mp3", "pop.mp3", "typing.mp3", "whoosh.mp3"]
    for sfx in required_sfx:
        assert (sfx_dir / sfx).exists(), f"Missing required SFX in starter kit: {sfx}"

    comps_dir = starter_dir / "compositions"
    assert comps_dir.exists()
    assert (comps_dir / "s-hook.html").exists()
    assert (comps_dir / "s-terminal.html").exists()
    assert (comps_dir / "s-end.html").exists()

