#!/usr/bin/env python3
"""
audio_onset_aligner.py

Calculates lead-in silence and transient onset offsets of audio sound effects
to precisely align auditory impacts with visual motion frames in HyperFrames / GSAP videos.

Why:
Sound effects (impacts, whooshes, typing clicks, pops, pings) rarely start at sample 0.
A whoosh might have 180ms of rising air before its peak.
An impact might have 35ms of silence or low-frequency rumble before the transient strike.
Placing `<audio data-start="27.2">` when a visual hit occurs at 27.2s results in the audio
landing 35-180ms late, breaking the illusion of tactile impact.

Formula:
    lead_in = t_onset - t_file_start
    audio_data_start = t_visual_target - lead_in

Supported Backends:
1. Native FFmpeg PCM Stream (MP3, WAV, AAC, M4A, OGG) + NumPy
2. Native Python `wave` + NumPy (zero-dependency fallback for WAV)
3. FFprobe packet / frame probe
4. Librosa / SciPy (optional if installed)

Usage:
    python audio_onset_aligner.py --audio impact.mp3 --visual-hit 27.2
    python audio_onset_aligner.py --audio whoosh.mp3 --visual-hit 6.5 --align-to peak
    python audio_onset_aligner.py --check-html index.html --assets-dir ./assets
"""

import argparse
import json
import math
import os
import shutil
import subprocess
import sys
import wave
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any

import numpy as np


# Default search locations for ffmpeg/ffprobe on this workstation
DEVOPS_FFMPEG_PATHS = [
    r"E:\03_Devops\hermes\tools\ffmpeg-9.0.1-win32-x64\bin",
    r"E:\03_Devops\bin",
]


def resolve_tool(tool_name: str) -> Optional[str]:
    """Finds an executable in PATH or known DevOps directories."""
    found = shutil.which(tool_name)
    if found:
        return found
    exts = [".exe", ""] if os.name == "nt" else [""]
    for d in DEVOPS_FFMPEG_PATHS:
        for ext in exts:
            candidate = os.path.join(d, tool_name + ext)
            if os.path.isfile(candidate):
                return candidate
    return None


FFMPEG_BIN = resolve_tool("ffmpeg")
FFPROBE_BIN = resolve_tool("ffprobe")


def load_audio_samples(file_path: Path, target_sr: int = 44100) -> Tuple[np.ndarray, int, float]:
    """
    Loads audio samples as a normalized mono float32 NumPy array [-1.0, 1.0].
    Returns (samples, sample_rate, duration_seconds).
    """
    ext = file_path.suffix.lower()

    # 1. Native WAV decoding using stdlib wave
    if ext == ".wav":
        try:
            with wave.open(str(file_path), "rb") as wf:
                channels = wf.getnchannels()
                sample_width = wf.getsampwidth()
                sr = wf.getframerate()
                n_frames = wf.getnframes()
                raw = wf.readframes(n_frames)

            if sample_width == 2:
                dtype = np.int16
                max_val = 32768.0
            elif sample_width == 4:
                dtype = np.int32
                max_val = 2147483648.0
            elif sample_width == 1:
                dtype = np.uint8
                samples = (np.frombuffer(raw, dtype=dtype).astype(np.float32) - 128.0) / 128.0
                if channels > 1:
                    samples = samples.reshape(-1, channels).mean(axis=1)
                duration = len(samples) / sr
                return samples, sr, duration
            else:
                raise ValueError(f"Unsupported sample width: {sample_width}")

            samples = np.frombuffer(raw, dtype=dtype).astype(np.float32) / max_val
            if channels > 1:
                samples = samples.reshape(-1, channels).mean(axis=1)
            duration = len(samples) / sr
            return samples, sr, duration
        except Exception as e:
            # Fall through to ffmpeg if standard wave parser fails
            pass

    # 2. FFmpeg pipe decoding (works for MP3, AAC, FLAC, M4A, OGG, WAV)
    if FFMPEG_BIN:
        cmd = [
            FFMPEG_BIN,
            "-v", "error",
            "-i", str(file_path),
            "-f", "s16le",
            "-ac", "1",
            "-ar", str(target_sr),
            "-"
        ]
        res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
        samples = np.frombuffer(res.stdout, dtype=np.int16).astype(np.float32) / 32768.0
        duration = len(samples) / target_sr
        return samples, target_sr, duration

    # 3. Librosa fallback if installed
    try:
        import librosa  # type: ignore
        samples, sr = librosa.load(str(file_path), sr=target_sr, mono=True)
        duration = float(len(samples) / sr)
        return samples.astype(np.float32), sr, duration
    except ImportError:
        pass

    raise RuntimeError(
        f"Cannot decode audio file {file_path}. FFmpeg was not found and librosa is not installed."
    )


def compute_energy_envelope(
    samples: np.ndarray,
    sr: int,
    frame_ms: float = 10.0,
    hop_ms: float = 2.5
) -> Tuple[np.ndarray, np.ndarray]:
    """
    Computes RMS energy envelope and timestamps.
    Returns (times, rms_values).
    """
    frame_len = max(1, int(sr * (frame_ms / 1000.0)))
    hop_len = max(1, int(sr * (hop_ms / 1000.0)))

    n_frames = max(1, (len(samples) - frame_len) // hop_len + 1)
    rms = np.zeros(n_frames, dtype=np.float32)
    times = np.zeros(n_frames, dtype=np.float32)

    for i in range(n_frames):
        start = i * hop_len
        end = start + frame_len
        chunk = samples[start:end]
        rms[i] = math.sqrt(float(np.mean(chunk * chunk)))
        times[i] = (start + frame_len / 2.0) / sr

    return times, rms


def analyze_onset(
    file_path: Path,
    threshold_ratio: float = 0.20,
    silence_db: float = -45.0
) -> Dict[str, Any]:
    """
    Analyzes an audio file to determine:
    - duration
    - peak energy and timestamp
    - onset hit timestamp (first frame reaching threshold_ratio of peak energy)
    - lead-in silence/attack duration
    """
    samples, sr, duration = load_audio_samples(file_path)

    if len(samples) == 0 or np.max(np.abs(samples)) == 0:
        return {
            "file": str(file_path),
            "duration": 0.0,
            "peak_time": 0.0,
            "onset_time": 0.0,
            "lead_in": 0.0,
            "peak_rms_dbfs": -100.0,
            "is_silent": True
        }

    times, rms = compute_energy_envelope(samples, sr, frame_ms=10.0, hop_ms=2.0)
    peak_idx = int(np.argmax(rms))
    peak_rms = float(rms[peak_idx])
    peak_time = float(times[peak_idx])

    peak_dbfs = 20.0 * math.log10(max(peak_rms, 1e-6))
    if peak_dbfs < silence_db:
        return {
            "file": str(file_path),
            "duration": duration,
            "peak_time": peak_time,
            "onset_time": 0.0,
            "lead_in": 0.0,
            "peak_rms_dbfs": peak_dbfs,
            "is_silent": True
        }

    # Onset threshold: fraction of peak RMS
    threshold = peak_rms * threshold_ratio

    # Find first moment crossing the threshold before or at the peak
    onset_idx = 0
    for i in range(peak_idx + 1):
        if rms[i] >= threshold:
            onset_idx = i
            break

    onset_time = float(times[onset_idx])
    lead_in = onset_time

    return {
        "file": str(file_path),
        "duration": round(duration, 3),
        "sample_rate": sr,
        "peak_time": round(peak_time, 3),
        "onset_time": round(onset_time, 3),
        "lead_in": round(lead_in, 3),
        "peak_lead_in": round(peak_time, 3),
        "peak_rms_dbfs": round(peak_dbfs, 1),
        "is_silent": False
    }


def calculate_alignment(
    file_path: Path,
    visual_hit_time: float,
    align_to: str = "onset",
    threshold_ratio: float = 0.20,
    tag_id: Optional[str] = None,
    volume: float = 0.8,
    track_index: int = 10
) -> Dict[str, Any]:
    """
    Calculates exact data-start to place the audio clip so that its onset or peak
    lands precisely at visual_hit_time.
    """
    stats = analyze_onset(file_path, threshold_ratio=threshold_ratio)

    if align_to == "peak":
        offset = stats["peak_lead_in"]
    else:
        offset = stats["lead_in"]

    target_data_start = max(0.0, visual_hit_time - offset)

    elem_id = tag_id or f"sfx-{file_path.stem}"
    tag_html = (
        f'<audio id="{elem_id}" src="{file_path.as_posix()}" '
        f'data-start="{target_data_start:.3f}" data-duration="{stats["duration"]:.2f}" '
        f'data-volume="{volume}" data-track-index="{track_index}"></audio>'
    )

    return {
        **stats,
        "visual_hit_time": visual_hit_time,
        "align_to": align_to,
        "calculated_data_start": round(target_data_start, 3),
        "html_tag": tag_html
    }


def main():
    parser = argparse.ArgumentParser(description="Analyze audio lead-ins and align with visual impact frames.")
    parser.add_argument("--audio", "-a", type=str, help="Path to sound effect file (MP3, WAV, etc.)")
    parser.add_argument("--visual-hit", "-t", type=float, default=None, help="Visual hit second on the video timeline (e.g. 27.2)")
    parser.add_argument("--align-to", choices=["onset", "peak"], default="onset", help="Target either the transient onset or peak energy")
    parser.add_argument("--threshold", type=float, default=0.20, help="Onset energy threshold ratio relative to peak (default: 0.20)")
    parser.add_argument("--id", type=str, default=None, help="HTML element id for generated <audio> tag")
    parser.add_argument("--volume", type=float, default=0.8, help="Audio volume for generated tag (default: 0.8)")
    parser.add_argument("--track-index", type=int, default=10, help="Track index for Studio lane (default: 10)")
    parser.add_argument("--json", action="store_true", help="Output machine-readable JSON")
    parser.add_argument("--tag-only", action="store_true", help="Print only the HTML <audio> tag")

    args = parser.parse_args()

    if not args.audio:
        parser.print_help()
        sys.exit(1)

    audio_path = Path(args.audio)
    if not audio_path.is_file():
        print(f"Error: Audio file not found at {audio_path}", file=sys.stderr)
        sys.exit(1)

    visual_hit = args.visual_hit if args.visual_hit is not None else 0.0
    result = calculate_alignment(
        audio_path,
        visual_hit_time=visual_hit,
        align_to=args.align_to,
        threshold_ratio=args.threshold,
        tag_id=args.id,
        volume=args.volume,
        track_index=args.track_index
    )

    if args.tag_only:
        print(result["html_tag"])
        return

    if args.json:
        print(json.dumps(result, indent=2))
        return

    print("=== Audio Onset & Timeline Aligner ===")
    print(f"File:           {result['file']}")
    print(f"Duration:       {result['duration']} s")
    print(f"Peak RMS:       {result['peak_rms_dbfs']} dBFS (at {result['peak_time']} s)")
    print(f"Onset Hit:      {result['onset_time']} s (lead-in delay: {result['lead_in']} s)")
    if args.visual_hit is not None:
        print(f"Visual Hit:     {args.visual_hit:.3f} s")
        print(f"Target Start:   {result['calculated_data_start']:.3f} s  (subtracting {offset_str(result, args.align_to)})")
        print("\nGenerated HyperFrames HTML Tag:")
        print(f"  {result['html_tag']}")


def offset_str(res: Dict[str, Any], align_to: str) -> str:
    lead = res["peak_lead_in"] if align_to == "peak" else res["lead_in"]
    return f"{lead:.3f}s {align_to} lead-in"


if __name__ == "__main__":
    main()
