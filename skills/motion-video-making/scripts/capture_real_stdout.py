#!/usr/bin/env python3
"""
capture_real_stdout.py - Executes real CLI commands and captures authentic stdout to assets/real_output.txt.
Ensures zero-placeholder authenticity in terminal motion graphics.
"""
import argparse
import subprocess
import sys
from pathlib import Path


def capture_commands(runs, output_file: Path):
    chunks = []
    py = sys.executable

    for raw_cmd, display_cmd in runs:
        cmd = [py if arg == "{PYTHON}" else arg for arg in raw_cmd]
        print(f"Executing: {' '.join(cmd)}")
        result = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8")
        if result.returncode != 0:
            print(f"Error executing command: {result.stderr}", file=sys.stderr)
            sys.exit(result.returncode)

        stdout_clean = result.stdout.rstrip("\r\n")
        chunks.append(f"$ {display_cmd}\n{stdout_clean}\n")

    output_file.parent.mkdir(parents=True, exist_ok=True)
    with open(output_file, "w", encoding="utf-8", newline="\n") as f:
        f.write("\n".join(chunks))

    print(f"Captured {len(runs)} command blocks to {output_file}")


def main():
    parser = argparse.ArgumentParser(description="Capture real CLI stdout for terminal animation.")
    parser.add_argument("-o", "--output", default="assets/real_output.txt", help="Output path")
    args = parser.parse_args()

    runs = [
        (
            ["{PYTHON}", "-m", "superghidra", "rtti-recover", "mfc140u.dll", "-o", "classes.json"],
            "superghidra rtti-recover mfc140u.dll -o classes.json"
        ),
        (
            ["{PYTHON}", "-m", "superghidra.formats.serialize_trace", "mfc140u.dll", "CDWordArray"],
            "python -m superghidra.formats.serialize_trace mfc140u.dll CDWordArray"
        ),
    ]

    capture_commands(runs, Path(args.output))


if __name__ == "__main__":
    main()
