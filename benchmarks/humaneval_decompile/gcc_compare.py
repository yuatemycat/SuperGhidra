"""Score published IDA output against filtered Ghidra output with gcc.

This is the official-style program: dependency, candidate, and test, compiled
with ``gcc -O0 -lm`` and no typedef header. It does not use the MSVC spare
allocator, and it does not change ``python -m benchmarks.humaneval_decompile``.

Point ``SUPERGHIDRA_GCC_ROOT`` at a MinGW prefix (the directory that contains
``bin/gcc.exe``) for this process only. gcc on PATH is used when the variable
is unset. cl.exe is refused.
"""

from __future__ import annotations

import json
import os
import shutil
import sys
from concurrent.futures import ProcessPoolExecutor
from pathlib import Path
from typing import Any, Dict, List, Optional

from benchmarks.humaneval_decompile.harness import (
    CACHE_DIR,
    DATASET_ID,
    KEEP_COLUMNS,
    PINNED_REVISION,
    _align_function_name,
    _dependency_text,
    _download_split,
    _humaneval_records,
    _language,
)

IDA_JSONL_NAME = "humaneval_with_ida.jsonl"

_C_PRELUDE = (
    "#include <stdio.h>\n"
    "#include <stdlib.h>\n"
    "#include <string.h>\n"
    "#include <assert.h>\n"
    "#include <stddef.h>\n"
)
_CPP_PRELUDE = (
    "#include <cstdio>\n"
    "#include <cstdlib>\n"
    "#include <cstring>\n"
    "#include <cassert>\n"
    "#include <cstddef>\n"
)


def _activate_gcc_root() -> None:
    root = os.environ.get("SUPERGHIDRA_GCC_ROOT", "").strip()
    if not root:
        return
    bin_dir = Path(root) / "bin"
    gcc = bin_dir / "gcc.exe"
    if not gcc.is_file():
        gcc = bin_dir / "gcc"
    if not gcc.is_file():
        bin_dir = Path(root)
    os.environ["PATH"] = str(bin_dir) + os.pathsep + os.environ.get("PATH", "")


_activate_gcc_root()


def gcc_compiler() -> Optional[str]:
    found = shutil.which("gcc")
    if not found:
        return None
    if Path(found).name.lower() not in ("gcc", "gcc.exe"):
        return None
    return found


def official_program(language: str, body_parts: List[str]) -> str:
    """Paper-style translation unit. No spare allocator and no typedef header."""
    chunks = [_CPP_PRELUDE if language == "C++" else _C_PRELUDE]
    chunks.extend(part for part in body_parts if part)
    return "\n".join(chunks)


def candidate_bodies(row: Dict[str, Any]) -> Dict[str, str]:
    """Return the IDA body, the raw Ghidra body, and the filtered Ghidra body."""
    from superghidra.core.compilable_filter import CompilableDecompilerFilter

    func_name = str(row.get("func_name") or "")
    ida = _align_function_name(
        "" if row.get("ida_pseudo") is None else str(row.get("ida_pseudo")),
        func_name,
    )
    ghidra = _align_function_name(
        "" if row.get("ghidra_pseudo") is None else str(row.get("ghidra_pseudo")),
        func_name,
    )
    return {
        "ida": ida,
        "ida_filtered": CompilableDecompilerFilter.filter(ida) if ida.strip() else "",
        "ghidra": ghidra,
        "filtered": CompilableDecompilerFilter.filter(ghidra) if ghidra.strip() else "",
    }


def load_rows_with_ida(cache_dir: Optional[Path] = None, allow_unpinned: bool = False) -> List[Dict[str, Any]]:
    """Same 1,312 HumanEval rows as the cl.exe scorer, plus ``ida_pseudo``."""
    cache = cache_dir or CACHE_DIR
    cache.mkdir(parents=True, exist_ok=True)
    jsonl = cache / IDA_JSONL_NAME
    rev_path = cache / "REVISION.txt"
    if rev_path.is_file():
        cached_rev = rev_path.read_text(encoding="utf-8").splitlines()[0].strip()
        if cached_rev != PINNED_REVISION and not allow_unpinned:
            if jsonl.is_file():
                jsonl.unlink()
    else:
        if jsonl.is_file():
            jsonl.unlink()

    if jsonl.is_file() and jsonl.stat().st_size > 0:
        rows = [json.loads(line) for line in jsonl.read_text(encoding="utf-8").splitlines() if line.strip()]
        if len(rows) == 1312 and rows and "ida_pseudo" in rows[0]:
            return rows

    split, _revision, _note = _download_split(allow_unpinned=allow_unpinned)
    columns = list(KEEP_COLUMNS) + ["ida_pseudo"]
    rows = []
    for record in _humaneval_records(split):
        rows.append({name: record.get(name) for name in columns})
    if len(rows) != 1312:
        raise RuntimeError(f"expected 1312 HumanEval rows, got {len(rows)}")
    with jsonl.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, ensure_ascii=False) + "\n")
    return rows


def _passes(source: str, language: str) -> bool:
    from superghidra.core.native_compiler import compile_and_run

    try:
        ok, _out, _err = compile_and_run(
            source,
            language=language,
            timeout_compile=20.0,
            timeout_run=5.0,
            repeat=1,
        )
    except OSError:
        return False
    return bool(ok)


def score_gcc_sample(row: Dict[str, Any]) -> Dict[str, Any]:
    language = _language(row.get("language"))
    opt = str(row.get("opt") or "")
    func_name = str(row.get("func_name") or "")
    index = row.get("index")
    task_id = f"{index}:{func_name}:{language}:{opt}"
    record = {
        "task_id": task_id,
        "language": language,
        "opt": opt,
        "evaluable": False,
        "ida_pass": False,
        "ida_filtered_pass": False,
        "ghidra_pass": False,
        "filtered_pass": False,
    }
    test = "" if row.get("test") is None else str(row.get("test"))
    original = "" if row.get("func") is None else str(row.get("func"))
    if not test.strip() or not original.strip():
        return record
    dep = _dependency_text(row.get("func_dep"))
    if not _passes(official_program(language, [dep, original, test]), language):
        return record
    record["evaluable"] = True
    bodies = candidate_bodies(row)
    record["ida_pass"] = bool(bodies["ida"].strip()) and _passes(
        official_program(language, [dep, bodies["ida"], test]),
        language,
    )
    record["ida_filtered_pass"] = bool(bodies.get("ida_filtered", "").strip()) and _passes(
        official_program(language, [dep, bodies["ida_filtered"], test]),
        language,
    )
    record["ghidra_pass"] = bool(bodies["ghidra"].strip()) and _passes(
        official_program(language, [dep, bodies["ghidra"], test]),
        language,
    )
    record["filtered_pass"] = bool(bodies["filtered"].strip()) and _passes(
        official_program(language, [dep, bodies["filtered"], test]),
        language,
    )
    return record


def score_gcc_batch(rows: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    return [score_gcc_sample(row) for row in rows]


def averages_from_gcc_log(path: Path) -> Dict[str, Any]:
    rows = [json.loads(line) for line in Path(path).read_text(encoding="utf-8").splitlines() if line.strip()]
    evaluable = [row for row in rows if row.get("evaluable")]
    denominator = len(evaluable)

    def percent(key: str) -> float:
        if denominator == 0:
            return 0.0
        hits = sum(1 for row in evaluable if row.get(key))
        return round(100.0 * hits / denominator, 2)

    def count(key: str) -> int:
        return sum(1 for row in evaluable if row.get(key))

    both = sum(1 for row in evaluable if row.get("ida_pass") and row.get("filtered_pass"))
    ida_only = sum(1 for row in evaluable if row.get("ida_pass") and not row.get("filtered_pass"))
    filtered_only = sum(1 for row in evaluable if row.get("filtered_pass") and not row.get("ida_pass"))
    neither = sum(1 for row in evaluable if not row.get("ida_pass") and not row.get("filtered_pass"))

    filter_gained_ghidra = sum(1 for row in evaluable if row.get("filtered_pass") and not row.get("ghidra_pass"))
    filter_broken_ghidra = sum(1 for row in evaluable if row.get("ghidra_pass") and not row.get("filtered_pass"))
    filter_gained_ida = sum(1 for row in evaluable if row.get("ida_filtered_pass") and not row.get("ida_pass"))
    filter_broken_ida = sum(1 for row in evaluable if row.get("ida_pass") and not row.get("ida_filtered_pass"))

    return {
        "ida_avg": percent("ida_pass"),
        "ida_filtered_avg": percent("ida_filtered_pass"),
        "ghidra_avg": percent("ghidra_pass"),
        "filtered_avg": percent("filtered_pass"),
        "ghidra_filtered_avg": percent("filtered_pass"),
        "ida_pass_count": count("ida_pass"),
        "ida_filtered_pass_count": count("ida_filtered_pass"),
        "ghidra_pass_count": count("ghidra_pass"),
        "filtered_pass_count": count("filtered_pass"),
        "ghidra_filtered_pass_count": count("filtered_pass"),
        "evaluable_denominator": denominator,
        "logged_samples": len(rows),
        "filter_gained_ghidra": filter_gained_ghidra,
        "filter_broken_ghidra": filter_broken_ghidra,
        "filter_gained_ida": filter_gained_ida,
        "filter_broken_ida": filter_broken_ida,
        "both_ida_raw_and_ghidra_filtered": both,
        "both_ida_and_ghidra_filtered": sum(1 for row in evaluable if row.get("ida_filtered_pass") and row.get("filtered_pass")),
        "both_ida_and_ghidra_raw": sum(1 for row in evaluable if row.get("ida_pass") and row.get("ghidra_pass")),
        "both_pass": both,
        "ida_only": ida_only,
        "filtered_only": filtered_only,
        "neither": neither,
    }


def format_gcc_summary(summary: Dict[str, Any]) -> str:
    keys = (
        "ida_avg",
        "ghidra_avg",
        "filtered_avg",
        "ida_pass_count",
        "ghidra_pass_count",
        "filtered_pass_count",
        "evaluable_denominator",
        "both_pass",
        "ida_only",
        "filtered_only",
        "neither",
    )
    return "\n".join(f"{key}: {summary[key]}" for key in keys)


def run_gcc_compare(output_dir: Path, workers: int = 6) -> Dict[str, Any]:
    compiler = gcc_compiler()
    if compiler is None:
        raise RuntimeError("gcc was not found; this comparison refuses cl.exe")
    output_dir.mkdir(parents=True, exist_ok=True)
    rows = load_rows_with_ida()
    rows.sort(
        key=lambda row: (
            str(row.get("language") or ""),
            str(row.get("opt") or ""),
            str(row.get("index")),
            str(row.get("func_name") or ""),
        )
    )
    batches = [rows[i : i + 16] for i in range(0, len(rows), 16)]
    records: List[Dict[str, Any]] = []
    done = 0
    total = len(rows)

    def _take(part: List[Dict[str, Any]]) -> None:
        nonlocal done
        records.extend(part)
        done += len(part)
        print(f"scored {done}/{total}", file=sys.stderr, flush=True)

    worker_count = max(1, int(workers))
    if worker_count == 1 or len(batches) == 1:
        for batch in batches:
            _take(score_gcc_batch(batch))
    else:
        with ProcessPoolExecutor(max_workers=worker_count) as pool:
            for part in pool.map(score_gcc_batch, batches):
                _take(part)
    records.sort(key=lambda rec: (rec["language"], rec["opt"], rec["task_id"]))
    output_dir.mkdir(parents=True, exist_ok=True)
    log_path = output_dir / "gcc_score_log.jsonl"
    with log_path.open("w", encoding="utf-8") as handle:
        for rec in records:
            handle.write(json.dumps(rec, sort_keys=True) + "\n")
    import platform
    import subprocess
    summary = averages_from_gcc_log(log_path)
    summary["dataset_id"] = DATASET_ID
    summary["dataset_revision"] = PINNED_REVISION
    summary["pinned"] = True
    summary["row_count"] = len(rows)
    summary["compiler"] = compiler
    try:
        ver = subprocess.run([compiler, "--version"], capture_output=True, text=True, check=True).stdout.splitlines()[0]
    except Exception:
        ver = "unknown"
    summary["compiler_version"] = ver
    summary["os"] = f"{platform.system()} {platform.machine()}"
    try:
        git_sha = subprocess.run(["git", "rev-parse", "HEAD"], capture_output=True, text=True, check=True).stdout.strip()
    except Exception:
        git_sha = "unknown"
    summary["git_commit"] = git_sha
    summary["score_log"] = str(log_path)
    (output_dir / "gcc_score_summary.json").write_text(
        json.dumps(summary, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return summary


def main(argv: Optional[List[str]] = None) -> int:
    import argparse

    parser = argparse.ArgumentParser(description="Compare IDA, raw Ghidra, and filtered Ghidra under gcc.")
    parser.add_argument("--output-dir", default="benchmarks/humaneval_decompile/gcc_compare_out")
    parser.add_argument("--workers", type=int, default=6)
    args = parser.parse_args(argv)
    try:
        summary = run_gcc_compare(Path(args.output_dir), workers=args.workers)
    except Exception as exc:
        print(f"[FAIL] {exc}", file=sys.stderr)
        return 2
    if summary["evaluable_denominator"] <= 0:
        print(format_gcc_summary(summary))
        return 1
    print(format_gcc_summary(summary))
    print(f"compiler: {summary['compiler']}")
    print(f"score_log: {summary['score_log']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
