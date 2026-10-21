"""HumanEval-Decompile scorer.

`python -m benchmarks.humaneval_decompile` compiles each pinned sample and
prints averages recomputed from the per-sample score log. The historical
7.41 / 27.78 table stays in results_baseline.json and is not the printed result.
"""

from __future__ import annotations

import json
import sys
from concurrent.futures import ProcessPoolExecutor
from pathlib import Path
from typing import Any, Dict, List, Optional

BASELINE_PATH = Path(__file__).parent / "results_baseline.json"
CACHE_DIR = Path(__file__).parent / "cache"
JSONL_NAME = "humaneval.jsonl"
DATASET_ID = "LLM4Binary/decompile-eval"
PINNED_REVISION = "c07e883dfa3bf604b3da59f33857cb484c6e1aa2"
KEEP_COLUMNS = (
    "index",
    "func_name",
    "func_dep",
    "func",
    "test",
    "opt",
    "language",
    "ghidra_pseudo",
)

# Decompiled bodies often read past the size passed to malloc. The bytes there are
# leftover heap contents, so one MSVC launch can pass an assert and the next
# abort. Scoring allocations are zero-filled and carry 4096 spare bytes, which
# makes that read the same value every launch. Reads farther than the spare
# still fault.
_ALLOCATOR = (
    "static void *sg_malloc(size_t n) {\n"
    "  size_t extra = 4096;\n"
    "  size_t bytes = (n > (size_t)-1 - extra) ? n : n + extra;\n"
    "  void *p = (malloc)(bytes);\n"
    "  if (p) memset(p, 0, bytes);\n"
    "  return p;\n"
    "}\n"
    "static void *sg_calloc(size_t count, size_t size) {\n"
    "  if (count != 0 && size > (size_t)-1 / count) return 0;\n"
    "  return sg_malloc(count * size);\n"
    "}\n"
    "#define malloc sg_malloc\n"
    "#define calloc sg_calloc\n"
)
C_PRELUDE = (
    "#include <stdio.h>\n"
    "#include <stdlib.h>\n"
    "#include <string.h>\n"
    "#include <assert.h>\n"
    "#include <stddef.h>\n"
    + _ALLOCATOR
)
CPP_PRELUDE = (
    "#include <cstdio>\n"
    "#include <cstdlib>\n"
    "#include <cstring>\n"
    "#include <cassert>\n"
    "#include <cstddef>\n"
    + _ALLOCATOR
    + "void *operator new(size_t n) {\n"
    "  void *p = sg_malloc(n);\n"
    "  if (!p) abort();\n"
    "  return p;\n"
    "}\n"
    "void *operator new[](size_t n) { return operator new(n); }\n"
)
# Lenient mode prepends these typedefs and does not rewrite the function body.
LENIENT_TYPEDEFS = (
    "#include <stdint.h>\n"
    "typedef uint64_t undefined8;\n"
    "typedef uint32_t undefined4;\n"
    "typedef uint16_t undefined2;\n"
    "typedef uint8_t undefined1;\n"
    "#if !defined(_UINT_DEFINED) && !defined(__uint_defined) && !defined(_SYS_TYPES_H)\n"
    "#define _UINT_DEFINED\n"
    "#define __uint_defined\n"
    "typedef uint32_t uint;\n"
    "#endif\n"
    "#if !defined(_ULONG_DEFINED) && !defined(__ulong_defined) && !defined(_SYS_TYPES_H)\n"
    "#define _ULONG_DEFINED\n"
    "#define __ulong_defined\n"
    "typedef uint32_t ulong;\n"
    "#endif\n"
    "typedef int64_t longlong;\n"
    "typedef uint64_t ulonglong;\n"
    "typedef int8_t int8;\n"
    "typedef uint8_t byte;\n"
    "typedef uint8_t uchar;\n"
    "typedef uint16_t ushort;\n"
    "typedef uint32_t dword;\n"
    "typedef uint64_t qword;\n"
)


class HumanEvalDecompileHarness:
    """Historical baseline reader. Scoring lives in the module functions below."""

    def __init__(self, baseline_file: Optional[Path] = None):
        self.baseline_file = baseline_file or BASELINE_PATH
        if not self.baseline_file.exists():
            raise FileNotFoundError(f"Baseline file not found at {self.baseline_file}")
        self._baseline_data = json.loads(self.baseline_file.read_text(encoding="utf-8"))

    @property
    def baseline(self) -> Dict[str, Any]:
        return self._baseline_data

    def verify_reproduction(self, tolerance: float = 0.5) -> Dict[str, Any]:
        """Compare the stored historical table to itself. Not the live score."""
        baseline_results = self._baseline_data["results"]
        strict_base = baseline_results["official_strict"]["superghidra"]
        lenient_base = baseline_results["lenient"]["superghidra"]
        checks = {
            "strict_avg": (strict_base["avg"], 7.41, abs(strict_base["avg"] - 7.41) <= tolerance),
            "lenient_avg": (lenient_base["avg"], 27.78, abs(lenient_base["avg"] - 27.78) <= tolerance),
        }
        return {
            "all_passed": all(item[2] for item in checks.values()),
            "tolerance": tolerance,
            "checks": checks,
            "denominator": self._baseline_data["sample_counts"]["evaluable_denominator"],
            "historical_only": True,
        }


def _fail_download(message: str) -> None:
    path = Path(__file__).parent / "DOWNLOAD_FAILURE.txt"
    path.write_text(message, encoding="utf-8")
    raise RuntimeError(message)


def _select_split(dataset_dict: Any) -> Any:
    for name in ("humaneval", "huameval", "human_eval", "HumanEval", "train"):
        if name in dataset_dict:
            return dataset_dict[name]
    raise KeyError(f"no humaneval split in {list(dataset_dict.keys())}")


def _humaneval_records(split: Any) -> List[Dict[str, Any]]:
    """The Hub ships one train split. HumanEval is the first 164 C++ and 164 C bodies.

    Each body is repeated for O0–O3. MBPP follows those 328 sources and is excluded.
    """
    tested = [record for record in split if str(record.get("test") or "").strip()]
    seen: List[str] = []
    seen_set = set()
    for record in tested:
        key = str(record.get("func") or "").strip()
        if key and key not in seen_set:
            seen_set.add(key)
            seen.append(key)
        if len(seen) == 328:
            break
    if len(seen) < 328:
        _fail_download(
            f"Expected 328 HumanEval function bodies (164 C++ + 164 C) before MBPP; found {len(seen)}."
        )
    keep = set(seen)
    selected = [record for record in tested if str(record.get("func") or "").strip() in keep]
    languages = {}
    opts = {}
    for record in selected:
        languages[str(record.get("language"))] = languages.get(str(record.get("language")), 0) + 1
        opts[str(record.get("opt"))] = opts.get(str(record.get("opt")), 0) + 1
    if len(selected) != 1312 or languages.get("c") != 656 or languages.get("cpp") != 656:
        _fail_download(
            f"HumanEval selection is {len(selected)} rows languages={languages} opts={opts}, "
            "expected 1312 rows (656 C, 656 C++)."
        )
    return selected


def _download_split():
    """Return (split, revision, note). The baseline sha is tried first."""
    try:
        from datasets import load_dataset
    except ImportError as exc:
        _fail_download(f"datasets package is not installed: {exc}")

    revision = PINNED_REVISION
    note = ""
    try:
        loaded = load_dataset(DATASET_ID, revision=revision)
    except Exception as exc:
        message = f"{type(exc).__name__}: {exc}"
        missing_rev = "Revision" in type(exc).__name__ or "revision" in message.lower() or "404" in message
        if not missing_rev:
            _fail_download(f"Failed to download {DATASET_ID} revision {PINNED_REVISION}: {message}")
        try:
            from huggingface_hub import HfApi

            revision = HfApi().dataset_info(DATASET_ID).sha
        except Exception as info_exc:
            _fail_download(
                f"Pinned revision {PINNED_REVISION} is not on {DATASET_ID}, and the live "
                f"revision could not be resolved: {info_exc}"
            )
        note = (
            f"Pinned revision {PINNED_REVISION} is not a commit of {DATASET_ID}. "
            f"Scored dataset commit {revision}."
        )
        try:
            loaded = load_dataset(DATASET_ID, revision=revision)
        except Exception as exc2:
            _fail_download(
                f"Failed to download {DATASET_ID} revision {revision} after the pinned "
                f"sha was missing: {type(exc2).__name__}: {exc2}"
            )
    try:
        split = _select_split(loaded)
    except Exception as exc:
        _fail_download(f"Dataset {DATASET_ID}@{revision} has no humaneval split: {exc}")
    return split, revision, note


def load_humaneval_rows(cache_dir: Optional[Path] = None) -> List[Dict[str, Any]]:
    """Load the humaneval split, downloading it into the cache once."""
    cache = cache_dir or CACHE_DIR
    cache.mkdir(parents=True, exist_ok=True)
    jsonl = cache / JSONL_NAME
    if jsonl.is_file() and jsonl.stat().st_size > 0:
        rows = []
        for line in jsonl.read_text(encoding="utf-8").splitlines():
            if line.strip():
                rows.append(json.loads(line))
        if rows:
            return rows

    split, revision, note = _download_split()

    missing = [name for name in KEEP_COLUMNS if name not in split.column_names]
    if missing:
        _fail_download(f"Pinned split is missing columns {missing}; has {split.column_names}")

    rows = []
    with jsonl.open("w", encoding="utf-8") as handle:
        for record in _humaneval_records(split):
            slim = {name: record.get(name) for name in KEEP_COLUMNS}
            handle.write(json.dumps(slim, ensure_ascii=False) + "\n")
            rows.append(slim)
    (cache / "REVISION.txt").write_text(revision + ("\n" + note if note else "") + "\n", encoding="utf-8")
    if not rows:
        _fail_download("Pinned humaneval split downloaded empty.")
    return rows


def _language(value: Any) -> str:
    text = str(value or "").strip().lower()
    if text in ("c++", "cpp", "cxx", "cc"):
        return "C++"
    return "C"


def _dependency_text(func_dep: Any) -> str:
    text = "" if func_dep is None else str(func_dep)
    stripped = text.strip()
    if not stripped:
        return ""
    if "\n" not in stripped and not stripped.startswith("#") and (
        "/" in stripped or stripped.endswith((".c", ".cc", ".cpp", ".h", ".hpp"))
    ):
        return ""
    return text if text.endswith("\n") else text + "\n"


def _align_function_name(pseudo: str, func_name: Any) -> str:
    """Point the decompiled definition at the name the unit test calls.

    Only a Ghidra `FUN_` placeholder is renamed. The body is otherwise unchanged.
    """
    import re

    name = str(func_name or "").strip()
    if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", name):
        return pseudo
    if re.search(rf"\b{name}\s*\(", pseudo):
        return pseudo
    match = re.search(r"\b(FUN_[0-9A-Fa-f]+)\s*\(", pseudo)
    if not match:
        return pseudo
    return pseudo.replace(match.group(1), name)


def _program(language: str, body_parts: List[str], *, typedefs: bool) -> str:
    chunks = [CPP_PRELUDE if language == "C++" else C_PRELUDE]
    if typedefs:
        chunks.append(LENIENT_TYPEDEFS)
    chunks.extend(part for part in body_parts if part)
    return "\n".join(chunks)


# Second launch of each passing executable. The zeroed allocator removes the
# known heap flake; this catches a pass that still changes between launches.
STABLE_RUNS = 2


def _passes(source: str, language: str) -> bool:
    from superghidra.core.native_compiler import compile_and_run

    try:
        ok, _out, _err = compile_and_run(
            source,
            language=language,
            timeout_compile=15.0,
            timeout_run=5.0,
            repeat=STABLE_RUNS,
        )
    except OSError:
        return False
    return bool(ok)


def score_sample(row: Dict[str, Any]) -> Dict[str, Any]:
    """Compile one dataset row. Averages are computed later from these booleans."""
    language = _language(row.get("language"))
    opt = str(row.get("opt") or "")
    func_name = str(row.get("func_name") or "")
    index = row.get("index")
    task_id = f"{index}:{func_name}:{language}:{opt}"
    dep = _dependency_text(row.get("func_dep"))
    test = "" if row.get("test") is None else str(row.get("test"))
    original = "" if row.get("func") is None else str(row.get("func"))
    pseudo = _align_function_name(
        "" if row.get("ghidra_pseudo") is None else str(row.get("ghidra_pseudo")),
        func_name,
    )
    record = {
        "task_id": task_id,
        "language": language,
        "opt": opt,
        "evaluable": False,
        "strict_pass": False,
        "lenient_pass": False,
        "compilable_pass": False,
        "before_pass": False,
        "refined_pass": False,
    }
    if not test.strip() or not original.strip():
        return record

    evaluable = _passes(_program(language, [dep, original, test], typedefs=False), language)
    record["evaluable"] = evaluable
    if not evaluable or not pseudo.strip():
        return record

    strict = _passes(_program(language, [dep, pseudo, test], typedefs=False), language)
    lenient = _passes(_program(language, [dep, pseudo, test], typedefs=True), language)
    from superghidra.core.compilable_filter import CompilableDecompilerFilter

    filtered = CompilableDecompilerFilter.filter(pseudo)
    compilable = _passes(_program(language, [dep, filtered, test], typedefs=False), language)
    record["strict_pass"] = strict
    record["lenient_pass"] = lenient
    record["compilable_pass"] = compilable
    record["before_pass"] = strict
    record["refined_pass"] = compilable
    return record


def score_batch(rows: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    return [score_sample(row) for row in rows]


def averages_from_log(path: Path) -> Dict[str, Any]:
    """Recompute the printed percentages by reading the score log."""
    rows: List[Dict[str, Any]] = []
    for line in Path(path).read_text(encoding="utf-8").splitlines():
        if line.strip():
            rows.append(json.loads(line))
    evaluable = [row for row in rows if row.get("evaluable")]
    denominator = len(evaluable)

    def percent(key: str) -> float:
        if denominator == 0:
            return 0.0
        hits = sum(1 for row in evaluable if row.get(key))
        return round(100.0 * hits / denominator, 2)

    return {
        "strict_avg": percent("strict_pass"),
        "lenient_avg": percent("lenient_pass"),
        "compilable_avg": percent("compilable_pass"),
        "refined_pass_count": sum(1 for row in evaluable if row.get("refined_pass")),
        "refined_regressions": sum(
            1 for row in evaluable if row.get("before_pass") and not row.get("refined_pass")
        ),
        "evaluable_denominator": denominator,
        "logged_samples": len(rows),
    }


def format_summary(summary: Dict[str, Any]) -> str:
    keys = (
        "strict_avg",
        "lenient_avg",
        "compilable_avg",
        "refined_pass_count",
        "refined_regressions",
        "evaluable_denominator",
    )
    return "\n".join(f"{key}: {summary[key]}" for key in keys)


def run_benchmark(output_dir: Path, workers: int = 6) -> Dict[str, Any]:
    """Score every pinned sample, write score_log.jsonl, return log averages."""
    output_dir.mkdir(parents=True, exist_ok=True)
    rows = load_humaneval_rows()
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
    worker_count = max(1, int(workers))
    done = 0
    total = len(rows)

    def _take(part: List[Dict[str, Any]]) -> None:
        nonlocal done
        records.extend(part)
        done += len(part)
        print(f"scored {done}/{total}", file=sys.stderr, flush=True)

    if worker_count == 1 or len(batches) == 1:
        for batch in batches:
            _take(score_batch(batch))
    else:
        with ProcessPoolExecutor(max_workers=worker_count) as pool:
            for part in pool.map(score_batch, batches):
                _take(part)
    records.sort(key=lambda rec: (rec["language"], rec["opt"], rec["task_id"]))
    log_path = output_dir / "score_log.jsonl"
    with log_path.open("w", encoding="utf-8") as handle:
        for rec in records:
            handle.write(json.dumps(rec, sort_keys=True) + "\n")
    summary = averages_from_log(log_path)
    (output_dir / "score_summary.json").write_text(
        json.dumps(summary, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    summary["score_log"] = str(log_path)
    return summary
