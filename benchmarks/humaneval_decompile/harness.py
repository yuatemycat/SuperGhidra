"""HumanEval-Decompile scorer.

`python -m benchmarks.humaneval_decompile` compiles each pinned sample and
prints averages recomputed from the per-sample score log. The historical
7.41 / 27.78 table stays in results_baseline.json and is not the printed result.
"""

from __future__ import annotations

import json
import random
import sys
from concurrent.futures import ProcessPoolExecutor
from pathlib import Path
from typing import Any, Dict, List, Tuple

from superghidra.core.compilable_filter import IDA_COMPAT_DEFS_H

BASELINE_PATH = Path(__file__).parent / "results_baseline.json"
CACHE_DIR = Path(__file__).parent / "cache"
JSONL_NAME = "humaneval.jsonl"
DATASET_ID = "LLM4Binary/decompile-eval"
PINNED_REVISION = "b9271fae3c556e46948559f4176ffa6f8b4f9491"
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

LENIENT_IDA_DEFS = IDA_COMPAT_DEFS_H


class HumanEvalDecompileHarness:
    """Historical baseline reader. Scoring lives in the module functions below."""

    def __init__(self, baseline_file: Path | None = None):
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


def _download_split(allow_unpinned: bool = False):
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
        if not allow_unpinned:
            _fail_download(
                f"Failed to download {DATASET_ID} revision {PINNED_REVISION}: {message}. "
                "Pass --allow-unpinned to fall back to the live revision."
            )
        try:
            from huggingface_hub import HfApi

            revision = HfApi().dataset_info(DATASET_ID).sha
        except Exception as info_exc:
            _fail_download(
                f"Pinned revision {PINNED_REVISION} is not on {DATASET_ID}, and the live "
                f"revision could not be resolved: {info_exc}"
            )
        note = (
            f"Pinned revision {PINNED_REVISION} could not be loaded from {DATASET_ID}. "
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


def load_humaneval_rows(cache_dir: Path | None = None, allow_unpinned: bool = False) -> List[Dict[str, Any]]:
    """Load the humaneval split, downloading it into the cache once."""
    cache = cache_dir or CACHE_DIR
    cache.mkdir(parents=True, exist_ok=True)
    jsonl = cache / JSONL_NAME
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
        rows = []
        for line in jsonl.read_text(encoding="utf-8").splitlines():
            if line.strip():
                rows.append(json.loads(line))
        if rows:
            return rows

    split, revision, note = _download_split(allow_unpinned=allow_unpinned)

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


def _program(
    language: str,
    body_parts: List[str],
    *,
    typedefs: bool,
    ida_defs: bool = False,
) -> str:
    chunks = [CPP_PRELUDE if language == "C++" else C_PRELUDE]
    if typedefs:
        chunks.append(LENIENT_TYPEDEFS)
    if ida_defs:
        chunks.append(LENIENT_IDA_DEFS)
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


def _canonical_function_key(
    row: Dict[str, Any],
    *,
    has_distinct_func: bool,
    has_distinct_func_name: bool,
) -> Tuple[str, str]:
    """Derive a canonical function group key shared across O0-O3 variants."""
    lang = _language(row.get("language"))
    func_body = str(row.get("func") or "").strip()
    func_name = str(row.get("func_name") or "").strip()
    task_id = str(row.get("task_id") or "").strip()
    idx = row.get("index")
    if idx is None and ":" in task_id:
        prefix = task_id.split(":", 1)[0]
        if prefix.isdigit():
            idx = int(prefix)
        parts = task_id.split(":")
        if len(parts) >= 2 and not func_name:
            func_name = parts[1]

    if has_distinct_func_name and func_name:
        return (lang, func_name)
    if has_distinct_func and func_body:
        return (lang, func_body)
    if idx is not None:
        return (lang, f"func_group_{int(idx) // 4:04d}")
    return (lang, func_name or func_body or task_id)


def _group_corpus_by_function(
    rows: List[Dict[str, Any]],
) -> Tuple[List[Tuple[str, str]], Dict[Tuple[str, str], List[Dict[str, Any]]]]:
    funcs = {str(r.get("func") or "").strip() for r in rows if str(r.get("func") or "").strip()}
    func_names = set()
    for r in rows:
        fn = str(r.get("func_name") or "").strip()
        if not fn and ":" in str(r.get("task_id") or ""):
            fn = str(r["task_id"]).split(":")[1]
        if fn:
            func_names.add(fn)
    has_distinct_func = len(funcs) > 1
    has_distinct_func_name = len(func_names) > 1

    groups: Dict[Tuple[str, str], List[Dict[str, Any]]] = {}
    group_min_idx: Dict[Tuple[str, str], int] = {}
    for pos, row in enumerate(rows):
        key = _canonical_function_key(
            row,
            has_distinct_func=has_distinct_func,
            has_distinct_func_name=has_distinct_func_name,
        )
        groups.setdefault(key, []).append(row)
        idx = row.get("index")
        if idx is None and ":" in str(row.get("task_id") or ""):
            prefix = str(row["task_id"]).split(":", 1)[0]
            if prefix.isdigit():
                idx = int(prefix)
        if idx is not None:
            group_min_idx[key] = min(group_min_idx.get(key, int(idx)), int(idx))
        else:
            group_min_idx.setdefault(key, pos)

    ordered_keys = sorted(groups.keys(), key=lambda k: (group_min_idx[k], k))
    return ordered_keys, groups


def split_humaneval_corpus(
    rows: List[Dict[str, Any]],
    train_ratio: float = 0.70,
    seed: int = 42,
) -> Dict[str, List[Dict[str, Any]]]:
    """Deterministic function-grouped train/test split with zero function leakage.

    Groups all optimization variants (O0-O3) of each unique function before
    splitting so that every function's variants reside strictly in either
    ``train`` (default 70%) or ``test`` (default 30%). Also returns
    ``o2_o3_test`` containing only the O2/O3 rows from the held-out test split.
    """
    if not 0.0 < train_ratio < 1.0:
        raise ValueError(f"train_ratio must be in (0, 1), got {train_ratio}")
    if not rows:
        return {"train": [], "test": [], "o2_o3_test": []}

    ordered_keys, groups = _group_corpus_by_function(rows)
    shuffled_keys = list(ordered_keys)
    rng = random.Random(seed)
    rng.shuffle(shuffled_keys)

    n_total = len(shuffled_keys)
    n_train = max(1, min(n_total - 1, int(round(n_total * train_ratio)))) if n_total > 1 else n_total
    train_keys = shuffled_keys[:n_train]
    test_keys = shuffled_keys[n_train:]

    train_rows = [row for key in train_keys for row in groups[key]]
    test_rows = [row for key in test_keys for row in groups[key]]
    o2_o3_test_rows = [
        row for row in test_rows if str(row.get("opt") or "").strip().upper() in ("O2", "O3")
    ]
    return {
        "train": train_rows,
        "test": test_rows,
        "o2_o3_test": o2_o3_test_rows,
    }


def _summarize_score_subset(rows: List[Dict[str, Any]]) -> Dict[str, Any]:
    evaluable = [row for row in rows if row.get("evaluable", True)]
    denom = len(evaluable)

    def _ghidra_raw(row: Dict[str, Any]) -> bool:
        if "ghidra_pass" in row:
            return bool(row["ghidra_pass"])
        return bool(row.get("strict_pass", row.get("before_pass", False)))

    def _ghidra_filt(row: Dict[str, Any]) -> bool:
        if "filtered_pass" in row:
            return bool(row["filtered_pass"])
        return bool(row.get("compilable_pass", row.get("refined_pass", False)))

    def _lenient(row: Dict[str, Any]) -> bool:
        if "lenient_pass" in row:
            return bool(row["lenient_pass"])
        return _ghidra_filt(row)

    def _ida_raw(row: Dict[str, Any]) -> bool:
        return bool(row.get("ida_pass", False))

    def _ida_filt(row: Dict[str, Any]) -> bool:
        if "ida_filtered_pass" in row:
            return bool(row["ida_filtered_pass"])
        return _ida_raw(row)

    def _pct(count: int) -> float:
        return round(100.0 * count / denom, 2) if denom > 0 else 0.0

    ghidra_raw_count = sum(1 for r in evaluable if _ghidra_raw(r))
    ghidra_filt_count = sum(1 for r in evaluable if _ghidra_filt(r))
    lenient_count = sum(1 for r in evaluable if _lenient(r))
    ida_raw_count = sum(1 for r in evaluable if _ida_raw(r))
    ida_filt_count = sum(1 for r in evaluable if _ida_filt(r))

    gained_ghidra = sum(1 for r in evaluable if _ghidra_filt(r) and not _ghidra_raw(r))
    broken_ghidra = sum(1 for r in evaluable if _ghidra_raw(r) and not _ghidra_filt(r))
    gained_ida = sum(1 for r in evaluable if _ida_filt(r) and not _ida_raw(r))
    broken_ida = sum(1 for r in evaluable if _ida_raw(r) and not _ida_filt(r))

    return {
        "logged_samples": len(rows),
        "evaluable_denominator": denom,
        "strict_pass_count": ghidra_raw_count,
        "strict_avg": _pct(ghidra_raw_count),
        "lenient_pass_count": lenient_count,
        "lenient_avg": _pct(lenient_count),
        "compilable_pass_count": ghidra_filt_count,
        "compilable_avg": _pct(ghidra_filt_count),
        "refined_pass_count": ghidra_filt_count,
        "refined_regressions": broken_ghidra,
        "ghidra_raw_pass_count": ghidra_raw_count,
        "ghidra_raw_avg": _pct(ghidra_raw_count),
        "ghidra_filtered_pass_count": ghidra_filt_count,
        "ghidra_filtered_avg": _pct(ghidra_filt_count),
        "ida_raw_pass_count": ida_raw_count,
        "ida_raw_avg": _pct(ida_raw_count),
        "ida_filtered_pass_count": ida_filt_count,
        "ida_filtered_avg": _pct(ida_filt_count),
        "filter_gained_ghidra": gained_ghidra,
        "filter_broken_ghidra": broken_ghidra,
        "filter_gained_ida": gained_ida,
        "filter_broken_ida": broken_ida,
    }


def compute_split_metrics(
    score_rows: List[Dict[str, Any]],
    train_ratio: float = 0.70,
    seed: int = 42,
) -> Dict[str, Any]:
    """Compute pass rates and filter gains across full, 70% train, 30% test, and O2/O3 test splits."""
    ordered_keys, _ = _group_corpus_by_function(score_rows) if score_rows else ([], {})
    n_total = len(ordered_keys)
    n_train = max(1, min(n_total - 1, int(round(n_total * train_ratio)))) if n_total > 1 else n_total
    splits = split_humaneval_corpus(score_rows, train_ratio=train_ratio, seed=seed)

    full_metrics = _summarize_score_subset(score_rows)
    train_metrics = _summarize_score_subset(splits["train"])
    test_metrics = _summarize_score_subset(splits["test"])
    o2_o3_metrics = _summarize_score_subset(splits["o2_o3_test"])

    train_metrics["unique_functions"] = n_train
    test_metrics["unique_functions"] = n_total - n_train
    o2_o3_metrics["unique_functions"] = n_total - n_train
    full_metrics["unique_functions"] = n_total

    return {
        "seed": seed,
        "train_ratio": train_ratio,
        "total_unique_functions": n_total,
        "train_unique_functions": n_train,
        "test_unique_functions": n_total - n_train,
        "full_corpus": full_metrics,
        "train_split_70": train_metrics,
        "test_split_30": test_metrics,
        "test_o2_o3_high_opt": o2_o3_metrics,
        "train_70": train_metrics,
        "test_30": test_metrics,
        "test_o2_o3": o2_o3_metrics,
    }


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
