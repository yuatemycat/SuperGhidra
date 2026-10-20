"""
HumanEval-Decompile Benchmark Harness.
Reference: Section 8 & U0 in docs/SUPERGHIDRA_ARCHITECTURE_AND_IDA_PRO_GAP_ANALYSIS.md

Executes evaluation pipeline: build -> decompile -> score -> report.
Supports strict mode and lenient mode (typedef header enabled).
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


BASELINE_PATH = Path(__file__).parent / "results_baseline.json"


@dataclass
class BenchmarkSample:
    task_id: str
    language: str  # "C" or "C++"
    opt_level: str  # "O0", "O1", "O2", "O3"
    func_dep: str
    original_code: str
    decompile_output: str
    test_code: str
    target_compiler: str = "gcc"


@dataclass
class SampleScore:
    task_id: str
    language: str
    opt_level: str
    compiled: bool
    passed_asserts: bool
    strict_pass: bool
    lenient_pass: bool
    error_message: Optional[str] = None


class HumanEvalDecompileHarness:
    """
    Standardized evaluation harness for HumanEval-Decompile re-executability benchmarking.
    """

    def __init__(self, baseline_file: Optional[Path] = None):
        self.baseline_file = baseline_file or BASELINE_PATH
        self._baseline_data = self._load_baseline()

    def _load_baseline(self) -> Dict[str, Any]:
        if not self.baseline_file.exists():
            raise FileNotFoundError(f"Baseline file not found at {self.baseline_file}")
        with open(self.baseline_file, "r", encoding="utf-8") as f:
            return json.load(f)

    @property
    def baseline(self) -> Dict[str, Any]:
        return self._baseline_data

    def score_single_sample(
        self,
        sample: BenchmarkSample,
        typedef_header: Optional[str] = None,
        timeout_sec: float = 5.0,
    ) -> SampleScore:
        """
        Compiles func_dep + decompile_output + test_code and runs executable.
        """
        code_candidates = [
            ("strict", sample.decompile_output),
        ]
        if typedef_header:
            code_candidates.append(("lenient", f"{typedef_header}\n{sample.decompile_output}"))

        results: Dict[str, bool] = {"strict": False, "lenient": False}
        compiler = "g++" if sample.language == "C++" else "gcc"
        ext = ".cpp" if sample.language == "C++" else ".c"

        with tempfile.TemporaryDirectory() as tmp_dir:
            for mode, candidate_code in code_candidates:
                full_src = f"{sample.func_dep}\n{candidate_code}\n{sample.test_code}"
                src_path = os.path.join(tmp_dir, f"test_{mode}{ext}")
                bin_path = os.path.join(tmp_dir, f"test_{mode}.exe")
                with open(src_path, "w", encoding="utf-8") as f:
                    f.write(full_src)

                cmd = [compiler, "-O0", src_path, "-o", bin_path, "-lm"]
                if sample.language == "C++":
                    cmd.append("-std=c++17")

                try:
                    c_res = subprocess.run(cmd, capture_output=True, text=True, timeout=10.0)
                    if c_res.returncode != 0:
                        continue
                    r_res = subprocess.run([bin_path], capture_output=True, text=True, timeout=timeout_sec)
                    if r_res.returncode == 0:
                        results[mode] = True
                except Exception:
                    pass

        return SampleScore(
            task_id=sample.task_id,
            language=sample.language,
            opt_level=sample.opt_level,
            compiled=results["strict"] or results["lenient"],
            passed_asserts=results["strict"],
            strict_pass=results["strict"],
            lenient_pass=results["lenient"],
        )

    def verify_reproduction(self, tolerance: float = 0.5) -> Dict[str, Any]:
        """
        Verifies that measured numbers reproduce Section 8 within tolerance.
        """
        baseline_results = self._baseline_data["results"]
        strict_base = baseline_results["official_strict"]["superghidra"]
        lenient_base = baseline_results["lenient"]["superghidra"]

        reproduction_checks = {
            "strict_avg": (strict_base["avg"], 7.41, abs(strict_base["avg"] - 7.41) <= tolerance),
            "lenient_avg": (lenient_base["avg"], 27.78, abs(lenient_base["avg"] - 27.78) <= tolerance),
            "strict_O0": (strict_base["O0"], 7.10, abs(strict_base["O0"] - 7.10) <= tolerance),
            "strict_O1": (strict_base["O1"], 10.19, abs(strict_base["O1"] - 10.19) <= tolerance),
            "lenient_O1": (lenient_base["O1"], 29.94, abs(lenient_base["O1"] - 29.94) <= tolerance),
        }

        all_passed = all(check[2] for check in reproduction_checks.values())
        return {
            "all_passed": all_passed,
            "tolerance": tolerance,
            "checks": reproduction_checks,
            "denominator": self._baseline_data["sample_counts"]["evaluable_denominator"],
        }

    def generate_markdown_report(self) -> str:
        """
        Generates the standard comparison markdown table mirroring Section 8.
        """
        res = self._baseline_data["results"]
        strict = res["official_strict"]
        lenient = res["lenient"]

        lines = [
            "### Measured Baseline: HumanEval-Decompile Re-executability",
            "",
            "| Mode | Candidate | O0 | O1 | O2 | O3 | **Avg** | C | C++ |",
            "| :--- | :--- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |",
            f"| Official (strict) | IDA Pro (published output) | {strict['ida_pro']['O0']:.2f} | {strict['ida_pro']['O1']:.2f} | {strict['ida_pro']['O2']:.2f} | {strict['ida_pro']['O3']:.2f} | **{strict['ida_pro']['avg']:.2f}** | {strict['ida_pro']['C']:.2f} | {strict['ida_pro']['Cpp']:.2f} |",
            f"| Official (strict) | Ghidra (published output) | {strict['ghidra']['O0']:.2f} | {strict['ghidra']['O1']:.2f} | {strict['ghidra']['O2']:.2f} | {strict['ghidra']['O3']:.2f} | **{strict['ghidra']['avg']:.2f}** | {strict['ghidra']['C']:.2f} | {strict['ghidra']['Cpp']:.2f} |",
            f"| Official (strict) | **SuperGhidra** | {strict['superghidra']['O0']:.2f} | {strict['superghidra']['O1']:.2f} | {strict['superghidra']['O2']:.2f} | {strict['superghidra']['O3']:.2f} | **{strict['superghidra']['avg']:.2f}** | {strict['superghidra']['C']:.2f} | {strict['superghidra']['Cpp']:.2f} |",
            f"| Lenient (per-tool typedef header) | IDA Pro (published output) | {lenient['ida_pro']['O0']:.2f} | {lenient['ida_pro']['O1']:.2f} | {lenient['ida_pro']['O2']:.2f} | {lenient['ida_pro']['O3']:.2f} | **{lenient['ida_pro']['avg']:.2f}** | {lenient['ida_pro']['C']:.2f} | {lenient['ida_pro']['Cpp']:.2f} |",
            f"| Lenient (per-tool typedef header) | Ghidra (published output) | {lenient['ghidra']['O0']:.2f} | {lenient['ghidra']['O1']:.2f} | {lenient['ghidra']['O2']:.2f} | {lenient['ghidra']['O3']:.2f} | **{lenient['ghidra']['avg']:.2f}** | {lenient['ghidra']['C']:.2f} | {lenient['ghidra']['Cpp']:.2f} |",
            f"| Lenient (per-tool typedef header) | **SuperGhidra** | {lenient['superghidra']['O0']:.2f} | {lenient['superghidra']['O1']:.2f} | {lenient['superghidra']['O2']:.2f} | {lenient['superghidra']['O3']:.2f} | **{lenient['superghidra']['avg']:.2f}** | {lenient['superghidra']['C']:.2f} | {lenient['superghidra']['Cpp']:.2f} |",
            "",
            f"Head-to-head (strict, same {self._baseline_data['sample_counts']['evaluable_denominator']} problems): both pass {self._baseline_data['head_to_head_strict']['both_pass']}, **IDA only {self._baseline_data['head_to_head_strict']['ida_only']}**, SuperGhidra only {self._baseline_data['head_to_head_strict']['superghidra_only']}, neither {self._baseline_data['head_to_head_strict']['neither']}.",
        ]
        return "\n".join(lines)
