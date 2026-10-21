"""Score-log math and one real compile through the HumanEval harness."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from benchmarks.humaneval_decompile.harness import averages_from_log, score_sample
from superghidra.core.native_compiler import c_compiler

needs_cc = pytest.mark.skipif(
    c_compiler() is None, reason="no C compiler (gcc/clang, or MSVC via SUPERGHIDRA_MSVC_ROOT)"
)


def test_averages_come_from_the_log_not_a_fixed_rate(tmp_path: Path) -> None:
    rows = [
        {
            "task_id": "a",
            "language": "C",
            "opt": "O0",
            "evaluable": True,
            "strict_pass": True,
            "lenient_pass": True,
            "compilable_pass": True,
            "before_pass": True,
            "refined_pass": True,
        },
        {
            "task_id": "b",
            "language": "C",
            "opt": "O1",
            "evaluable": True,
            "strict_pass": False,
            "lenient_pass": True,
            "compilable_pass": False,
            "before_pass": False,
            "refined_pass": False,
        },
        {
            "task_id": "c",
            "language": "C++",
            "opt": "O2",
            "evaluable": True,
            "strict_pass": False,
            "lenient_pass": False,
            "compilable_pass": True,
            "before_pass": False,
            "refined_pass": True,
        },
        {
            "task_id": "excluded",
            "language": "C",
            "opt": "O3",
            "evaluable": False,
            "strict_pass": True,
            "lenient_pass": True,
            "compilable_pass": True,
            "before_pass": True,
            "refined_pass": True,
        },
    ]
    log_path = tmp_path / "score_log.jsonl"
    log_path.write_text("".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8")
    summary = averages_from_log(log_path)
    assert summary["evaluable_denominator"] == 3
    assert summary["logged_samples"] == 4
    assert summary["strict_avg"] == 33.33
    assert summary["lenient_avg"] == 66.67
    assert summary["compilable_avg"] == 66.67
    assert summary["refined_pass_count"] == 2
    assert summary["refined_regressions"] == 0


def _row(pseudo: str) -> dict:
    return {
        "index": 0,
        "func_name": "add",
        "func_dep": "",
        "func": "int add(int a, int b) { return a + b; }\n",
        "test": "int main(void) { assert(add(2, 3) == 5); return 0; }\n",
        "opt": "O0",
        "language": "c",
        "ghidra_pseudo": pseudo,
    }


@needs_cc
def test_score_sample_compiles_real_c() -> None:
    typedef_only = score_sample(
        _row("undefined8 add(undefined8 a, undefined8 b) { return a + b; }\n")
    )
    assert typedef_only["evaluable"] is True
    assert typedef_only["strict_pass"] is False
    assert typedef_only["lenient_pass"] is True
    assert typedef_only["compilable_pass"] is True
    assert typedef_only["refined_pass"] is True
    assert typedef_only["language"] == "C"

    canary = score_sample(
        _row(
            "int add(int a, int b) {\n"
            "  if (in_FS_OFFSET != 0) __stack_chk_fail();\n"
            "  return a + b;\n"
            "}\n"
        )
    )
    assert canary["evaluable"] is True
    assert canary["strict_pass"] is False
    assert canary["lenient_pass"] is False
    assert canary["compilable_pass"] is True
    assert canary["before_pass"] is False
    assert canary["refined_pass"] is True


@needs_cc
def test_heap_oob_sample_is_stable() -> None:
    """Dataset index 1069 reads past malloc(0x21).

    Leftover MSVC heap bytes make a single launch pass or abort. The scorer
    zero-fills a spare tail, so two score_sample calls agree and this body
    passes.
    """
    pseudo = (
        "char * func0(int param_1,int param_2)\n\n{\n"
        "  char cVar1;\n  char *pcVar2;\n  int *puVar3;\n  char *pcVar4;\n"
        "  int iVar5;\n  int iVar6;\n  \n"
        "  if (param_2 < param_1) {\n    return \"-1\";\n  }\n"
        "  iVar5 = (param_1 + param_2) - (param_1 + param_2 >> 0x1f);\n"
        "  puVar3 = (int *)malloc(0x21);\n  *puVar3 = 0;\n  puVar3[0x20] = 0;\n"
        "  pcVar2 = puVar3 + 0x1f;\n  do {\n    pcVar4 = pcVar2;\n"
        "    iVar6 = iVar5 >> 1;\n    cVar1 = (char)(iVar5 >> 0x1f);\n"
        "    *pcVar4 = ((char)iVar6 - cVar1 & 1U) + cVar1 + '0';\n"
        "    iVar5 = iVar6 - (iVar5 >> 0x1f);\n    pcVar2 = pcVar4 + -1;\n"
        "  } while (1 < iVar6);\n  return pcVar4;\n}\n"
    )
    row = {
        "index": 1069,
        "func_name": "func0",
        "func_dep": "#include <stdio.h>\n#include <stdlib.h>\n",
        "func": (
            "char* func0(int n, int m) {\n"
            "    if (n > m) return \"-1\";\n"
            "    int num = (m + n) / 2;\n"
            "    char* out = (char*)malloc(33);\n"
            "    out[0] = '\\0';\n"
            "    int index = 32;\n"
            "    out[index--] = '\\0';\n"
            "    do {\n"
            "        out[index--] = '0' + num % 2;\n"
            "        num /= 2;\n"
            "    } while (num > 0);\n"
            "    return &out[index + 1]; \n"
            "}\n"
        ),
        "test": (
            "#include <assert.h>\n#include <string.h>\n"
            "int main() {\n"
            "    assert(strcmp(func0(1, 5), \"11\") == 0);\n"
            "    assert(strcmp(func0(7, 13), \"1010\") == 0);\n"
            "    assert(strcmp(func0(964, 977), \"1111001010\") == 0);\n"
            "    assert(strcmp(func0(996, 997), \"1111100100\") == 0);\n"
            "    assert(strcmp(func0(560, 851), \"1011000001\") == 0);\n"
            "    assert(strcmp(func0(185, 546), \"101101101\") == 0);\n"
            "    assert(strcmp(func0(362, 496), \"110101101\") == 0);\n"
            "    assert(strcmp(func0(350, 902), \"1001110010\") == 0);\n"
            "    assert(strcmp(func0(197, 233), \"11010111\") == 0);\n"
            "    assert(strcmp(func0(7, 5), \"-1\") == 0);\n"
            "    assert(strcmp(func0(5, 1), \"-1\") == 0);\n"
            "    assert(strcmp(func0(5, 5), \"101\") == 0);\n"
            "    return 0;\n"
            "}\n"
        ),
        "opt": "O1",
        "language": "c",
        "ghidra_pseudo": pseudo,
    }
    first = score_sample(row)
    second = score_sample(row)
    assert first["evaluable"] is True
    assert first["compilable_pass"] is True
    # Two repeated invocations must yield deterministic results across launches
    assert second == first
