"""The gcc head-to-head builds paper-style programs from the shipped filter."""

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from benchmarks.humaneval_decompile.gcc_compare import (
    averages_from_gcc_log,
    candidate_bodies,
    official_program,
    score_gcc_sample,
)
from benchmarks.humaneval_decompile.harness import (
    load_humaneval_rows,
)


class TestGccCompare(unittest.TestCase):
    def test_filtered_body_uses_the_shipped_filter(self):
        row = {
            "func_name": "func0",
            "ida_pseudo": "long long func0(int a1) {\n  return a1;\n}\n",
            "ghidra_pseudo": (
                "int4 func0(int4 x) {\n"
                "  long in_FS_OFFSET;\n"
                "  if (in_FS_OFFSET) {\n"
                "    return x;\n"
                "  }\n"
                "  __stack_chk_fail();\n"
                "}\n"
            ),
        }
        bodies = candidate_bodies(row)
        self.assertIn("long long func0(int a1)", bodies["ida"])
        self.assertNotIn("int32_t", bodies["ida"])
        self.assertIn("ida_filtered", bodies)
        self.assertIn("int32_t func0(int32_t x)", bodies["filtered"])
        self.assertIn("return x;", bodies["filtered"])
        self.assertNotIn("in_FS_OFFSET", bodies["filtered"])
        self.assertNotIn("__stack_chk_fail", bodies["filtered"])

    def test_official_program_has_no_spare_allocator(self):
        source = official_program(
            "C",
            ["int func0(int x) { return x; }\n", "int main(void) { return func0(1); }\n"],
        )
        self.assertIn("#include <assert.h>", source)
        self.assertNotIn("sg_malloc", source)
        self.assertNotIn("typedef uint64_t undefined8", source)
        self.assertIn("int func0(int x)", source)

    def test_score_gcc_sample_scores_ida_filtered(self):
        # Synthetic row where raw IDA has invalid syntax that CompilableDecompilerFilter rewrites,
        # or where mock _passes returns False for raw IDA and True for filtered IDA
        row = {
            "index": 42,
            "func_name": "func0",
            "language": "C",
            "opt": "O0",
            "func": "int func0(int x) { return x; }\n",
            "test": "int main(void) { return 0; }\n",
            "func_dep": "",
            "ida_pseudo": "int func0(int x) { return x; }\n",
            "ghidra_pseudo": "int func0(int x) { return x; }\n",
        }
        with patch("benchmarks.humaneval_decompile.gcc_compare._passes") as mock_passes:
            # Let official program pass, then raw IDA fail, filtered IDA pass, raw Ghidra fail, filtered Ghidra pass
            mock_passes.side_effect = [True, False, True, False, True]
            record = score_gcc_sample(row)
            self.assertTrue(record["evaluable"])
            self.assertFalse(record["ida_pass"])
            self.assertTrue(record["ida_filtered_pass"])
            self.assertFalse(record["ghidra_pass"])
            self.assertTrue(record["filtered_pass"])

    def test_averages_from_gcc_log_counts_gains_and_regressions(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            log_path = Path(tmpdir) / "test_log.jsonl"
            records = [
                # Sample 1: Ghidra gained (raw=F, filt=T), IDA unchanged (raw=T, filt=T)
                {
                    "task_id": "1",
                    "evaluable": True,
                    "ida_pass": True,
                    "ida_filtered_pass": True,
                    "ghidra_pass": False,
                    "filtered_pass": True,
                },
                # Sample 2: Ghidra broken (raw=T, filt=F), IDA broken (raw=T, filt=F)
                {
                    "task_id": "2",
                    "evaluable": True,
                    "ida_pass": True,
                    "ida_filtered_pass": False,
                    "ghidra_pass": True,
                    "filtered_pass": False,
                },
                # Sample 3: IDA gained (raw=F, filt=T), Ghidra unchanged (raw=T, filt=T)
                {
                    "task_id": "3",
                    "evaluable": True,
                    "ida_pass": False,
                    "ida_filtered_pass": True,
                    "ghidra_pass": True,
                    "filtered_pass": True,
                },
                # Sample 4: Unevaluable sample (should be ignored in denominator and counts)
                {
                    "task_id": "4",
                    "evaluable": False,
                    "ida_pass": False,
                    "ida_filtered_pass": False,
                    "ghidra_pass": False,
                    "filtered_pass": False,
                },
            ]
            with log_path.open("w", encoding="utf-8") as f:
                for r in records:
                    f.write(json.dumps(r) + "\n")

            summary = averages_from_gcc_log(log_path)
            self.assertEqual(summary["evaluable_denominator"], 3)
            self.assertEqual(summary["logged_samples"], 4)
            self.assertEqual(summary["filter_gained_ghidra"], 1)
            self.assertEqual(summary["filter_broken_ghidra"], 1)
            self.assertEqual(summary["filter_gained_ida"], 1)
            self.assertEqual(summary["filter_broken_ida"], 1)
            self.assertEqual(summary["ghidra_pass_count"], 2)
            self.assertEqual(summary["filtered_pass_count"], 2)
            self.assertEqual(summary["ida_pass_count"], 2)
            self.assertEqual(summary["ida_filtered_pass_count"], 2)

    def test_cache_revision_mismatch_forces_redownload(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            cache = Path(tmpdir)
            jsonl = cache / "humaneval.jsonl"
            jsonl.write_text('{"dummy": 1}\n', encoding="utf-8")
            rev_file = cache / "REVISION.txt"
            rev_file.write_text("old_stale_commit_hash\n", encoding="utf-8")

            with patch("benchmarks.humaneval_decompile.harness._download_split") as mock_dl:
                mock_dl.side_effect = RuntimeError("Mocked download split called")
                # Because rev does not match PINNED_REVISION and allow_unpinned=False, it unlinks jsonl and tries to download
                with self.assertRaises(RuntimeError) as ctx:
                    load_humaneval_rows(cache_dir=cache, allow_unpinned=False)
                self.assertIn("Mocked download split called", str(ctx.exception))
                self.assertFalse(jsonl.is_file(), "Stale jsonl should have been unlinked")


if __name__ == "__main__":
    unittest.main()
