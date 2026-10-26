"""
Tests for the held-out evaluation dataset and runner (Issue #27).
"""

from __future__ import annotations

import json
import unittest

from benchmarks.eval_held_out import (
    DATA_PATH,
    evaluate_sample,
    format_text_table,
    run_held_out_evaluation,
)


class TestHeldOutEvaluation(unittest.TestCase):
    def test_dataset_exists_and_contains_200_valid_records(self) -> None:
        self.assertTrue(DATA_PATH.is_file(), f"Dataset file missing: {DATA_PATH}")
        lines = [
            line.strip()
            for line in DATA_PATH.read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]
        self.assertEqual(len(lines), 200)

        required_keys = {
            "id",
            "library",
            "func_name",
            "original_c",
            "ghidra_pseudo",
            "ida_pseudo",
            "test",
        }
        libraries = set()
        for idx, line in enumerate(lines):
            row = json.loads(line)
            for k in required_keys:
                self.assertIn(k, row, f"Row {idx} missing key {k}")
            libraries.add(row["library"])

        self.assertEqual(libraries, {"sqlite", "zlib", "coreutils"})

    def test_evaluate_sample_contract(self) -> None:
        lines = [
            line.strip()
            for line in DATA_PATH.read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]
        sample = json.loads(lines[0])
        res = evaluate_sample(sample)

        self.assertIn("id", res)
        self.assertIn("library", res)
        self.assertIn("func_name", res)
        self.assertIn("ghidra_raw", res)
        self.assertIn("ghidra_filtered", res)
        self.assertIn("ida_raw", res)
        self.assertIn("ida_with_defs", res)
        self.assertIn("ida_filtered", res)
        self.assertTrue(res["ghidra_filtered"])
        self.assertTrue(res["ida_with_defs"])

    def test_run_held_out_evaluation_bounded(self) -> None:
        summary = run_held_out_evaluation(DATA_PATH, limit=6, workers=2)
        self.assertEqual(summary["total_evaluated"], 6)
        self.assertIn("overall", summary)
        self.assertIn("by_library", summary)
        self.assertEqual(summary["overall"]["count"], 6)

        table = format_text_table(summary)
        self.assertIn("SUPERGHIDRA SYNTHETIC IDIOM EVALUATION", table)
        self.assertIn("Ghidra Filtered (SG)", table)
        self.assertIn("IDA with defs.h (Fair)", table)


if __name__ == "__main__":
    unittest.main()
