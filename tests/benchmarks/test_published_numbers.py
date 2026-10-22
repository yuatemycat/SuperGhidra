"""Verifies that published benchmark numbers in documentation match committed summaries."""

import json
import re
import unittest
from pathlib import Path

from benchmarks.humaneval_decompile.harness import PINNED_REVISION
from scripts.render_humaneval_table import DEFAULT_SUMMARY, check_target_file, generate_table

REPO_ROOT = Path(__file__).resolve().parent.parent.parent


class TestPublishedNumbers(unittest.TestCase):
    def test_pinned_revision_format(self):
        self.assertRegex(PINNED_REVISION, r"^[0-9a-f]{40}$")
        if DEFAULT_SUMMARY.is_file():
            summary = json.loads(DEFAULT_SUMMARY.read_text(encoding="utf-8"))
            self.assertEqual(summary.get("dataset_revision"), PINNED_REVISION)

    def test_readme_matches_humaneval_summary(self):
        if not DEFAULT_SUMMARY.is_file():
            self.skipTest("gcc_score_summary.json does not exist yet")

        summary = json.loads(DEFAULT_SUMMARY.read_text(encoding="utf-8"))
        # If still in intermediate state (0 evaluable), skip
        if summary.get("evaluable_denominator", 0) == 0:
            self.skipTest("Summary has 0 evaluable denominator")

        table_text = generate_table(summary)
        readme = REPO_ROOT / "README.md"
        matrix = REPO_ROOT / "docs" / "benchmarks" / "EMPIRICAL_TEST_BENCHMARK_MATRIX.md"

        self.assertTrue(
            check_target_file(readme, table_text),
            f"README.md table does not match generated table from {DEFAULT_SUMMARY}",
        )
        self.assertTrue(
            check_target_file(matrix, table_text),
            f"EMPIRICAL_TEST_BENCHMARK_MATRIX.md table does not match generated table from {DEFAULT_SUMMARY}",
        )

    def test_no_unverified_claims_in_docs(self):
        targets = [
            REPO_ROOT / "README.md",
            REPO_ROOT / "docs" / "benchmarks" / "EMPIRICAL_TEST_BENCHMARK_MATRIX.md",
            REPO_ROOT / "docs" / "benchmarks" / "EMPIRICAL_BENCHMARK_MATRIX_v0.2.0.md",
            REPO_ROOT / "docs" / "SUPERGHIDRA_ARCHITECTURE_AND_IDA_PRO_GAP_ANALYSIS.md",
        ]
        forbidden = [
            "+5.79% over commercial IDA Pro",
            "0 regressions",
        ]
        for path in targets:
            if not path.is_file():
                continue
            content = path.read_text(encoding="utf-8")
            for phrase in forbidden:
                self.assertNotIn(
                    phrase,
                    content,
                    f"Found forbidden unverified phrase {phrase!r} in {path}",
                )


if __name__ == "__main__":
    unittest.main()
