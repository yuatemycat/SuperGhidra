"""
tests/core/test_deflatten_gcc.py
================================

Unit test verifying that the control flow deflattener recognizes GCC -O0
register-compare switch dispatchers from static fixture bytes without requiring a compiler.
"""

import tempfile
import unittest
from pathlib import Path

from superghidra.core.live_binary_tools import (
    _deflatten_chain,
    _find_cmp_chains,
    deflatten_control_flow,
)
from superghidra.lifters.x86_decode import iter_decode
from tests.formats.test_binary_loader import build_pe


class TestDeflattenGcc(unittest.TestCase):
    """Test deflattening on GCC -O0 compiled switch fixtures."""

    @classmethod
    def setUpClass(cls):
        fixture_path = Path(__file__).parents[1] / "fixtures" / "deflatten" / "gcc_flattened_score.bin"
        cls.fixture_bytes = fixture_path.read_bytes()

    def test_gcc_register_compare_chain_detected(self):
        # Entry address in original executable was 0x140001760
        base_addr = 0x140001760
        insns = list(iter_decode(self.fixture_bytes, address=base_addr, mode=64))

        chains = _find_cmp_chains(insns)
        self.assertTrue(len(chains) >= 1, "Expected at least 1 compare chain in GCC fixture")

        gcc_chain = chains[0]
        # Verify chain has compares on register (e.g. eax)
        self.assertGreaterEqual(len(gcc_chain), 3)

        # De-flatten the chain
        report = _deflatten_chain(insns, gcc_chain)
        self.assertTrue(report.get("deflattened"), f"Deflatten failed: {report}")
        self.assertGreater(report.get("gotos_eliminated", 0), 0)
        self.assertGreater(report.get("back_edges_removed", 0), 0)

        # Invariant: duplicate compares for range splits (e.g. cmp eax, 2; je ... cmp eax, 2; jg ...)
        # must not add a second case for state 2
        state_cases = report.get("state_cases", [])
        self.assertEqual(state_cases.count(2), 1, "Duplicate compare must not produce duplicate state case 2")
        self.assertIn(0, state_cases)
        self.assertIn(1, state_cases)
        self.assertIn(2, state_cases)

    def test_deflatten_control_flow_on_fixture_pe(self):
        # Wrap fixture bytes in a synthetic PE binary
        pe_bytes, _ = build_pe(bits=64, text=self.fixture_bytes)

        with tempfile.NamedTemporaryFile(suffix=".dll", delete=False) as tf:
            tf.write(pe_bytes)
            tmp_path = tf.name

        try:
            res = deflatten_control_flow(tmp_path)
            self.assertTrue(res["deflattened"])
            self.assertGreater(res["gotos_eliminated"], 0)
            self.assertGreater(res["back_edges_removed"], 0)
        finally:
            Path(tmp_path).unlink(missing_ok=True)


if __name__ == "__main__":
    unittest.main()
