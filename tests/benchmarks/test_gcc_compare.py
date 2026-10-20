"""The gcc head-to-head builds paper-style programs from the shipped filter."""

import unittest

from benchmarks.humaneval_decompile.gcc_compare import candidate_bodies, official_program


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


if __name__ == "__main__":
    unittest.main()
