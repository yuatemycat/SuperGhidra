"""
Unit tests for CompilableDecompilerFilter (U1, U2, U3).
"""

import unittest
from superghidra.core.compilable_filter import CompilableDecompilerFilter


class TestCompilableDecompilerFilter(unittest.TestCase):
    def test_rewrite_types(self):
        raw_code = (
            "undefined8 compute(undefined4 a, ulonglong b, byte c) {\n"
            "    longlong x = (longlong)a + b;\n"
            "    return (undefined8)(x + c);\n"
            "}"
        )
        filtered = CompilableDecompilerFilter.rewrite_types(raw_code)
        self.assertIn("uint64_t compute(uint32_t a, uint64_t b, uint8_t c)", filtered)
        self.assertIn("int64_t x = (int64_t)a + b;", filtered)
        self.assertIn("return (uint64_t)(x + c);", filtered)

    def test_expand_intrinsics(self):
        raw_code = (
            "uint64_t join_parts(uint32_t hi, uint32_t lo) {\n"
            "    uint64_t combined = CONCAT44(hi, lo);\n"
            "    uint32_t low_word = SUB84(combined, 0);\n"
            "    uint64_t z = ZEXT48(lo);\n"
            "    int64_t s = SEXT48(lo);\n"
            "    return combined + low_word + z + s;\n"
            "}"
        )
        expanded = CompilableDecompilerFilter.expand_intrinsics(raw_code)
        self.assertIn("(((uint64_t)(hi) << 32) | (uint32_t)(lo))", expanded)
        self.assertIn("((uint32_t)((combined) >> ((0) * 8)))", expanded)
        self.assertIn("((uint64_t)(uint32_t)(lo))", expanded)
        self.assertIn("((int64_t)(int32_t)(lo))", expanded)

    def test_nested_intrinsics(self):
        raw = "uint64_t v = CONCAT44(SUB84(x, 4), lo);"
        expanded = CompilableDecompilerFilter.expand_intrinsics(raw)
        self.assertIn("(((uint64_t)(((uint32_t)((x) >> ((4) * 8)))) << 32) | (uint32_t)(lo))", expanded)

    def test_cleanup_canaries_and_warnings(self):
        raw_code = (
            "int main(void) {\n"
            "    int64_t in_FS_OFFSET;\n"
            "    uint64_t canary = *(uint64_t *)(in_FS_OFFSET + 0x28);\n"
            "    /* WARNING: Unknown calling convention */\n"
            "    int res = do_work() + extraout_EDX;\n"
            "    if (canary != *(uint64_t *)(in_FS_OFFSET + 0x28)) {\n"
            "        __stack_chk_fail();\n"
            "    }\n"
            "    return res;\n"
            "}"
        )
        cleaned = CompilableDecompilerFilter.cleanup_canaries_and_idioms(raw_code)
        self.assertNotIn("in_FS_OFFSET", cleaned)
        self.assertNotIn("__stack_chk_fail", cleaned)
        self.assertNotIn("WARNING", cleaned)
        self.assertNotIn("extraout_EDX", cleaned)

    def test_full_filter_pipeline(self):
        ghidra_code = (
            "undefined8 process_buffer(undefined4 len, byte *buf) {\n"
            "    long in_FS_OFFSET;\n"
            "    long canary = *(long *)(in_FS_OFFSET + 0x28);\n"
            "    ulonglong sum = 0;\n"
            "    for (uint i = 0; i < len; i++) {\n"
            "        sum += (ulonglong)buf[i];\n"
            "    }\n"
            "    if (canary != *(long *)(in_FS_OFFSET + 0x28)) {\n"
            "        __stack_chk_fail();\n"
            "    }\n"
            "    return sum;\n"
            "}"
        )
        res = CompilableDecompilerFilter.filter(ghidra_code, emit_compilable=True)
        self.assertTrue(res.startswith("#include <stdint.h>"))
        self.assertIn("uint64_t process_buffer(uint32_t len, uint8_t *buf)", res)
        self.assertNotIn("in_FS_OFFSET", res)
        self.assertNotIn("undefined8", res)
        self.assertNotIn("ulonglong", res)

    def test_int4_and_success_side_canary(self):
        ghidra_code = (
            "int4 func0(int4 x) {\n"
            "    long in_FS_OFFSET;\n"
            "    long local_10;\n"
            "    int4 local_2c;\n"
            "    local_10 = *(long *)(in_FS_OFFSET + 0x28);\n"
            "    local_2c = x + 1;\n"
            "    if (local_10 == *(long *)(in_FS_OFFSET + 0x28)) {\n"
            "        return local_2c;\n"
            "    }\n"
            "                    /* WARNING: Subroutine does not return */\n"
            "    __stack_chk_fail();\n"
            "}\n"
        )
        res = CompilableDecompilerFilter.filter(ghidra_code)
        self.assertIn("int32_t func0(int32_t x)", res)
        self.assertIn("int32_t local_2c;", res)
        self.assertIn("return local_2c;", res)
        self.assertNotIn("int4", res)
        self.assertNotIn("in_FS_OFFSET", res)
        self.assertNotIn("__stack_chk_fail", res)
        self.assertEqual(res.count("{"), res.count("}"))

    def test_glibc_ctype_helpers_are_defined_when_used(self):
        ghidra_code = (
            "int func0(int ch) {\n"
            "    ushort **table;\n"
            "    __int32_t **lower;\n"
            "    table = __ctype_b_loc();\n"
            "    lower = __ctype_tolower_loc();\n"
            "    if (((*table)[ch] & 0x200) != 0) {\n"
            "        return (*lower)[ch];\n"
            "    }\n"
            "    return ch;\n"
            "}\n"
        )
        res = CompilableDecompilerFilter.filter(ghidra_code)
        self.assertIn("static unsigned short **__ctype_b_loc(void)", res)
        self.assertIn("static int **__ctype_tolower_loc(void)", res)
        self.assertNotIn("__ctype_toupper_loc", res)
        self.assertNotIn("__int32_t", res)
        self.assertIn("int32_t **lower", res)
        plain = CompilableDecompilerFilter.filter("int func0(int x) { return x; }\n")
        self.assertNotIn("__ctype_b_loc", plain)


if __name__ == "__main__":
    unittest.main()
