"""
tests/core/test_pointer_stride_collapsing.py
============================================

Tests for Roadmap U20:
- Nested pointer-stride collapsing into natural array accesses
- Callee prototype auto-resolution via STRUCT_CATALOG
"""

import unittest
from superghidra.core.compilable_filter import CompilableDecompilerFilter


class TestPointerStrideCollapsing(unittest.TestCase):
    """Test pointer-stride arithmetic collapsing into array subscriptions."""

    def test_simple_multiplied_stride(self):
        raw = "int val = *(int *)(arr + i * 4);"
        collapsed = CompilableDecompilerFilter.collapse_pointer_strides(raw)
        self.assertIn("arr[i]", collapsed)

    def test_shifted_stride(self):
        raw = "uint64_t val = *(uint64_t *)(buf + (idx << 3));"
        collapsed = CompilableDecompilerFilter.collapse_pointer_strides(raw)
        self.assertIn("buf[idx]", collapsed)

    def test_nested_struct_array_dereference(self):
        raw = "*(_QWORD *)(*(_QWORD *)(param_1 + 0x18) + (longlong)i * 8) = 42;"
        collapsed = CompilableDecompilerFilter.collapse_pointer_strides(raw)
        self.assertIn("param_1->field_18[i] = 42;", collapsed)

    def test_callee_type_resolution(self):
        code = (
            "void test() {\n"
            "    void *p = VirtualAlloc(0, 4096, 0x1000, 0x40);\n"
            "}\n"
        )
        resolved = CompilableDecompilerFilter.resolve_callee_types(code)
        self.assertIn("LPVOID VirtualAlloc", resolved)

    def test_struct_catalog_forward_declaration(self):
        code = (
            "void process(Point *pt) {\n"
            "    pt->x = 10;\n"
            "}\n"
        )
        catalog = {"Point": object()}
        resolved = CompilableDecompilerFilter.resolve_callee_types(code, struct_catalog=catalog)
        self.assertIn("typedef struct Point Point;", resolved)

    def test_full_filter_pipeline_with_strides(self):
        raw = (
            "undefined8 foo(undefined8 *arr, int i) {\n"
            "    undefined8 val = *(undefined8 *)(arr + i * 8);\n"
            "    return val;\n"
            "}\n"
        )
        clean = CompilableDecompilerFilter.filter(raw)
        self.assertIn("uint64_t", clean)
        self.assertIn("arr[i]", clean)
        self.assertIn("#include <stdint.h>", clean)


if __name__ == "__main__":
    unittest.main()
