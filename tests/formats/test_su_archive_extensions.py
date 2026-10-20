"""SOLIDWORKS su_CArchive support in serialize_trace / mfc_archive (synthetic data)."""
import struct
import unittest

from superghidra.formats.mfc_archive import LayoutOp, decode_stream
from superghidra.formats.serialize_trace import SerializeTracer, _archive_query, object_operator_class


def _new_class(name: str, schema: int = 1) -> bytes:
    return b"\xff\xff" + struct.pack("<HH", schema, len(name)) + name.encode("ascii")


class TestImportClassification(unittest.TestCase):
    def test_member_operators(self):
        c = SerializeTracer._classify_import
        self.assertEqual(c("??6su_CArchive@@QEAAAEAV0@J@Z"), ("write", "i32", 4))
        self.assertEqual(c("??5su_CArchive@@QEAAAEAV0@AEAG@Z"), ("read", "u16", 2))
        self.assertEqual(c("??6su_CArchive@@QEAAAEAV0@N@Z"), ("write", "f64", 8))
        self.assertEqual(c("??6su_CArchive@@QAEAAV0@K@Z"), ("write", "u32", 4))  # x86 thiscall

    def test_object_pointer_operators(self):
        name = "??6@YAAEAVsu_CArchive@@AEAV0@AEAPEAVmoNodeName_c@@@Z"
        self.assertEqual(SerializeTracer._classify_import(name), ("write", "object", None))
        self.assertEqual(object_operator_class(name), "moNodeName_c")
        self.assertIsNone(object_operator_class("??6su_CArchive@@QEAAAEAV0@J@Z"))

    def test_archive_queries(self):
        self.assertEqual(_archive_query("?IsStoring@su_CArchive@@QEBAHXZ"), "IsStoring")
        self.assertEqual(_archive_query("?IsDBStream@su_CArchive@@QEBAHXZ"), "IsDBStream")
        self.assertIsNone(_archive_query("?IsEmpty@CString@@QEBAHXZ"))
        self.assertIsNone(_archive_query("?Serialize@su_CObject@@UEAAXAEAVCArchive@@@Z"))


class TestDecoderExtensions(unittest.TestCase):
    def test_expected_class_learns_shared_index(self):
        # Class #4 was registered by another stream of the same archive; the writer's
        # `operator<<(ar, Name_c*)` says which class it is.
        layouts = {
            "Outer_c": [LayoutOp("object", None, False, "this+0x18", "Name_c", []),
                        LayoutOp("object", None, False, "this+0x20", "Name_c", [])],
            "Name_c": [LayoutOp("u32", 4, False, "this+0x8", None, [])],
        }
        data = _new_class("Outer_c") + b"\x04\x80" + struct.pack("<I", 7) + b"\x04\x80" + struct.pack("<I", 9)
        res = decode_stream(data, layouts, map_count=40)
        outer = res["objects"][0]
        self.assertEqual(outer["status"], "decoded")
        names = [f["value"]["class"] for f in outer["fields"]]
        self.assertEqual(names, ["Name_c", "Name_c"])

    def test_presence_flag_gates_pointer_member(self):
        layouts = {"Holder_c": [
            LayoutOp("i32", 4, False, None, None, []),
            LayoutOp("u32", 4, False, "this+0x60->+0x8", None, [("this+0x60", "!=", 0)]),
            LayoutOp("u16", 2, False, "this+0x10", None, []),
        ]}
        absent = _new_class("Holder_c") + struct.pack("<iH", 0, 0x55)
        present = _new_class("Holder_c") + struct.pack("<iIH", 1, 0xAABB, 0x55)
        for data, n_fields in ((absent, 2), (present, 3)):
            obj = decode_stream(data, layouts)["objects"][0]
            self.assertEqual(obj["status"], "decoded")
            self.assertEqual(len(obj["fields"]), n_fields)
            self.assertEqual(obj["fields"][-1]["value"], 0x55)


class TestOpaqueBranches(unittest.TestCase):
    def test_if_else_on_call_result_takes_one_branch(self):
        # `if (f() == 0 && g() != 0) write count A; else write count B;` - the else side is
        # recorded as an `or` of the negations. Only one of the two counts is in the stream.
        then_c = [("ret@0x10", "==", 0), ("ret@0x20", "!=", 0)]
        else_c = [("or", ((("ret@0x10", "!=", 0),), (("ret@0x20", "==", 0),)))]
        layouts = {"Branchy_c": [
            LayoutOp("count", None, False, "this+0x18", None, then_c),
            LayoutOp("count", None, False, "this+0x18", None, else_c),
            LayoutOp("u16", 2, False, "this+0x20", None, []),
        ]}
        data = _new_class("Branchy_c") + struct.pack("<HH", 0, 0x77)
        obj = decode_stream(data, layouts)["objects"][0]
        self.assertEqual(obj["status"], "decoded")
        self.assertEqual([f["kind"] for f in obj["fields"]], ["count", "u16"])
        self.assertEqual(obj["fields"][-1]["value"], 0x77)


if __name__ == "__main__":
    unittest.main()
