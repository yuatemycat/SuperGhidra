"""Tests for serialize_trace (static Serialize() layouts) and mfc_archive (CArchive decoding)."""

import os
import struct
import unittest

import mfc_archive as MA
import serialize_trace as ST
from test_msvc_class_recovery import BASE, build_pe_sections


def _asm_serialize() -> bytes:
    """x64 `CPoint3::Serialize(CArchive& ar)` in the shape MFC's inline operators produce.

    store: ar << m_x (u32, this+8); if (m_ver >= 5) ar << m_d (f64, this+0x10)
    load : ar >> m_x;               if (m_ver >= 5) ar >> m_d
    Archive layout (as in mfc140u): m_nMode at +0x20 (bit 0 = load), cursor at +0x38.
    """
    code = bytearray()
    fix = {}

    def emit(b, label=None):
        if label:
            fix[label] = len(code)
        code.extend(b)

    def jcc(op, target):  # short jump placeholder
        fix.setdefault("_patch", []).append((len(code), target))
        code.extend(bytes([op, 0]))

    emit(b"\x53\x57\x48\x83\xEC\x28")  # push rbx; push rdi; sub rsp,0x28
    emit(b"\x48\x89\xD3\x48\x89\xCF")  # mov rbx,rdx ; mov rdi,rcx
    emit(b"\xF6\x42\x20\x01")  # test byte [rdx+0x20],1   (IsLoading)
    jcc(0x75, "load")  # jne load
    # ---- storing ----
    emit(b"\x48\x8B\x43\x38\x8B\x4F\x08\x89\x08\x48\x83\x43\x38\x04")  # cursor; mov ecx,[rdi+8]; mov [rax],ecx; add cur,4
    emit(b"\x83\x7F\x18\x05")  # cmp dword [rdi+0x18],5
    jcc(0x72, "done")  # jb done
    emit(b"\x48\x8B\x43\x38\xF2\x0F\x10\x47\x10\xF2\x0F\x11\x00\x48\x83\x43\x38\x08")  # movsd via cursor; add cur,8
    jcc(0xEB, "done")
    # ---- loading ----
    emit(b"\x48\x8B\x43\x38\x8B\x08\x89\x4F\x08\x48\x83\x43\x38\x04", "load")  # mov ecx,[cur]; mov [rdi+8],ecx
    emit(b"\x83\x7F\x18\x05")
    jcc(0x72, "done")
    emit(b"\x48\x8B\x43\x38\xF2\x0F\x10\x00\xF2\x0F\x11\x47\x10\x48\x83\x43\x38\x08")
    emit(b"\x48\x83\xC4\x28\x5F\x5B\xC3", "done")  # add rsp,0x28; pop rdi; pop rbx; ret
    for at, label in fix["_patch"]:
        code[at + 1] = (fix[label] - (at + 2)) & 0xFF
    return bytes(code)


def build_serialize_dll() -> bytes:
    va = lambda rva: BASE + rva  # noqa: E731
    text = bytearray(b"\xCC" * 0x140)
    text[0:8] = b"\x48\x8D\x05" + struct.pack("<i", va(0x2010) - (va(0x1000) + 7)) + b"\xC3"
    text[0x10] = text[0x20] = 0xC3
    ser = _asm_serialize()
    text[0x40:0x40 + len(ser)] = ser
    rdata = bytearray(0x200)
    rdata[0:8] = b"CPoint3\x00"
    struct.pack_into("<QiIQQQQ", rdata, 0x10, va(0x2000), 0x20, 0x80000002, va(0x1020), va(0x2150), 0, 0)
    rdata[0x140:0x148] = b"CObject\x00"
    struct.pack_into("<QiIQQQQ", rdata, 0x150, va(0x2140), 8, 0xFFFF, 0, 0, 0, 0)
    struct.pack_into("<QQQ", rdata, 0x100, va(0x1000), va(0x1010), va(0x1040))
    return build_pe_sections([(b".text", 0x1000, bytes(text), 0x60000020),
                              (b".rdata", 0x2000, bytes(rdata), 0x40000040)])


def write_stream(objects) -> bytes:
    """Minimal CArchive writer: [(class, schema, payload_bytes)], MFC map semantics."""
    out, classes, n = bytearray(), {}, 1
    for name, schema, payload in objects:
        if name in classes:
            out += struct.pack("<H", 0x8000 | classes[name])
            n += 1
        else:
            out += struct.pack("<HHH", 0xFFFF, schema, len(name)) + name.encode()
            classes[name] = n
            n += 2
        out += payload
    return bytes(out)


class TestTracer(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tracer = ST.SerializeTracer(build_serialize_dll())
        cls.trace = cls.tracer.trace_classes(["CPoint3"])[0]

    def test_store_and_load_paths(self):
        st = [(o.direction, o.kind) for o in self.trace.storing]
        ld = [(o.direction, o.kind) for o in self.trace.loading]
        self.assertEqual(st, [("write", "u32"), ("write", "f64")])
        self.assertEqual(ld, [("read", "u32"), ("read", "f64")])
        self.assertTrue(self.trace.mirrored)

    def test_members_and_gates(self):
        w32, w64 = self.trace.storing
        self.assertEqual(w32.member, "this+0x8")
        self.assertEqual(w32.gates, [])
        self.assertEqual(w64.gates, ["this+0x18 >= 0x5"])
        r32 = self.trace.loading[0]
        self.assertEqual(r32.member, "this+0x8")  # named by the store of the value read

    def test_to_dict(self):
        d = self.trace.to_dict()
        self.assertEqual(d["class"], "CPoint3")
        self.assertEqual(d["storing"][1]["text"], "write f64  [this+0x18 >= 0x5]")


class TestArchiveReader(unittest.TestCase):
    def test_strings(self):
        r = MA.ArchiveReader(b"\x03abc" + b"\xff\xfe\xff\x02" + "hé".encode("utf-16-le") + b"\xff\x00\x01" + b"x" * 256)
        self.assertEqual(r.cstring(), "abc")
        self.assertEqual(r.cstring(), "hé")
        self.assertEqual(r.cstring(), "x" * 256)

    def test_counts(self):
        r = MA.ArchiveReader(b"\x05\x00" + b"\xff\xff\x00\x00\x01\x00")
        self.assertEqual(r.count(), 5)
        self.assertEqual(r.count(), 0x10000)

    def test_tags_and_map(self):
        data = write_stream([("CA", 1, b""), ("CB", 2, b""), ("CA", 1, b"")]) + b"\x02\x00\x00\x00"
        r = MA.ArchiveReader(data)
        self.assertEqual(r.read_tag()[:3], ("new_class", 1, "CA"))
        r.register_object(MA.ArchiveObject(0, "CA", 1, None))  # map 2
        self.assertEqual(r.read_tag()[:3], ("new_class", 3, "CB"))
        r.register_object(MA.ArchiveObject(0, "CB", 2, None))  # map 4
        self.assertEqual(r.read_tag()[:3], ("class_ref", 1, "CA"))
        r.register_object(MA.ArchiveObject(0, "CA", 1, None))  # map 5
        self.assertEqual(r.read_tag()[:2], ("ref", 2))
        self.assertEqual(r.read_tag()[0], "null")

    def test_bad_class_ref(self):
        with self.assertRaises(MA.ArchiveError):
            MA.ArchiveReader(b"\x05\x80").read_tag()

    def test_scan_class_tags(self):
        data = b"junk" + write_stream([("moThing_c", 1, b"\x01\x02")])
        tags = MA.scan_class_tags(data)
        self.assertEqual([(t.offset, t.name, t.schema) for t in tags], [(4, "moThing_c", 1)])


class TestTraceDrivenDecode(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        tracer = ST.SerializeTracer(build_serialize_dll())
        cls.layouts = MA.layouts_from_traces(tracer.class_layouts())

    def test_decode_with_version(self):
        data = write_stream([("CPoint3", 2, struct.pack("<Id", 7, 1.5)), ("CPoint3", 2, struct.pack("<Id", 9, -2.0))])
        res = MA.decode_stream(data, self.layouts, env={"this+0x18": 5})
        objs = res["objects"]
        self.assertEqual([o["status"] for o in objs], ["decoded", "decoded"])
        self.assertEqual([f["value"] for f in objs[0]["fields"]], [7, 1.5])
        self.assertEqual([f["value"] for f in objs[1]["fields"]], [9, -2.0])
        self.assertEqual(objs[1]["map_index"], 3)  # class #1, object #2, class-ref object #3
        self.assertTrue(res["map_reliable"])

    def test_calibrate_finds_old_version(self):
        # Written by an "old" version: the gated f64 is absent.
        data = write_stream([("CPoint3", 2, struct.pack("<I", 7)), ("CPoint3", 2, struct.pack("<I", 8))])
        cal = MA.calibrate(data, self.layouts)
        self.assertEqual(cal["variable"], "this+0x18")
        self.assertLess(cal["value"], 5)
        res = MA.decode_stream(data, self.layouts, env={cal["variable"]: cal["value"]})
        self.assertEqual([f["value"] for o in res["objects"] for f in o["fields"]], [7, 8])

    def test_unknown_class_is_skipped(self):
        data = write_stream([("CMystery", 1, b"\xde\xad\xbe\xef"), ("CPoint3", 2, struct.pack("<Id", 1, 2.0))])
        res = MA.decode_stream(data, self.layouts, env={"this+0x18": 5})
        self.assertEqual([o["status"] for o in res["objects"]], ["opaque", "decoded"])
        self.assertFalse(res["map_reliable"])


SWDM = r"C:\Program Files\SOLIDWORKS Corp\SOLIDWORKS PCB Viewer\System\Model3DWrapper\SWAPI64\swdocumentmgr.dll"
MFC64 = r"C:\Windows\System32\mfc140u.dll"


@unittest.skipUnless(os.path.exists(MFC64), "mfc140u.dll not present")
class TestRealMfc(unittest.TestCase):
    def test_collections(self):
        traces = {t.class_name: t for t in ST.trace_serialize_functions(MFC64, ["CObList", "CStringArray"])}
        oblist = traces["CObList"]
        self.assertTrue(oblist.mirrored)
        self.assertEqual([(o.kind, o.repeat) for o in oblist.loading], [("count", False), ("object", True)])
        self.assertEqual([o.kind for o in traces["CStringArray"].storing], ["count", "cstring"])


@unittest.skipUnless(os.path.exists(SWDM) and os.path.exists(MFC64), "SOLIDWORKS Document Manager DLL not present")
class TestRealSolidWorks(unittest.TestCase):
    def test_traces_and_decode(self):
        sw, mfc = ST.SerializeTracer(SWDM), ST.SerializeTracer(MFC64)
        stamp = sw.trace_classes(["moStamp_c"])[0]
        self.assertTrue(stamp.mirrored)
        self.assertEqual([o.kind for o in stamp.storing], ["serialize", "u16", "u16", "u16", "u32", "cstring"])
        layouts = MA.layouts_from_traces(sw.class_layouts(others=(mfc,)))
        # A moLogs_c history entry as SOLIDWORKS writes it (taken from a real Header2 stream).
        entry = bytes.fromhex(
            "ffff01000800 6d6f4c6f67735f63 0100 ffff01000900 6d6f5374616d705f63 000000000000 33b6836a"
            "fffeff07 4300720065006100740065006400 00000000 fffeff05 5000610072007400 3100".replace(" ", ""))
        res = MA.decode_stream(entry, layouts)
        log = res["objects"][0]
        self.assertEqual(log["status"], "decoded")
        stamp_obj = log["fields"][1]["value"]
        self.assertEqual(stamp_obj["class"], "moStamp_c")
        self.assertEqual(stamp_obj["fields"][-1]["value"], "Created")
        self.assertEqual(log["fields"][-1]["value"], "Part1")


if __name__ == "__main__":
    unittest.main()
