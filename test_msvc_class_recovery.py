"""Tests for msvc_class_recovery (RTTI + MFC CRuntimeClass), synthetic and real DLLs."""

import os
import struct
import unittest

import msvc_class_recovery as R

BASE = 0x180000000


def build_pe_sections(sections, bits=64, image_base=BASE, machine=0x8664):
    """PE image from [(name, rva, bytes, characteristics)] with no data directories."""
    opt_size = 240 if bits == 64 else 224
    e_lfanew, headers = 0x80, 0x400
    hdr = bytearray(headers)
    hdr[0:2] = b"MZ"
    struct.pack_into("<I", hdr, 0x3C, e_lfanew)
    hdr[e_lfanew : e_lfanew + 4] = b"PE\x00\x00"
    struct.pack_into("<HHIIIHH", hdr, e_lfanew + 4, machine, len(sections), 0, 0, 0, opt_size, 0x2022)
    opt = e_lfanew + 24
    if bits == 64:
        struct.pack_into("<HQ", hdr, opt, 0x20B, 0)
        struct.pack_into("<Q", hdr, opt + 24, image_base)
        struct.pack_into("<I", hdr, opt + 108, 16)
    else:
        struct.pack_into("<H", hdr, opt, 0x10B)
        struct.pack_into("<I", hdr, opt + 28, image_base)
        struct.pack_into("<I", hdr, opt + 92, 16)
    raw = bytearray(hdr)
    for i, (name, rva, blob, ch) in enumerate(sections):
        blob = blob.ljust((len(blob) + 0x1FF) & ~0x1FF, b"\x00")
        struct.pack_into("<8sIIIIIIHHI", raw, opt + opt_size + 40 * i, name, len(blob), rva, len(blob), len(raw),
                         0, 0, 0, 0, ch)
        raw += blob
    return bytes(raw)


def build_mfc_dll():
    va = lambda rva: BASE + rva  # noqa: E731
    text = bytearray(b"\xCC" * 0x40)
    # GetRuntimeClass: lea rax,[rip+CRuntimeClass] ; ret
    rel = va(0x2010) - (va(0x1000) + 7)
    text[0:8] = b"\x48\x8D\x05" + struct.pack("<i", rel) + b"\xC3"
    text[0x10] = text[0x20] = text[0x30] = 0xC3  # dtor, Serialize, CreateObject
    rdata = bytearray(0x200)
    rdata[0x00:0x09] = b"CFeature\x00"
    struct.pack_into("<QiIQQQQ", rdata, 0x10, va(0x2000), 0x40, 0x80000003, va(0x1030), 0, 0, 0)
    struct.pack_into("<QQ", rdata, 0x40, 0, 0)
    rdata[0x50:0x50 + 15] = b".?AVCFeature@@\x00"
    struct.pack_into("<IIIiii", rdata, 0x70, 1, 0, 0, 0x2040, 0x20A0, 0x2070)  # COL
    struct.pack_into("<IIIi", rdata, 0xA0, 0, 0, 1, 0x20C0)  # CHD
    struct.pack_into("<i", rdata, 0xC0, 0x20D0)  # base class array
    struct.pack_into("<iIiiiIi", rdata, 0xD0, 0x2040, 0, 0, -1, 0, 0, 0x20A0)  # BCD
    struct.pack_into("<QQQQQ", rdata, 0xF8, va(0x2070), va(0x1000), va(0x1010), va(0x1020), 0)
    return build_pe_sections([(b".text", 0x1000, bytes(text), 0x60000020),
                              (b".rdata", 0x2000, bytes(rdata), 0x40000040)])


class TestDemangle(unittest.TestCase):
    def test_names(self):
        self.assertEqual(R.demangle_rtti_name(".?AVCWnd@@"), "CWnd")
        self.assertEqual(R.demangle_rtti_name(".?AUInner@Outer@ns@@"), "ns::Outer::Inner")
        self.assertEqual(R.demangle_rtti_name(".?AV?$CArray@VCPoint@@V1@@@"), "CArray<...>")
        self.assertEqual(R.demangle_rtti_name(".?AV?$vector@HV?$allocator@H@std@@@std@@"), "std::vector<...>")
        self.assertEqual(R.demangle_rtti_name("not_mangled"), "not_mangled")


class TestSyntheticDll(unittest.TestCase):
    def setUp(self):
        self.report = R.recover_classes(build_mfc_dll())

    def test_mfc_runtime_class(self):
        cls = self.report.mfc_by_name()["CFeature"]
        self.assertEqual(cls.address, BASE + 0x2010)
        self.assertEqual(cls.object_size, 0x40)
        self.assertEqual(cls.schema & 0xFFFF, 3)
        self.assertTrue(cls.versionable)
        self.assertTrue(cls.serializable)
        self.assertEqual(cls.create_object, BASE + 0x1030)

    def test_vtable_and_serialize_link(self):
        cls = self.report.mfc_by_name()["CFeature"]
        self.assertEqual(cls.vtable, BASE + 0x2100)
        self.assertEqual(cls.get_runtime_class, BASE + 0x1000)
        self.assertEqual(cls.serialize, BASE + 0x1020)

    def test_rtti(self):
        rtti = self.report.rtti_by_name()["CFeature"]
        self.assertEqual(rtti.mangled, ".?AVCFeature@@")
        self.assertEqual([v.address for v in rtti.vtables], [BASE + 0x2100])
        self.assertEqual(rtti.vtables[0].functions, [BASE + 0x1000, BASE + 0x1010, BASE + 0x1020])

    def test_report_serialises(self):
        d = self.report.to_dict()
        self.assertEqual(d["counts"]["mfc_serializable"], 1)
        self.assertEqual(d["mfc_classes"][0]["serialize"], hex(BASE + 0x1020))

    def test_rejects_non_pe(self):
        from test_binary_loader import build_elf
        with self.assertRaises(ValueError):
            R.recover_classes(build_elf(64, "little", 0x3E)[0])


MFC64 = r"C:\Windows\System32\mfc140u.dll"
MFC32 = r"C:\Windows\SysWOW64\mfc140u.dll"


class TestRealMfc(unittest.TestCase):
    def _check(self, path, ptr):
        rep = R.recover_classes(path)
        mfc = rep.mfc_by_name()
        self.assertEqual(mfc["CObject"].object_size, ptr)  # just the vptr
        self.assertEqual(mfc["CWnd"].base_name, "CCmdTarget")
        self.assertTrue(mfc["CObArray"].serializable)
        self.assertIsNotNone(mfc["CObArray"].serialize)
        self.assertGreater(len(rep.mfc_classes), 300)
        self.assertIn("CCmdTarget", rep.rtti_by_name()["CWnd"].bases)

    @unittest.skipUnless(os.path.exists(MFC64), "64-bit mfc140u.dll not present")
    def test_mfc140u_x64(self):
        self._check(MFC64, 8)

    @unittest.skipUnless(os.path.exists(MFC32), "32-bit mfc140u.dll not present")
    def test_mfc140u_x86(self):
        self._check(MFC32, 4)


if __name__ == "__main__":
    unittest.main()
