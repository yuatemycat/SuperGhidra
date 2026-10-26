"""Tests for msvc_class_recovery (RTTI + MFC CRuntimeClass), synthetic and real DLLs."""

import os
import struct
import unittest

from superghidra.formats import msvc_class_recovery as R

BASE = 0x180000000


def build_pe_sections(sections, bits=64, image_base=BASE, machine=0x8664, dirs=None):
    """PE image from [(name, rva, bytes, characteristics)]; `dirs` = {index: (rva, size)}."""
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
    dirs_off = opt + (112 if bits == 64 else 96)
    for idx, (rva, size) in (dirs or {}).items():
        struct.pack_into("<II", hdr, dirs_off + 8 * idx, rva, size)
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
    # Static-MFC style: m_pBaseClass points straight at CObject's CRuntimeClass.
    struct.pack_into("<QiIQQQQ", rdata, 0x10, va(0x2000), 0x40, 0x80000003, va(0x1030), va(0x2150), 0, 0)
    rdata[0x140:0x148] = b"CObject\x00"
    struct.pack_into("<QiIQQQQ", rdata, 0x150, va(0x2140), 8, 0xFFFF, 0, 0, 0, 0)
    struct.pack_into("<QQ", rdata, 0x40, 0, 0)
    rdata[0x50:0x50 + 15] = b".?AVCFeature@@\x00"
    struct.pack_into("<IIIiii", rdata, 0x70, 1, 0, 0, 0x2040, 0x20A0, 0x2070)  # COL
    struct.pack_into("<IIIi", rdata, 0xA0, 0, 0, 1, 0x20C0)  # CHD
    struct.pack_into("<i", rdata, 0xC0, 0x20D0)  # base class array
    struct.pack_into("<iIiiiIi", rdata, 0xD0, 0x2040, 0, 0, -1, 0, 0, 0x20A0)  # BCD
    struct.pack_into("<QQQQQ", rdata, 0xF8, va(0x2070), va(0x1000), va(0x1010), va(0x1020), 0)
    return build_pe_sections([(b".text", 0x1000, bytes(text), 0x60000020),
                              (b".rdata", 0x2000, bytes(rdata), 0x40000040)])


MFC_GETTHISCLASS_ORDINAL = 7068  # ?GetThisClass@CObject@@SAPEAUCRuntimeClass@@XZ in mfc140u


def build_forwarding_dll():
    """SolidWorks-style class: no RTTI, incremental-link thunks, Serialize forwarded to slot 4,
    base class imported from mfc140u.dll by ordinal (`jmp [__imp_CObject::GetThisClass]`)."""
    va = lambda rva: BASE + rva  # noqa: E731
    t = va(0x1000)
    text = bytearray(b"\xCC" * 0x80)

    def jmp(at, to):
        text[at:at + 5] = b"\xE9" + struct.pack("<i", to - (at + 5))

    jmp(0x00, 0x40)  # GetRuntimeClass thunk
    jmp(0x08, 0x50)  # Serialize thunk -> forwarder
    jmp(0x10, 0x60)  # GetBaseClass thunk -> imported
    text[0x18] = text[0x20] = text[0x28] = 0xC3  # dtor, CreateObject, slot 3
    jmp(0x30, 0x70)  # slot 4 thunk -> real Serialize body
    text[0x40:0x48] = b"\x48\x8D\x05" + struct.pack("<i", va(0x2010) - (t + 0x47)) + b"\xC3"
    text[0x50:0x56] = b"\x48\x8B\x01\xFF\x60\x20"  # mov rax,[rcx] ; jmp [rax+0x20]
    text[0x60:0x66] = b"\xFF\x25" + struct.pack("<i", va(0x21C0) - (t + 0x66))  # jmp [IAT]
    text[0x70] = 0xC3

    rdata = bytearray(0x200)
    rdata[0x00:0x0C] = b"moFeature_c\x00"
    struct.pack_into("<QiIQQQQ", rdata, 0x10, va(0x2000), 0x58, 0x80000001, t + 0x20, t + 0x10, 0, 0)
    struct.pack_into("<5Q", rdata, 0x100, t + 0x00, t + 0x18, t + 0x08, t + 0x28, t + 0x30)
    struct.pack_into("<IIIII", rdata, 0x180, 0x21B0, 0, 0, 0x21D0, 0x21C0)  # import descriptor
    struct.pack_into("<Q", rdata, 0x1B0, (1 << 63) | MFC_GETTHISCLASS_ORDINAL)  # ILT
    struct.pack_into("<Q", rdata, 0x1C0, (1 << 63) | MFC_GETTHISCLASS_ORDINAL)  # IAT
    rdata[0x1D0:0x1DC] = b"mfc140u.dll\x00"
    return build_pe_sections([(b".text", 0x1000, bytes(text), 0x60000020),
                              (b".rdata", 0x2000, bytes(rdata), 0x40000040)],
                             dirs={1: (0x2180, 40)})


class TestForwardingDll(unittest.TestCase):
    def test_thunks_and_forwarder(self):
        cls = R.recover_classes(build_forwarding_dll(), symbol_dirs=[]).mfc_by_name()["moFeature_c"]
        self.assertEqual(cls.vtable, BASE + 0x2100)
        self.assertEqual(cls.get_runtime_class, BASE + 0x1040)  # thunk followed
        self.assertEqual(cls.serialize, BASE + 0x1070)  # forwarder -> slot 4 -> thunk -> body
        self.assertEqual(cls.serialize_slot, 4)
        self.assertIsNone(cls.base_name)  # ordinal import, no name table

    def test_ordinal_base_named_from_exports_table(self):
        import tempfile

        with tempfile.TemporaryDirectory() as d:
            with open(os.path.join(d, "mfc140u.exports"), "w", encoding="utf-8") as f:
                f.write('<LIBRARY NAME="mfc140u.dll">\n<EXPORT ORDINAL="%d" '
                        'NAME="?GetThisClass@CObject@@SAPEAUCRuntimeClass@@XZ" />\n</LIBRARY>\n'
                        % MFC_GETTHISCLASS_ORDINAL)
            rep = R.recover_classes(build_forwarding_dll(), symbol_dirs=[d])
        self.assertEqual(rep.mfc_by_name()["moFeature_c"].base_name, "CObject")

    def test_imported_serialize_reported_as_external(self):
        raw = bytearray(build_forwarding_dll())
        # Point vtable slot 4 at the `jmp [IAT]` stub: the class inherits an imported Serialize.
        off = raw.find(struct.pack("<Q", BASE + 0x1030), 0x400)
        struct.pack_into("<Q", raw, off, BASE + 0x1060)
        cls = R.recover_classes(bytes(raw), symbol_dirs=[]).mfc_by_name()["moFeature_c"]
        self.assertIsNone(cls.serialize)
        self.assertEqual(cls.serialize_slot, 4)
        self.assertEqual(cls.serialize_external, f"mfc140u.dll#{MFC_GETTHISCLASS_ORDINAL}")

    def test_root_class_filter(self):
        names = {c.name for c in R.recover_classes(build_mfc_dll()).mfc_classes}
        self.assertEqual(names, {"CFeature", "CObject"})


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
        self.assertEqual(cls.base_name, "CObject")

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
        from tests.formats.test_binary_loader import build_elf
        with self.assertRaises(ValueError):
            R.recover_classes(build_elf(64, "little", 0x3E)[0])


class TestRttiRecoverCli(unittest.TestCase):
    """`superghidra rtti-recover` must stay in step with recover_classes()."""

    def _run(self, *args):
        import subprocess
        import sys
        from pathlib import Path
        return subprocess.run([sys.executable, "-m", "superghidra", "rtti-recover", *args],
                              capture_output=True, text=True, cwd=str(Path(__file__).parents[2]))

    def test_writes_report_json(self):
        import json
        import tempfile
        from pathlib import Path
        with tempfile.TemporaryDirectory() as tmp:
            dll, out = Path(tmp) / "t.dll", Path(tmp) / "classes.json"
            dll.write_bytes(build_mfc_dll())
            proc = self._run(str(dll), "-o", str(out))
            self.assertEqual(proc.returncode, 0, proc.stderr)
            self.assertIn("2 MFC runtime classes (1 serializable)", proc.stdout)
            report = json.loads(out.read_text(encoding="utf-8"))
            self.assertEqual(report["counts"]["mfc_serializable"], 1)
            self.assertIn("CFeature", [c["name"] for c in report["mfc_classes"]])

    def test_non_pe_exits_nonzero(self):
        import tempfile
        from pathlib import Path
        with tempfile.TemporaryDirectory() as tmp:
            junk = Path(tmp) / "junk.bin"
            junk.write_bytes(b"\x7fELF" + b"\x00" * 64)
            proc = self._run(str(junk))
            self.assertEqual(proc.returncode, 1)
            self.assertIn("Error:", proc.stderr)


MFC64 =r"C:\Windows\System32\mfc140u.dll"
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
        serializable = [c for c in rep.mfc_classes if c.serializable]
        self.assertEqual([c.name for c in serializable if not c.serialize], [])

    @unittest.skipUnless(os.path.exists(MFC64), "64-bit mfc140u.dll not present")
    def test_mfc140u_x64(self):
        self._check(MFC64, 8)

    @unittest.skipUnless(os.path.exists(MFC32), "32-bit mfc140u.dll not present")
    def test_mfc140u_x86(self):
        self._check(MFC32, 4)


SWDM = r"C:\Program Files\SOLIDWORKS Corp\SOLIDWORKS PCB Viewer\System\Model3DWrapper\SWAPI64\swdocumentmgr.dll"


class TestRealSolidWorks(unittest.TestCase):
    @unittest.skipUnless(os.path.exists(SWDM), "SOLIDWORKS Document Manager DLL not present")
    def test_swdocumentmgr(self):
        rep = R.recover_classes(SWDM)
        ser = [c for c in rep.mfc_classes if c.serializable]
        self.assertGreater(len(ser), 100)
        unresolved = [c.name for c in ser if not c.serialize and not c.serialize_external]
        self.assertEqual(unresolved, [])
        hdr = rep.mfc_by_name()["moHeader_c"]
        self.assertEqual(hdr.base_name, "su_CObject")
        self.assertEqual(hdr.serialize_slot, 5)  # su_CObject::Serialize forwards to slot 5


# Full SOLIDWORKS install folder (the one holding SLDWORKS.exe and swccu.dll).
SW_ROOT = os.environ.get("SUPERGHIDRA_TEST_SW_ROOT", "")


class TestRealSolidWorksApp(unittest.TestCase):
    @unittest.skipUnless(SW_ROOT and os.path.exists(os.path.join(SW_ROOT, "sldarchiveu.dll")),
                         "set SUPERGHIDRA_TEST_SW_ROOT to a full SOLIDWORKS install")
    def test_imported_serialize_forwarder(self):
        # App modules import su_CObject::Serialize from swccu.dll; it forwards to slot 5.
        rep = R.recover_classes(os.path.join(SW_ROOT, "sldarchiveu.dll"))
        ser = [c for c in rep.mfc_classes if c.serializable]
        self.assertTrue(ser)
        self.assertEqual([c.name for c in ser if not c.serialize and not c.serialize_external], [])
        self.assertEqual({c.serialize_slot for c in ser}, {5})
        # Own bodies, except list classes that inherit suObList::Serialize from sldmfcu.dll.
        by_name = rep.mfc_by_name()
        self.assertIsNotNone(by_name["moHeader_c"].serialize)
        self.assertIn("suObList", by_name["moExtObjectList_c"].serialize_external)


if __name__ == "__main__":
    unittest.main()
