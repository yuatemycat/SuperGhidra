"""
Tests for 64-bit Mach-O Objective-C runtime metadata recovery (Issue #28).
"""

import json
import unittest
from pathlib import Path

from superghidra.formats.macho_objc_recovery import (
    ObjCRecoveryReport,
    recover_objc_classes,
)

FIXTURES_DIR = Path(__file__).resolve().parent.parent / "fixtures" / "binaries"
OBJC_DYLIB = FIXTURES_DIR / "sample_objc_arm64.dylib"
PE_DLL = FIXTURES_DIR / "sample_x64.dll"


class TestMachOObjCRecovery(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not OBJC_DYLIB.exists():
            from tests.fixtures.generate_sample_binaries import generate_objc_arm64_dylib

            generate_objc_arm64_dylib(OBJC_DYLIB)

    def test_recover_classes_from_sample_dylib(self):
        report = recover_objc_classes(OBJC_DYLIB)
        self.assertIsInstance(report, ObjCRecoveryReport)
        self.assertEqual(report.counts["classes"], 2)
        self.assertEqual(report.counts["instance_methods"], 3)
        self.assertEqual(report.counts["class_methods"], 1)
        self.assertEqual(report.counts["ivars"], 1)

        names = [c.name for c in report.classes]
        self.assertEqual(names, ["MyBaseModel", "MyCustomController"])

        base_cls = next(c for c in report.classes if c.name == "MyBaseModel")
        self.assertIsNone(base_cls.superclass)
        self.assertEqual(base_cls.instance_size, 32)
        inst_meth_names = {m.name: m for m in base_cls.instance_methods}
        self.assertIn("init", inst_meth_names)
        self.assertIn("count", inst_meth_names)
        self.assertEqual(inst_meth_names["init"].types, "@16@0:8")
        self.assertEqual(inst_meth_names["count"].types, "Q16@0:8")
        self.assertEqual(len(base_cls.ivars), 1)
        ivar = base_cls.ivars[0]
        self.assertEqual(ivar.name, "_identifier")
        self.assertEqual(ivar.offset, 16)
        self.assertEqual(ivar.size, 8)

        ctrl_cls = next(c for c in report.classes if c.name == "MyCustomController")
        self.assertEqual(ctrl_cls.superclass, "MyBaseModel")
        self.assertEqual(ctrl_cls.instance_size, 48)
        self.assertEqual(len(ctrl_cls.instance_methods), 1)
        self.assertEqual(ctrl_cls.instance_methods[0].name, "viewDidLoad")
        self.assertEqual(ctrl_cls.instance_methods[0].types, "v16@0:8")
        self.assertEqual(len(ctrl_cls.class_methods), 1)
        self.assertEqual(ctrl_cls.class_methods[0].name, "sharedInstance")
        self.assertTrue(ctrl_cls.class_methods[0].is_class_method)

    def test_to_dict_serialization(self):
        report = recover_objc_classes(OBJC_DYLIB)
        data = report.to_dict()
        self.assertIn("counts", data)
        self.assertIn("classes", data)
        self.assertEqual(len(data["classes"]), 2)
        self.assertEqual(data["classes"][0]["name"], "MyBaseModel")
        self.assertEqual(data["classes"][1]["superclass"], "MyBaseModel")

    def test_non_macho_raises_value_error(self):
        with self.assertRaises(ValueError):
            recover_objc_classes(PE_DLL)

    def test_cli_objc_recover_output(self):
        import subprocess
        import sys
        import tempfile

        with tempfile.TemporaryDirectory() as tmpdir:
            out_json = Path(tmpdir) / "objc.json"
            cmd = [
                sys.executable,
                "-m",
                "superghidra",
                "objc-recover",
                str(OBJC_DYLIB),
                "-o",
                str(out_json),
            ]
            res = subprocess.run(cmd, capture_output=True, text=True, check=False)
            self.assertEqual(res.returncode, 0)
            self.assertIn("Recovered 2 Objective-C classes", res.stdout)
            self.assertTrue(out_json.exists())
            loaded = json.loads(out_json.read_text(encoding="utf-8"))
            self.assertEqual(loaded["counts"]["classes"], 2)


if __name__ == "__main__":
    unittest.main()
