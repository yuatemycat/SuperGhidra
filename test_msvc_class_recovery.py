"""Backward-compatibility shim for `test_msvc_class_recovery`.

Canonical location: `tests.formats.test_msvc_class_recovery`.
"""
import importlib.util
from pathlib import Path
import sys

_target = Path(__file__).parent / "tests" / "formats" / "test_msvc_class_recovery.py"
_spec = importlib.util.spec_from_file_location("test_msvc_class_recovery", _target)
_mod = importlib.util.module_from_spec(_spec)
sys.modules["test_msvc_class_recovery"] = _mod
_spec.loader.exec_module(_mod)

globals().update({k: getattr(_mod, k) for k in dir(_mod) if not k.startswith("__")})
