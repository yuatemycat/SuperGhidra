"""Backward-compatibility shim for `test_serialize_trace`.

Canonical location: `tests.formats.test_serialize_trace`.
"""
import importlib.util
from pathlib import Path
import sys

_target = Path(__file__).parent / "tests" / "formats" / "test_serialize_trace.py"
_spec = importlib.util.spec_from_file_location("test_serialize_trace", _target)
_mod = importlib.util.module_from_spec(_spec)
sys.modules["test_serialize_trace"] = _mod
_spec.loader.exec_module(_mod)

globals().update({k: getattr(_mod, k) for k in dir(_mod) if not k.startswith("__")})
