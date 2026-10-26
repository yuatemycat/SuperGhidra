"""Root test helper shim for `test_serialize_trace` (imported by sibling SuperghidraMCP)."""
from __future__ import annotations
import os as _os
import sys as _sys
import importlib.util as _util

_root = _os.path.dirname(_os.path.abspath(__file__))
_src = _os.path.join(_root, "src")
_tests_formats = _os.path.join(_root, "tests", "formats")
for _p in (_src, _root, _tests_formats):
    if _p not in _sys.path:
        _sys.path.insert(0, _p)

_target_file = _os.path.join(_tests_formats, "test_serialize_trace.py")
_spec = _util.spec_from_file_location("test_serialize_trace", _target_file)
_mod = _util.module_from_spec(_spec)
_sys.modules[__name__] = _mod
_sys.modules["test_serialize_trace"] = _mod
_spec.loader.exec_module(_mod)
globals().update({k: getattr(_mod, k) for k in dir(_mod) if not k.startswith("__")})
