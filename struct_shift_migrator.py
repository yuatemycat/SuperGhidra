"""Root backward-compatibility shim for `struct_shift_migrator`.

Canonical package location: `superghidra.compat.struct_shift_migrator`.
"""
from __future__ import annotations

import os as _os
import sys as _sys

_src_dir = _os.path.join(_os.path.dirname(_os.path.abspath(__file__)), "src")
if _src_dir not in _sys.path:
    _sys.path.insert(0, _src_dir)

from superghidra.compat import struct_shift_migrator as _mod
from superghidra.compat.struct_shift_migrator import *  # noqa: F401,F403

if __name__ == "__main__":
    import runpy as _runpy
    _runpy.run_module("superghidra.compat.struct_shift_migrator", run_name="__main__", alter_sys=True)
else:
    _sys.modules[__name__] = _mod
