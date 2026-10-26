"""Root backward-compatibility shim for `binary_diff_engine`.

Canonical package location: `superghidra.compat.binary_diff_engine`.
"""
from __future__ import annotations

import os as _os
import sys as _sys

_src_dir = _os.path.join(_os.path.dirname(_os.path.abspath(__file__)), "src")
if _src_dir not in _sys.path:
    _sys.path.insert(0, _src_dir)

from superghidra.compat import binary_diff_engine as _mod
from superghidra.compat.binary_diff_engine import *  # noqa: F401,F403

if __name__ == "__main__":
    import runpy as _runpy
    _runpy.run_module("superghidra.compat.binary_diff_engine", run_name="__main__", alter_sys=True)
else:
    _sys.modules[__name__] = _mod
