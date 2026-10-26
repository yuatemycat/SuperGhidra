"""Root backward-compatibility shim for `gpu_adrp_scanner`.

Canonical package location: `superghidra.compat.gpu_adrp_scanner`.
"""
from __future__ import annotations

import os as _os
import sys as _sys

_src_dir = _os.path.join(_os.path.dirname(_os.path.abspath(__file__)), "src")
if _src_dir not in _sys.path:
    _sys.path.insert(0, _src_dir)

from superghidra.compat import gpu_adrp_scanner as _mod
from superghidra.compat.gpu_adrp_scanner import *  # noqa: F401,F403

if __name__ == "__main__":
    import runpy as _runpy
    _runpy.run_module("superghidra.compat.gpu_adrp_scanner", run_name="__main__", alter_sys=True)
else:
    _sys.modules[__name__] = _mod
