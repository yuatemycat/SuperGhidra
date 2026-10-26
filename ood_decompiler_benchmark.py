"""Root backward-compatibility shim for `ood_decompiler_benchmark`.

Canonical package location: `superghidra.compat.ood_decompiler_benchmark`.
"""
from __future__ import annotations

import os as _os
import sys as _sys

_src_dir = _os.path.join(_os.path.dirname(_os.path.abspath(__file__)), "src")
if _src_dir not in _sys.path:
    _sys.path.insert(0, _src_dir)

from superghidra.compat import ood_decompiler_benchmark as _mod
from superghidra.compat.ood_decompiler_benchmark import *  # noqa: F401,F403

if __name__ == "__main__":
    import runpy as _runpy
    _runpy.run_module("superghidra.compat.ood_decompiler_benchmark", run_name="__main__", alter_sys=True)
else:
    _sys.modules[__name__] = _mod
