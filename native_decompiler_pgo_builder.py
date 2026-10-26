"""Root backward-compatibility shim for `native_decompiler_pgo_builder`.

Canonical package location: `superghidra.compat.native_decompiler_pgo_builder`.
"""
from __future__ import annotations

import os as _os
import sys as _sys

_src_dir = _os.path.join(_os.path.dirname(_os.path.abspath(__file__)), "src")
if _src_dir not in _sys.path:
    _sys.path.insert(0, _src_dir)

from superghidra.compat import native_decompiler_pgo_builder as _mod
from superghidra.compat.native_decompiler_pgo_builder import *  # noqa: F401,F403

if __name__ == "__main__":
    import runpy as _runpy
    _runpy.run_module("superghidra.compat.native_decompiler_pgo_builder", run_name="__main__", alter_sys=True)
else:
    _sys.modules[__name__] = _mod
