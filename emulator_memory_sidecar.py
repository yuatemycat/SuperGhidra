"""Root backward-compatibility shim for `emulator_memory_sidecar`.

Canonical package location: `superghidra.compat.emulator_memory_sidecar`.
"""
from __future__ import annotations

import os as _os
import sys as _sys

_src_dir = _os.path.join(_os.path.dirname(_os.path.abspath(__file__)), "src")
if _src_dir not in _sys.path:
    _sys.path.insert(0, _src_dir)

from superghidra.compat import emulator_memory_sidecar as _mod
from superghidra.compat.emulator_memory_sidecar import *  # noqa: F401,F403

if __name__ == "__main__":
    import runpy as _runpy
    _runpy.run_module("superghidra.compat.emulator_memory_sidecar", run_name="__main__", alter_sys=True)
else:
    _sys.modules[__name__] = _mod
