"""Backward-compatibility shim for `shm_decompiler_bridge`.

Canonical location: `superghidra.core.shm_decompiler_bridge`.
"""
from __future__ import annotations

import sys as _sys
from superghidra.core import shm_decompiler_bridge as _mod
from superghidra.core.shm_decompiler_bridge import *  # noqa: F401,F403

if __name__ == "__main__":
    import runpy as _runpy
    _runpy.run_module("superghidra.core.shm_decompiler_bridge", run_name="__main__", alter_sys=True)
else:
    _sys.modules[__name__] = _mod
