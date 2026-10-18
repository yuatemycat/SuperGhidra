"""Backward-compatibility shim for `gpu_adrp_scanner`.

Canonical location: `superghidra.acceleration.gpu_adrp_scanner`.
"""
from __future__ import annotations

import sys as _sys
from superghidra.acceleration import gpu_adrp_scanner as _mod
from superghidra.acceleration.gpu_adrp_scanner import *  # noqa: F401,F403

if __name__ == "__main__":
    import runpy as _runpy
    _runpy.run_module("superghidra.acceleration.gpu_adrp_scanner", run_name="__main__", alter_sys=True)
else:
    _sys.modules[__name__] = _mod
