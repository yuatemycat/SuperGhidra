"""Backward-compatibility shim for `gpu_function_seeder`.

Canonical location: `superghidra.acceleration.gpu_function_seeder`.
"""
from __future__ import annotations

import sys as _sys
from superghidra.acceleration import gpu_function_seeder as _mod
from superghidra.acceleration.gpu_function_seeder import *  # noqa: F401,F403

if __name__ == "__main__":
    import runpy as _runpy
    _runpy.run_module("superghidra.acceleration.gpu_function_seeder", run_name="__main__", alter_sys=True)
else:
    _sys.modules[__name__] = _mod
