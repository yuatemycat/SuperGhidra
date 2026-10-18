"""Backward-compatibility shim for `struct_shift_migrator`.

Canonical location: `superghidra.diff.struct_shift_migrator`.
"""
from __future__ import annotations

import sys as _sys
from superghidra.diff import struct_shift_migrator as _mod
from superghidra.diff.struct_shift_migrator import *  # noqa: F401,F403

if __name__ == "__main__":
    import runpy as _runpy
    _runpy.run_module("superghidra.diff.struct_shift_migrator", run_name="__main__", alter_sys=True)
else:
    _sys.modules[__name__] = _mod
