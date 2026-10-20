"""Backward-compatibility shim for `native_compiler`.

Canonical location: `superghidra.core.native_compiler`.
"""
from __future__ import annotations

import sys as _sys
from superghidra.core import native_compiler as _mod
from superghidra.core.native_compiler import *  # noqa: F401,F403

if __name__ == "__main__":
    import runpy as _runpy
    _runpy.run_module("superghidra.core.native_compiler", run_name="__main__", alter_sys=True)
else:
    _sys.modules[__name__] = _mod
