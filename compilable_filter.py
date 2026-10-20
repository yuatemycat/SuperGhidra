"""Backward-compatibility shim for `compilable_filter`.

Canonical location: `superghidra.core.compilable_filter`.
"""
from __future__ import annotations

import sys as _sys
from superghidra.core import compilable_filter as _mod
from superghidra.core.compilable_filter import *  # noqa: F401,F403

if __name__ == "__main__":
    import runpy as _runpy
    _runpy.run_module("superghidra.core.compilable_filter", run_name="__main__", alter_sys=True)
else:
    _sys.modules[__name__] = _mod
