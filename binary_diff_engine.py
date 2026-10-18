"""Backward-compatibility shim for `binary_diff_engine`.

Canonical location: `superghidra.diff.binary_diff_engine`.
"""
from __future__ import annotations

import sys as _sys
from superghidra.diff import binary_diff_engine as _mod
from superghidra.diff.binary_diff_engine import *  # noqa: F401,F403

if __name__ == "__main__":
    import runpy as _runpy
    _runpy.run_module("superghidra.diff.binary_diff_engine", run_name="__main__", alter_sys=True)
else:
    _sys.modules[__name__] = _mod
