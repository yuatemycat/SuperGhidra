"""Backward-compatibility shim for `ood_decompiler_benchmark`.

Canonical location: `superghidra.diff.ood_decompiler_benchmark`.
"""
from __future__ import annotations

import sys as _sys
from superghidra.diff import ood_decompiler_benchmark as _mod
from superghidra.diff.ood_decompiler_benchmark import *  # noqa: F401,F403

if __name__ == "__main__":
    import runpy as _runpy
    _runpy.run_module("superghidra.diff.ood_decompiler_benchmark", run_name="__main__", alter_sys=True)
else:
    _sys.modules[__name__] = _mod
