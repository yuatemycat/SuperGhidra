"""Backward-compatibility shim for `egraph_mlir_pipeline`.

Canonical location: `superghidra.lifters.egraph_mlir_pipeline`.
"""
from __future__ import annotations

import sys as _sys
from superghidra.lifters import egraph_mlir_pipeline as _mod
from superghidra.lifters.egraph_mlir_pipeline import *  # noqa: F401,F403

if __name__ == "__main__":
    import runpy as _runpy
    _runpy.run_module("superghidra.lifters.egraph_mlir_pipeline", run_name="__main__", alter_sys=True)
else:
    _sys.modules[__name__] = _mod
