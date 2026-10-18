"""Backward-compatibility shim for `neural_decompiler_pipeline`.

Canonical location: `superghidra.integrations.neural_decompiler_pipeline`.
"""
from __future__ import annotations

import sys as _sys
from superghidra.integrations import neural_decompiler_pipeline as _mod
from superghidra.integrations.neural_decompiler_pipeline import *  # noqa: F401,F403

if __name__ == "__main__":
    import runpy as _runpy
    _runpy.run_module("superghidra.integrations.neural_decompiler_pipeline", run_name="__main__", alter_sys=True)
else:
    _sys.modules[__name__] = _mod
