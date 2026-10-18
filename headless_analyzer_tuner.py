"""Backward-compatibility shim for `headless_analyzer_tuner`.

Canonical location: `superghidra.core.headless_analyzer_tuner`.
"""
from __future__ import annotations

import sys as _sys
from superghidra.core import headless_analyzer_tuner as _mod
from superghidra.core.headless_analyzer_tuner import *  # noqa: F401,F403

if __name__ == "__main__":
    import runpy as _runpy
    _runpy.run_module("superghidra.core.headless_analyzer_tuner", run_name="__main__", alter_sys=True)
else:
    _sys.modules[__name__] = _mod
