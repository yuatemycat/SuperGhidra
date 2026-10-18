"""Backward-compatibility shim for `ghidra_oracle`.

Canonical location: `superghidra.core.ghidra_oracle`.
"""
from __future__ import annotations

import sys as _sys
from superghidra.core import ghidra_oracle as _mod
from superghidra.core.ghidra_oracle import *  # noqa: F401,F403

if __name__ == "__main__":
    import runpy as _runpy
    _runpy.run_module("superghidra.core.ghidra_oracle", run_name="__main__", alter_sys=True)
else:
    _sys.modules[__name__] = _mod
