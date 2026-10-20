"""Backward-compatibility shim for `live_binary_tools`.

Canonical location: `superghidra.core.live_binary_tools`.
"""
from __future__ import annotations

import sys as _sys
from superghidra.core import live_binary_tools as _mod
from superghidra.core.live_binary_tools import *  # noqa: F401,F403

if __name__ == "__main__":
    import runpy as _runpy
    _runpy.run_module("superghidra.core.live_binary_tools", run_name="__main__", alter_sys=True)
else:
    _sys.modules[__name__] = _mod
