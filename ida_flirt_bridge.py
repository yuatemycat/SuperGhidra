"""Backward-compatibility shim for `ida_flirt_bridge`.

Canonical location: `superghidra.formats.ida_flirt_bridge`.
"""
from __future__ import annotations

import sys as _sys
from superghidra.formats import ida_flirt_bridge as _mod
from superghidra.formats.ida_flirt_bridge import *  # noqa: F401,F403

if __name__ == "__main__":
    import runpy as _runpy
    _runpy.run_module("superghidra.formats.ida_flirt_bridge", run_name="__main__", alter_sys=True)
else:
    _sys.modules[__name__] = _mod
