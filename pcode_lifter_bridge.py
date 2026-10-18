"""Backward-compatibility shim for `pcode_lifter_bridge`.

Canonical location: `superghidra.lifters.pcode_lifter_bridge`.
"""
from __future__ import annotations

import sys as _sys
from superghidra.lifters import pcode_lifter_bridge as _mod
from superghidra.lifters.pcode_lifter_bridge import *  # noqa: F401,F403

if __name__ == "__main__":
    import runpy as _runpy
    _runpy.run_module("superghidra.lifters.pcode_lifter_bridge", run_name="__main__", alter_sys=True)
else:
    _sys.modules[__name__] = _mod
