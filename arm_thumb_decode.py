"""Backward-compatibility shim for `arm_thumb_decode`.

Canonical location: `superghidra.lifters.arm_thumb_decode`.
"""
from __future__ import annotations

import sys as _sys
from superghidra.lifters import arm_thumb_decode as _mod
from superghidra.lifters.arm_thumb_decode import *  # noqa: F401,F403

if __name__ == "__main__":
    import runpy as _runpy
    _runpy.run_module("superghidra.lifters.arm_thumb_decode", run_name="__main__", alter_sys=True)
else:
    _sys.modules[__name__] = _mod
