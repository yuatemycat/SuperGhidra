"""Backward-compatibility shim for `binary_loader`.

Canonical location: `superghidra.formats.binary_loader`.
"""
from __future__ import annotations

import sys as _sys
from superghidra.formats import binary_loader as _mod
from superghidra.formats.binary_loader import *  # noqa: F401,F403

if __name__ == "__main__":
    import runpy as _runpy
    _runpy.run_module("superghidra.formats.binary_loader", run_name="__main__", alter_sys=True)
else:
    _sys.modules[__name__] = _mod
