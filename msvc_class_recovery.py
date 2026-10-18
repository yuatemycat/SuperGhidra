"""Backward-compatibility shim for `msvc_class_recovery`.

Canonical location: `superghidra.formats.msvc_class_recovery`.
"""
from __future__ import annotations

import sys as _sys
from superghidra.formats import msvc_class_recovery as _mod
from superghidra.formats.msvc_class_recovery import *  # noqa: F401,F403

if __name__ == "__main__":
    import runpy as _runpy
    _runpy.run_module("superghidra.formats.msvc_class_recovery", run_name="__main__", alter_sys=True)
else:
    _sys.modules[__name__] = _mod
