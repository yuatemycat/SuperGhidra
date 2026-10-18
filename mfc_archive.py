"""Backward-compatibility shim for `mfc_archive`.

Canonical location: `superghidra.formats.mfc_archive`.
"""
from __future__ import annotations

import sys as _sys
from superghidra.formats import mfc_archive as _mod
from superghidra.formats.mfc_archive import *  # noqa: F401,F403

if __name__ == "__main__":
    import runpy as _runpy
    _runpy.run_module("superghidra.formats.mfc_archive", run_name="__main__", alter_sys=True)
else:
    _sys.modules[__name__] = _mod
