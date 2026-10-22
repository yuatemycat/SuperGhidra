"""Backward-compatibility shim for `database_migrator`.

Canonical location: `superghidra.formats.database_migrator`.
"""
from __future__ import annotations

import sys as _sys
from superghidra.formats import database_migrator as _mod
from superghidra.formats.database_migrator import *  # noqa: F401,F403

if __name__ == "__main__":
    import runpy as _runpy
    _runpy.run_module("superghidra.formats.database_migrator", run_name="__main__", alter_sys=True)
else:
    _sys.modules[__name__] = _mod
