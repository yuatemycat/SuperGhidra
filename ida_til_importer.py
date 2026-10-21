"""Backward-compatibility shim for `ida_til_importer`.

Canonical location: `superghidra.formats.ida_til_importer`.
"""
from __future__ import annotations

import sys as _sys
from superghidra.formats import ida_til_importer as _mod
from superghidra.formats.ida_til_importer import *  # noqa: F401,F403

if __name__ == "__main__":
    import runpy as _runpy
    _runpy.run_module("superghidra.formats.ida_til_importer", run_name="__main__", alter_sys=True)
else:
    _sys.modules[__name__] = _mod
