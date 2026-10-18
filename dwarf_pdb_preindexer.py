"""Backward-compatibility shim for `dwarf_pdb_preindexer`.

Canonical location: `superghidra.formats.dwarf_pdb_preindexer`.
"""
from __future__ import annotations

import sys as _sys
from superghidra.formats import dwarf_pdb_preindexer as _mod
from superghidra.formats.dwarf_pdb_preindexer import *  # noqa: F401,F403

if __name__ == "__main__":
    import runpy as _runpy
    _runpy.run_module("superghidra.formats.dwarf_pdb_preindexer", run_name="__main__", alter_sys=True)
else:
    _sys.modules[__name__] = _mod
