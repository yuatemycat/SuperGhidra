"""Backward-compatibility shim for `synthetic_symbol_exporter`.

Canonical location: `superghidra.formats.synthetic_symbol_exporter`.
"""
from __future__ import annotations

import sys as _sys
from superghidra.formats import synthetic_symbol_exporter as _mod
from superghidra.formats.synthetic_symbol_exporter import *  # noqa: F401,F403

if __name__ == "__main__":
    import runpy as _runpy
    _runpy.run_module("superghidra.formats.synthetic_symbol_exporter", run_name="__main__", alter_sys=True)
else:
    _sys.modules[__name__] = _mod
