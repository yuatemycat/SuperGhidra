"""Root backward-compatibility shim for `ida_til_importer`.

Canonical package location: `superghidra.compat.ida_til_importer`.
"""
from __future__ import annotations

import os as _os
import sys as _sys

_src_dir = _os.path.join(_os.path.dirname(_os.path.abspath(__file__)), "src")
if _src_dir not in _sys.path:
    _sys.path.insert(0, _src_dir)

from superghidra.compat import ida_til_importer as _mod
from superghidra.compat.ida_til_importer import *  # noqa: F401,F403

if __name__ == "__main__":
    import runpy as _runpy
    _runpy.run_module("superghidra.compat.ida_til_importer", run_name="__main__", alter_sys=True)
else:
    _sys.modules[__name__] = _mod
