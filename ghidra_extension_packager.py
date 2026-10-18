"""Backward-compatibility shim for `ghidra_extension_packager`.

Canonical location: `superghidra.storage.ghidra_extension_packager`.
"""
from __future__ import annotations

import sys as _sys
from superghidra.storage import ghidra_extension_packager as _mod
from superghidra.storage.ghidra_extension_packager import *  # noqa: F401,F403

if __name__ == "__main__":
    import runpy as _runpy
    _runpy.run_module("superghidra.storage.ghidra_extension_packager", run_name="__main__", alter_sys=True)
else:
    _sys.modules[__name__] = _mod
