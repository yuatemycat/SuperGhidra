"""Backward-compatibility shim for `native_decompiler_pgo_builder`.

Canonical location: `superghidra.core.native_decompiler_pgo_builder`.
"""
from __future__ import annotations

import sys as _sys
from superghidra.core import native_decompiler_pgo_builder as _mod
from superghidra.core.native_decompiler_pgo_builder import *  # noqa: F401,F403

if __name__ == "__main__":
    import runpy as _runpy
    _runpy.run_module("superghidra.core.native_decompiler_pgo_builder", run_name="__main__", alter_sys=True)
else:
    _sys.modules[__name__] = _mod
