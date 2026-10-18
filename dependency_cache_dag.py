"""Backward-compatibility shim for `dependency_cache_dag`.

Canonical location: `superghidra.core.dependency_cache_dag`.
"""
from __future__ import annotations

import sys as _sys
from superghidra.core import dependency_cache_dag as _mod
from superghidra.core.dependency_cache_dag import *  # noqa: F401,F403

if __name__ == "__main__":
    import runpy as _runpy
    _runpy.run_module("superghidra.core.dependency_cache_dag", run_name="__main__", alter_sys=True)
else:
    _sys.modules[__name__] = _mod
