"""Backward-compatibility shim for `storage_compression_prototype`.

Canonical location: `superghidra.storage.storage_compression_prototype`.
"""
from __future__ import annotations

import sys as _sys
from superghidra.storage import storage_compression_prototype as _mod
from superghidra.storage.storage_compression_prototype import *  # noqa: F401,F403

if __name__ == "__main__":
    import runpy as _runpy
    _runpy.run_module("superghidra.storage.storage_compression_prototype", run_name="__main__", alter_sys=True)
else:
    _sys.modules[__name__] = _mod
