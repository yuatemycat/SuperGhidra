"""Backward-compatibility shim for `serialize_trace`.

Canonical location: `superghidra.formats.serialize_trace`.
"""
from __future__ import annotations

import sys as _sys
from superghidra.formats import serialize_trace as _mod
from superghidra.formats.serialize_trace import *  # noqa: F401,F403

if __name__ == "__main__":
    import runpy as _runpy
    _runpy.run_module("superghidra.formats.serialize_trace", run_name="__main__", alter_sys=True)
else:
    _sys.modules[__name__] = _mod
