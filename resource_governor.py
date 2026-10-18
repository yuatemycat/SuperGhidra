"""Backward-compatibility shim for `resource_governor`.

Canonical location: `superghidra.core.resource_governor`.
"""
from __future__ import annotations

import sys as _sys
from superghidra.core import resource_governor as _mod
from superghidra.core.resource_governor import *  # noqa: F401,F403

if __name__ == "__main__":
    import runpy as _runpy
    _runpy.run_module("superghidra.core.resource_governor", run_name="__main__", alter_sys=True)
else:
    _sys.modules[__name__] = _mod
