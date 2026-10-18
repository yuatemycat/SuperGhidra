"""Backward-compatibility shim for `emulator_memory_sidecar`.

Canonical location: `superghidra.integrations.emulator_memory_sidecar`.
"""
from __future__ import annotations

import sys as _sys
from superghidra.integrations import emulator_memory_sidecar as _mod
from superghidra.integrations.emulator_memory_sidecar import *  # noqa: F401,F403

if __name__ == "__main__":
    import runpy as _runpy
    _runpy.run_module("superghidra.integrations.emulator_memory_sidecar", run_name="__main__", alter_sys=True)
else:
    _sys.modules[__name__] = _mod
