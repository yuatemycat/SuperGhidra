"""Backward-compatibility shim for `ghidra_gui_overlay_sync`.

Canonical location: `superghidra.integrations.ghidra_gui_overlay_sync`.
"""
from __future__ import annotations

import sys as _sys
from superghidra.integrations import ghidra_gui_overlay_sync as _mod
from superghidra.integrations.ghidra_gui_overlay_sync import *  # noqa: F401,F403

if __name__ == "__main__":
    import runpy as _runpy
    _runpy.run_module("superghidra.integrations.ghidra_gui_overlay_sync", run_name="__main__", alter_sys=True)
else:
    _sys.modules[__name__] = _mod
