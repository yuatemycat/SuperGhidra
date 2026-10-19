"""Backward-compatibility shim for `superghidra_section5_mitigation_roadmap_engine`.

Canonical location: `superghidra.core.mitigation_roadmap_engine`.
"""
from __future__ import annotations

import sys as _sys
from superghidra.core import mitigation_roadmap_engine as _mod
from superghidra.core.mitigation_roadmap_engine import *  # noqa: F401,F403

if __name__ == "__main__":
    import runpy as _runpy
    _runpy.run_module("superghidra.core.mitigation_roadmap_engine", run_name="__main__", alter_sys=True)
else:
    _sys.modules[__name__] = _mod
