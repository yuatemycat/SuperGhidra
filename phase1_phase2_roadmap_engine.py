"""Root backward-compatibility shim for `phase1_phase2_roadmap_engine`.

Canonical package location: `superghidra.compat.phase1_phase2_roadmap_engine`.
"""
from __future__ import annotations

import os as _os
import sys as _sys

_src_dir = _os.path.join(_os.path.dirname(_os.path.abspath(__file__)), "src")
if _src_dir not in _sys.path:
    _sys.path.insert(0, _src_dir)

from superghidra.compat import phase1_phase2_roadmap_engine as _mod
from superghidra.compat.phase1_phase2_roadmap_engine import *  # noqa: F401,F403

if __name__ == "__main__":
    import runpy as _runpy
    _runpy.run_module("superghidra.compat.phase1_phase2_roadmap_engine", run_name="__main__", alter_sys=True)
else:
    _sys.modules[__name__] = _mod
