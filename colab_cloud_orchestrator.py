"""Root backward-compatibility shim for `colab_cloud_orchestrator`.

Canonical package location: `superghidra.compat.colab_cloud_orchestrator`.
"""
from __future__ import annotations

import os as _os
import sys as _sys

_src_dir = _os.path.join(_os.path.dirname(_os.path.abspath(__file__)), "src")
if _src_dir not in _sys.path:
    _sys.path.insert(0, _src_dir)

from superghidra.compat import colab_cloud_orchestrator as _mod
from superghidra.compat.colab_cloud_orchestrator import *  # noqa: F401,F403

if __name__ == "__main__":
    import runpy as _runpy
    _runpy.run_module("superghidra.compat.colab_cloud_orchestrator", run_name="__main__", alter_sys=True)
else:
    _sys.modules[__name__] = _mod
