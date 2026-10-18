"""Backward-compatibility shim for `colab_cloud_orchestrator`.

Canonical location: `superghidra.integrations.colab_cloud_orchestrator`.
"""
from __future__ import annotations

import sys as _sys
from superghidra.integrations import colab_cloud_orchestrator as _mod
from superghidra.integrations.colab_cloud_orchestrator import *  # noqa: F401,F403

if __name__ == "__main__":
    import runpy as _runpy
    _runpy.run_module("superghidra.integrations.colab_cloud_orchestrator", run_name="__main__", alter_sys=True)
else:
    _sys.modules[__name__] = _mod
