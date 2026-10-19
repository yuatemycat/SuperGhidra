"""Backward-compatibility shim for `d_lift_verifier`.

Canonical location: `superghidra.integrations.d_lift_verifier`.
"""
from __future__ import annotations

import sys as _sys
from superghidra.integrations import d_lift_verifier as _mod
from superghidra.integrations.d_lift_verifier import *  # noqa: F401,F403

if __name__ == "__main__":
    import runpy as _runpy
    _runpy.run_module("superghidra.integrations.d_lift_verifier", run_name="__main__", alter_sys=True)
else:
    _sys.modules[__name__] = _mod
