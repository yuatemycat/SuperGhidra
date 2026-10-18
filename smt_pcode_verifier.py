"""Backward-compatibility shim for `smt_pcode_verifier`.

Canonical location: `superghidra.lifters.smt_pcode_verifier`.
"""
from __future__ import annotations

import sys as _sys
from superghidra.lifters import smt_pcode_verifier as _mod
from superghidra.lifters.smt_pcode_verifier import *  # noqa: F401,F403

if __name__ == "__main__":
    import runpy as _runpy
    _runpy.run_module("superghidra.lifters.smt_pcode_verifier", run_name="__main__", alter_sys=True)
else:
    _sys.modules[__name__] = _mod
