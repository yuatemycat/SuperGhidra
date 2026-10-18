"""Backward-compatibility shim for `evidence_ledger`.

Canonical location: `superghidra.diff.evidence_ledger`.
"""
from __future__ import annotations

import sys as _sys
from superghidra.diff import evidence_ledger as _mod
from superghidra.diff.evidence_ledger import *  # noqa: F401,F403

if __name__ == "__main__":
    import runpy as _runpy
    _runpy.run_module("superghidra.diff.evidence_ledger", run_name="__main__", alter_sys=True)
else:
    _sys.modules[__name__] = _mod
