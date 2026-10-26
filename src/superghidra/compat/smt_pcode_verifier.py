"""Backward-compatibility shim for `smt_pcode_verifier` under `superghidra.compat`.

Canonical location: `superghidra.<domain>.smt_pcode_verifier`.
"""
from __future__ import annotations

import importlib as _importlib
import sys as _sys

_DOMAINS = ["core", "formats", "diff", "acceleration", "lifters", "integrations", "storage"]
_mod = None
for _d in _DOMAINS:
    try:
        _mod = _importlib.import_module(f"superghidra.{_d}.smt_pcode_verifier")
        break
    except (ImportError, AttributeError):
        pass

if _mod is None:
    try:
        _mod = _importlib.import_module("superghidra.smt_pcode_verifier")
    except Exception:
        pass

if _mod is not None:
    _exported = {k: getattr(_mod, k) for k in dir(_mod) if not k.startswith("__")}
    globals().update(_exported)
    _sys.modules[__name__] = _mod
