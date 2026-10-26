"""Backward-compatibility shim for `gpu_adrp_scanner` under `superghidra.compat`.

Canonical location: `superghidra.<domain>.gpu_adrp_scanner`.
"""
from __future__ import annotations

import importlib as _importlib
import sys as _sys

_DOMAINS = ["core", "formats", "diff", "acceleration", "lifters", "integrations", "storage"]
_mod = None
for _d in _DOMAINS:
    try:
        _mod = _importlib.import_module(f"superghidra.{_d}.gpu_adrp_scanner")
        break
    except (ImportError, AttributeError):
        pass

if _mod is None:
    try:
        _mod = _importlib.import_module("superghidra.gpu_adrp_scanner")
    except Exception:
        pass

if _mod is not None:
    _d = {k: getattr(_mod, k) for k in dir(_mod) if not k.startswith("__")}
    globals().update(_d)
    _sys.modules[__name__] = _mod
