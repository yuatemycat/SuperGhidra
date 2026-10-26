"""Backward-compatibility shim for `arm_thumb_decode` under `superghidra.compat`.

Canonical location: `superghidra.<domain>.arm_thumb_decode`.
"""
from __future__ import annotations

import sys as _sys
import importlib as _importlib

_DOMAINS = ["core", "formats", "diff", "acceleration", "lifters", "integrations", "storage"]
_mod = None
for _d in _DOMAINS:
    try:
        _mod = _importlib.import_module(f"superghidra.{_d}.arm_thumb_decode")
        break
    except (ImportError, AttributeError):
        pass

if _mod is None:
    try:
        _mod = _importlib.import_module(f"superghidra.arm_thumb_decode")
    except Exception:
        pass

if _mod is not None:
    _d = {k: getattr(_mod, k) for k in dir(_mod) if not k.startswith("__")}
    globals().update(_d)
    _sys.modules[__name__] = _mod
