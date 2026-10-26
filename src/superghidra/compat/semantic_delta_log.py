"""Backward-compatibility shim for `semantic_delta_log` under `superghidra.compat`.

Canonical location: `superghidra.<domain>.semantic_delta_log`.
"""
from __future__ import annotations

import sys as _sys
import importlib as _importlib

_DOMAINS = ["core", "formats", "diff", "acceleration", "lifters", "integrations", "storage"]
_mod = None
for _d in _DOMAINS:
    try:
        _mod = _importlib.import_module(f"superghidra.{_d}.semantic_delta_log")
        break
    except (ImportError, AttributeError):
        pass

if _mod is None:
    try:
        _mod = _importlib.import_module(f"superghidra.semantic_delta_log")
    except Exception:
        pass

if _mod is not None:
    _d = {k: getattr(_mod, k) for k in dir(_mod) if not k.startswith("__")}
    globals().update(_d)
    _sys.modules[__name__] = _mod
