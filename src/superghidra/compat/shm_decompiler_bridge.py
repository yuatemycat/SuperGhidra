"""Backward-compatibility shim for `shm_decompiler_bridge` under `superghidra.compat`.

Canonical location: `superghidra.<domain>.shm_decompiler_bridge`.
"""
from __future__ import annotations

import importlib as _importlib
import sys as _sys

_DOMAINS = ["core", "formats", "diff", "acceleration", "lifters", "integrations", "storage"]
_mod = None
for _d in _DOMAINS:
    try:
        _mod = _importlib.import_module(f"superghidra.{_d}.shm_decompiler_bridge")
        break
    except (ImportError, AttributeError):
        pass

if _mod is None:
    try:
        _mod = _importlib.import_module("superghidra.shm_decompiler_bridge")
    except Exception:
        pass

if _mod is not None:
    _exported = {k: getattr(_mod, k) for k in dir(_mod) if not k.startswith("__")}
    globals().update(_exported)
    _sys.modules[__name__] = _mod
