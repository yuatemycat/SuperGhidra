"""Backward-compatibility shim for `native_decompiler_pgo_builder` under `superghidra.compat`.

Canonical location: `superghidra.<domain>.native_decompiler_pgo_builder`.
"""
from __future__ import annotations

import sys as _sys
import importlib as _importlib

_DOMAINS = ["core", "formats", "diff", "acceleration", "lifters", "integrations", "storage"]
_mod = None
for _d in _DOMAINS:
    try:
        _mod = _importlib.import_module(f"superghidra.{_d}.native_decompiler_pgo_builder")
        break
    except (ImportError, AttributeError):
        pass

if _mod is None:
    try:
        _mod = _importlib.import_module(f"superghidra.native_decompiler_pgo_builder")
    except Exception:
        pass

if _mod is not None:
    _d = {k: getattr(_mod, k) for k in dir(_mod) if not k.startswith("__")}
    globals().update(_d)
    _sys.modules[__name__] = _mod
