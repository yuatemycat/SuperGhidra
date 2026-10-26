"""Backward-compatibility shim for `apk_jni_cross_referencer` under `superghidra.compat`.

Canonical location: `superghidra.<domain>.apk_jni_cross_referencer`.
"""
from __future__ import annotations

import importlib as _importlib
import sys as _sys

_DOMAINS = ["core", "formats", "diff", "acceleration", "lifters", "integrations", "storage"]
_mod = None
for _d in _DOMAINS:
    try:
        _mod = _importlib.import_module(f"superghidra.{_d}.apk_jni_cross_referencer")
        break
    except (ImportError, AttributeError):
        pass

if _mod is None:
    try:
        _mod = _importlib.import_module("superghidra.apk_jni_cross_referencer")
    except Exception:
        pass

if _mod is not None:
    _d = {k: getattr(_mod, k) for k in dir(_mod) if not k.startswith("__")}
    globals().update(_d)
    _sys.modules[__name__] = _mod
