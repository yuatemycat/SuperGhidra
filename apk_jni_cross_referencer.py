"""Backward-compatibility shim for `apk_jni_cross_referencer`.

Canonical location: `superghidra.integrations.apk_jni_cross_referencer`.
"""
from __future__ import annotations

import sys as _sys
from superghidra.integrations import apk_jni_cross_referencer as _mod
from superghidra.integrations.apk_jni_cross_referencer import *  # noqa: F401,F403

if __name__ == "__main__":
    import runpy as _runpy
    _runpy.run_module("superghidra.integrations.apk_jni_cross_referencer", run_name="__main__", alter_sys=True)
else:
    _sys.modules[__name__] = _mod
