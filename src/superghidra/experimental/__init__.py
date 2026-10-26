"""SuperGhidra Experimental Features & Frontiers.

Subsystems under active research or rapid API iteration:
- acceleration: WGPU and NumPy SIMD ARM64 reference scanners and function seeders
- diff: Semantic CFG differ, struct shift migrator, CRDT swarms, whole-binary type lattice
- lifters: Zero-JVM P-Code lifters, Z3 SMT verifier, E-Graph MLIR rewriter, x86/Thumb decoders, Wasm pipeline
- integrations: APK JNI cross-referencer, emulator memory sidecar, Colab orchestrator, D-LiFT verifier
- storage: LZ4/Zstandard 16 KB buffer compression codecs, extension packager
- core: Dynamic resource governor, SHM IPC ring buffer, dependency DAG, cluster coordinator

Public stable APIs reside directly in the root package `superghidra.*`.
"""

from __future__ import annotations

import importlib
from typing import Any

__all__ = [
    "acceleration",
    "diff",
    "lifters",
    "integrations",
    "storage",
    "core",
]

_EXPERIMENTAL_DOMAINS = {
    "acceleration": "superghidra.acceleration",
    "diff": "superghidra.diff",
    "lifters": "superghidra.lifters",
    "integrations": "superghidra.integrations",
    "storage": "superghidra.storage",
    "core": "superghidra.core",
}


def __getattr__(name: str) -> Any:
    if name in _EXPERIMENTAL_DOMAINS:
        return importlib.import_module(_EXPERIMENTAL_DOMAINS[name])
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
