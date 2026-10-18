"""SuperGhidra Storage Domain: LZ4/Zstandard 16 KB Block Codec, 64-bit Slot Directory & Java BufferFile Extension."""

from __future__ import annotations

import importlib
from typing import Any

_EXPORTS: dict[str, tuple[str, str]] = {
    "DataBuffer": ("superghidra.storage.storage_compression_prototype", "DataBuffer"),
    "SlotDirectory": ("superghidra.storage.storage_compression_prototype", "SlotDirectory"),
    "SlotDirectoryEntry": ("superghidra.storage.storage_compression_prototype", "SlotDirectoryEntry"),
    "CompressedLocalManagedBufferFile": ("superghidra.storage.storage_compression_prototype", "CompressedLocalManagedBufferFile"),
    "StorageCompressionBenchmark": ("superghidra.storage.storage_compression_prototype", "StorageCompressionBenchmark"),
    "GhidraExtensionPackager": ("superghidra.storage.ghidra_extension_packager", "GhidraExtensionPackager"),
    "ExtensionValidationError": ("superghidra.storage.ghidra_extension_packager", "ExtensionValidationError"),
}

__all__ = list(_EXPORTS.keys())


def __getattr__(name: str) -> Any:
    if name in _EXPORTS:
        mod_path, attr_name = _EXPORTS[name]
        mod = importlib.import_module(mod_path)
        val = getattr(mod, attr_name)
        globals()[name] = val
        return val
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
