"""
Backward-compatibility root shim for superghidra.lifters.wasm_decompiler_pipeline.
"""

import sys
from superghidra.lifters import wasm_decompiler_pipeline

sys.modules["wasm_decompiler_pipeline"] = wasm_decompiler_pipeline

from superghidra.lifters.wasm_decompiler_pipeline import *
