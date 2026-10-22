"""
SuperGhidra GPU Function Seeder (gpu_function_seeder.py)

Features:
1. High-Performance ARM64 Instruction Classifier:
   - Multi-backend acceleration: WGPU Compute Shaders (Vulkan/DirectX12/Metal), PyTorch CUDA, and vectorized NumPy.
   - Extracts BL call targets: ((insn & 0xFC000000) == 0x94000000) with sign-extended PC-relative offset.
   - Detects function prologues:
     * PACIASP: 0xD503233F
     * STP x29, x30, [sp, #-imm]!: ((insn & 0xFFC07FFF) == 0xA9807BFD)
     * SUB sp, sp, #imm: ((insn & 0xFF8003FF) == 0xD10003FF)
     * BTI c / BTI jc: (0xD503245F / 0xD50324DF)
     * Associated epilogues / returns: RET (0xD65F03C0), AUTIASP (0xD50323BF)

2. Fast Data Pointer Scanner:
   - Vectorized scanning of 64-bit aligned pointers in .rodata / .data.rel.ro pointing into .text.
   - Identifies vtables, callback arrays, and dispatch tables.

3. Function Seed Deduplication & Aggregation:
   - Unifies seeds from BL targets, prologues, and data pointers.
   - Computes confidence scores based on multi-source corroboration and prologue structure.
   - Resolves composite entry points (e.g. PACIASP + STP preceding sequence alignment).

4. Export Capabilities:
   - Exports rich JSON metadata report.
   - Generates high-throughput Ghidra Java batch registration script (SuperGhidraBatchFunctionRegistrar.java).
"""

from __future__ import annotations

import dataclasses
import json
import logging
import os
import struct
import sys
import time
from typing import Any, Dict, List, Optional, Set, Tuple, Union

import numpy as np

logger = logging.getLogger("gpu_function_seeder")

# Optional GPU acceleration backends
try:
    import wgpu
    HAS_WGPU = True
except ImportError:
    wgpu = None  # type: ignore
    HAS_WGPU = False

try:
    import torch
    HAS_TORCH = True
    HAS_CUDA = torch.cuda.is_available()
except ImportError:
    torch = None  # type: ignore
    HAS_TORCH = False
    HAS_CUDA = False

# Instruction Kind Bits (for GPU classification)
KIND_PACIASP = 1        # 0xD503233F
KIND_STP_FP_LR = 2      # (insn & 0xFFC07FFF) == 0xA9807BFD
KIND_SUB_SP = 3         # (insn & 0xFF8003FF) == 0xD10003FF
KIND_BL = 4             # (insn & 0xFC000000) == 0x94000000
KIND_RET = 5            # 0xD65F03C0
KIND_BTI = 6            # 0xD503245F or 0xD50324DF

# Bitmasks
MASK_BL = 0xFC000000
VAL_BL = 0x94000000
MASK_STP_FP_LR = 0xFFC07FFF
VAL_STP_FP_LR = 0xA9807BFD
MASK_SUB_SP = 0xFF8003FF
VAL_SUB_SP = 0xD10003FF
VAL_PACIASP = 0xD503233F
VAL_AUTIASP = 0xD50323BF
VAL_RET = 0xD65F03C0
VAL_BTI_C = 0xD503245F
VAL_BTI_JC = 0xD50324DF


@dataclasses.dataclass
class FunctionSeed:
    """Represents a discovered function entry point seed."""
    entry_vaddr: int
    sources: Set[str] = dataclasses.field(default_factory=set)
    confidence: float = 0.5
    prologue_type: Optional[str] = None
    callers: List[int] = dataclasses.field(default_factory=list)
    data_refs: List[int] = dataclasses.field(default_factory=list)

    @property
    def caller_count(self) -> int:
        return len(self.callers)

    @property
    def data_ref_count(self) -> int:
        return len(self.data_refs)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "entry_vaddr": hex(self.entry_vaddr),
            "sources": sorted(list(self.sources)),
            "confidence": round(self.confidence, 3),
            "prologue_type": self.prologue_type,
            "caller_count": self.caller_count,
            "data_ref_count": self.data_ref_count,
            "callers": [hex(c) for c in self.callers[:50]],
            "data_refs": [hex(r) for r in self.data_refs[:50]],
        }


# ==============================================================================
# Vectorized / GPU Compute Shader Kernels
# ==============================================================================

WGSL_SEEDER_SOURCE = """
@group(0) @binding(0) var<storage, read> instructions: array<u32>;
@group(0) @binding(1) var<storage, read_write> match_data: array<u32>;
@group(0) @binding(2) var<storage, read_write> counter: atomic<u32>;

@compute @workgroup_size(256)
fn main(@builtin(global_invocation_id) global_id: vec3<u32>) {
    let idx = global_id.x;
    let total = arrayLength(&instructions);
    if (idx >= total) {
        return;
    }

    let insn = instructions[idx];
    var kind: u32 = 0u;

    // 1. PACIASP: 0xD503233Fu
    if (insn == 0xD503233Fu) {
        kind = 1u;
    }
    // 2. STP x29, x30, [sp, #-imm]!: (insn & 0xFFC07FFFu) == 0xA9807BFDu
    else if ((insn & 0xFFC07FFFu) == 0xA9807BFDu) {
        kind = 2u;
    }
    // 3. SUB sp, sp, #imm: (insn & 0xFF8003FFu) == 0xD10003FFu
    else if ((insn & 0xFF8003FFu) == 0xD10003FFu) {
        kind = 3u;
    }
    // 4. BL: (insn & 0xFC000000u) == 0x94000000u
    else if ((insn & 0xFC000000u) == 0x94000000u) {
        kind = 4u;
    }
    // 5. RET: 0xD65F03C0u
    else if (insn == 0xD65F03C0u) {
        kind = 5u;
    }
    // 6. BTI c (0xD503245Fu) or BTI jc (0xD50324DFu)
    else if (insn == 0xD503245Fu || insn == 0xD50324DFu) {
        kind = 6u;
    }

    if (kind != 0u) {
        let slot = atomicAdd(&counter, 1u);
        if (slot < arrayLength(&match_data)) {
            // High 3 bits = kind (1..6), Low 29 bits = instruction index (up to 2.14 GB)
            match_data[slot] = (kind << 29u) | (idx & 0x1FFFFFFFu);
        }
    }
}
"""


def pack_seeder_match(idx: int, kind: int) -> int:
    """
    Packs instruction index (29-bit, up to 2.14 GB / 536,870,911 instructions)
    and instruction kind (3-bit: 1..6) into a single 32-bit unsigned integer.
    """
    return int(((kind & 0x7) << 29) | (idx & 0x1FFFFFFF))


def unpack_seeder_match(packed: int) -> Tuple[int, int]:
    """
    Unpacks packed uint32 into (idx, kind).
    idx: 29-bit instruction index (0 .. 0x1FFFFFFF)
    kind: 3-bit instruction kind (1..6)
    """
    idx = int(packed & 0x1FFFFFFF)
    kind = int((packed >> 29) & 0x7)
    return idx, kind


class WGPUFunctionSeederEngine:
    """Hardware GPU acceleration seeder engine utilizing WebGPU compute shaders."""

    def __init__(self, max_matches: int = 500000):
        if not HAS_WGPU:
            raise RuntimeError("wgpu package is not available")
        self.max_matches = max_matches
        # Request adapter with graceful fallback if Metal/Vulkan/D3D12 hardware adapter is unavailable
        try:
            self.adapter = wgpu.gpu.request_adapter_sync()
            if self.adapter is None:
                raise RuntimeError("No suitable graphics adapter found for WGPU (unsupported Metal or missing GPU driver)")
            self.device = self.adapter.request_device_sync()
        except Exception as e:
            raise RuntimeError(f"WGPU adapter request failed: {e}") from e
        self._init_pipeline()

    def _init_pipeline(self) -> None:
        self.shader_module = self.device.create_shader_module(code=WGSL_SEEDER_SOURCE)
        self.bind_group_layout = self.device.create_bind_group_layout(
            entries=[
                {"binding": 0, "visibility": wgpu.ShaderStage.COMPUTE, "buffer": {"type": wgpu.BufferBindingType.read_only_storage}},
                {"binding": 1, "visibility": wgpu.ShaderStage.COMPUTE, "buffer": {"type": wgpu.BufferBindingType.storage}},
                {"binding": 2, "visibility": wgpu.ShaderStage.COMPUTE, "buffer": {"type": wgpu.BufferBindingType.storage}},
            ]
        )
        self.pipeline_layout = self.device.create_pipeline_layout(bind_group_layouts=[self.bind_group_layout])
        self.pipeline = self.device.create_compute_pipeline(
            layout=self.pipeline_layout,
            compute={"module": self.shader_module, "entry_point": "main"},
        )

        self.b_out = self.device.create_buffer(
            size=self.max_matches * 4,
            usage=wgpu.BufferUsage.STORAGE | wgpu.BufferUsage.COPY_SRC,
        )
        self.b_counter = self.device.create_buffer(
            size=4,
            usage=wgpu.BufferUsage.STORAGE | wgpu.BufferUsage.COPY_SRC | wgpu.BufferUsage.COPY_DST,
        )
        self.b_readback_counter = self.device.create_buffer(
            size=4,
            usage=wgpu.BufferUsage.COPY_DST | wgpu.BufferUsage.MAP_READ,
        )
        self.b_readback_data = self.device.create_buffer(
            size=self.max_matches * 4,
            usage=wgpu.BufferUsage.COPY_DST | wgpu.BufferUsage.MAP_READ,
        )

    def scan(self, instructions: np.ndarray) -> np.ndarray:
        """Uploads instructions and executes compute shader sweep, returning packed kind+index uint32 array."""
        if instructions.dtype != np.uint32:
            instructions = instructions.astype(np.uint32)
        num_insns = len(instructions)
        if num_insns == 0:
            return np.empty(0, dtype=np.uint32)

        b_in = self.device.create_buffer_with_data(
            data=instructions,
            usage=wgpu.BufferUsage.STORAGE | wgpu.BufferUsage.COPY_DST,
        )
        bind_group = self.device.create_bind_group(
            layout=self.bind_group_layout,
            entries=[
                {"binding": 0, "resource": {"buffer": b_in}},
                {"binding": 1, "resource": {"buffer": self.b_out}},
                {"binding": 2, "resource": {"buffer": self.b_counter}},
            ],
        )

        workgroups = (num_insns + 255) // 256
        encoder = self.device.create_command_encoder()
        encoder.clear_buffer(self.b_counter, 0, 4)
        cpass = encoder.begin_compute_pass()
        cpass.set_pipeline(self.pipeline)
        cpass.set_bind_group(0, bind_group)
        cpass.dispatch_workgroups(workgroups)
        cpass.end()

        encoder.copy_buffer_to_buffer(self.b_counter, 0, self.b_readback_counter, 0, 4)
        self.device.queue.submit([encoder.finish()])

        self.b_readback_counter.map_sync(wgpu.MapMode.READ)
        match_count = int(np.frombuffer(self.b_readback_counter.read_mapped(), dtype=np.uint32)[0])
        self.b_readback_counter.unmap()

        if match_count == 0:
            return np.empty(0, dtype=np.uint32)

        if match_count > self.max_matches:
            logger.warning(
                f"[WGPUFunctionSeederEngine] GPU match count ({match_count}) exceeded max_matches ({self.max_matches}). "
                f"Falling back to NumPy engine to prevent dropped hits."
            )
            return NumPyFunctionSeederEngine.classify_instructions(instructions)

        encoder = self.device.create_command_encoder()
        encoder.copy_buffer_to_buffer(self.b_out, 0, self.b_readback_data, 0, match_count * 4)
        self.device.queue.submit([encoder.finish()])

        self.b_readback_data.map_sync(wgpu.MapMode.READ)
        res = np.frombuffer(self.b_readback_data.read_mapped(), dtype=np.uint32, count=match_count).copy()
        self.b_readback_data.unmap()
        # Sort results deterministically by instruction index
        res = res[np.argsort(res & 0x1FFFFFFF)]
        return res


class TorchFunctionSeederEngine:
    """PyTorch CUDA accelerated instruction classifier using vectorized tensor operations."""

    def __init__(self):
        if not HAS_CUDA:
            raise RuntimeError("PyTorch CUDA is not available")
        self.val_paciasp = int(np.uint32(VAL_PACIASP).view(np.int32))
        self.mask_stp = int(np.uint32(MASK_STP_FP_LR).view(np.int32))
        self.val_stp = int(np.uint32(VAL_STP_FP_LR).view(np.int32))
        self.mask_sub = int(np.uint32(MASK_SUB_SP).view(np.int32))
        self.val_sub = int(np.uint32(VAL_SUB_SP).view(np.int32))
        self.mask_bl = int(np.uint32(MASK_BL).view(np.int32))
        self.val_bl = int(np.uint32(VAL_BL).view(np.int32))
        self.val_ret = int(np.uint32(VAL_RET).view(np.int32))
        self.val_bti_c = int(np.uint32(VAL_BTI_C).view(np.int32))
        self.val_bti_jc = int(np.uint32(VAL_BTI_JC).view(np.int32))

    def scan(self, instructions: np.ndarray) -> np.ndarray:
        if len(instructions) == 0:
            return np.empty(0, dtype=np.uint32)

        t_cpu = torch.from_numpy(instructions)
        d = t_cpu.cuda(non_blocking=True).view(torch.int32)

        m_pac = d == self.val_paciasp
        m_stp = (d & self.mask_stp) == self.val_stp
        m_sub = (d & self.mask_sub) == self.val_sub
        m_bl = (d & self.mask_bl) == self.val_bl
        m_ret = d == self.val_ret
        m_bti = (d == self.val_bti_c) | (d == self.val_bti_jc)

        # Build packed representation (High 3 bits = kind, Low 29 bits = idx)
        results: List[torch.Tensor] = []
        for kind, mask in [
            (KIND_PACIASP, m_pac),
            (KIND_STP_FP_LR, m_stp),
            (KIND_SUB_SP, m_sub),
            (KIND_BL, m_bl),
            (KIND_RET, m_ret),
            (KIND_BTI, m_bti),
        ]:
            idx = torch.nonzero(mask).squeeze(1).to(torch.int64)
            if idx.numel() > 0:
                packed = (((kind & 0x7) << 29) | (idx & 0x1FFFFFFF)).to(torch.uint32 if hasattr(torch, "uint32") else torch.int64)
                results.append(packed)

        if not results:
            torch.cuda.synchronize()
            return np.empty(0, dtype=np.uint32)

        all_packed = torch.cat(results)
        torch.cuda.synchronize()
        return all_packed.cpu().numpy().astype(np.uint32)


class NumPyFunctionSeederEngine:
    """Vectorized NumPy CPU instruction classifier."""

    @staticmethod
    def scan(instructions: np.ndarray) -> np.ndarray:
        if instructions.dtype != np.uint32:
            instructions = instructions.astype(np.uint32)
        if len(instructions) == 0:
            return np.empty(0, dtype=np.uint32)

        m_pac = instructions == VAL_PACIASP
        m_stp = (instructions & MASK_STP_FP_LR) == VAL_STP_FP_LR
        m_sub = (instructions & MASK_SUB_SP) == VAL_SUB_SP
        m_bl = (instructions & MASK_BL) == VAL_BL
        m_ret = instructions == VAL_RET
        m_bti = (instructions == VAL_BTI_C) | (instructions == VAL_BTI_JC)

        results: List[np.ndarray] = []
        for kind, mask in [
            (KIND_PACIASP, m_pac),
            (KIND_STP_FP_LR, m_stp),
            (KIND_SUB_SP, m_sub),
            (KIND_BL, m_bl),
            (KIND_RET, m_ret),
            (KIND_BTI, m_bti),
        ]:
            idx = np.flatnonzero(mask).astype(np.uint32)
            if len(idx) > 0:
                packed = (np.uint32(kind & 0x7) << np.uint32(29)) | (idx & np.uint32(0x1FFFFFFF))
                results.append(packed)

        if not results:
            return np.empty(0, dtype=np.uint32)

        concat = np.concatenate(results)
        return concat[np.argsort(concat & 0x1FFFFFFF)]


# ==============================================================================
# GPU Function Seeder Main Controller
# ==============================================================================

class GPUFunctionSeeder:
    """
    Orchestrates GPU/vectorized instruction sweeps, BL target calculation,
    prologue alignment detection, and data pointer scans to discover function seeds.
    """

    def __init__(self, backend: str = "auto", max_matches: Optional[int] = None):
        self.backend = backend
        self.max_matches = max_matches
        self._wgpu_engine: Optional[WGPUFunctionSeederEngine] = None
        self._torch_engine: Optional[TorchFunctionSeederEngine] = None

        if backend == "auto":
            if HAS_WGPU:
                try:
                    self._wgpu_engine = WGPUFunctionSeederEngine(max_matches=max_matches) if max_matches else WGPUFunctionSeederEngine()
                    self.active_backend = "wgpu"
                    logger.info("GPUFunctionSeeder: initialized 'wgpu' backend")
                except Exception as e:
                    logger.warning(f"GPUFunctionSeeder: wgpu init failed ({e}), falling back")
                    self._fallback_backend(reason=f"wgpu init failed: {e}")
            else:
                self._fallback_backend(reason="HAS_WGPU is False")
        elif backend == "wgpu":
            self._wgpu_engine = WGPUFunctionSeederEngine(max_matches=max_matches) if max_matches else WGPUFunctionSeederEngine()
            self.active_backend = "wgpu"
            logger.info("GPUFunctionSeeder: active backend is 'wgpu'")
        elif backend == "cuda":
            self._torch_engine = TorchFunctionSeederEngine()
            self.active_backend = "cuda"
            logger.info("GPUFunctionSeeder: active backend is 'cuda'")
        elif backend == "numpy":
            self.active_backend = "numpy"
            logger.info("GPUFunctionSeeder: active backend is 'numpy'")
        else:
            raise ValueError(f"Unknown backend {backend}. Choose 'auto', 'wgpu', 'cuda', or 'numpy'.")

    def _fallback_backend(self, reason: str = "") -> None:
        if HAS_CUDA:
            try:
                self._torch_engine = TorchFunctionSeederEngine()
                self.active_backend = "cuda"
                logger.info(f"GPUFunctionSeeder: fell back to 'cuda' (reason: {reason})")
                return
            except Exception as e:
                logger.warning(f"GPUFunctionSeeder: cuda init failed ({e})")
                reason = f"{reason}; cuda init failed: {e}"
        self.active_backend = "numpy"
        logger.info(f"GPUFunctionSeeder: fell back to 'numpy' (reason: {reason})")

    @staticmethod
    def pack_seeder_match(idx: int, kind: int) -> int:
        """Packs 29-bit instruction index and 3-bit instruction kind (1..6) into uint32."""
        return pack_seeder_match(idx, kind)

    @staticmethod
    def unpack_seeder_match(packed: int) -> Tuple[int, int]:
        """Unpacks packed uint32 into (idx, kind)."""
        return unpack_seeder_match(packed)

    def _scan_wgpu(self, instructions: np.ndarray) -> List[Tuple[int, int]]:
        """Executes WGPU (or active backend) scan and unpacks 29-bit (idx, kind) tuples."""
        packed_arr = self.classify_instructions(instructions)
        results: List[Tuple[int, int]] = []
        for packed in packed_arr:
            packed_int = int(packed)
            kind = (packed_int >> 29) & 0x7
            idx = packed_int & 0x1FFFFFFF
            results.append((idx, kind))
        return results

    def classify_instructions(self, instructions: np.ndarray) -> np.ndarray:
        """Runs the active backend classifier to produce packed kind+index results."""
        if self.active_backend == "wgpu" and self._wgpu_engine is not None:
            return self._wgpu_engine.scan(instructions)
        elif self.active_backend == "cuda" and self._torch_engine is not None:
            return self._torch_engine.scan(instructions)
        else:
            return NumPyFunctionSeederEngine.scan(instructions)

    @staticmethod
    def decode_bl_target(pc: int, insn: int) -> int:
        """
        Decodes ARM64 BL instruction:
        BL <label>
        Formula:
            imm26 = insn & 0x03FFFFFF
            sign_extend 26-bit to signed offset * 4
            target = pc + offset
        """
        imm26 = insn & 0x03FFFFFF
        if imm26 & 0x02000000:
            imm26 -= 0x04000000
        offset = imm26 << 2
        return pc + offset

    @staticmethod
    def decode_stp_stack_offset(insn: int) -> int:
        """
        Decodes stack immediate displacement in:
        STP x29, x30, [sp, #-imm]!
        Returns signed byte offset (e.g. -16, -32, -48, etc.).
        """
        imm7 = (insn >> 15) & 0x7F
        if imm7 & 0x40:
            imm7 -= 0x80
        return imm7 * 8

    @staticmethod
    def decode_sub_sp_imm(insn: int) -> int:
        """
        Decodes immediate value in:
        SUB sp, sp, #imm
        """
        imm12 = (insn >> 10) & 0xFFF
        shift = (insn >> 22) & 1
        if shift:
            imm12 <<= 12
        return imm12

    def scan_data_pointers(
        self,
        rodata_bytes: bytes,
        rodata_base_vaddr: int,
        text_vaddr_start: int,
        text_vaddr_end: int,
    ) -> List[Tuple[int, int]]:
        """
        Scans .rodata / .data.rel.ro for 64-bit aligned pointers pointing into .text.
        Returns list of (rodata_ref_vaddr, target_function_vaddr).
        """
        num_qwords = len(rodata_bytes) // 8
        if num_qwords == 0:
            return []

        # Vectorized uint64 examination
        qwords = np.frombuffer(rodata_bytes[: num_qwords * 8], dtype=np.uint64)
        valid_mask = (
            (qwords >= text_vaddr_start)
            & (qwords < text_vaddr_end)
            & ((qwords & 3) == 0)
        )
        matched_indices = np.flatnonzero(valid_mask)
        if len(matched_indices) == 0:
            return []

        results: List[Tuple[int, int]] = []
        for idx in matched_indices:
            ref_vaddr = rodata_base_vaddr + int(idx * 8)
            target_vaddr = int(qwords[idx])
            results.append((ref_vaddr, target_vaddr))

        return results

    def seed_functions(
        self,
        text_instructions: np.ndarray,
        text_base_vaddr: int,
        rodata_bytes: Optional[bytes] = None,
        rodata_base_vaddr: Optional[int] = None,
    ) -> List[FunctionSeed]:
        """
        Performs full function seeding sweep over .text and optional .rodata.
        Returns deduplicated, confidence-scored list of FunctionSeed objects.
        """
        if text_instructions.dtype != np.uint32:
            text_instructions = text_instructions.astype(np.uint32)

        num_insns = len(text_instructions)
        text_end_vaddr = text_base_vaddr + num_insns * 4

        # 1. Classify instructions on GPU / vectorized CPU
        packed_matches = self.classify_instructions(text_instructions)

        # Dictionary mapping entry_vaddr -> FunctionSeed
        seeds: Dict[int, FunctionSeed] = {}

        def get_or_create_seed(vaddr: int) -> FunctionSeed:
            if vaddr not in seeds:
                seeds[vaddr] = FunctionSeed(entry_vaddr=vaddr)
            return seeds[vaddr]

        # Separate indices by kind (High 3 bits = kind 1..6, Low 29 bits = idx)
        kinds = (packed_matches >> 29) & 0x07
        indices = packed_matches & 0x1FFFFFFF

        bl_indices = indices[kinds == KIND_BL]
        paciasp_indices = set(indices[kinds == KIND_PACIASP])
        stp_indices = set(indices[kinds == KIND_STP_FP_LR])
        sub_indices = set(indices[kinds == KIND_SUB_SP])
        bti_indices = set(indices[kinds == KIND_BTI])

        # 2. Extract and validate BL targets
        for idx in bl_indices:
            idx = int(idx)
            insn = int(text_instructions[idx])
            pc = text_base_vaddr + idx * 4
            target_vaddr = self.decode_bl_target(pc, insn)

            # Target must fall within executable .text
            if text_base_vaddr <= target_vaddr < text_end_vaddr and (target_vaddr & 3) == 0:
                s = get_or_create_seed(target_vaddr)
                s.sources.add("bl_target")
                s.callers.append(pc)

        # 3. Detect and align function prologues
        # Check PACIASP entries
        for idx in paciasp_indices:
            idx = int(idx)
            entry_vaddr = text_base_vaddr + idx * 4
            # If preceded by BTI c, entry is at BTI
            if (idx - 1) in bti_indices:
                entry_vaddr = text_base_vaddr + (idx - 1) * 4
                s = get_or_create_seed(entry_vaddr)
                s.sources.add("prologue_bti_paciasp")
                s.prologue_type = "BTI+PACIASP"
            else:
                s = get_or_create_seed(entry_vaddr)
                s.sources.add("prologue_paciasp")
                if (idx + 1) in stp_indices:
                    s.prologue_type = "PACIASP+STP_FP_LR"
                else:
                    s.prologue_type = "PACIASP"

        # Check STP x29, x30 entries
        for idx in stp_indices:
            idx = int(idx)
            insn = int(text_instructions[idx])
            imm = self.decode_stp_stack_offset(insn)

            # Check if preceded by PACIASP or BTI
            if (idx - 1) in paciasp_indices:
                # Handled in paciasp pass, entry is idx - 1
                entry_vaddr = text_base_vaddr + (idx - 1) * 4
                s = get_or_create_seed(entry_vaddr)
                s.sources.add("prologue_stp_fp_lr")
                s.prologue_type = f"PACIASP; STP x29, x30, [sp, #{imm}]!"
            elif (idx - 1) in bti_indices:
                entry_vaddr = text_base_vaddr + (idx - 1) * 4
                s = get_or_create_seed(entry_vaddr)
                s.sources.add("prologue_bti_stp")
                s.prologue_type = f"BTI; STP x29, x30, [sp, #{imm}]!"
            else:
                entry_vaddr = text_base_vaddr + idx * 4
                s = get_or_create_seed(entry_vaddr)
                s.sources.add("prologue_stp_fp_lr")
                s.prologue_type = f"STP x29, x30, [sp, #{imm}]!"

        # Check SUB sp, sp entries
        for idx in sub_indices:
            idx = int(idx)
            # Only consider SUB sp as standalone entry if not preceded by STP or PACIASP
            if (idx - 1) not in stp_indices and (idx - 1) not in paciasp_indices:
                insn = int(text_instructions[idx])
                sub_imm = self.decode_sub_sp_imm(insn)
                # Stack allocation usually >= 16 bytes and 16-byte aligned
                if sub_imm >= 16 and (sub_imm % 16) == 0:
                    entry_vaddr = text_base_vaddr + idx * 4
                    # Don't overwrite higher confidence prologue if already registered
                    s = get_or_create_seed(entry_vaddr)
                    s.sources.add("prologue_sub_sp")
                    if s.prologue_type is None:
                        s.prologue_type = f"SUB sp, sp, #{sub_imm}"

        # 4. Scan .rodata pointers
        if rodata_bytes is not None and rodata_base_vaddr is not None:
            rodata_matches = self.scan_data_pointers(
                rodata_bytes=rodata_bytes,
                rodata_base_vaddr=rodata_base_vaddr,
                text_vaddr_start=text_base_vaddr,
                text_vaddr_end=text_end_vaddr,
            )
            for ref_vaddr, target_vaddr in rodata_matches:
                s = get_or_create_seed(target_vaddr)
                s.sources.add("rodata_pointer")
                s.data_refs.append(ref_vaddr)

        # 5. Compute Confidence Scores
        for s in seeds.values():
            has_prologue = any(src.startswith("prologue") for src in s.sources)
            has_bl = "bl_target" in s.sources
            has_data = "rodata_pointer" in s.sources

            score = 0.5
            if has_prologue and (has_bl or has_data):
                score = 1.0
            elif has_prologue:
                score = 0.95
            elif has_bl and has_data:
                score = 0.90
            elif has_bl:
                # Scale with number of independent callers
                score = min(0.88, 0.75 + 0.03 * len(s.callers))
            elif has_data:
                score = min(0.80, 0.70 + 0.02 * len(s.data_refs))

            s.confidence = score

        # Return sorted by virtual address
        sorted_seeds = sorted(seeds.values(), key=lambda x: x.entry_vaddr)
        return sorted_seeds

    def seed_x86_64_functions(
        self,
        code_bytes: bytes,
        text_base_vaddr: int = 0x401000,
        rodata_bytes: Optional[bytes] = None,
        rodata_base_vaddr: Optional[int] = None,
    ) -> List[FunctionSeed]:
        """
        Scans x86_64 .text bytes to discover function entry points from:
          - ENDBR64 (F3 0F 1E FA)
          - PUSH rbp; MOV rbp, rsp (55 48 89 E5)
          - SUB rsp, imm8 (48 83 EC <imm8>)
          - CALL rel32 (E8 <rel32>) targets
        Returns deduplicated, confidence-scored list of FunctionSeed objects.
        """
        n = len(code_bytes)
        if n == 0:
            return []

        text_end_vaddr = text_base_vaddr + n
        seeds: Dict[int, FunctionSeed] = {}

        def get_or_create_seed(vaddr: int) -> FunctionSeed:
            if vaddr not in seeds:
                seeds[vaddr] = FunctionSeed(entry_vaddr=vaddr)
            return seeds[vaddr]

        endbr_offsets: Set[int] = set()
        push_rbp_offsets: Set[int] = set()
        sub_rsp_offsets: Dict[int, int] = {}

        # 1. Scan for ENDBR64, PUSH rbp; MOV rbp, rsp, and SUB rsp, imm8
        for i in range(n - 3):
            b0 = code_bytes[i]
            if b0 == 0xF3 and code_bytes[i : i + 4] == b"\xf3\x0f\x1e\xfa":
                endbr_offsets.add(i)
            elif b0 == 0x55 and code_bytes[i : i + 4] in (b"\x55\x48\x89\xe5", b"\x55\x48\x8b\xec"):
                push_rbp_offsets.add(i)
            elif b0 == 0x48 and code_bytes[i : i + 3] == b"\x48\x83\xec":
                sub_rsp_offsets[i] = code_bytes[i + 3]

        # Register ENDBR64 entries
        for off in sorted(endbr_offsets):
            entry_vaddr = text_base_vaddr + off
            s = get_or_create_seed(entry_vaddr)
            s.sources.add("prologue_endbr64")
            if (off + 4) in push_rbp_offsets:
                s.sources.add("prologue_push_rbp")
                s.prologue_type = "ENDBR64; PUSH rbp; MOV rbp, rsp"
            elif (off + 4) in sub_rsp_offsets:
                imm8 = sub_rsp_offsets[off + 4]
                s.sources.add("prologue_sub_rsp")
                s.prologue_type = f"ENDBR64; SUB rsp, 0x{imm8:X}"
            else:
                s.prologue_type = "ENDBR64"

        # Register PUSH rbp; MOV rbp, rsp entries
        for off in sorted(push_rbp_offsets):
            if (off - 4) in endbr_offsets:
                continue  # Already coalesced into preceding ENDBR64
            entry_vaddr = text_base_vaddr + off
            s = get_or_create_seed(entry_vaddr)
            s.sources.add("prologue_push_rbp")
            s.prologue_type = "PUSH rbp; MOV rbp, rsp"

        # Register standalone SUB rsp, imm8 entries
        for off, imm8 in sorted(sub_rsp_offsets.items()):
            if (off - 4) in endbr_offsets or (off - 4) in push_rbp_offsets or (off - 8) in endbr_offsets:
                continue
            if imm8 > 0 and (imm8 % 8) == 0:
                entry_vaddr = text_base_vaddr + off
                s = get_or_create_seed(entry_vaddr)
                s.sources.add("prologue_sub_rsp")
                if s.prologue_type is None:
                    s.prologue_type = f"SUB rsp, 0x{imm8:X}"

        # 2. Scan for CALL rel32 (0xE8) targets
        i = 0
        while i <= n - 5:
            if code_bytes[i] == 0xE8:
                rel32 = struct.unpack_from("<i", code_bytes, i + 1)[0]
                pc = text_base_vaddr + i
                target_vaddr = pc + 5 + rel32
                if text_base_vaddr <= target_vaddr < text_end_vaddr:
                    s = get_or_create_seed(target_vaddr)
                    s.sources.add("call_target")
                    s.callers.append(pc)
                    i += 5
                    continue
            i += 1

        # 3. Scan optional .rodata pointers
        if rodata_bytes is not None and rodata_base_vaddr is not None:
            num_qwords = len(rodata_bytes) // 8
            if num_qwords > 0:
                qwords = np.frombuffer(rodata_bytes[: num_qwords * 8], dtype=np.uint64)
                valid_mask = (qwords >= text_base_vaddr) & (qwords < text_end_vaddr)
                for idx in np.flatnonzero(valid_mask):
                    ref_vaddr = rodata_base_vaddr + int(idx * 8)
                    target_vaddr = int(qwords[idx])
                    s = get_or_create_seed(target_vaddr)
                    s.sources.add("rodata_pointer")
                    s.data_refs.append(ref_vaddr)

        # 4. Compute Confidence Scores
        for s in seeds.values():
            has_prologue = any(src.startswith("prologue") for src in s.sources)
            has_call = ("call_target" in s.sources) or ("bl_target" in s.sources)
            has_data = "rodata_pointer" in s.sources

            score = 0.5
            if has_prologue and (has_call or has_data):
                score = 1.0
            elif has_prologue:
                score = 0.95
            elif has_call and has_data:
                score = 0.90
            elif has_call:
                score = min(0.88, 0.75 + 0.03 * len(s.callers))
            elif has_data:
                score = min(0.80, 0.70 + 0.02 * len(s.data_refs))

            s.confidence = score

        return sorted(seeds.values(), key=lambda x: x.entry_vaddr)

    @staticmethod
    def export_seeds_to_json(
        seeds: List[FunctionSeed],
        filepath: str,
        binary_name: str = "binary.so",
        text_base_vaddr: int = 0,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> None:
        """Exports function seeds to a structured JSON ledger."""
        data = {
            "binary_name": binary_name,
            "text_base_vaddr": hex(text_base_vaddr),
            "total_seeds": len(seeds),
            "high_confidence_count": sum(1 for s in seeds if s.confidence >= 0.9),
            "metadata": metadata or {},
            "functions": [s.to_dict() for s in seeds],
        }
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)

    @staticmethod
    def export_ghidra_java_script(
        seeds: List[FunctionSeed],
        filepath: str,
        script_name: str = "SuperGhidraBatchFunctionRegistrar",
        batch_size: int = 2500,
    ) -> None:
        """
        Generates a high-throughput Ghidra Java headless script that registers
        discovered function entry points in batch transactions.
        """
        entries_hex = [f"0x{s.entry_vaddr:X}L" for s in seeds]

        java_code = f"""// SuperGhidra Headless Batch Function Registration Script
// Automatically generated by SuperGhidra GPU Function Seeder
// Total Entry Seeds: {len(seeds)}

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.SourceType;

public class {script_name} extends GhidraScript {{

    private static final long[] FUNCTION_ENTRY_SEEDS = new long[] {{
        {", ".join(entries_hex)}
    }};

    @Override
    public void run() throws Exception {{
        println("=== SuperGhidra Batch Function Seeder Starting ===");
        println("Target function seeds to register: " + FUNCTION_ENTRY_SEEDS.length);

        Program prog = currentProgram;
        Listing listing = prog.getListing();

        int registeredCount = 0;
        int alreadyExistingCount = 0;
        int errorCount = 0;

        int totalSeeds = FUNCTION_ENTRY_SEEDS.length;
        int txId = prog.startTransaction("SuperGhidra Function Registration");

        try {{
            for (int i = 0; i < totalSeeds; i++) {{
                long rawAddr = FUNCTION_ENTRY_SEEDS[i];
                Address addr = toAddr(rawAddr);

                // Check if function already exists at address
                Function existing = listing.getFunctionAt(addr);
                if (existing != null) {{
                    alreadyExistingCount++;
                    continue;
                }}

                try {{
                    // Disassemble and create function entry
                    disassemble(addr);
                    String funcName = String.format("FUN_%08X", rawAddr);
                    Function func = createFunction(addr, funcName);
                    if (func != null) {{
                        registeredCount++;
                    }} else {{
                        errorCount++;
                    }}
                }} catch (Exception e) {{
                    errorCount++;
                }}

                if ((i + 1) % {batch_size} == 0) {{
                    prog.endTransaction(txId, true);
                    println(String.format("Batch progress: %d / %d functions registered", i + 1, totalSeeds));
                    txId = prog.startTransaction("SuperGhidra Function Registration Batch");
                }}
            }}
        }} finally {{
            prog.endTransaction(txId, true);
        }}

        println("=== SuperGhidra Registration Complete ===");
        println("Successfully Registered: " + registeredCount);
        println("Already Existing:       " + alreadyExistingCount);
        println("Errors / Skipped:       " + errorCount);
    }}
}}
"""
        with open(filepath, "w", encoding="utf-8") as f:
            f.write(java_code)
