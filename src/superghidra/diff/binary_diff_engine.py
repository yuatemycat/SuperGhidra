"""
Binary Diffing Engine for SuperGhidra.

Features:
- Normalized CFG Feature Vector Extractor for stripped ARM64 and x86_64 binaries.
- Graph-theoretic features: cyclomatic complexity, block density, loops, degrees, flow topology.
- Semantic features: normalized instruction opcode distribution, memory load/store ratios,
  branch types, calls, constants, and entropy.
- Batched Cosine-Similarity Matcher utilizing NumPy BLAS and PyTorch CUDA.
- Mutual Top-1 Bipartite Matching and Greedy Maximum-Weight Matching algorithms.
- Fast pairing and symbol propagation across stripped builds.
"""

from __future__ import annotations

import collections
import dataclasses
import enum
import logging
import math
import os
import struct
import time
from typing import Any, Dict, Iterable, List, Set, Tuple

import numpy as np

from superghidra.formats import binary_loader
from superghidra.lifters import arm_thumb_decode, x86_decode

logger = logging.getLogger("binary_diff_engine")

try:
    import torch
    HAS_TORCH = True
    HAS_CUDA = torch.cuda.is_available()
except ImportError:
    torch = None  # type: ignore
    HAS_TORCH = False
    HAS_CUDA = False


class InsnCategory(str, enum.Enum):
    ARITHMETIC = "ARITHMETIC"
    LOGICAL = "LOGICAL"
    MEMORY_LOAD = "MEMORY_LOAD"
    MEMORY_STORE = "MEMORY_STORE"
    BRANCH_COND = "BRANCH_COND"
    BRANCH_UNCOND = "BRANCH_UNCOND"
    CALL = "CALL"
    RETURN = "RETURN"
    COMPARE = "COMPARE"
    VECTOR_FP = "VECTOR_FP"
    SYSTEM = "SYSTEM"
    OTHER = "OTHER"


# Common opcode categorizations across ARM64 & x86
OPCODE_MAP = {
    # ARM64
    "add": InsnCategory.ARITHMETIC, "adds": InsnCategory.ARITHMETIC,
    "sub": InsnCategory.ARITHMETIC, "subs": InsnCategory.ARITHMETIC,
    "mul": InsnCategory.ARITHMETIC, "smull": InsnCategory.ARITHMETIC,
    "sdiv": InsnCategory.ARITHMETIC, "udiv": InsnCategory.ARITHMETIC,
    "neg": InsnCategory.ARITHMETIC, "negs": InsnCategory.ARITHMETIC,
    "and": InsnCategory.LOGICAL, "ands": InsnCategory.LOGICAL,
    "orr": InsnCategory.LOGICAL, "eor": InsnCategory.LOGICAL,
    "bic": InsnCategory.LOGICAL, "bics": InsnCategory.LOGICAL,
    "orn": InsnCategory.LOGICAL, "eon": InsnCategory.LOGICAL,
    "lsl": InsnCategory.LOGICAL, "lsr": InsnCategory.LOGICAL,
    "asr": InsnCategory.LOGICAL, "mvn": InsnCategory.LOGICAL,
    "mov": InsnCategory.ARITHMETIC, "movz": InsnCategory.ARITHMETIC,
    "movn": InsnCategory.ARITHMETIC, "movk": InsnCategory.ARITHMETIC,
    "adr": InsnCategory.ARITHMETIC, "adrp": InsnCategory.ARITHMETIC,
    "ldr": InsnCategory.MEMORY_LOAD, "ldp": InsnCategory.MEMORY_LOAD,
    "ldrb": InsnCategory.MEMORY_LOAD, "ldrh": InsnCategory.MEMORY_LOAD,
    "ldur": InsnCategory.MEMORY_LOAD, "ldurb": InsnCategory.MEMORY_LOAD,
    "ldurh": InsnCategory.MEMORY_LOAD, "ldursw": InsnCategory.MEMORY_LOAD,
    "str": InsnCategory.MEMORY_STORE, "stp": InsnCategory.MEMORY_STORE,
    "strb": InsnCategory.MEMORY_STORE, "strh": InsnCategory.MEMORY_STORE,
    "stur": InsnCategory.MEMORY_STORE, "sturb": InsnCategory.MEMORY_STORE,
    "sturh": InsnCategory.MEMORY_STORE,
    "b": InsnCategory.BRANCH_UNCOND, "br": InsnCategory.BRANCH_UNCOND,
    "b.eq": InsnCategory.BRANCH_COND, "b.ne": InsnCategory.BRANCH_COND,
    "b.lt": InsnCategory.BRANCH_COND, "b.gt": InsnCategory.BRANCH_COND,
    "b.le": InsnCategory.BRANCH_COND, "b.ge": InsnCategory.BRANCH_COND,
    "cbz": InsnCategory.BRANCH_COND, "cbnz": InsnCategory.BRANCH_COND,
    "tbz": InsnCategory.BRANCH_COND, "tbnz": InsnCategory.BRANCH_COND,
    "bl": InsnCategory.CALL, "blr": InsnCategory.CALL,
    "ret": InsnCategory.RETURN,
    "cmp": InsnCategory.COMPARE, "cmn": InsnCategory.COMPARE, "tst": InsnCategory.COMPARE,
    "fadd": InsnCategory.VECTOR_FP, "fsub": InsnCategory.VECTOR_FP,
    "fmul": InsnCategory.VECTOR_FP, "fdiv": InsnCategory.VECTOR_FP,
    "fmov": InsnCategory.VECTOR_FP,
    "nop": InsnCategory.OTHER, "hint": InsnCategory.OTHER,
    "svc": InsnCategory.SYSTEM, "brk": InsnCategory.SYSTEM,
    "mrs": InsnCategory.SYSTEM, "msr": InsnCategory.SYSTEM,

    # x86_64
    "lea": InsnCategory.ARITHMETIC,
    "push": InsnCategory.MEMORY_STORE, "pop": InsnCategory.MEMORY_LOAD,
    "jmp": InsnCategory.BRANCH_UNCOND, "je": InsnCategory.BRANCH_COND,
    "jne": InsnCategory.BRANCH_COND, "jz": InsnCategory.BRANCH_COND,
    "jnz": InsnCategory.BRANCH_COND, "jl": InsnCategory.BRANCH_COND,
    "jle": InsnCategory.BRANCH_COND, "jg": InsnCategory.BRANCH_COND,
    "jge": InsnCategory.BRANCH_COND, "jb": InsnCategory.BRANCH_COND,
    "jae": InsnCategory.BRANCH_COND, "jbe": InsnCategory.BRANCH_COND,
    "ja": InsnCategory.BRANCH_COND, "js": InsnCategory.BRANCH_COND,
    "jns": InsnCategory.BRANCH_COND, "jo": InsnCategory.BRANCH_COND,
    "jno": InsnCategory.BRANCH_COND, "jp": InsnCategory.BRANCH_COND,
    "jnp": InsnCategory.BRANCH_COND, "call": InsnCategory.CALL,
    "test": InsnCategory.COMPARE, "xor": InsnCategory.LOGICAL,
    "or": InsnCategory.LOGICAL, "imul": InsnCategory.ARITHMETIC,
    "endbr64": InsnCategory.OTHER, "leave": InsnCategory.OTHER,
}


@dataclasses.dataclass
class InstructionInfo:
    address: int
    mnemonic: str
    op_str: str = ""
    category: InsnCategory = InsnCategory.OTHER

    @classmethod
    def create(cls, address: int, mnemonic: str, op_str: str = "") -> InstructionInfo:
        mnem_clean = mnemonic.lower().strip()
        cat = OPCODE_MAP.get(mnem_clean, InsnCategory.OTHER)
        return cls(address=address, mnemonic=mnem_clean, op_str=op_str, category=cat)


def decode_arm64_instruction(pc: int, insn: int) -> InstructionInfo:
    """
    Decodes an ARM64 32-bit machine word into an InstructionInfo instance,
    resolving mnemonic, immediate operands/targets, and semantic category.
    """
    # 1. RET: (insn & 0xFFFFFC1F) == 0xD65F0000
    if (insn & 0xFFFFFC1F) == 0xD65F0000:
        rn = (insn >> 5) & 0x1F
        op_str = "" if rn == 30 else f"x{rn}"
        return InstructionInfo(address=pc, mnemonic="ret", op_str=op_str, category=InsnCategory.RETURN)

    # 2. Unconditional Branch Immediate (B): (insn & 0xFC000000) == 0x14000000
    if (insn & 0xFC000000) == 0x14000000:
        imm26 = insn & 0x03FFFFFF
        if imm26 & 0x02000000:
            imm26 -= 0x04000000
        target = pc + (imm26 << 2)
        return InstructionInfo(address=pc, mnemonic="b", op_str=f"#{hex(target)}", category=InsnCategory.BRANCH_UNCOND)

    # 3. Branch with Link (BL - Call): (insn & 0xFC000000) == 0x94000000
    if (insn & 0xFC000000) == 0x94000000:
        imm26 = insn & 0x03FFFFFF
        if imm26 & 0x02000000:
            imm26 -= 0x04000000
        target = pc + (imm26 << 2)
        return InstructionInfo(address=pc, mnemonic="bl", op_str=f"#{hex(target)}", category=InsnCategory.CALL)

    # 4. Conditional Branch Immediate (B.cond): (insn & 0xFF000010) == 0x54000000
    if (insn & 0xFF000010) == 0x54000000:
        cond = insn & 0x0F
        cond_names = ["eq", "ne", "cs", "cc", "mi", "pl", "vs", "vc", "hi", "ls", "ge", "lt", "gt", "le", "al", "nv"]
        cond_str = cond_names[cond] if cond < len(cond_names) else "cond"
        imm19 = (insn >> 5) & 0x7FFFF
        if imm19 & 0x40000:
            imm19 -= 0x80000
        target = pc + (imm19 << 2)
        return InstructionInfo(address=pc, mnemonic=f"b.{cond_str}", op_str=f"#{hex(target)}", category=InsnCategory.BRANCH_COND)

    # 5. Compare and Branch (CBZ / CBNZ): (insn & 0x7E000000) == 0x34000000
    if (insn & 0x7E000000) == 0x34000000:
        is_cbnz = bool((insn >> 24) & 1)
        sf = (insn >> 31) & 1
        rt = insn & 0x1F
        imm19 = (insn >> 5) & 0x7FFFF
        if imm19 & 0x40000:
            imm19 -= 0x80000
        target = pc + (imm19 << 2)
        mnem = "cbnz" if is_cbnz else "cbz"
        r_prefix = "x" if sf else "w"
        return InstructionInfo(address=pc, mnemonic=mnem, op_str=f"{r_prefix}{rt}, #{hex(target)}", category=InsnCategory.BRANCH_COND)

    # 6. Test and Branch (TBZ / TBNZ): (insn & 0x7E000000) == 0x36000000
    if (insn & 0x7E000000) == 0x36000000:
        is_tbnz = bool((insn >> 24) & 1)
        b5 = (insn >> 31) & 1
        b40 = (insn >> 19) & 0x1F
        bit = (b5 << 5) | b40
        rt = insn & 0x1F
        imm14 = (insn >> 5) & 0x3FFF
        if imm14 & 0x2000:
            imm14 -= 0x4000
        target = pc + (imm14 << 2)
        mnem = "tbnz" if is_tbnz else "tbz"
        return InstructionInfo(address=pc, mnemonic=mnem, op_str=f"x{rt}, #{bit}, #{hex(target)}", category=InsnCategory.BRANCH_COND)

    # 7. Register Branch (BR / BLR)
    if (insn & 0xFFFFFC1F) == 0xD61F0000:
        rn = (insn >> 5) & 0x1F
        return InstructionInfo(address=pc, mnemonic="br", op_str=f"x{rn}", category=InsnCategory.BRANCH_UNCOND)
    if (insn & 0xFFFFFC1F) == 0xD63F0000:
        rn = (insn >> 5) & 0x1F
        return InstructionInfo(address=pc, mnemonic="blr", op_str=f"x{rn}", category=InsnCategory.CALL)

    # 8. Load / Store Unsigned Immediate
    if (insn & 0x3B000000) == 0x39000000:
        size = (insn >> 30) & 0x03
        is_load = bool((insn >> 22) & 0x01)
        imm12 = (insn >> 10) & 0xFFF
        offset = imm12 << size
        rn = (insn >> 5) & 0x1F
        rt = insn & 0x1F
        mnem = "ldr" if is_load else "str"
        if size == 0:
            mnem += "b"
        elif size == 1:
            mnem += "h"
        cat = InsnCategory.MEMORY_LOAD if is_load else InsnCategory.MEMORY_STORE
        reg = f"x{rt}" if size == 3 else f"w{rt}"
        base = "sp" if rn == 31 else f"x{rn}"
        return InstructionInfo(address=pc, mnemonic=mnem, op_str=f"{reg}, [{base}, #{hex(offset)}]", category=cat)

    # 9. Load / Store Pair (LDP / STP)
    if (insn & 0x3B800000) == 0x28000000:
        is_load = bool((insn >> 22) & 0x01)
        mnem = "ldp" if is_load else "stp"
        cat = InsnCategory.MEMORY_LOAD if is_load else InsnCategory.MEMORY_STORE
        return InstructionInfo(address=pc, mnemonic=mnem, op_str="", category=cat)

    # 10. Load / Store Unscaled (LDUR / STUR)
    if (insn & 0x3B200C00) == 0x38000000:
        is_load = bool((insn >> 22) & 0x01)
        mnem = "ldur" if is_load else "stur"
        cat = InsnCategory.MEMORY_LOAD if is_load else InsnCategory.MEMORY_STORE
        return InstructionInfo(address=pc, mnemonic=mnem, op_str="", category=cat)

    # 11. ADRP / ADR
    if (insn & 0x9F000000) == 0x90000000:
        immhi = (insn >> 5) & 0x7FFFF
        immlo = (insn >> 29) & 0x03
        imm = (immhi << 2) | immlo
        if imm & 0x100000:
            imm -= 0x200000
        target = (pc & ~0xFFF) + (imm << 12)
        rd = insn & 0x1F
        return InstructionInfo(address=pc, mnemonic="adrp", op_str=f"x{rd}, #{hex(target)}", category=InsnCategory.ARITHMETIC)
    if (insn & 0x9F000000) == 0x10000000:
        immhi = (insn >> 5) & 0x7FFFF
        immlo = (insn >> 29) & 0x03
        imm = (immhi << 2) | immlo
        if imm & 0x100000:
            imm -= 0x200000
        target = pc + imm
        rd = insn & 0x1F
        return InstructionInfo(address=pc, mnemonic="adr", op_str=f"x{rd}, #{hex(target)}", category=InsnCategory.ARITHMETIC)

    # 12. Add/Sub Immediate
    if (insn & 0x1F000000) == 0x11000000:
        is_sub = bool((insn >> 30) & 1)
        is_s = bool((insn >> 29) & 1)
        rd = insn & 0x1F
        if is_sub and is_s and rd == 31:
            return InstructionInfo(address=pc, mnemonic="cmp", op_str="", category=InsnCategory.COMPARE)
        mnem = ("subs" if is_s else "sub") if is_sub else ("adds" if is_s else "add")
        return InstructionInfo(address=pc, mnemonic=mnem, op_str="", category=InsnCategory.ARITHMETIC)

    # 13. Move Wide (MOVZ / MOVN / MOVK)
    if (insn & 0x7F800000) == 0x52800000:
        imm16 = (insn >> 5) & 0xFFFF
        rd = insn & 0x1F
        return InstructionInfo(address=pc, mnemonic="movz", op_str=f"r{rd}, #{hex(imm16)}", category=InsnCategory.ARITHMETIC)
    if (insn & 0x7F800000) == 0x12800000:
        imm16 = (insn >> 5) & 0xFFFF
        rd = insn & 0x1F
        return InstructionInfo(address=pc, mnemonic="movn", op_str=f"r{rd}, #{hex(imm16)}", category=InsnCategory.ARITHMETIC)
    if (insn & 0x7F800000) == 0x72800000:
        imm16 = (insn >> 5) & 0xFFFF
        rd = insn & 0x1F
        return InstructionInfo(address=pc, mnemonic="movk", op_str=f"r{rd}, #{hex(imm16)}", category=InsnCategory.ARITHMETIC)

    # 14. Logical (AND, ORR, EOR, BIC, ORN, EON)
    if ((insn & 0x1F000000) == 0x0A000000) or ((insn & 0x1F800000) == 0x12000000):
        # Register MOV alias (orr rd, xzr, rm)
        if (insn & 0x7FE0FFE0) == 0x2A0003E0:
            return InstructionInfo(address=pc, mnemonic="mov", op_str="", category=InsnCategory.ARITHMETIC)
        opc = (insn >> 29) & 3
        n = (insn >> 21) & 1
        log_mnems = {
            (0, 0): "and", (0, 1): "bic",
            (1, 0): "orr", (1, 1): "orn",
            (2, 0): "eor", (2, 1): "eon",
            (3, 0): "ands", (3, 1): "bics"
        }
        mnem = log_mnems.get((opc, n), "orr")
        return InstructionInfo(address=pc, mnemonic=mnem, op_str="", category=InsnCategory.LOGICAL)

    # 15. Floating Point / Vector
    if ((insn & 0x5E000000) == 0x1E000000) or ((insn & 0x1E400000) == 0x0E000000):
        return InstructionInfo(address=pc, mnemonic="fmov", op_str="", category=InsnCategory.VECTOR_FP)

    # 16. NOP / Hints
    if insn == 0xD503201F:
        return InstructionInfo(address=pc, mnemonic="nop", op_str="", category=InsnCategory.OTHER)
    if (insn & 0xFFFFF01F) == 0xD503201F:
        return InstructionInfo(address=pc, mnemonic="hint", op_str="", category=InsnCategory.OTHER)

    # 17. System (SVC, BRK)
    if (insn & 0xFFE0001F) == 0xD4000001:
        return InstructionInfo(address=pc, mnemonic="svc", op_str="", category=InsnCategory.SYSTEM)
    if (insn & 0xFFE0001F) == 0xD4200000:
        return InstructionInfo(address=pc, mnemonic="brk", op_str="", category=InsnCategory.SYSTEM)

    # Default fallback
    return InstructionInfo(address=pc, mnemonic="unknown", op_str="", category=InsnCategory.OTHER)


def get_arm64_branch_info(pc: int, insn: int) -> Tuple[str, int | None, bool]:
    """
    Returns (branch_type, target_address, is_conditional) for an ARM64 instruction.
    branch_type is one of: 'ret', 'b', 'b.cond', 'cbz', 'tbz', 'bl', 'blr', 'br', 'none'.
    """
    # RET
    if (insn & 0xFFFFFC1F) == 0xD65F0000:
        return ("ret", None, False)

    # Unconditional B
    if (insn & 0xFC000000) == 0x14000000:
        imm26 = insn & 0x03FFFFFF
        if imm26 & 0x02000000:
            imm26 -= 0x04000000
        return ("b", pc + (imm26 << 2), False)

    # BL
    if (insn & 0xFC000000) == 0x94000000:
        imm26 = insn & 0x03FFFFFF
        if imm26 & 0x02000000:
            imm26 -= 0x04000000
        return ("bl", pc + (imm26 << 2), False)

    # B.cond
    if (insn & 0xFF000010) == 0x54000000:
        imm19 = (insn >> 5) & 0x7FFFF
        if imm19 & 0x40000:
            imm19 -= 0x80000
        return ("b.cond", pc + (imm19 << 2), True)

    # CBZ / CBNZ
    if (insn & 0x7E000000) == 0x34000000:
        imm19 = (insn >> 5) & 0x7FFFF
        if imm19 & 0x40000:
            imm19 -= 0x80000
        return ("cbz", pc + (imm19 << 2), True)

    # TBZ / TBNZ
    if (insn & 0x7E000000) == 0x36000000:
        imm14 = (insn >> 5) & 0x3FFF
        if imm14 & 0x2000:
            imm14 -= 0x4000
        return ("tbz", pc + (imm14 << 2), True)

    # BR
    if (insn & 0xFFFFFC1F) == 0xD61F0000:
        return ("br", None, False)

    # BLR
    if (insn & 0xFFFFFC1F) == 0xD63F0000:
        return ("blr", None, False)

    return ("none", None, False)


@dataclasses.dataclass
class BasicBlock:
    start_addr: int
    end_addr: int
    instructions: List[InstructionInfo] = dataclasses.field(default_factory=list)
    successors: List[int] = dataclasses.field(default_factory=list)
    predecessors: List[int] = dataclasses.field(default_factory=list)

    @property
    def instruction_count(self) -> int:
        return len(self.instructions)


@dataclasses.dataclass
class FunctionCFG:
    """Represents a disassembled function and its control flow graph."""
    func_id: str
    address: int
    name: str = ""
    blocks: Dict[int, BasicBlock] = dataclasses.field(default_factory=dict)
    edges: List[Tuple[int, int]] = dataclasses.field(default_factory=list)
    callees: List[str] = dataclasses.field(default_factory=list)
    constants: Set[int] = dataclasses.field(default_factory=set)
    strings: Set[str] = dataclasses.field(default_factory=set)

    def add_block(self, block: BasicBlock) -> None:
        self.blocks[block.start_addr] = block

    def add_edge(self, src: int, dst: int) -> None:
        self.edges.append((src, dst))
        if src in self.blocks and dst not in self.blocks[src].successors:
            self.blocks[src].successors.append(dst)
        if dst in self.blocks and src not in self.blocks[dst].predecessors:
            self.blocks[dst].predecessors.append(src)


class CFGFeatureExtractor:
    """
    Extracts normalized, fixed-dimensional feature vectors (32-dim)
    from Function CFGs for invariant cross-version comparison.
    """

    FEATURE_DIM = 32

    @classmethod
    def extract_vector(cls, cfg: FunctionCFG) -> np.ndarray:
        vec = np.zeros(cls.FEATURE_DIM, dtype=np.float32)

        num_blocks = len(cfg.blocks)
        num_edges = len(cfg.edges)
        if num_blocks == 0:
            return vec

        # 1. Graph Topology Features
        # Cyclomatic complexity: E - N + 2P (assuming P=1)
        cyclomatic = max(1, num_edges - num_blocks + 2)
        density = (2.0 * num_edges) / float(num_blocks) if num_blocks > 0 else 0.0

        in_degrees = [len(b.predecessors) for b in cfg.blocks.values()]
        out_degrees = [len(b.successors) for b in cfg.blocks.values()]
        max_in = max(in_degrees) if in_degrees else 0
        max_out = max(out_degrees) if out_degrees else 0

        # Back-edges (loop indicators): edge where dst address <= src address in topological ordering
        back_edges = sum(1 for (src, dst) in cfg.edges if dst <= src)
        exit_blocks = sum(1 for b in cfg.blocks.values() if len(b.successors) == 0)

        # 2. Instruction Features
        total_insns = sum(b.instruction_count for b in cfg.blocks.values())
        avg_insns_per_block = float(total_insns) / float(num_blocks) if num_blocks > 0 else 0.0

        cat_counts: Dict[InsnCategory, int] = collections.defaultdict(int)
        mnem_counts: Dict[str, int] = collections.defaultdict(int)

        for b in cfg.blocks.values():
            for insn in b.instructions:
                cat_counts[insn.category] += 1
                mnem_counts[insn.mnemonic] += 1

        denom = float(max(1, total_insns))

        # Entropy of instruction mnemonics
        entropy = 0.0
        for cnt in mnem_counts.values():
            p = float(cnt) / denom
            if p > 0:
                entropy -= p * math.log2(p)

        # Populate feature vector:
        # Topology (Log-scaled for broad dynamic range)
        vec[0] = math.log1p(num_blocks)
        vec[1] = math.log1p(num_edges)
        vec[2] = math.log1p(cyclomatic)
        vec[3] = density
        vec[4] = float(max_in)
        vec[5] = float(max_out)
        vec[6] = math.log1p(back_edges)
        vec[7] = float(exit_blocks)

        # Semantic distributions (normalized ratios [0.0 - 1.0])
        vec[8] = math.log1p(total_insns)
        vec[9] = avg_insns_per_block
        vec[10] = cat_counts[InsnCategory.ARITHMETIC] / denom
        vec[11] = cat_counts[InsnCategory.LOGICAL] / denom
        vec[12] = cat_counts[InsnCategory.MEMORY_LOAD] / denom
        vec[13] = cat_counts[InsnCategory.MEMORY_STORE] / denom
        vec[14] = cat_counts[InsnCategory.BRANCH_COND] / denom
        vec[15] = cat_counts[InsnCategory.BRANCH_UNCOND] / denom
        vec[16] = cat_counts[InsnCategory.CALL] / denom
        vec[17] = cat_counts[InsnCategory.RETURN] / denom
        vec[18] = cat_counts[InsnCategory.COMPARE] / denom
        vec[19] = cat_counts[InsnCategory.VECTOR_FP] / denom
        vec[20] = entropy

        # Constants, strings, call graph connectivity
        vec[21] = math.log1p(len(cfg.constants))
        vec[22] = math.log1p(len(cfg.strings))
        vec[23] = math.log1p(len(cfg.callees))

        # Entry block features
        if cfg.address in cfg.blocks:
            entry_b = cfg.blocks[cfg.address]
            vec[24] = float(entry_b.instruction_count)
            vec[25] = float(len(entry_b.successors))
        else:
            vec[24] = 0.0
            vec[25] = 0.0

        # High-order graph moment proxies
        vec[26] = float(np.std(out_degrees)) if len(out_degrees) > 1 else 0.0
        vec[27] = float(np.std([b.instruction_count for b in cfg.blocks.values()])) if num_blocks > 1 else 0.0
        vec[28] = float(cat_counts[InsnCategory.OTHER]) / denom
        vec[29] = float(len(mnem_counts)) / denom
        vec[30] = float(cyclomatic) / float(max(1, num_blocks))
        vec[31] = 1.0  # Bias component

        # L2-normalization for fast cosine distance via dot product
        norm = np.linalg.norm(vec)
        if norm > 1e-6:
            vec /= norm

        return vec

    @classmethod
    def batch_extract(cls, cfgs: List[FunctionCFG]) -> np.ndarray:
        """Extracts feature matrix (N x 32) for a list of functions."""
        if not cfgs:
            return np.empty((0, cls.FEATURE_DIM), dtype=np.float32)
        matrix = np.zeros((len(cfgs), cls.FEATURE_DIM), dtype=np.float32)
        for i, cfg in enumerate(cfgs):
            matrix[i] = cls.extract_vector(cfg)
        return matrix


@dataclasses.dataclass
class FunctionMatch:
    func_a_id: str
    func_a_name: str
    func_a_addr: int
    func_b_id: str
    func_b_name: str
    func_b_addr: int
    similarity: float
    confidence: str  # HIGH, MEDIUM, LOW
    match_type: str  # MUTUAL_TOP1, GREEDY

    def to_dict(self) -> Dict[str, Any]:
        return {
            "func_a_id": self.func_a_id,
            "func_a_name": self.func_a_name,
            "func_a_addr": hex(self.func_a_addr),
            "func_b_id": self.func_b_id,
            "func_b_name": self.func_b_name,
            "func_b_addr": hex(self.func_b_addr),
            "similarity": round(float(self.similarity), 4),
            "confidence": self.confidence,
            "match_type": self.match_type,
        }


@dataclasses.dataclass
class DiffResult:
    matches: List[FunctionMatch]
    unmatched_a: List[str]
    unmatched_b: List[str]
    execution_time_ms: float
    avg_similarity: float
    match_rate_pct: float

    def to_dict(self) -> Dict[str, Any]:
        return {
            "total_matches": len(self.matches),
            "unmatched_a_count": len(self.unmatched_a),
            "unmatched_b_count": len(self.unmatched_b),
            "execution_time_ms": round(self.execution_time_ms, 2),
            "avg_similarity": round(self.avg_similarity, 4),
            "match_rate_pct": round(self.match_rate_pct, 2),
            "matches": [m.to_dict() for m in self.matches],
        }


class BatchedBinaryMatcher:
    """
    Batched Cosine-Similarity Matcher for pairing functions across stripped binaries.
    """

    def __init__(self, threshold: float = 0.75, use_gpu: bool = True):
        self.threshold = threshold
        self.use_gpu = use_gpu and HAS_CUDA

    def compute_similarity_matrix(self, feats_a: np.ndarray, feats_b: np.ndarray) -> np.ndarray:
        """Computes N x M cosine similarity matrix between two normalized feature sets."""
        if feats_a.shape[0] == 0 or feats_b.shape[0] == 0:
            return np.empty((feats_a.shape[0], feats_b.shape[0]), dtype=np.float32)

        if self.use_gpu:
            t_a = torch.from_numpy(feats_a).cuda()
            t_b = torch.from_numpy(feats_b).cuda()
            sim = torch.mm(t_a, t_b.t())
            torch.cuda.synchronize()
            return sim.cpu().numpy()
        else:
            # BLAS GEMM dot-product of L2-normalized vectors
            return np.dot(feats_a, feats_b.T)

    def diff_binaries(
        self,
        funcs_a: List[FunctionCFG],
        funcs_b: List[FunctionCFG],
        strategy: str = "mutual",  # 'mutual' or 'greedy'
    ) -> DiffResult:
        """
        Pairs functions between Binary A and Binary B.

        Args:
            funcs_a: Functions in Binary A.
            funcs_b: Functions in Binary B.
            strategy: 'mutual' for Top-1 Mutual Bipartite match, 'greedy' for Max-Weight matching.
        """
        t0 = time.perf_counter()
        feats_a = CFGFeatureExtractor.batch_extract(funcs_a)
        feats_b = CFGFeatureExtractor.batch_extract(funcs_b)

        sim_matrix = self.compute_similarity_matrix(feats_a, feats_b)
        n, m = sim_matrix.shape

        matches: List[FunctionMatch] = []
        matched_a: Set[int] = set()
        matched_b: Set[int] = set()

        if strategy == "mutual" and n > 0 and m > 0:
            # Best in B for each in A
            best_in_b = np.argmax(sim_matrix, axis=1)
            # Best in A for each in B
            best_in_a = np.argmax(sim_matrix, axis=0)

            for i in range(n):
                j = int(best_in_b[i])
                score = float(sim_matrix[i, j])
                if score >= self.threshold and best_in_a[j] == i:
                    matched_a.add(i)
                    matched_b.add(j)
                    conf = "HIGH" if score >= 0.90 else "MEDIUM"
                    matches.append(
                        FunctionMatch(
                            func_a_id=funcs_a[i].func_id,
                            func_a_name=funcs_a[i].name or funcs_a[i].func_id,
                            func_a_addr=funcs_a[i].address,
                            func_b_id=funcs_b[j].func_id,
                            func_b_name=funcs_b[j].name or funcs_b[j].func_id,
                            func_b_addr=funcs_b[j].address,
                            similarity=score,
                            confidence=conf,
                            match_type="MUTUAL_TOP1",
                        )
                    )

        # Greedy fallback / completion for remaining unmatched candidates
        if n > 0 and m > 0:
            unmatched_i = [i for i in range(n) if i not in matched_a]
            unmatched_j = [j for j in range(m) if j not in matched_b]

            if unmatched_i and unmatched_j:
                pairs = []
                for i in unmatched_i:
                    for j in unmatched_j:
                        s = float(sim_matrix[i, j])
                        if s >= self.threshold:
                            pairs.append((s, i, j))
                pairs.sort(key=lambda x: x[0], reverse=True)

                for score, i, j in pairs:
                    if i not in matched_a and j not in matched_b:
                        matched_a.add(i)
                        matched_b.add(j)
                        matches.append(
                            FunctionMatch(
                                func_a_id=funcs_a[i].func_id,
                                func_a_name=funcs_a[i].name or funcs_a[i].func_id,
                                func_a_addr=funcs_a[i].address,
                                func_b_id=funcs_b[j].func_id,
                                func_b_name=funcs_b[j].name or funcs_b[j].func_id,
                                func_b_addr=funcs_b[j].address,
                                similarity=score,
                                confidence="MEDIUM" if score >= 0.85 else "LOW",
                                match_type="GREEDY",
                            )
                        )

        elapsed_ms = (time.perf_counter() - t0) * 1000
        unmatched_a_ids = [funcs_a[i].func_id for i in range(n) if i not in matched_a]
        unmatched_b_ids = [funcs_b[j].func_id for j in range(m) if j not in matched_b]
        avg_sim = float(np.mean([m.similarity for m in matches])) if matches else 0.0
        match_rate = (len(matches) / max(1, min(n, m))) * 100.0

        return DiffResult(
            matches=matches,
            unmatched_a=unmatched_a_ids,
            unmatched_b=unmatched_b_ids,
            execution_time_ms=elapsed_ms,
            avg_similarity=avg_sim,
            match_rate_pct=match_rate,
        )


# ==============================================================================
# Direct Binary & ARM64 Machine Code CFG Extraction
# ==============================================================================

def extract_cfgs_from_arm64_bytes(
    code_bytes: bytes,
    base_vaddr: int = 0x100000,
) -> List[FunctionCFG]:
    """
    Directly extracts FunctionCFGs from raw ARM64 machine bytes.
    Partitions functions using GPUFunctionSeeder(backend="numpy") and RET (0xD65F03C0) boundaries,
    then parses BasicBlocks, control flow edges, branch targets, and call sites.
    """
    num_insns = len(code_bytes) // 4
    if num_insns == 0:
        return []

    insns = np.frombuffer(code_bytes[: num_insns * 4], dtype=np.uint32)

    # Discover function entry points
    entry_addrs: Set[int] = {base_vaddr}

    # 1. GPUFunctionSeeder discovery
    try:
        from superghidra.acceleration.gpu_function_seeder import GPUFunctionSeeder
        seeder = GPUFunctionSeeder(backend="numpy")
        seeds = seeder.seed_functions(insns, text_base_vaddr=base_vaddr)
        for s in seeds:
            if base_vaddr <= s.entry_vaddr < base_vaddr + num_insns * 4:
                entry_addrs.add(s.entry_vaddr)
    except Exception:
        pass

    # 2. RET boundary partitioning (0xD65F03C0 or (insn & 0xFFFFFC1F) == 0xD65F0000)
    for i in range(num_insns):
        insn_val = int(insns[i])
        if (insn_val & 0xFFFFFC1F) == 0xD65F0000:  # RET
            # Next valid instruction after padding is a candidate function start
            next_idx = i + 1
            while next_idx < num_insns and insns[next_idx] in (0xD503201F, 0x00000000):
                next_idx += 1
            if next_idx < num_insns:
                entry_addrs.add(base_vaddr + next_idx * 4)

    sorted_entries = sorted(list(entry_addrs))
    cfgs: List[FunctionCFG] = []

    for k, start_pc in enumerate(sorted_entries):
        end_pc = sorted_entries[k + 1] if k + 1 < len(sorted_entries) else (base_vaddr + num_insns * 4)
        if start_pc >= end_pc:
            continue

        start_idx = (start_pc - base_vaddr) // 4
        end_idx = (end_pc - base_vaddr) // 4
        func_insns = insns[start_idx:end_idx]
        if len(func_insns) == 0:
            continue

        # Look for the last RET within this function range to exclude trailing padding
        actual_end_pc = end_pc
        for cur_idx in range(len(func_insns) - 1, -1, -1):
            if (int(func_insns[cur_idx]) & 0xFFFFFC1F) == 0xD65F0000:
                actual_end_pc = start_pc + (cur_idx + 1) * 4
                break

        cfg = FunctionCFG(
            func_id=f"func_{start_pc:08x}",
            address=start_pc,
            name=f"sub_{start_pc:08x}",
        )

        # 3. Identify BasicBlock leaders within [start_pc, actual_end_pc)
        leaders: Set[int] = {start_pc}
        cur_pc = start_pc
        for insn_val_raw in func_insns:
            if cur_pc >= actual_end_pc:
                break
            insn_val = int(insn_val_raw)
            btype, target, is_cond = get_arm64_branch_info(cur_pc, insn_val)

            if target is not None and start_pc <= target < actual_end_pc:
                leaders.add(target)

            if is_cond:
                fallthrough = cur_pc + 4
                if fallthrough < actual_end_pc:
                    leaders.add(fallthrough)
            elif btype in ("b", "ret", "br"):
                fallthrough = cur_pc + 4
                if fallthrough < actual_end_pc:
                    leaders.add(fallthrough)

            cur_pc += 4

        sorted_leaders = sorted(list(leaders))

        # 4. Construct BasicBlocks
        for idx, leader_pc in enumerate(sorted_leaders):
            limit_bb_pc = sorted_leaders[idx + 1] if idx + 1 < len(sorted_leaders) else actual_end_pc
            bb = BasicBlock(start_addr=leader_pc, end_addr=limit_bb_pc)

            bb_cur_pc = leader_pc
            while bb_cur_pc < limit_bb_pc:
                insn_idx = (bb_cur_pc - base_vaddr) // 4
                if insn_idx >= num_insns:
                    break
                insn_val = int(insns[insn_idx])
                info = decode_arm64_instruction(bb_cur_pc, insn_val)
                bb.instructions.append(info)

                # Record constants if immediate
                if info.mnemonic in ("movz", "movk", "movn"):
                    imm16 = (insn_val >> 5) & 0xFFFF
                    cfg.constants.add(imm16)
                elif info.mnemonic in ("adrp", "adr"):
                    cfg.constants.add(info.address)

                btype, target, is_cond = get_arm64_branch_info(bb_cur_pc, insn_val)
                if btype == "bl" and target is not None:
                    cfg.callees.append(hex(target))

                bb_cur_pc += 4

                # Terminator instruction ends the basic block
                if btype in ("b", "ret", "br") or is_cond:
                    bb.end_addr = bb_cur_pc
                    break

            cfg.add_block(bb)

        # 5. Wire edges between basic blocks
        for bb in cfg.blocks.values():
            if not bb.instructions:
                continue
            last_insn = bb.instructions[-1]
            insn_idx = (last_insn.address - base_vaddr) // 4
            insn_val = int(insns[insn_idx])
            btype, target, is_cond = get_arm64_branch_info(last_insn.address, insn_val)

            if is_cond:
                if target is not None and start_pc <= target < actual_end_pc:
                    cfg.add_edge(bb.start_addr, target)
                fallthrough = last_insn.address + 4
                if fallthrough < actual_end_pc and fallthrough in cfg.blocks:
                    cfg.add_edge(bb.start_addr, fallthrough)
            elif btype == "b":
                if target is not None and start_pc <= target < actual_end_pc:
                    cfg.add_edge(bb.start_addr, target)
            elif btype == "ret":
                pass  # Function return: exit block, no outgoing edge within function
            elif btype == "br":
                pass  # Indirect branch
            else:
                # Fallthrough to subsequent block
                fallthrough = bb.end_addr
                if fallthrough in cfg.blocks:
                    cfg.add_edge(bb.start_addr, fallthrough)

        cfgs.append(cfg)

    return cfgs


_X86_JCC_NAMES = (
    "jo", "jno", "jb", "jae", "je", "jne", "jbe", "ja",
    "js", "jns", "jp", "jnp", "jl", "jge", "jle", "jg",
)


_X86_MODRM_CLASS = {
    0x89: ("mov", InsnCategory.MEMORY_STORE),
    0x88: ("mov", InsnCategory.MEMORY_STORE),
    0x8B: ("mov", InsnCategory.MEMORY_LOAD),
    0x8A: ("mov", InsnCategory.MEMORY_LOAD),
    0x8D: ("lea", InsnCategory.ARITHMETIC),
    0x01: ("add", InsnCategory.ARITHMETIC),
    0x03: ("add", InsnCategory.ARITHMETIC),
    0x29: ("sub", InsnCategory.ARITHMETIC),
    0x2B: ("sub", InsnCategory.ARITHMETIC),
    0x31: ("xor", InsnCategory.LOGICAL),
    0x33: ("xor", InsnCategory.LOGICAL),
    0x21: ("and", InsnCategory.LOGICAL),
    0x23: ("and", InsnCategory.LOGICAL),
    0x09: ("or", InsnCategory.LOGICAL),
    0x0B: ("or", InsnCategory.LOGICAL),
    0x39: ("cmp", InsnCategory.COMPARE),
    0x3B: ("cmp", InsnCategory.COMPARE),
    0x85: ("test", InsnCategory.COMPARE),
    0x84: ("test", InsnCategory.COMPARE),
}
_X86_GRP1 = {
    0: ("add", InsnCategory.ARITHMETIC),
    1: ("or", InsnCategory.LOGICAL),
    2: ("adc", InsnCategory.ARITHMETIC),
    3: ("sbb", InsnCategory.ARITHMETIC),
    4: ("and", InsnCategory.LOGICAL),
    5: ("sub", InsnCategory.ARITHMETIC),
    6: ("xor", InsnCategory.LOGICAL),
    7: ("cmp", InsnCategory.COMPARE),
}


def _classify_x86(insn: x86_decode.X86Insn) -> Tuple[str, InsnCategory, int | None]:
    """Coarse (mnemonic, category, immediate) for CFG feature vectors."""
    op, mp, imm = insn.opcode, insn.map, insn.imm
    mem = insn.mem is not None
    if mp == 0 and not insn.vex:
        if op == 0x90:
            return "nop", InsnCategory.OTHER, None
        if op in (0xC2, 0xC3, 0xCA, 0xCB):
            return "ret", InsnCategory.RETURN, None
        if op == 0xC9:
            return "leave", InsnCategory.OTHER, None
        if op == 0xCC:
            return "int3", InsnCategory.SYSTEM, None
        if 0x50 <= op <= 0x57 or op in (0x68, 0x6A):
            return "push", InsnCategory.MEMORY_STORE, None
        if 0x58 <= op <= 0x5F:
            return "pop", InsnCategory.MEMORY_LOAD, None
        if 0x40 <= op <= 0x4F:  # 16/32-bit only; in 64-bit mode these bytes are REX prefixes
            return ("inc" if op < 0x48 else "dec"), InsnCategory.ARITHMETIC, None
        if op == 0xE8:
            return "call", InsnCategory.CALL, None
        if op in (0xE9, 0xEB):
            return "jmp", InsnCategory.BRANCH_UNCOND, None
        if 0x70 <= op <= 0x7F:
            return _X86_JCC_NAMES[op - 0x70], InsnCategory.BRANCH_COND, None
        if 0xE0 <= op <= 0xE3:
            return "loop", InsnCategory.BRANCH_COND, None
        if 0xB8 <= op <= 0xBF or 0xB0 <= op <= 0xB7:
            return "mov", InsnCategory.ARITHMETIC, imm
        if op in (0x05, 0x2D, 0x3D):
            cat = InsnCategory.COMPARE if op == 0x3D else InsnCategory.ARITHMETIC
            return ("add" if op == 0x05 else "sub" if op == 0x2D else "cmp"), cat, imm
        if op in _X86_MODRM_CLASS:
            mnem, cat = _X86_MODRM_CLASS[op]
            if mnem == "mov" and not mem:
                cat = InsnCategory.ARITHMETIC
            return mnem, cat, None
        if op in (0x80, 0x81, 0x83):
            mnem, cat = _X86_GRP1[insn.reg & 7]
            return mnem, cat, imm
        if op in (0xC6, 0xC7):
            val = (imm & 0xFF) if (op == 0xC6 and imm is not None) else imm
            return "mov", (InsnCategory.MEMORY_STORE if mem else InsnCategory.ARITHMETIC), val
        if op in (0xC0, 0xC1, 0xD0, 0xD1, 0xD2, 0xD3):
            return "shift", InsnCategory.LOGICAL, imm
        if op in (0xF6, 0xF7):
            r = insn.reg & 7
            if r in (0, 1):
                return "test", InsnCategory.COMPARE, imm
            return ("not" if r == 2 else "neg" if r == 3 else "mul" if r in (4, 5) else "div"), (
                InsnCategory.LOGICAL if r == 2 else InsnCategory.ARITHMETIC), None
        if op == 0xFF:
            r = insn.reg & 7
            if r in (2, 3):
                return "call", InsnCategory.CALL, None
            if r in (4, 5):
                return "jmp", InsnCategory.BRANCH_UNCOND, None
            if r == 6:
                return "push", InsnCategory.MEMORY_STORE, None
            return ("inc" if r == 0 else "dec"), InsnCategory.ARITHMETIC, None
        if op in (0x69, 0x6B):
            return "imul", InsnCategory.ARITHMETIC, imm
        if op in (0x86, 0x87):
            return "xchg", InsnCategory.MEMORY_STORE if mem else InsnCategory.OTHER, None
        if op == 0x63:
            return "movsxd", InsnCategory.MEMORY_LOAD if mem else InsnCategory.ARITHMETIC, None
        if op < 0x40 and (op & 7) <= 5:
            name = ("add", "or", "adc", "sbb", "and", "sub", "xor", "cmp")[op >> 3]
            cat = InsnCategory.COMPARE if name == "cmp" else (
                InsnCategory.LOGICAL if name in ("or", "and", "xor") else InsnCategory.ARITHMETIC)
            return name, cat, imm
    if mp == 1 and not insn.vex:
        if 0x80 <= op <= 0x8F:
            return _X86_JCC_NAMES[op - 0x80], InsnCategory.BRANCH_COND, None
        if op == 0x1E and insn.rep == 0xF3 and insn.modrm in (0xFA, 0xFB):
            return "endbr64" if insn.modrm == 0xFA else "endbr32", InsnCategory.OTHER, None
        if op in (0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x0D):
            return "nop", InsnCategory.OTHER, None
        if op == 0xAF:
            return "imul", InsnCategory.ARITHMETIC, None
        if op in (0xB6, 0xB7, 0xBE, 0xBF):
            return "mov", InsnCategory.MEMORY_LOAD, None
        if 0x40 <= op <= 0x4F:
            return "cmov", InsnCategory.MEMORY_LOAD if mem else InsnCategory.OTHER, None
        if 0x90 <= op <= 0x9F:
            return "setcc", InsnCategory.MEMORY_STORE if mem else InsnCategory.OTHER, None
        if op in (0x05, 0x34, 0x0B, 0xA2, 0x31):
            return "sys", InsnCategory.SYSTEM, None
    # SSE / AVX / everything else: classify by data movement.
    if mem:
        return "simd" if (mp or insn.vex) else "op", (
            InsnCategory.MEMORY_STORE if insn.is_memory_write() else InsnCategory.MEMORY_LOAD), None
    return ("simd" if (mp or insn.vex) else "op"), InsnCategory.OTHER, None


def decode_x86_64_instruction(
    code_bytes: bytes,
    offset: int,
    base_vaddr: int = 0x401000,
    mode: int = 64,
) -> Tuple[InstructionInfo, int, str, int | None, bool, int | None]:
    """
    Decodes a single x86 instruction (mode 64, 32 or 16) at `offset` in `code_bytes`.
    Returns (insn_info, byte_length, branch_type, branch_target, is_cond, immediate_const).
    branch_type is one of: 'ret', 'jmp', 'jcc', 'call', 'none'.

    Lengths come from the table-driven x86_decode module (validated against Capstone),
    so the sweep stays in sync through SSE/AVX/AVX-512 code.
    """
    pc = base_vaddr + offset
    if offset >= len(code_bytes):
        return InstructionInfo(pc, "unknown", "", InsnCategory.OTHER), 1, "none", None, False, None
    insn = x86_decode.decode(code_bytes, offset, pc, mode)
    if insn.invalid:
        return InstructionInfo(pc, "unknown", "", InsnCategory.OTHER), 1, "none", None, False, None
    mnem, cat, imm_const = _classify_x86(insn)
    flow = insn.flow
    if flow == "ret":
        btype = "ret"
    elif flow == "call":
        btype = "call"
    elif flow in ("jmp", "jmp_ind"):
        btype = "jmp"
    elif flow in ("jcc", "loop"):
        btype = "jcc"
    else:
        btype = "none"  # indirect calls, interrupts, plain instructions
    target = insn.target if btype in ("jmp", "jcc", "call") else None
    operands = f"#{hex(target)}" if target is not None else (
        f"#{hex(imm_const)}" if (imm_const is not None and cat == InsnCategory.ARITHMETIC and mnem == "mov") else "")
    return (InstructionInfo(pc, mnem, operands, cat), insn.length, btype, target, btype == "jcc",
            imm_const)


def extract_cfgs_from_x86_64_bytes(
    code_bytes: bytes,
    base_vaddr: int = 0x401000,
    mode: int = 64,
    function_starts: Iterable[int] | None = None,
) -> List[FunctionCFG]:
    """
    Directly extracts FunctionCFGs from raw x86 machine bytes (mode 64 or 32).
    Splits functions on known `function_starts` (e.g. PE .pdata / exports), RET, ENDBR,
    PUSH rbp; MOV rbp, rsp and CALL rel targets, decodes instructions, builds BasicBlocks
    and control-flow edges, and populates FunctionCFG objects.
    """
    import bisect

    n = len(code_bytes)
    if n == 0:
        return []

    # 1. Decode linear instruction stream
    decoded_stream: List[Tuple[int, int, InstructionInfo, str, int | None, bool, int | None]] = []
    valid_addrs: Set[int] = set()
    off = 0
    while off < n:
        info, length, btype, target, is_cond, imm_const = decode_x86_64_instruction(
            code_bytes, off, base_vaddr=base_vaddr, mode=mode
        )
        decoded_stream.append((off, length, info, btype, target, is_cond, imm_const))
        valid_addrs.add(info.address)
        off += length

    if not decoded_stream:
        return []
    stream_addrs = [item[2].address for item in decoded_stream]

    # 2. Discover function entry points
    entry_addrs: Set[int] = {base_vaddr}
    if function_starts:
        end_va = base_vaddr + n
        for fs in function_starts:
            if base_vaddr <= fs < end_va:
                if fs not in valid_addrs:  # resync the linear sweep is not needed: snap to stream
                    idx = bisect.bisect_left(stream_addrs, fs)
                    if idx < len(stream_addrs):
                        fs = stream_addrs[idx]
                entry_addrs.add(fs)

    if mode == 64:
        try:
            from superghidra.acceleration.gpu_function_seeder import GPUFunctionSeeder
            seeder = GPUFunctionSeeder(backend="numpy")
            seeds = seeder.seed_x86_64_functions(code_bytes, text_base_vaddr=base_vaddr)
            for s in seeds:
                if s.entry_vaddr in valid_addrs:
                    entry_addrs.add(s.entry_vaddr)
        except Exception as exc:  # seeding is an optional hint
            logger.debug("x86_64 seeder unavailable: %s", exc)

    for idx_s, (i_off, i_len, info, btype, target, is_cond, _) in enumerate(decoded_stream):
        # Explicit prologue starts
        if i_off + 4 <= n and code_bytes[i_off : i_off + 4] == b"\xf3\x0f\x1e\xfa":
            entry_addrs.add(info.address)
        elif i_off + 4 <= n and code_bytes[i_off : i_off + 4] in (b"\x55\x48\x89\xe5", b"\x55\x48\x8b\xec"):
            if i_off < 4 or code_bytes[i_off - 4 : i_off] != b"\xf3\x0f\x1e\xfa":
                entry_addrs.add(info.address)

        # Call targets
        if btype == "call" and target is not None and target in valid_addrs:
            entry_addrs.add(target)

        # Post-RET boundary
        if btype == "ret":
            next_s = idx_s + 1
            while next_s < len(decoded_stream) and decoded_stream[next_s][2].mnemonic in ("nop", "int3"):
                next_s += 1
            if next_s < len(decoded_stream):
                entry_addrs.add(decoded_stream[next_s][2].address)

    sorted_entries = sorted(list(entry_addrs))
    cfgs: List[FunctionCFG] = []

    for k, start_pc in enumerate(sorted_entries):
        end_pc = sorted_entries[k + 1] if k + 1 < len(sorted_entries) else (base_vaddr + n)
        if start_pc >= end_pc:
            continue

        lo = bisect.bisect_left(stream_addrs, start_pc)
        hi = bisect.bisect_left(stream_addrs, end_pc)
        func_insns = decoded_stream[lo:hi]
        # Strip trailing padding (nop/int3) after the last ret
        while len(func_insns) > 1 and func_insns[-1][2].mnemonic in ("nop", "int3"):
            func_insns.pop()

        if not func_insns:
            continue

        actual_end_pc = func_insns[-1][2].address + func_insns[-1][1]
        func_addr_set = {item[2].address for item in func_insns}

        cfg = FunctionCFG(
            func_id=f"func_{start_pc:08x}",
            address=start_pc,
            name=f"sub_{start_pc:08x}",
        )

        # 3. Identify BasicBlock leaders within [start_pc, actual_end_pc)
        leaders: Set[int] = {start_pc}
        for i_off, i_len, info, btype, target, is_cond, _ in func_insns:
            if btype in ("jmp", "jcc") and target is not None and target in func_addr_set:
                leaders.add(target)
            if is_cond or btype in ("jmp", "ret"):
                fallthrough = info.address + i_len
                if fallthrough in func_addr_set:
                    leaders.add(fallthrough)

        sorted_leaders = sorted(list(leaders))

        # 4. Construct BasicBlocks
        last_branch_map: Dict[int, Tuple[str, int | None, bool, int]] = {}
        func_addrs = [item[2].address for item in func_insns]
        for idx, leader_pc in enumerate(sorted_leaders):
            limit_bb_pc = sorted_leaders[idx + 1] if idx + 1 < len(sorted_leaders) else actual_end_pc
            bb = BasicBlock(start_addr=leader_pc, end_addr=limit_bb_pc)

            first = bisect.bisect_left(func_addrs, leader_pc)
            for i_off, i_len, info, btype, target, is_cond, imm_const in func_insns[first:]:
                if info.address >= limit_bb_pc:
                    break

                bb.instructions.append(info)
                if imm_const is not None:
                    cfg.constants.add(imm_const)
                if btype == "call" and target is not None:
                    cfg.callees.append(hex(target))

                next_pc = info.address + i_len
                last_branch_map[bb.start_addr] = (btype, target, is_cond, next_pc)

                if btype in ("jmp", "ret") or is_cond:
                    bb.end_addr = next_pc
                    break

            if bb.instructions:
                cfg.add_block(bb)

        # 5. Wire control-flow edges
        for bb_addr, bb in cfg.blocks.items():
            btype, target, is_cond, fallthrough = last_branch_map.get(
                bb_addr, ("none", None, False, bb.end_addr)
            )
            if is_cond:
                if target is not None and target in cfg.blocks:
                    cfg.add_edge(bb_addr, target)
                if fallthrough in cfg.blocks:
                    cfg.add_edge(bb_addr, fallthrough)
            elif btype == "jmp":
                if target is not None and target in cfg.blocks:
                    cfg.add_edge(bb_addr, target)
            elif btype == "ret":
                pass
            else:
                if fallthrough in cfg.blocks:
                    cfg.add_edge(bb_addr, fallthrough)

        cfgs.append(cfg)

    return cfgs


def extract_cfgs_from_arm32_bytes(
    code_bytes: bytes,
    base_vaddr: int = 0x10000,
    thumb_mode: bool = False,
    function_starts: Iterable[int] | None = None,
) -> List[FunctionCFG]:
    """
    Directly extracts FunctionCFGs from raw ARM32 or Thumb/Thumb-2 machine bytes.
    Splits functions on known function_starts (e.g. ELF symbols/exports, PE exports),
    epilogue boundaries (BX lr, POP/LDMIA {..., pc}), and prologue patterns (PUSH/STMDB {..., lr}),
    decodes instructions using arm_thumb_decode, builds BasicBlocks and control-flow edges,
    and populates FunctionCFG objects.
    """
    import bisect

    n = len(code_bytes)
    if n == 0:
        return []

    # 1. Decode linear instruction stream
    decoded_stream: List[Tuple[int, int, InstructionInfo, str, int | None, bool, int | None, bool, bool]] = []
    valid_addrs: Set[int] = set()
    off = 0
    while off < n:
        cur_va = base_vaddr + off
        insn = arm_thumb_decode.decode(code_bytes, off, cur_va, thumb=thumb_mode)
        length = max(2 if thumb_mode else 4, insn.length)

        if isinstance(insn.category, InsnCategory):
            diff_cat: InsnCategory = insn.category
        else:
            diff_cat = InsnCategory(insn.category.value if hasattr(insn.category, "value") else str(insn.category))

        info = InstructionInfo(
            address=cur_va,
            mnemonic=insn.mnemonic,
            op_str=insn.op_str,
            category=diff_cat,
        )
        btype = insn.flow or "none"
        target = insn.target
        is_cond = insn.is_cond
        imm_const = insn.imm
        is_prologue = insn.is_prologue
        is_epilogue = insn.is_epilogue

        decoded_stream.append((off, length, info, btype, target, is_cond, imm_const, is_prologue, is_epilogue))
        valid_addrs.add(cur_va)
        off += length

    if not decoded_stream:
        return []

    stream_addrs = [item[2].address for item in decoded_stream]

    # 2. Discover function entry points
    entry_addrs: Set[int] = {base_vaddr}
    if function_starts:
        end_va = base_vaddr + n
        for fs in function_starts:
            fs_clean = fs & ~1
            if base_vaddr <= fs_clean < end_va:
                if fs_clean not in valid_addrs:
                    idx = bisect.bisect_left(stream_addrs, fs_clean)
                    if idx < len(stream_addrs):
                        fs_clean = stream_addrs[idx]
                entry_addrs.add(fs_clean)

    for idx_s, (i_off, i_len, info, btype, target, is_cond, _, is_prologue, is_epilogue) in enumerate(decoded_stream):
        # Prologues start a function
        if is_prologue and info.address != base_vaddr:
            entry_addrs.add(info.address)

        # Call targets
        if btype == "call" and target is not None:
            tgt_clean = target & ~1
            if tgt_clean in valid_addrs:
                entry_addrs.add(tgt_clean)

        # Epilogue boundary ends a function; next valid instruction starts a candidate function
        if is_epilogue or btype == "ret":
            next_s = idx_s + 1
            while next_s < len(decoded_stream) and decoded_stream[next_s][2].mnemonic in ("nop", "other"):
                s_off, s_len = decoded_stream[next_s][0], decoded_stream[next_s][1]
                if code_bytes[s_off : s_off + s_len] == b"\x00" * s_len:
                    next_s += 1
                elif decoded_stream[next_s][2].mnemonic == "nop":
                    next_s += 1
                else:
                    break
            if next_s < len(decoded_stream):
                entry_addrs.add(decoded_stream[next_s][2].address)

    sorted_entries = sorted(list(entry_addrs))
    cfgs: List[FunctionCFG] = []

    for k, start_pc in enumerate(sorted_entries):
        end_pc = sorted_entries[k + 1] if k + 1 < len(sorted_entries) else (base_vaddr + n)
        if start_pc >= end_pc:
            continue

        start_s_idx = bisect.bisect_left(stream_addrs, start_pc)
        end_s_idx = bisect.bisect_left(stream_addrs, end_pc)
        func_stream = decoded_stream[start_s_idx:end_s_idx]
        if not func_stream:
            continue

        # Exclude trailing padding after last return/terminator within function range
        actual_end_pc = end_pc
        for cur_idx in range(len(func_stream) - 1, -1, -1):
            s_item = func_stream[cur_idx]
            if s_item[3] == "ret" or s_item[8]:  # btype == 'ret' or is_epilogue
                actual_end_pc = s_item[2].address + s_item[1]
                break

        cfg = FunctionCFG(
            func_id=f"func_{start_pc:08x}",
            address=start_pc,
            name=f"sub_{start_pc:08x}",
        )

        # 3. Identify BasicBlock leaders within [start_pc, actual_end_pc)
        leaders: Set[int] = {start_pc}
        for (i_off, i_len, info, btype, target, is_cond, imm_const, _, _) in func_stream:
            cur_pc = info.address
            if cur_pc >= actual_end_pc:
                break
            if target is not None:
                tgt_clean = target & ~1
                if start_pc <= tgt_clean < actual_end_pc:
                    leaders.add(tgt_clean)

            if is_cond:
                fallthrough = cur_pc + i_len
                if fallthrough < actual_end_pc:
                    leaders.add(fallthrough)
            elif btype in ("jmp", "ret", "jmp_ind"):
                fallthrough = cur_pc + i_len
                if fallthrough < actual_end_pc:
                    leaders.add(fallthrough)

        sorted_leaders = sorted(list(leaders))

        # 4. Construct BasicBlocks
        for idx, leader_pc in enumerate(sorted_leaders):
            limit_bb_pc = sorted_leaders[idx + 1] if idx + 1 < len(sorted_leaders) else actual_end_pc
            bb = BasicBlock(start_addr=leader_pc, end_addr=limit_bb_pc)

            bb_s_idx = bisect.bisect_left(stream_addrs, leader_pc)
            while bb_s_idx < len(decoded_stream):
                s_item = decoded_stream[bb_s_idx]
                insn_addr = s_item[2].address
                if insn_addr >= limit_bb_pc:
                    break

                info = s_item[2]
                bb.instructions.append(info)

                # Record constants
                imm_const = s_item[6]
                if imm_const is not None:
                    cfg.constants.add(imm_const)

                btype = s_item[3]
                target = s_item[4]
                if btype == "call" and target is not None:
                    cfg.callees.append(hex(target))

                # Terminator ends the basic block
                is_cond = s_item[5]
                if btype in ("jmp", "ret", "jmp_ind") or is_cond:
                    bb.end_addr = insn_addr + s_item[1]
                    break

                bb_s_idx += 1

            cfg.add_block(bb)

        # 5. Wire edges between basic blocks
        for bb in cfg.blocks.values():
            if not bb.instructions:
                continue
            last_info = bb.instructions[-1]
            last_s_idx = bisect.bisect_left(stream_addrs, last_info.address)
            if last_s_idx >= len(decoded_stream):
                continue
            s_item = decoded_stream[last_s_idx]
            btype = s_item[3]
            target = s_item[4]
            is_cond = s_item[5]

            if is_cond:
                if target is not None:
                    tgt_clean = target & ~1
                    if start_pc <= tgt_clean < actual_end_pc and tgt_clean in cfg.blocks:
                        cfg.add_edge(bb.start_addr, tgt_clean)
                fallthrough = last_info.address + s_item[1]
                if fallthrough < actual_end_pc and fallthrough in cfg.blocks:
                    cfg.add_edge(bb.start_addr, fallthrough)
            elif btype == "jmp":
                if target is not None:
                    tgt_clean = target & ~1
                    if start_pc <= tgt_clean < actual_end_pc and tgt_clean in cfg.blocks:
                        cfg.add_edge(bb.start_addr, tgt_clean)
            elif btype in ("ret", "jmp_ind"):
                pass  # Function return or indirect branch
            else:
                # Fallthrough to subsequent block
                fallthrough = bb.end_addr
                if fallthrough in cfg.blocks:
                    cfg.add_edge(bb.start_addr, fallthrough)

        cfgs.append(cfg)

    return cfgs


CFG_SUPPORTED_ARCHES = ("x86_64", "x86", "arm64", "arm")


def extract_cfgs_from_image(image: binary_loader.BinaryImage) -> List[FunctionCFG]:
    """FunctionCFGs for every executable region of a loaded ELF / PE / Mach-O image.

    Known function starts (PE .pdata, exports, ELF/Mach-O symbols, LC_FUNCTION_STARTS)
    seed function boundaries. Unsupported architectures return [] with a warning rather
    than being decoded with the wrong instruction set.
    """
    if image.arch not in CFG_SUPPORTED_ARCHES:
        logger.warning("CFG extraction not supported for %s (%s); returning no functions",
                       image.arch, image.path or image.format)
        return []
    starts = sorted(set(image.function_starts) | ({image.entry} if image.entry else set()))
    cfgs: List[FunctionCFG] = []

    thumb_funcs: Set[int] = set()
    if image.arch == "arm":
        if getattr(image, "thumb_entry", False) and image.entry:
            thumb_funcs.add(image.entry & ~1)
        for s in image.symbols:
            if s.address & 1:
                thumb_funcs.add(s.address & ~1)
        for e in image.exports:
            if e.address & 1:
                thumb_funcs.add(e.address & ~1)
        default_thumb = getattr(image, "thumb_entry", False) or bool(thumb_funcs)

    for start_va, code in image.code_regions():
        if image.arch == "arm64":
            cfgs.extend(extract_cfgs_from_arm64_bytes(code, base_vaddr=start_va))
        elif image.arch == "arm":
            region_starts = [s & ~1 for s in starts if start_va <= (s & ~1) < start_va + len(code)]
            is_thumb = default_thumb
            cfgs.extend(extract_cfgs_from_arm32_bytes(
                code, base_vaddr=start_va, thumb_mode=is_thumb, function_starts=region_starts
            ))
        else:
            region_starts = [s for s in starts if start_va <= s < start_va + len(code)]
            cfgs.extend(extract_cfgs_from_x86_64_bytes(
                code, base_vaddr=start_va, mode=64 if image.arch == "x86_64" else 32,
                function_starts=region_starts))
    names = {((e.address & ~1) if image.arch == "arm" else e.address): e.name for e in image.exports if e.name and e.forwarder is None}
    names.update({((s.address & ~1) if image.arch == "arm" else s.address): s.name for s in image.symbols if s.kind == "func" and s.name})
    for cfg in cfgs:
        if cfg.address in names:
            cfg.name = names[cfg.address]
    return cfgs


def extract_cfgs_from_binary(
    path_or_bytes: str | bytes,
    base_vaddr: int = 0x100000,
) -> List[FunctionCFG]:
    """
    Loads an ELF / PE / Mach-O file or buffer (any bitness/endianness binary_loader handles)
    and returns FunctionCFGs for x86, x86-64 and ARM64 code. Headerless blobs are treated
    as raw ARM64 code at `base_vaddr`.
    """
    if isinstance(path_or_bytes, str):
        if not os.path.exists(path_or_bytes):
            return []
        with open(path_or_bytes, "rb") as f:
            raw = f.read()
    else:
        raw = path_or_bytes

    if not raw:
        return []

    # 0. Real executable formats go through the shared loader.
    if binary_loader.detect_format(raw) != "raw":
        try:
            image = binary_loader.load_binary(raw)
        except binary_loader.BinaryFormatError as exc:
            logger.debug("binary_loader rejected input (%s); using legacy header sniffing", exc)
            image = None
        if image is not None and image.executable_sections():
            return extract_cfgs_from_image(image)

    # 1. Legacy: minimal/synthetic ELF headers without usable section or segment tables
    if raw.startswith(b"\x7fELF"):
        is_x86_64 = False
        if len(raw) >= 20:
            e_machine = struct.unpack_from("<H", raw, 18)[0]
            is_x86_64 = e_machine == 0x3E

        if len(raw) >= 64:
            try:
                # 64-bit ELF parser
                e_shoff = struct.unpack_from("<Q", raw, 40)[0]
                e_shentsize = struct.unpack_from("<H", raw, 58)[0]
                e_shnum = struct.unpack_from("<H", raw, 60)[0]
                e_shstrndx = struct.unpack_from("<H", raw, 62)[0]

                if e_shoff > 0 and e_shnum > 0 and e_shstrndx < e_shnum:
                    shstr_hdr = e_shoff + (e_shstrndx * e_shentsize)
                    shstr_offset = struct.unpack_from("<Q", raw, shstr_hdr + 24)[0]
                    shstr_size = struct.unpack_from("<Q", raw, shstr_hdr + 32)[0]
                    shstrtab = raw[shstr_offset : shstr_offset + shstr_size]

                    for i in range(e_shnum):
                        sh_entry = e_shoff + (i * e_shentsize)
                        sh_name_idx, sh_type, sh_flags, sh_addr, sh_offset, sh_size = struct.unpack_from(
                            "<IIQQQQ", raw, sh_entry
                        )
                        end_idx = shstrtab.find(b"\x00", sh_name_idx)
                        sec_name = shstrtab[sh_name_idx:end_idx].decode("latin-1", errors="ignore") if end_idx != -1 else ""
                        if sec_name == ".text" and sh_size > 0:
                            text_bytes = raw[sh_offset : sh_offset + sh_size]
                            if is_x86_64:
                                return extract_cfgs_from_x86_64_bytes(
                                    text_bytes, base_vaddr=sh_addr or (base_vaddr if base_vaddr != 0x100000 else 0x401000)
                                )
                            return extract_cfgs_from_arm64_bytes(text_bytes, base_vaddr=sh_addr or base_vaddr)
            except Exception:
                pass
        if len(raw) > 16:
            if is_x86_64:
                hdr_len = 64 if (len(raw) > 64 and raw[20:64] == b"\x00" * 44) else (20 if len(raw) > 20 else 16)
                return extract_cfgs_from_x86_64_bytes(
                    raw[hdr_len:], base_vaddr=base_vaddr if base_vaddr != 0x100000 else 0x401000
                )
            return extract_cfgs_from_arm64_bytes(raw[16:], base_vaddr=base_vaddr)

    # 2. Check for PE32+/PE64 ("MZ")
    if raw.startswith(b"MZ") and len(raw) >= 0x40:
        try:
            e_lfanew = struct.unpack_from("<I", raw, 0x3C)[0]
            if e_lfanew + 24 <= len(raw) and raw[e_lfanew : e_lfanew + 4] == b"PE\x00\x00":
                machine, num_sections, _, _, _, size_opt_hdr, _ = struct.unpack_from(
                    "<HHIIIHH", raw, e_lfanew + 4
                )
                image_base = 0x140000000 if machine in (0x8664, 0xAA64) else base_vaddr
                if size_opt_hdr >= 32 and (e_lfanew + 24 + size_opt_hdr) <= len(raw):
                    opt_magic = struct.unpack_from("<H", raw, e_lfanew + 24)[0]
                    if opt_magic == 0x20B and size_opt_hdr >= 32:
                        image_base = struct.unpack_from("<Q", raw, e_lfanew + 24 + 24)[0]
                    elif opt_magic == 0x10B and size_opt_hdr >= 32:
                        image_base = struct.unpack_from("<I", raw, e_lfanew + 24 + 28)[0]

                sec_table_off = e_lfanew + 24 + size_opt_hdr
                for i in range(num_sections):
                    sh_off = sec_table_off + i * 40
                    if sh_off + 40 > len(raw):
                        break
                    sec_name = raw[sh_off : sh_off + 8].rstrip(b"\x00").decode("latin-1", errors="ignore")
                    vsize, vaddr, raw_size, raw_ptr = struct.unpack_from("<IIII", raw, sh_off + 8)
                    if sec_name == ".text":
                        actual_size = vsize if (0 < vsize <= raw_size) else (raw_size if raw_size > 0 else vsize)
                        text_bytes = raw[raw_ptr : raw_ptr + actual_size]
                        sec_vaddr = (image_base + vaddr) if vaddr else base_vaddr
                        if machine == 0xAA64:
                            return extract_cfgs_from_arm64_bytes(text_bytes, base_vaddr=sec_vaddr)
                        return extract_cfgs_from_x86_64_bytes(text_bytes, base_vaddr=sec_vaddr)
        except Exception:
            pass

    return extract_cfgs_from_arm64_bytes(raw, base_vaddr=base_vaddr)


# --- Synthetic Binary Generator for Testing & Diff Verification ---

def create_synthetic_function(
    func_id: str,
    address: int,
    num_blocks: int = 5,
    instruction_profile: str = "balanced",
    seed: int | None = None,
    name: str = "",
) -> FunctionCFG:
    """Constructs a deterministic synthetic function CFG for diff validation."""
    rng = np.random.RandomState(seed if seed is not None else address & 0xFFFFFFFF)
    cfg = FunctionCFG(func_id=func_id, address=address, name=name)

    block_addrs = [address + (i * 0x40) for i in range(num_blocks)]

    for i, b_addr in enumerate(block_addrs):
        bb = BasicBlock(start_addr=b_addr, end_addr=b_addr + 0x3C)
        insn_count = rng.randint(4, 12)

        for insn_idx in range(insn_count):
            insn_pc = b_addr + (insn_idx * 4)
            if instruction_profile == "crypto":
                mnems = ["eor", "and", "orr", "add", "lsl", "lsr", "ldr"]
            elif instruction_profile == "memory":
                mnems = ["ldr", "ldp", "str", "stp", "add", "cmp"]
            elif instruction_profile == "float":
                mnems = ["fadd", "fmul", "fdiv", "fmov", "ldr", "str"]
            else:
                mnems = ["add", "sub", "ldr", "str", "cmp", "b.eq", "b.ne", "mov", "bl"]

            mnem = rng.choice(mnems)
            bb.instructions.append(InstructionInfo.create(address=insn_pc, mnemonic=mnem))

        # Add terminator
        if i == num_blocks - 1:
            bb.instructions.append(InstructionInfo.create(address=b_addr + 0x3C, mnemonic="ret"))
        else:
            bb.instructions.append(InstructionInfo.create(address=b_addr + 0x3C, mnemonic="b.eq"))

        cfg.add_block(bb)

    # Wire edges: linear backbone + diamond branches / loop
    for i in range(num_blocks - 1):
        cfg.add_edge(block_addrs[i], block_addrs[i + 1])
        if i + 2 < num_blocks and rng.rand() > 0.5:
            cfg.add_edge(block_addrs[i], block_addrs[i + 2])
        if i > 0 and rng.rand() > 0.7:  # Loop back-edge
            cfg.add_edge(block_addrs[i], block_addrs[0])

    return cfg


def generate_paired_synthetic_binaries(
    num_funcs: int = 100,
    mutation_rate: float = 0.2,
    seed: int = 42,
) -> Tuple[List[FunctionCFG], List[FunctionCFG]]:
    """
    Generates two versions of a binary (Binary A and stripped/mutated Binary B)
    to validate cross-version function diffing and pairing accuracy.
    """
    rng = np.random.RandomState(seed)
    funcs_a: List[FunctionCFG] = []
    funcs_b: List[FunctionCFG] = []

    profiles = ["balanced", "crypto", "memory", "float"]

    for idx in range(num_funcs):
        base_addr_a = 0x10000000 + (idx * 0x1000)
        base_addr_b = 0x20000000 + (idx * 0x1000)
        n_blocks = rng.randint(3, 10)
        profile = rng.choice(profiles)
        func_name = f"Function_{profile}_{idx}"

        # Function in Version A
        fa = create_synthetic_function(
            func_id=f"fa_{idx:04d}",
            address=base_addr_a,
            num_blocks=n_blocks,
            instruction_profile=profile,
            seed=1000 + idx,
            name=func_name,
        )
        funcs_a.append(fa)

        # Function in Version B (stripped name, slightly mutated if mutation occurs)
        mutated_blocks = n_blocks
        if rng.rand() < mutation_rate:
            mutated_blocks = max(2, n_blocks + rng.choice([-1, 1]))

        fb = create_synthetic_function(
            func_id=f"fb_{idx:04d}",
            address=base_addr_b,
            num_blocks=mutated_blocks,
            instruction_profile=profile,
            seed=1000 + idx,  # Identical seed for base instructions
            name=f"sub_{base_addr_b:x}",  # Stripped symbol
        )
        funcs_b.append(fb)

    # Shuffle Version B to simulate stripped non-contiguous binary ordering
    rng.shuffle(funcs_b)
    return funcs_a, funcs_b


if __name__ == "__main__":
    print("=== SuperGhidra Binary Diffing Engine Demo ===")
    num_funcs = 250
    print(f"Generating synthetic binaries with {num_funcs} functions...")
    bin_a, bin_b = generate_paired_synthetic_binaries(num_funcs=num_funcs, mutation_rate=0.15, seed=123)

    matcher = BatchedBinaryMatcher(threshold=0.80, use_gpu=True)
    print(f"Running batched diff (GPU acceleration: {matcher.use_gpu})...")

    result = matcher.diff_binaries(bin_a, bin_b, strategy="mutual")
    print(f"Diff execution time:  {result.execution_time_ms:.2f} ms")
    print(f"Matched pairs:        {len(result.matches)} / {num_funcs} ({result.match_rate_pct:.1f}%)")
    print(f"Average similarity:   {result.avg_similarity:.4f}")
    print(f"Unmatched in A:       {len(result.unmatched_a)}")
    print(f"Unmatched in B:       {len(result.unmatched_b)}")

    # Display sample top matches
    print("\nSample paired functions:")
    for match in result.matches[:5]:
        print(f"  {match.func_a_name} ({match.func_a_id}) <==> {match.func_b_name} ({match.func_b_id}) "
              f"[Sim: {match.similarity:.4f}, Conf: {match.confidence}]")
