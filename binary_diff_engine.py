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
import json
import math
import time
from typing import Any, Dict, List, Optional, Set, Tuple, Union

import numpy as np

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
    "lsl": InsnCategory.LOGICAL, "lsr": InsnCategory.LOGICAL,
    "asr": InsnCategory.LOGICAL, "mvn": InsnCategory.LOGICAL,
    "ldr": InsnCategory.MEMORY_LOAD, "ldp": InsnCategory.MEMORY_LOAD,
    "ldrb": InsnCategory.MEMORY_LOAD, "ldrh": InsnCategory.MEMORY_LOAD,
    "str": InsnCategory.MEMORY_STORE, "stp": InsnCategory.MEMORY_STORE,
    "strb": InsnCategory.MEMORY_STORE, "strh": InsnCategory.MEMORY_STORE,
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
    
    # x86_64
    "mov": InsnCategory.MEMORY_LOAD, "lea": InsnCategory.ARITHMETIC,
    "push": InsnCategory.MEMORY_STORE, "pop": InsnCategory.MEMORY_LOAD,
    "jmp": InsnCategory.BRANCH_UNCOND, "je": InsnCategory.BRANCH_COND,
    "jne": InsnCategory.BRANCH_COND, "jl": InsnCategory.BRANCH_COND,
    "jle": InsnCategory.BRANCH_COND, "jg": InsnCategory.BRANCH_COND,
    "jge": InsnCategory.BRANCH_COND, "call": InsnCategory.CALL,
    "test": InsnCategory.COMPARE, "xor": InsnCategory.LOGICAL,
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


# --- Synthetic Binary Generator for Testing & Diff Verification ---

def create_synthetic_function(
    func_id: str,
    address: int,
    num_blocks: int = 5,
    instruction_profile: str = "balanced",
    seed: Optional[int] = None,
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
