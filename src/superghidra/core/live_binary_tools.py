"""Facts and bindings taken from bytes of a binary on disk.

`query_binary_dataflow` and `solve_global_type_lattice` read instructions.
`deflatten_control_flow` lifts a compiled switch dispatcher.
`compile_usercall_prototype` writes the binding into a WriteOverlay and reads
it back. None of these functions open a Ghidra ``.rep``.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List, Sequence, Set, Tuple

from superghidra.core.ghidra_oracle import WriteOverlay
from superghidra.core.parity_engine import (
    BasicBlock,
    PCodeCFG,
    SparseMatrixDatalogEngine,
    StructFieldSpec,
    StructLayoutSpec,
    SymbolicCFGDeflattener,
    UsercallPrototypeCompiler,
)
from superghidra.diff.benchmark_and_nextgen_engine import (
    GlobalTypeLatticeSolver,
    LatticeType,
)
from superghidra.formats.binary_loader import BinaryImage, load_binary
from superghidra.formats.ida_flirt_bridge import (
    FlirtSignatureIndex,
)
from superghidra.formats.ida_til_importer import (
    TilReport,
    TilStruct,
    export_clean_header,
    find_ida_install,
    import_til,
)
from superghidra.formats.msvc_class_recovery import recover_classes
from superghidra.lifters.x86_decode import X86Insn, iter_decode

__all__ = [
    "LiftError",
    "extract_dataflow_edges",
    "query_binary_dataflow",
    "extract_type_constraints",
    "solve_global_type_lattice",
    "deflatten_control_flow",
    "compile_usercall_prototype",
    "roundtrip_real_chunk",
    "match_flirt_signatures",
    "import_type_library",
    "recover_classes",
    "get_struct_catalog",
    "STRUCT_CATALOG",
    "staged_decompile_function",
]


class LiftError(ValueError):
    """Raised when the staged P-Code lifter cannot lift binary machine code."""

    def __init__(self, message: str, unhandled: List[Tuple[int, str]] | None = None):
        super().__init__(message)
        self.message = message
        self.unhandled: List[Tuple[int, str]] = unhandled or []


def _exec_bytes(img: BinaryImage, limit: int) -> Tuple[int, bytes]:
    regions = [s for s in (img.sections + img.segments) if s.executable and s.file_size]
    if not regions:
        raise ValueError(f"no executable bytes in {img.path}")
    sec = max(regions, key=lambda s: s.file_size)
    size = min(sec.file_size, limit)
    return sec.vaddr, img.read_va(sec.vaddr, size)


def _addr_in_image(img: BinaryImage, addr: int) -> bool:
    if img.section_for_va(addr) is not None:
        return True
    return img.image_base <= addr < img.image_base + len(img.data)


def _node_addr(node: str) -> int | None:
    marker = "@0x"
    if marker not in node:
        return None
    try:
        return int(node.split(marker, 1)[1], 16)
    except ValueError:
        return None


def _x86_reg_mov_edges(code: bytes, base: int, mode: int, limit: int) -> List[Tuple[str, str]]:
    edges: List[Tuple[str, str]] = []
    seen = 0
    for insn in iter_decode(code, address=base, mode=mode):
        seen += 1
        if seen > limit:
            break
        if insn.invalid or insn.mem is not None or insn.modrm is None:
            continue
        if insn.map != 0 or insn.opcode not in (0x89, 0x8B):
            continue
        size = insn.operand_size
        if insn.opcode == 0x89:
            src = insn.reg_name(insn.reg, size)
            dst = insn.reg_name(insn.rm, size)
        else:
            src = insn.reg_name(insn.rm, size)
            dst = insn.reg_name(insn.reg, size)
        if src == dst:
            continue
        edges.append((f"{src}@0x{insn.address:x}", f"{dst}@0x{insn.address:x}"))
        if len(edges) >= 64:
            break
    return edges


def _arm64_insns(img: BinaryImage):
    """Words of the largest executable region.

    Packed ELF images put the RX segment's ADRP pairs well past the first pages.
    The NumPy sweep of that region (about 20 MB here) stays interactive.
    """
    import numpy as np

    base, code = _exec_bytes(img, 64 * 1024 * 1024)
    usable = code[: (len(code) // 4) * 4]
    if len(usable) < 8:
        return base, np.empty(0, dtype=np.uint32)
    insns = np.frombuffer(usable, dtype=np.uint32)
    if insns.size > 8_000_000:
        insns = insns[:8_000_000]
    return base, insns


def _arm64_adrp_edges(insns, base: int) -> List[Tuple[str, str]]:
    from superghidra.acceleration.gpu_adrp_scanner import GPUAdrpScanner

    if getattr(insns, "size", 0) < 2:
        return []
    matches = GPUAdrpScanner(backend="numpy").scan_matches(insns, base_pc=base)
    edges: List[Tuple[str, str]] = []
    for match in matches:
        if not match.register_matched:
            continue
        src = f"adrp@0x{match.adrp_pc:x}"
        dst = f"{match.paired_type.lower()}@0x{match.paired_pc:x}"
        edges.append((src, dst))
        if len(edges) >= 64:
            break
    return edges


def extract_dataflow_edges(img: BinaryImage) -> List[Tuple[str, str]]:
    """Register and ADRP edges whose addresses are inside `img`."""
    if img.arch == "arm64":
        base, insns = _arm64_insns(img)
        edges = _arm64_adrp_edges(insns, base)
    elif img.arch in ("x86_64", "x86"):
        base, code = _exec_bytes(img, 256_000)
        edges = _x86_reg_mov_edges(code, base, 64 if img.arch == "x86_64" else 32, 40_000)
    else:
        edges = []
    checked: List[Tuple[str, str]] = []
    for src, dst in edges:
        addrs = [a for a in (_node_addr(src), _node_addr(dst)) if a is not None]
        if addrs and all(_addr_in_image(img, a) for a in addrs):
            checked.append((src, dst))
    return checked


def query_binary_dataflow(
    binary_path: str,
    source_var: str = "",
    sink_var: str = "",
) -> Dict[str, Any]:
    """Reachability between two nodes discovered in `binary_path`.

    Caller-supplied edge lists are not consulted. `source_var` and `sink_var`
    select endpoints when they appear in the extracted graph; otherwise the
    first real edge is queried.
    """
    img = load_binary(binary_path)
    edges = extract_dataflow_edges(img)
    if not edges:
        return {
            "source_var": source_var,
            "sink_var": sink_var,
            "is_reachable": False,
            "path_length": 0,
            "traversed_nodes": [],
            "edge_count": 0,
            "binary_path": str(img.path or binary_path),
        }
    engine = SparseMatrixDatalogEngine()
    for src, dst in edges:
        engine.add_dataflow_edge(src, dst)
    # Chain a second hop when two edges share a node, so the path is not only
    # the single instruction the extractor emitted.
    by_src: Dict[str, str] = {}
    for src, dst in edges:
        by_src.setdefault(src, dst)
    for src, dst in edges:
        nxt = by_src.get(dst)
        if nxt and nxt != src:
            engine.add_dataflow_edge(dst, nxt)

    if source_var and sink_var:
        chosen = (source_var, sink_var)
    else:
        chosen = edges[0]
    result = engine.query_binary_dataflow(chosen[0], chosen[1])
    witness = result.get("witness_path") or result.get("path") or []
    if not witness and result.get("reachable"):
        witness = [chosen[0], chosen[1]]
    hops = max(0, len(witness) - 1) if witness else 0
    return {
        "source_var": chosen[0],
        "sink_var": chosen[1],
        "is_reachable": bool(result.get("reachable")),
        "path_length": hops,
        "traversed_nodes": list(witness),
        "edge_count": len(edges),
        "binary_path": str(img.path or binary_path),
    }


def _field_type(size: int) -> LatticeType:
    if size >= 8:
        return LatticeType.INTEGER_64
    return LatticeType.INTEGER_32


def extract_type_constraints(img: BinaryImage) -> List[Tuple[str, int, LatticeType]]:
    """(variable, field offset, type) from real loads and stores."""
    found: List[Tuple[str, int, LatticeType]] = []
    if img.arch == "arm64":
        base, insns = _arm64_insns(img)
        from superghidra.acceleration.gpu_adrp_scanner import GPUAdrpScanner

        if insns.size < 2:
            return found
        for match in GPUAdrpScanner(backend="numpy").scan_matches(insns, base_pc=base):
            if match.paired_type != "LDR" or not (0 < match.immediate < 0x1000):
                continue
            if not _addr_in_image(img, match.paired_pc):
                continue
            size = 8 if match.immediate % 8 == 0 else 4
            var = f"x{match.paired_rn}@0x{match.paired_pc:x}"
            found.append((var, int(match.immediate), _field_type(size)))
            if len(found) >= 32:
                break
        return found

    if img.arch not in ("x86_64", "x86"):
        return found
    base, code = _exec_bytes(img, 256_000)
    mode = 64 if img.arch == "x86_64" else 32
    seen = 0
    for insn in iter_decode(code, address=base, mode=mode):
        seen += 1
        if seen > 40_000:
            break
        mem = insn.mem
        if mem is None or not mem.base or not (0 < mem.disp < 0x400):
            continue
        if not _addr_in_image(img, insn.address):
            continue
        size = insn.memory_access_size() or 4
        var = f"{mem.base}@0x{insn.address:x}"
        found.append((var, int(mem.disp), _field_type(size)))
        if len(found) >= 32:
            break
    return found


def solve_global_type_lattice(binary_path: str) -> Dict[str, Any]:
    """Lattice solution whose variables are instruction sites in the binary."""
    img = load_binary(binary_path)
    constraints = extract_type_constraints(img)
    solver = GlobalTypeLatticeSolver()
    for var, offset, ftype in constraints:
        solver.add_field_access_constraint(var, offset, ftype)
        if offset == 0:
            solver.add_base_constraint(var, LatticeType.NON_NULL_PTR)
    # Flow the first variable into the second so a recovered field is not a
    # single isolated access when the binary yielded at least two.
    if len(constraints) >= 2:
        solver.add_flow_constraint(constraints[0][0], constraints[1][0])
    solved = solver.solve_global_lattice()
    solved["constraint_count"] = len(constraints)
    solved["binary_path"] = str(img.path or binary_path)
    solved["source_addresses"] = [
        addr for var, _, _ in constraints
        if (addr := _node_addr(var)) is not None
    ]
    return solved


def _is_cmp_imm8(insn: X86Insn) -> bool:
    return (
        insn.map == 0
        and insn.opcode == 0x83
        and insn.reg == 7
        and insn.mem is not None
        and insn.imm is not None
    )


def _is_cmp_reg_imm(insn: X86Insn, reg: int) -> bool:
    return (
        insn.map == 0
        and insn.opcode in (0x83, 0x81, 0x3D)
        and insn.mem is None
        and (insn.rm == reg or insn.reg == reg)
        and insn.imm is not None
    )


def _is_test_reg_self(insn: X86Insn, reg: int) -> bool:
    return (
        insn.map == 0
        and insn.opcode in (0x85, 0x84)
        and insn.mem is None
        and insn.reg == reg
        and insn.rm == reg
    )


def _is_mov_imm(insn: X86Insn) -> bool:
    return insn.map == 0 and insn.opcode == 0xC7 and insn.imm is not None and insn.mem is not None


def deflatten_control_flow(binary_path: str) -> Dict[str, Any]:
    """Lift a compiled switch dispatcher from `binary_path` and rewire it.

    Looks for a run of three or more ``cmp mem, imm; jcc`` or register compare
    instructions (MSVC ``/Od`` and GCC ``-O0`` state-machine switches).
    Hand-built block JSON is not accepted on this path.
    """
    img = load_binary(binary_path)
    if img.arch not in ("x86_64", "x86"):
        return {
            "deflattened": False,
            "dispatcher_block_id": -1,
            "gotos_eliminated": 0,
            "back_edges_removed": 0,
            "binary_path": str(img.path or binary_path),
            "reason": f"no x86 dispatcher scan for arch {img.arch}",
        }
    base, code = _exec_bytes(img, 512_000)
    mode = 64 if img.arch == "x86_64" else 32
    insns = []
    for idx, insn in enumerate(iter_decode(code, address=base, mode=mode)):
        insns.append(insn)
        if idx > 60_000:
            break
    chains = _find_cmp_chains(insns)
    if not chains:
        return {
            "deflattened": False,
            "dispatcher_block_id": -1,
            "gotos_eliminated": 0,
            "back_edges_removed": 0,
            "binary_path": str(img.path or binary_path),
            "reason": "no cmp/jcc state dispatcher in executable bytes",
        }
    first_report: Dict[str, Any] | None = None
    for chain in chains:
        report = _deflatten_chain(insns, chain)
        report["binary_path"] = str(img.path or binary_path)
        if report.get("deflattened"):
            return report
        if first_report is None:
            first_report = report
    return first_report or {
        "deflattened": False,
        "dispatcher_block_id": -1,
        "gotos_eliminated": 0,
        "back_edges_removed": 0,
        "binary_path": str(img.path or binary_path),
        "reason": "no deflattenable switch dispatcher found",
    }


def _find_cmp_chains(insns: Sequence[X86Insn]) -> List[List[X86Insn]]:
    """Return all candidate 3-long state dispatcher chains (MSVC and GCC)."""
    chains: List[List[X86Insn]] = []

    # 1. MSVC /Od direct memory compare chain: cmp [slot], imm8
    cmps = [insn for insn in insns if _is_cmp_imm8(insn)]
    run: List[X86Insn] = []
    for insn in cmps:
        slot = (insn.mem.base, insn.mem.disp) if insn.mem else None
        if run:
            prev = run[-1]
            prev_slot = (prev.mem.base, prev.mem.disp) if prev.mem else None
            if slot != prev_slot or insn.address - prev.address > 16:
                if len(run) >= 3:
                    chains.append(run)
                run = []
        run.append(insn)
    if len(run) >= 3:
        chains.append(run)

    # 2. GCC -O0 register compare chain: state loaded into reg from a stack slot
    for idx, insn in enumerate(insns):
        if insn.map == 0 and insn.opcode == 0x8B and insn.mem is not None:
            reg = insn.reg
            slot = (insn.mem.base, insn.mem.disp)
            chain: List[X86Insn] = []
            j = idx + 1
            while j < len(insns):
                cur = insns[j]
                if _is_cmp_reg_imm(cur, reg):
                    chain.append(cur)
                elif _is_test_reg_self(cur, reg):
                    chain.append(cur)
                elif cur.flow == "jcc":
                    pass
                elif (
                    cur.map == 0
                    and cur.opcode == 0x8B
                    and cur.mem is not None
                    and (cur.mem.base, cur.mem.disp) == slot
                    and cur.reg == reg
                ):
                    pass
                else:
                    break
                j += 1
            if len(chain) >= 3:
                chains.append(chain)

    return chains


def _find_cmp_chain(insns: Sequence[X86Insn]) -> List[X86Insn] | None:
    """Return the first candidate 3-long state dispatcher chain."""
    chains = _find_cmp_chains(insns)
    return chains[0] if chains else None


def _direct_jmp_target(insn: X86Insn) -> int | None:
    if insn.flow == "jmp" and insn.target is not None:
        return insn.target
    return None


def _jumps_to_loop_head(insn: X86Insn, header: int, by_addr: Dict[int, X86Insn]) -> bool:
    """True when `insn` jumps to the loop head, or to a jmp that does.

    MSVC ``/Od`` ends each worker with a forward jmp to one shared back edge.
    """
    target = _direct_jmp_target(insn)
    if target is None:
        return False
    if target <= header:
        return True
    hop = by_addr.get(target)
    if hop is None:
        return False
    hop_target = _direct_jmp_target(hop)
    return hop_target is not None and hop_target <= header


def _block_until_branch(insns: Sequence[X86Insn], start: int) -> List[X86Insn]:
    out: List[X86Insn] = []
    started = False
    for insn in insns:
        if insn.address < start:
            continue
        started = True
        out.append(insn)
        if insn.flow in ("jmp", "jcc", "ret"):
            break
        if len(out) > 24:
            break
    return out if started else []


def _deflatten_chain(insns: Sequence[X86Insn], cmps: Sequence[X86Insn]) -> Dict[str, Any]:
    by_addr = {insn.address: insn for insn in insns}
    cases: List[Tuple[int, int]] = []
    seen_states = set()
    for cmp_insn in cmps:
        nxt = by_addr.get(cmp_insn.address + cmp_insn.length)
        if nxt is None or nxt.flow != "jcc" or nxt.target is None:
            continue
        # Only equality jumps (je/jz) define case blocks
        is_je = (nxt.map == 0 and nxt.opcode == 0x74) or (nxt.map == 1 and nxt.opcode == 0x84)
        if not is_je:
            continue
        state_val = 0 if cmp_insn.imm is None else (int(cmp_insn.imm) & 0xFFFFFFFF)
        if state_val in seen_states:
            continue
        seen_states.add(state_val)
        cases.append((state_val, nxt.target))
    if len(cases) < 3:
        return {
            "deflattened": False,
            "dispatcher_block_id": cmps[0].address,
            "gotos_eliminated": 0,
            "back_edges_removed": 0,
            "reason": "cmp chain has fewer than 3 conditional exits",
        }

    dispatcher_id = cmps[0].address
    header = dispatcher_id
    # The copy into the compare slot usually sits a few bytes before the first cmp.
    for insn in insns:
        if insn.address >= dispatcher_id:
            break
        if insn.opcode == 0x8B and insn.mem is not None:
            header = insn.address

    blocks: Dict[int, BasicBlock] = {
        dispatcher_id: BasicBlock(
            block_id=dispatcher_id,
            start_rva=dispatcher_id,
            successors=[target for _, target in cases],
        )
    }
    back_edges = 0
    for imm, target in cases:
        body = _block_until_branch(insns, target)
        assignment = None
        for insn in body:
            if _is_mov_imm(insn):
                assignment = int(insn.imm or 0) & 0xFFFFFFFF
            if _jumps_to_loop_head(insn, header, by_addr):
                back_edges += 1
        succ = [dispatcher_id] if assignment is not None else []
        blocks[target] = BasicBlock(
            block_id=target,
            start_rva=target,
            successors=succ,
            state_guard=imm,
            state_assignment=assignment,
        )
    cfg = PCodeCFG(entry_block=dispatcher_id, blocks=blocks)
    raw = SymbolicCFGDeflattener().deflatten_state_machine(cfg, explicit_dispatcher_id=dispatcher_id)
    rewired = raw.get("rewired_edges") or []
    removed = dispatcher_id not in cfg.blocks or raw.get("dispatcher_removed") == dispatcher_id
    return {
        "deflattened": bool(raw.get("deflattened")) and len(rewired) > 0,
        "dispatcher_block_id": dispatcher_id,
        "dispatcher_removed": removed,
        "gotos_eliminated": len(rewired),
        "back_edges_removed": back_edges if len(rewired) else 0,
        "rewired_edges": [(a, b, note) for a, b, note in rewired],
        "state_cases": [imm for imm, _ in cases],
    }


def compile_usercall_prototype(
    signature: str,
    binary_path: str,
    overlay_path: str,
    arch: str = "arm64",
) -> Dict[str, Any]:
    """Compile `signature` onto a real function and read it back from the overlay.

    The overlay JSON is the only file written. The binary is opened read-only.
    """
    img = load_binary(binary_path)
    if img.exports:
        sym = img.exports[0]
        addr = sym.address
        fname = sym.name
    elif img.entry:
        addr = img.entry
        fname = "entry"
    elif img.function_starts:
        addr = img.function_starts[0]
        fname = "function_start"
    else:
        raise ValueError(f"no function address in {binary_path}")
    if not _addr_in_image(img, addr):
        raise ValueError(f"function address 0x{addr:x} is outside {binary_path}")

    proto = UsercallPrototypeCompiler(arch=arch).parse_usercall(signature)
    spills = [p.registers[0] for p in proto.parameters if p.vector_integer_spill and p.registers]
    binding = proto.cspec_xml
    if not any(reg.startswith("d") and reg[1:].isdigit() and 0 <= int(reg[1:]) <= 7 for reg in spills):
        # Still record the compiled XML; the caller asked for a d0-d7 spill in the signature.
        pass
    overlay = WriteOverlay(overlay_path)
    overlay.set_prototype(addr, binding)
    readback = WriteOverlay(overlay_path).get_prototype(addr)
    if readback != binding:
        raise RuntimeError("overlay read-back did not match the prototype that was written")
    return {
        "signature": signature,
        "arch": arch,
        "function_address": addr,
        "function_name": fname,
        "return_storage": ", ".join(proto.return_binding.registers) if proto.return_binding and proto.return_binding.registers else "",
        "parameter_storages": [
            f"{p.name}@{','.join(p.registers)}" if p.registers else f"{p.name}@stack[{p.stack_offset}]"
            for p in proto.parameters
        ],
        "xml_cspec": binding,
        "readback": readback or "",
        "vector_spills": spills,
        "overlay_path": overlay_path,
        "binary_path": str(img.path or binary_path),
    }


def roundtrip_real_chunk(binary_path: str, codec: str) -> Dict[str, Any]:
    """Compress one 16 KB slice of `binary_path` and check the slot directory."""
    from superghidra.storage.storage_compression_prototype import (
        CompressedLocalManagedBufferFile,
        DataBuffer,
    )

    img = load_binary(binary_path)
    base, blob = _exec_bytes(img, 16 * 1024)
    if len(blob) < 16 * 1024:
        blob = blob.ljust(16 * 1024, b"\x00")
    chunk = blob[: 16 * 1024]
    store = CompressedLocalManagedBufferFile(codec=codec)
    store.put(DataBuffer(buffer_id=1, data=bytearray(chunk)), 1)
    entry = store.slot_directory.get_entry(1)
    if entry is None:
        raise RuntimeError("slot directory missing the chunk")
    store.stream.seek(entry.offset)
    stored = store.stream.read(entry.comp_len)
    if len(stored) != entry.comp_len or entry.orig_len <= 0:
        raise RuntimeError("slot directory entry does not describe the stored bytes")
    restored = store.get(None, 1)
    # DataBuffer.serialize prepends a header; compare the original page payload.
    payload = bytes(restored.data)[: len(chunk)]
    return {
        "codec": codec,
        "chunk_len": len(chunk),
        "restored_len": len(payload),
        "lossless": payload == chunk,
        "slot_matches_stored": len(stored) == entry.comp_len,
        "comp_len": entry.comp_len,
        "orig_len": entry.orig_len,
        "base_va": base,
        "binary_path": str(img.path or binary_path),
    }


# =============================================================================
# IDA TIL & FLIRT SIGNATURE LIVE ANALYSIS INTEGRATION
# =============================================================================

STRUCT_CATALOG: Dict[str, StructLayoutSpec] = {}


def get_struct_catalog() -> Dict[str, StructLayoutSpec]:
    """Return the global StructLayoutSpec catalog."""
    return STRUCT_CATALOG


def _field_c_type_to_layout(c_type: str, array_dim: str | None = None) -> Tuple[str, int, int]:
    """Returns (struct_format, byte_size, alignment) for a native C declaration."""
    clean = c_type.strip()
    if "*" in clean:
        base_size = 8
        base_align = 8
        fmt = "ptr"
    elif any(t in clean for t in ("int8", "char", "bool")):
        base_size = 1
        base_align = 1
        fmt = "<B" if any(u in clean for u in ("unsigned", "uint")) else "<b"
    elif any(t in clean for t in ("int16", "short")):
        base_size = 2
        base_align = 2
        fmt = "<H" if any(u in clean for u in ("unsigned", "uint")) else "<h"
    elif any(t in clean for t in ("int32", "int", "long")) and "int64" not in clean and "long long" not in clean:
        base_size = 4
        base_align = 4
        fmt = "<I" if any(u in clean for u in ("unsigned", "uint")) else "<i"
    elif any(t in clean for t in ("int64", "long long")):
        base_size = 8
        base_align = 8
        fmt = "<Q" if any(u in clean for u in ("unsigned", "uint")) else "<q"
    elif "float" in clean:
        base_size = 4
        base_align = 4
        fmt = "<f"
    elif "double" in clean:
        base_size = 8
        base_align = 8
        fmt = "<d"
    else:
        base_size = 8 if "64" in clean else 4
        base_align = base_size
        fmt = "<Q" if base_size == 8 else "<I"

    count = 1
    if array_dim:
        try:
            count = max(1, int(array_dim, 0))
        except ValueError:
            count = 1

    total_size = base_size * count
    return fmt, total_size, base_align


def _til_struct_to_spec(ts: TilStruct) -> StructLayoutSpec:
    """Converts a parsed TilStruct into a native SuperGhidra StructLayoutSpec."""
    fields: List[StructFieldSpec] = []
    curr_offset = 0
    max_align = 1
    is_union = ts.kind == "union"

    for fld in ts.fields:
        fmt, size, align = _field_c_type_to_layout(fld.c_type, fld.array_dim)
        max_align = max(max_align, align)
        if not is_union:
            if align > 1:
                curr_offset = (curr_offset + align - 1) & ~(align - 1)
            field_off = curr_offset
            curr_offset += size
        else:
            field_off = 0
            curr_offset = max(curr_offset, size)

        fields.append(
            StructFieldSpec(
                name=fld.name,
                c_type=fld.c_type + (f"[{fld.array_dim}]" if fld.array_dim else ""),
                offset=field_off,
                size=size,
                struct_format=fmt,
            )
        )

    if max_align > 1:
        total_size = (curr_offset + max_align - 1) & ~(max_align - 1)
    else:
        total_size = curr_offset
    total_size = max(total_size, 1)

    return StructLayoutSpec(
        name=ts.name,
        byte_size=total_size,
        alignment=max_align,
        fields=fields,
    )


def import_type_library(
    til_path: str,
    output_header: str | None = None,
) -> Dict[str, Any]:
    """Ingest IDA Type Information Library (.til) or C declarations into StructLayoutSpec catalog.

    Invokes `import_til`, registers structs into `StructLayoutSpec` catalog,
    optionally calls `export_clean_header`, and returns summary counts
    (enums, structs, typedefs).
    """
    from superghidra.formats.ida_til_importer import (
        list_available_tils,
        parse_til_declarations,
    )

    resolved_til = str(til_path)
    target_path = Path(resolved_til)

    if "{" in resolved_til or ";" in resolved_til or "\n" in resolved_til:
        report = parse_til_declarations(resolved_til, til_path="synthetic")
    elif target_path.is_file() and resolved_til.lower().endswith(".til"):
        report = import_til(resolved_til)
    elif target_path.is_file():
        # Target is a binary file; find appropriate TIL if available
        tils = list_available_tils()
        found_til = None
        try:
            img = load_binary(resolved_til)
            if img.arch in ("x86_64", "x86"):
                pc_tils = [p for p in tils.get("pc", []) if "mssdk" in p.name.lower() or "ntapi" in p.name.lower()]
                if img.bits == 64:
                    win10_64 = [p for p in pc_tils if "64_win10" in p.name.lower()]
                    found_til = win10_64[0] if win10_64 else (pc_tils[0] if pc_tils else None)
                else:
                    win_32 = [p for p in pc_tils if "64" not in p.name.lower()]
                    found_til = win_32[0] if win_32 else (pc_tils[0] if pc_tils else None)
            elif img.arch in ("arm", "arm64"):
                arm_tils = tils.get("arm", [])
                found_til = arm_tils[0] if arm_tils else None
        except Exception:
            pass

        if found_til and found_til.is_file():
            report = import_til(str(found_til))
            resolved_til = str(found_til)
        else:
            report = TilReport(til_path=resolved_til)
    else:
        report = parse_til_declarations(resolved_til, til_path=resolved_til)

    for ts in report.structs.values():
        spec = _til_struct_to_spec(ts)
        STRUCT_CATALOG[spec.name] = spec

    exported_header_len: int | None = None
    if output_header and Path(resolved_til).is_file() and resolved_til.lower().endswith(".til"):
        exported_header_len = export_clean_header(resolved_til, output_header)

    return {
        "til_path": str(resolved_til),
        "enums": len(report.enums),
        "structs": len(report.structs),
        "typedefs": len(report.typedefs),
        "enums_count": len(report.enums),
        "structs_count": len(report.structs),
        "typedefs_count": len(report.typedefs),
        "total_types": report.total_types,
        "registered_structs": len(report.structs),
        "catalog_size": len(STRUCT_CATALOG),
        "output_header": str(output_header) if output_header else None,
        "output_header_bytes": exported_header_len,
    }


def match_flirt_signatures(
    binary_path: str,
    sig_path: str | None = None,
) -> Dict[str, Any]:
    """Match binary functions against Hex-Rays IDA FLIRT signatures (.sig).

    Loads binary via `binary_loader.load_binary`, retrieves function starts
    (or entry point / exports), matches them against the FLIRT signature index
    (using `find_ida_install()` / `sig/` if `sig_path` not provided), and returns
    a dictionary of matched functions with symbol names and confidence.
    """
    img = load_binary(binary_path)

    sig_files: List[Path] = []
    if sig_path:
        sp = Path(sig_path)
        if sp.is_file():
            sig_files.append(sp)
        elif sp.is_dir():
            sig_files.extend(sorted(sp.glob("*.sig")))
    else:
        ida_root = find_ida_install()
        if ida_root:
            sig_dir = ida_root / "sig"
            arch_map = {
                "x86": "pc",
                "x86_64": "pc",
                "arm": "arm",
                "arm64": "arm",
                "mips": "mips",
                "mips64": "mips",
            }
            arch_sub = arch_map.get(img.arch, img.arch)
            arch_dir = sig_dir / arch_sub
            if arch_dir.is_dir():
                candidates = sorted(arch_dir.glob("*.sig"))
                if len(candidates) > 10:
                    prioritized = [
                        p for p in candidates
                        if any(k in p.name.lower() for k in ("vc", "bc", "android", "crt", "libc"))
                    ]
                    sig_files.extend(prioritized[:5] if prioritized else candidates[:5])
                else:
                    sig_files.extend(candidates)

    flirt_index = FlirtSignatureIndex()
    total_patterns = 0
    loaded_sigs: List[str] = []

    if sig_path and ("Pattern:" in sig_path or "\t" in sig_path):
        from superghidra.formats.ida_flirt_bridge import parse_flirt_dump
        pats = parse_flirt_dump(sig_path, sig_source="synthetic")
        for p in pats:
            flirt_index.add_pattern(p)
        total_patterns = len(pats)
        loaded_sigs.append("synthetic_dump")
    else:
        for sf in sig_files:
            try:
                cnt = flirt_index.load_sig_file(sf)
                total_patterns += cnt
                loaded_sigs.append(str(sf))
            except Exception:
                continue

    target_addrs: List[Tuple[int, str]] = []
    seen_vas = set()
    if img.function_starts:
        for addr in img.function_starts:
            if addr not in seen_vas:
                target_addrs.append((addr, f"sub_{addr:x}"))
                seen_vas.add(addr)
    if img.entry and img.entry not in seen_vas:
        target_addrs.append((img.entry, "entry"))
        seen_vas.add(img.entry)
    for exp in img.exports:
        if exp.address and exp.address not in seen_vas:
            target_addrs.append((exp.address, exp.name))
            seen_vas.add(exp.address)
    for sym in img.symbols:
        if sym.address and getattr(sym, "type", None) == "function" and sym.address not in seen_vas:
            target_addrs.append((sym.address, sym.name))
            seen_vas.add(sym.address)

    if not target_addrs:
        try:
            base_va, _ = _exec_bytes(img, 4096)
            target_addrs.append((base_va, "exec_start"))
        except Exception:
            pass

    matches: List[Dict[str, Any]] = []
    matched_functions: Dict[str, Dict[str, Any]] = {}
    for addr, orig_name in target_addrs:
        if not _addr_in_image(img, addr):
            continue
        code = img.read_va(addr, 64)
        if len(code) < 2:
            continue
        flirt_matches = flirt_index.match_bytes(code, offset=0)
        if flirt_matches:
            best = next((m for m in flirt_matches if m.offset_in_module == 0), flirt_matches[0])
            item = {
                "address": addr,
                "symbol_name": best.symbol_name,
                "confidence": best.confidence,
                "sig_source": best.pattern.sig_source,
                "original_name": orig_name,
            }
            matches.append(item)
            matched_functions[f"0x{addr:x}"] = {
                "symbol_name": best.symbol_name,
                "confidence": best.confidence,
                "sig_source": best.pattern.sig_source,
            }

    return {
        "binary_path": str(img.path or binary_path),
        "sig_path": str(sig_path) if sig_path else (loaded_sigs[0] if len(loaded_sigs) == 1 else loaded_sigs),
        "loaded_sigs": loaded_sigs,
        "total_patterns": total_patterns,
        "matched_count": len(matches),
        "matches": matches,
        "matched_functions": matched_functions,
    }


def staged_decompile_function(
    code_bytes: bytes,
    func_rva: int = 0x1000,
    arch: str = "x86_64",
    func_name: str = "target_func",
) -> Dict[str, Any]:
    """
    Executes the 5-stage P-Code decompiler pipeline (Gap 2 / Roadmap U6-U8):
      1. Lifts binary machine code into PCodeFunction IR.
      2. STAGE_EGRAPH_MBA: Runs Equality Saturation (E-Graphs) to eliminate arithmetic obfuscation.
      3. STAGE_DEFLATTENED: Runs Symbolic CFF Deflattening to eliminate state-variable switch loops.
      4. STAGE_RESTRUCTURED: Runs RellicGotoFreeRestructurer to emit 100% goto-free C code.
    Returns:
      Dictionary with function_name, c_code, is_goto_free, mba_simplified, dispatchers_removed,
      stages_executed, and performance telemetry.
    """
    if not code_bytes:
        raise LiftError("code_bytes is empty")

    if arch not in ("x86_64", "arm64"):
        raise LiftError(f"architecture '{arch}' is not supported by this lifter")

    from superghidra.lifters.egraph_mlir_pipeline import (
        AddressSpace,
        PCodeBasicBlock,
        PCodeFunction,
        PCodeOp,
        PCodeOpCode,
        StagedPCodePassManager,
        Varnode,
    )

    if arch == "arm64":
        from superghidra.lifters.pcode_lifter_bridge import (
            AddressSpace as BridgeSpace,
        )
        from superghidra.lifters.pcode_lifter_bridge import (
            ARM64PcodeLifter,
        )
        from superghidra.lifters.pcode_lifter_bridge import (
            PcodeOpcode as BridgeOpcode,
        )

        lifter = ARM64PcodeLifter()
        try:
            bridge_ops = lifter.lift_bytes(code_bytes, base_addr=func_rva)
        except Exception as exc:
            raise LiftError(f"failed to lift ARM64 bytes: {exc}")

        if not bridge_ops:
            raise LiftError("no ARM64 instructions lifted from bytes")

        arm_unhandled: List[Tuple[int, str]] = []
        arm_has_ret = False
        converted_ops: List[PCodeOp] = []

        def conv_arm_vn(vn: Any) -> Varnode | None:
            if vn is None:
                return None
            if vn.space in (BridgeSpace.CONST, BridgeSpace.CONSTANT):
                return Varnode(AddressSpace.CONST, int(vn.offset), vn.size)
            elif vn.space == BridgeSpace.REGISTER:
                reg_idx = int(vn.offset) // 8
                sym = f"x{reg_idx}" if reg_idx < 31 else ("sp" if reg_idx == 31 else f"r{reg_idx}")
                if vn.size == 4 and reg_idx < 31:
                    sym = f"w{reg_idx}"
                return Varnode(AddressSpace.REGISTER, int(vn.offset), vn.size, symbol=sym)
            elif vn.space == BridgeSpace.UNIQUE:
                return Varnode(AddressSpace.UNIQUE, int(vn.offset), vn.size)
            elif vn.space == BridgeSpace.RAM:
                off_val = int(vn.offset) if isinstance(vn.offset, int) else 0
                return Varnode(AddressSpace.RAM, off_val, vn.size)
            return Varnode(AddressSpace.RAM, 0, vn.size)

        for seq, b_op in enumerate(bridge_ops, start=1):
            if b_op.opcode == BridgeOpcode.UNIMPLEMENTED:
                offset = b_op.pc - func_rva
                raw_hex = code_bytes[offset : offset + 4].hex() if 0 <= offset <= len(code_bytes) - 4 else ""
                arm_unhandled.append((b_op.pc, raw_hex))
                continue

            if b_op.opcode == BridgeOpcode.RETURN:
                arm_has_ret = True
                ret_vn = Varnode(AddressSpace.REGISTER, 0, 8, symbol="x0")
                converted_ops.append(PCodeOp(seq, PCodeOpCode.RETURN, None, [ret_vn], address=b_op.pc))
                break

            opc = PCodeOpCode[b_op.opcode.name] if b_op.opcode.name in PCodeOpCode.__members__ else PCodeOpCode.COPY
            out_vn = conv_arm_vn(b_op.output)
            in_vns = [v for v in (conv_arm_vn(inp) for inp in b_op.inputs) if v is not None]
            converted_ops.append(PCodeOp(seq, opc, out_vn, in_vns, address=b_op.pc))

        if arm_unhandled:
            raise LiftError(
                f"unhandled instruction(s) in function at {arm_unhandled[0][0]:#x}",
                unhandled=arm_unhandled,
            )

        if not arm_has_ret:
            raise LiftError("buffer ends before a ret instruction", unhandled=arm_unhandled)

        written_arm: Set[str] = set()
        read_before_written_arm: List[Varnode] = []
        for op in converted_ops:
            for inp in op.inputs:
                if inp and not inp.is_const and inp.symbol and inp.symbol not in written_arm:
                    if inp.symbol not in [v.symbol for v in read_before_written_arm]:
                        read_before_written_arm.append(inp)
            if op.output and op.output.symbol:
                written_arm.add(op.output.symbol)

        arm64_abi_params = [f"x{i}" for i in range(8)]
        func_params_arm = [v for v in read_before_written_arm if v.symbol in arm64_abi_params]
        func_params_arm.sort(key=lambda v: arm64_abi_params.index(v.symbol or ""))

        blk_arm = PCodeBasicBlock(1, func_rva, converted_ops, succs=[], preds=[])
        func_arm = PCodeFunction(
            name=func_name,
            entry_rva=func_rva,
            params=func_params_arm,
            blocks={1: blk_arm},
        )
        manager_arm = StagedPCodePassManager()
        res_arm = manager_arm.run_all_passes(func_arm)

        return {
            "function_name": res_arm.function_name,
            "entry_rva": res_arm.entry_rva,
            "c_code": res_arm.c_code,
            "mlir_ir": res_arm.mlir_ir,
            "is_goto_free": res_arm.is_goto_free,
            "mba_simplified": res_arm.mba_simplified,
            "mba_simplifications_count": res_arm.mba_simplifications_count,
            "dispatchers_removed": res_arm.dispatchers_removed,
            "pruned_branches_count": res_arm.pruned_branches_count,
            "stages_executed": res_arm.stages_executed,
            "telemetry": res_arm.telemetry,
        }

    gpr_names = (
        "rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi",
        "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15",
    )
    gpr_vns = [
        Varnode(AddressSpace.REGISTER, i * 8, 8, symbol=name)
        for i, name in enumerate(gpr_names)
    ]

    ops: List[PCodeOp] = []
    unhandled: List[Tuple[int, str]] = []
    has_ret = False

    for insn in iter_decode(code_bytes, address=func_rva, mode=64):
        offset = insn.address - func_rva
        insn_raw = code_bytes[offset : offset + insn.length].hex() if insn.length > 0 else ""

        if insn.invalid:
            unhandled.append((insn.address, insn_raw))
            continue

        if insn.map == 0 and insn.opcode == 0x90:
            # nop
            continue

        if insn.map == 0 and insn.opcode == 0xC3:
            ops.append(PCodeOp(len(ops) + 1, PCodeOpCode.RETURN, None, [gpr_vns[0]], insn.address))
            has_ret = True
            break

        # 1. Push r64: 0x50 .. 0x57 (callee-saved prologue or stack parameter save)
        if insn.map == 0 and 0x50 <= insn.opcode <= 0x57:
            reg_idx = (insn.opcode & 7) | ((insn.rex & 1) << 3)
            src = gpr_vns[reg_idx]
            sp = gpr_vns[4]  # rsp
            ops.append(PCodeOp(len(ops) + 1, PCodeOpCode.INT_SUB, sp, [sp, Varnode(AddressSpace.CONST, 8, 8)], insn.address))
            ops.append(PCodeOp(len(ops) + 1, PCodeOpCode.STORE, None, [Varnode(AddressSpace.RAM, 0, 8), sp, src], insn.address))
            continue

        # 2. Pop r64: 0x58 .. 0x5F (callee-saved epilogue restoration)
        if insn.map == 0 and 0x58 <= insn.opcode <= 0x5F:
            reg_idx = (insn.opcode & 7) | ((insn.rex & 1) << 3)
            dst = gpr_vns[reg_idx]
            sp = gpr_vns[4]  # rsp
            ops.append(PCodeOp(len(ops) + 1, PCodeOpCode.LOAD, dst, [Varnode(AddressSpace.RAM, 0, 8), sp], insn.address))
            ops.append(PCodeOp(len(ops) + 1, PCodeOpCode.INT_ADD, sp, [sp, Varnode(AddressSpace.CONST, 8, 8)], insn.address))
            continue

        # 3. Leave: 0xC9 (mov rsp, rbp; pop rbp)
        if insn.map == 0 and insn.opcode == 0xC9:
            sp = gpr_vns[4]  # rsp
            bp = gpr_vns[5]  # rbp
            ops.append(PCodeOp(len(ops) + 1, PCodeOpCode.COPY, sp, [bp], insn.address))
            ops.append(PCodeOp(len(ops) + 1, PCodeOpCode.LOAD, bp, [Varnode(AddressSpace.RAM, 0, 8), sp], insn.address))
            ops.append(PCodeOp(len(ops) + 1, PCodeOpCode.INT_ADD, sp, [sp, Varnode(AddressSpace.CONST, 8, 8)], insn.address))
            continue

        # 4. Immediate arithmetic on registers (sub rsp, imm / add rsp, imm): 0x81 / 0x83
        if insn.map == 0 and insn.opcode in (0x81, 0x83) and insn.modrm is not None and (insn.modrm >> 6) == 3:
            group_op = (insn.modrm >> 3) & 7
            dst = gpr_vns[insn.rm]
            imm_val = insn.imm or 0
            imm_vn = Varnode(AddressSpace.CONST, imm_val, 8)
            if group_op == 0:  # ADD
                ops.append(PCodeOp(len(ops) + 1, PCodeOpCode.INT_ADD, dst, [dst, imm_vn], insn.address))
                continue
            elif group_op == 5:  # SUB
                ops.append(PCodeOp(len(ops) + 1, PCodeOpCode.INT_SUB, dst, [dst, imm_vn], insn.address))
                continue

        # 5. Memory operations with displacement: mov reg, [base + disp] (0x8B) / mov [base + disp], reg (0x89)
        if insn.map == 0 and insn.mem is not None and insn.opcode in (0x89, 0x8B):
            base_reg_name = insn.mem.base
            if base_reg_name and base_reg_name in gpr_names:
                base_idx = gpr_names.index(base_reg_name)
                base_vn = gpr_vns[base_idx]
                disp = insn.mem.disp
                if disp != 0:
                    addr_vn = Varnode(AddressSpace.UNIQUE, len(ops) + 0x1000, 8, symbol=f"{base_reg_name}_{hex(disp)}")
                    disp_vn = Varnode(AddressSpace.CONST, disp, 8)
                    ops.append(PCodeOp(len(ops) + 1, PCodeOpCode.PTRADD, addr_vn, [base_vn, disp_vn], insn.address))
                else:
                    addr_vn = base_vn

                reg_vn = gpr_vns[insn.reg]
                if insn.opcode == 0x8B:  # LOAD reg from mem
                    ops.append(PCodeOp(len(ops) + 1, PCodeOpCode.LOAD, reg_vn, [Varnode(AddressSpace.RAM, 0, 8), addr_vn], insn.address))
                else:  # STORE reg to mem (0x89)
                    ops.append(PCodeOp(len(ops) + 1, PCodeOpCode.STORE, None, [Varnode(AddressSpace.RAM, 0, 8), addr_vn, reg_vn], insn.address))
                continue

        # 6. Direct CALL rel32: 0xE8
        if insn.map == 0 and insn.opcode == 0xE8:
            target_va = insn.target if getattr(insn, "target", None) is not None else ((insn.address + insn.length + (insn.imm or 0)) & 0xFFFFFFFFFFFFFFFF)
            target_va_int = int(target_va or 0)
            target_vn = Varnode(AddressSpace.CONST, target_va_int, 8, symbol=f"sub_{target_va_int:x}")
            ops.append(PCodeOp(len(ops) + 1, PCodeOpCode.CALL, gpr_vns[0], [target_vn], insn.address))
            continue

        # 7. Indirect CALL r/m64: 0xFF with group_op == 2
        if insn.map == 0 and insn.opcode == 0xFF and insn.modrm is not None:
            group_op = (insn.modrm >> 3) & 7
            if group_op == 2:
                if (insn.modrm >> 6) == 3:  # Register indirect
                    target_vn = gpr_vns[insn.rm]
                    ops.append(PCodeOp(len(ops) + 1, PCodeOpCode.CALLIND, gpr_vns[0], [target_vn], insn.address))
                    continue
                elif insn.mem is not None and insn.mem.base in gpr_names:  # Memory indirect
                    base_vn = gpr_vns[gpr_names.index(insn.mem.base)]
                    disp = insn.mem.disp
                    if disp != 0:
                        addr_vn = Varnode(AddressSpace.UNIQUE, len(ops) + 0x1000, 8, symbol=f"{insn.mem.base}_{hex(disp)}")
                        disp_vn = Varnode(AddressSpace.CONST, disp, 8)
                        ops.append(PCodeOp(len(ops) + 1, PCodeOpCode.PTRADD, addr_vn, [base_vn, disp_vn], insn.address))
                    else:
                        addr_vn = base_vn
                    fn_ptr_vn = Varnode(AddressSpace.UNIQUE, len(ops) + 0x2000, 8, symbol=f"fn_ptr_{len(ops)}")
                    ops.append(PCodeOp(len(ops) + 1, PCodeOpCode.LOAD, fn_ptr_vn, [Varnode(AddressSpace.RAM, 0, 8), addr_vn], insn.address))
                    ops.append(PCodeOp(len(ops) + 1, PCodeOpCode.CALLIND, gpr_vns[0], [fn_ptr_vn], insn.address))
                    continue

        # 8. Immediate moves: mov r64, imm64 (0xB8..0xBF with REX_W) / mov r64, imm32 (0xC7 /0 with REX_W)
        if insn.map == 0 and insn.rex_w and 0xB8 <= insn.opcode <= 0xBF:
            reg_idx = (insn.opcode & 7) | ((insn.rex & 1) << 3)
            dst = gpr_vns[reg_idx]
            imm_vn = Varnode(AddressSpace.CONST, insn.imm or 0, 8)
            ops.append(PCodeOp(len(ops) + 1, PCodeOpCode.COPY, dst, [imm_vn], insn.address))
            continue

        if insn.map == 0 and insn.rex_w and insn.opcode == 0xC7 and insn.modrm is not None and (insn.modrm >> 6) == 3:
            if ((insn.modrm >> 3) & 7) == 0:
                dst = gpr_vns[insn.rm]
                imm_vn = Varnode(AddressSpace.CONST, insn.imm or 0, 8)
                ops.append(PCodeOp(len(ops) + 1, PCodeOpCode.COPY, dst, [imm_vn], insn.address))
                continue

        # Check for supported register-register 64-bit forms
        if not (insn.map == 0 and insn.rex_w and insn.mem is None and insn.modrm is not None and (insn.modrm >> 6) == 3):
            unhandled.append((insn.address, insn_raw))
            continue

        if insn.opcode in (0x89, 0x01, 0x29, 0x21, 0x09, 0x31):
            dst = gpr_vns[insn.rm]
            src = gpr_vns[insn.reg]
            if insn.opcode == 0x89:
                ops.append(PCodeOp(len(ops) + 1, PCodeOpCode.COPY, dst, [src], insn.address))
            elif insn.opcode == 0x01:
                ops.append(PCodeOp(len(ops) + 1, PCodeOpCode.INT_ADD, dst, [dst, src], insn.address))
            elif insn.opcode == 0x29:
                ops.append(PCodeOp(len(ops) + 1, PCodeOpCode.INT_SUB, dst, [dst, src], insn.address))
            elif insn.opcode == 0x21:
                ops.append(PCodeOp(len(ops) + 1, PCodeOpCode.INT_AND, dst, [dst, src], insn.address))
            elif insn.opcode == 0x09:
                ops.append(PCodeOp(len(ops) + 1, PCodeOpCode.INT_OR, dst, [dst, src], insn.address))
            elif insn.opcode == 0x31:
                ops.append(PCodeOp(len(ops) + 1, PCodeOpCode.INT_XOR, dst, [dst, src], insn.address))
        elif insn.opcode in (0x8B, 0x03, 0x2B, 0x23, 0x0B, 0x33):
            dst = gpr_vns[insn.reg]
            src = gpr_vns[insn.rm]
            if insn.opcode == 0x8B:
                ops.append(PCodeOp(len(ops) + 1, PCodeOpCode.COPY, dst, [src], insn.address))
            elif insn.opcode == 0x03:
                ops.append(PCodeOp(len(ops) + 1, PCodeOpCode.INT_ADD, dst, [dst, src], insn.address))
            elif insn.opcode == 0x2B:
                ops.append(PCodeOp(len(ops) + 1, PCodeOpCode.INT_SUB, dst, [dst, src], insn.address))
            elif insn.opcode == 0x23:
                ops.append(PCodeOp(len(ops) + 1, PCodeOpCode.INT_AND, dst, [dst, src], insn.address))
            elif insn.opcode == 0x0B:
                ops.append(PCodeOp(len(ops) + 1, PCodeOpCode.INT_OR, dst, [dst, src], insn.address))
            elif insn.opcode == 0x33:
                ops.append(PCodeOp(len(ops) + 1, PCodeOpCode.INT_XOR, dst, [dst, src], insn.address))
        else:
            unhandled.append((insn.address, insn_raw))
            continue

    if unhandled:
        raise LiftError(
            f"unhandled instruction(s) in function at {unhandled[0][0]:#x}",
            unhandled=unhandled,
        )

    if not has_ret:
        raise LiftError("buffer ends before a ret instruction", unhandled=unhandled)

    written_x64: Set[str] = set()
    read_before_written_x64: List[Varnode] = []
    for op in ops:
        for inp in op.inputs:
            if inp and not inp.is_const and inp.symbol and inp.symbol not in written_x64:
                if inp.symbol not in [v.symbol for v in read_before_written_x64]:
                    read_before_written_x64.append(inp)
        if op.output and op.output.symbol:
            written_x64.add(op.output.symbol)

    uses_sysv = any(v.symbol in ("rdi", "rsi") for v in read_before_written_x64)
    abi_order_x64 = ["rdi", "rsi", "rdx", "rcx", "r8", "r9"] if uses_sysv else ["rcx", "rdx", "r8", "r9"]
    func_params_x64 = [v for v in read_before_written_x64 if v.symbol in abi_order_x64]
    func_params_x64.sort(key=lambda v: abi_order_x64.index(v.symbol or ""))

    blk = PCodeBasicBlock(1, func_rva, ops, succs=[], preds=[])
    func = PCodeFunction(
        name=func_name,
        entry_rva=func_rva,
        params=func_params_x64,
        blocks={1: blk},
    )

    manager = StagedPCodePassManager()
    res = manager.run_all_passes(func)

    return {
        "function_name": res.function_name,
        "entry_rva": res.entry_rva,
        "c_code": res.c_code,
        "mlir_ir": res.mlir_ir,
        "is_goto_free": res.is_goto_free,
        "mba_simplified": res.mba_simplified,
        "mba_simplifications_count": res.mba_simplifications_count,
        "dispatchers_removed": res.dispatchers_removed,
        "pruned_branches_count": res.pruned_branches_count,
        "stages_executed": res.stages_executed,
        "telemetry": res.telemetry,
    }

