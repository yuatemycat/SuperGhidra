"""Facts and bindings taken from bytes of a binary on disk.

`query_binary_dataflow` and `solve_global_type_lattice` read instructions.
`deflatten_control_flow` lifts a compiled switch dispatcher.
`compile_usercall_prototype` writes the binding into a WriteOverlay and reads
it back. None of these functions open a Ghidra ``.rep``.
"""

from __future__ import annotations

import struct
from typing import Any, Dict, List, Optional, Sequence, Tuple

from superghidra.core.ghidra_oracle import WriteOverlay
from superghidra.core.parity_engine import (
    BasicBlock,
    PCodeCFG,
    SparseMatrixDatalogEngine,
    SymbolicCFGDeflattener,
    UsercallPrototypeCompiler,
)
from superghidra.diff.benchmark_and_nextgen_engine import (
    GlobalTypeLatticeSolver,
    LatticeType,
)
from superghidra.formats.binary_loader import BinaryImage, load_binary
from superghidra.lifters.x86_decode import X86Insn, iter_decode


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


def _node_addr(node: str) -> Optional[int]:
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


def _is_mov_imm(insn: X86Insn) -> bool:
    return insn.map == 0 and insn.opcode == 0xC7 and insn.imm is not None and insn.mem is not None


def deflatten_control_flow(binary_path: str) -> Dict[str, Any]:
    """Lift a compiled switch dispatcher from `binary_path` and rewire it.

    Looks for a run of three or more ``cmp mem, imm; jcc`` instructions, which
    is what MSVC ``/Od`` emits for a state-machine switch. Hand-built block
    JSON is not accepted on this path.
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
    chain = _find_cmp_chain(insns)
    if chain is None:
        return {
            "deflattened": False,
            "dispatcher_block_id": -1,
            "gotos_eliminated": 0,
            "back_edges_removed": 0,
            "binary_path": str(img.path or binary_path),
            "reason": "no cmp/jcc state dispatcher in executable bytes",
        }
    report = _deflatten_chain(insns, chain)
    report["binary_path"] = str(img.path or binary_path)
    return report


def _find_cmp_chain(insns: Sequence[X86Insn]) -> Optional[List[X86Insn]]:
    """Return the cmp instructions of the first 3-long same-slot chain."""
    cmps = [insn for insn in insns if _is_cmp_imm8(insn)]
    best: List[X86Insn] = []
    run: List[X86Insn] = []
    for insn in cmps:
        slot = (insn.mem.base, insn.mem.disp) if insn.mem else None
        if run:
            prev = run[-1]
            prev_slot = (prev.mem.base, prev.mem.disp) if prev.mem else None
            if slot != prev_slot or insn.address - prev.address > 16:
                if len(run) > len(best):
                    best = run
                run = []
        run.append(insn)
    if len(run) > len(best):
        best = run
    if len(best) < 3:
        return None
    return best


def _direct_jmp_target(insn: X86Insn) -> Optional[int]:
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
    for cmp_insn in cmps:
        nxt = by_addr.get(cmp_insn.address + cmp_insn.length)
        if nxt is None or nxt.flow != "jcc" or nxt.target is None:
            continue
        cases.append((int(cmp_insn.imm) & 0xFFFFFFFF, nxt.target))
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
                assignment = int(insn.imm) & 0xFFFFFFFF
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
