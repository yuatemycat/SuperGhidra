"""
serialize_trace.py - static field layouts of MFC `Serialize(CArchive&)` functions (x86 / x64).

For every serializable class found by msvc_class_recovery, walk its Serialize() body and
list the archive operations in program order, split into the loading and storing paths:

    read u32 -> this+0x40          [local->0x780 >= 0x8de]
    read f64 -> this+0x50
    read cstring -> this+0x18
    read object
    serialize moSharedFileDef_c <- local

How the operations are recognised (no symbols needed):
  * The CArchive is tracked from the Serialize argument through register copies and into
    called functions ("which argument holds the archive" is propagated interprocedurally).
    Register state is path sensitive: it follows branches and is merged where they join.
  * A function that advances the archive buffer cursor (`add qword [ar+D], N`) and moves
    data through the old cursor value is a primitive: its direction (load/store through the
    cursor) and N give `read u32`, `write f64`, ... This covers MFC's inline operators and
    statically linked CArchive clones such as SolidWorks' su_CArchive.
  * Imported MFC methods are named from their mangled names (operator>> / ReadObject /
    ReadString / Read / ...), including ordinal-only mfc140u imports when Ghidra's
    .exports tables are available (binary_loader.resolve_import_ordinals).
  * Helpers that read MFC strings (the 0xFFFE Unicode marker or CStringT imports) collapse
    to `cstring`; helpers built on ReadObject/WriteObject (the 0x7FFF big-tag constant)
    collapse to `object`.
  * Calls to another class's Serialize with the same archive become `serialize <Class>`,
    and `call [vtable+slot]` on a member with the archive becomes `virtual_serialize`.
  * Branch conditions on the path to an operation are reported as gates, e.g. SolidWorks'
    file-version checks `local->0x780 >= 0x8de`. Tests of the archive's load bit
    (`IsLoading()`) decide which path an otherwise direction-less operation belongs to.

The loading and storing paths of a Serialize function normally mirror each other; the
`mirrored` flag on a trace reports whether their operation kinds match, which is a cheap
self-check of the recovered layout.
"""

from __future__ import annotations

import bisect
from dataclasses import asdict, dataclass, field
from typing import Dict, List, Optional, Tuple

try:  # package import or flat module import
    from . import binary_loader, msvc_class_recovery, x86_decode
except ImportError:
    import binary_loader
    import msvc_class_recovery
    import x86_decode

__all__ = ["ArchiveOp", "SerializeTrace", "SerializeTracer", "trace_serialize_functions"]

_MAX_INSNS = 6000
_MAX_DEPTH = 5
_VOLATILE64 = (0, 1, 2, 8, 9, 10, 11)  # rax rcx rdx r8-r11
_VOLATILE32 = (0, 1, 2)  # eax ecx edx
_ARGS64 = (1, 2, 8, 9)  # rcx rdx r8 r9

# operator>> / operator<< type codes in MSVC mangled names.
_TYPE_CODES = {
    "E": ("u8", 1), "D": ("i8", 1), "C": ("i8", 1), "_N": ("bool", 1),
    "G": ("u16", 2), "F": ("i16", 2), "_W": ("u16", 2),
    "I": ("u32", 4), "H": ("i32", 4), "K": ("u32", 4), "J": ("i32", 4),
    "_K": ("u64", 8), "_J": ("i64", 8), "M": ("f32", 4), "N": ("f64", 8),
}

_NEG = {">=": "<", "<": ">=", ">": "<=", "<=": ">", "==": "!=", "!=": "=="}
# jcc condition (low nibble of 7x / 0F 8x) after `cmp X, imm` -> relation that holds when taken.
_JCC_REL = {0x2: "<", 0x3: ">=", 0x4: "==", 0x5: "!=", 0x6: "<=", 0x7: ">",
            0xC: "<", 0xD: ">=", 0xE: "<=", 0xF: ">", 0x8: "<", 0x9: ">="}

LOADING = ("mode", "loading")
STORING = ("mode", "storing")

_PRIMITIVES = {"u8", "u16", "u32", "u64", "i8", "i16", "i32", "i64", "f32", "f64", "bool", "bytes"}
_OBJECT_INTERNAL = {"object", "class", "virtual_serialize", "cstring", "u16", "u32"}


@dataclass
class ArchiveOp:
    address: int  # call site in the traced function
    direction: str  # read | write | both
    kind: str  # u8..u64, i8..i64, f32, f64, bool, bytes, cstring, object, class, count,
    #            serialize, virtual_serialize
    size: Optional[int] = None
    member: Optional[str] = None  # "this+0x40", "local", "this+0x18->0x8", "base"
    callee: Optional[str] = None  # import / class name / helper address
    gates: List[str] = field(default_factory=list)
    via: List[str] = field(default_factory=list)  # helper chain that produced the op
    repeat: bool = False  # inside a loop (typically once per element of a preceding count)
    conditions: List = field(default_factory=list)  # structured gates (see _gate_text)

    def describe(self) -> str:
        what = f"bytes[{self.size}]" if self.kind == "bytes" and self.size else self.kind
        s = f"{self.direction} {what}" + (" (repeated)" if self.repeat else "")
        if self.callee and self.kind in ("serialize", "virtual_serialize"):
            s += f" {self.callee}"
        if self.member:
            s += f" -> {self.member}" if self.direction == "read" else f" <- {self.member}"
        if self.gates:
            s += "  [" + ", ".join(self.gates) + "]"
        return s


@dataclass
class SerializeTrace:
    class_name: Optional[str]
    function: int
    ops: List[ArchiveOp]
    schema: Optional[int] = None
    truncated: bool = False

    @property
    def loading(self) -> List[ArchiveOp]:
        return [o for o in self.ops if o.direction in ("read", "both")]

    @property
    def storing(self) -> List[ArchiveOp]:
        return [o for o in self.ops if o.direction in ("write", "both")]

    @property
    def mirrored(self) -> bool:
        """True when load and store paths perform the same kinds of operations in order."""
        def sig(ops):
            return [o.kind for o in ops]
        return bool(self.ops) and sig(self.loading) == sig(self.storing)

    def to_dict(self) -> Dict[str, object]:
        def op(o: ArchiveOp) -> Dict[str, object]:
            d = asdict(o)
            d["address"] = hex(o.address)
            d["text"] = o.describe()
            return d
        return {"class": self.class_name, "function": hex(self.function), "schema": self.schema,
                "mirrored": self.mirrored, "truncated": self.truncated,
                "loading": [op(o) for o in self.loading], "storing": [op(o) for o in self.storing]}


# --------------------------------------------------------------------------------------
# Abstract values held in registers
# --------------------------------------------------------------------------------------
#   ("ar",)                      the archive
#   ("this",)                    the traced function's `this`
#   ("ptr", base, disp)          address base+disp; base is "this" | "stack" | "glob" | a value
#   ("load", base, disp, size)   value loaded from base+disp
#   ("cursor", disp)             archive buffer cursor loaded from [ar+disp]
#   ("arword", disp, inverted)   a dword of the archive object, possibly bit-inverted
#   ("modebit", inverted)        (archive mode & 1), i.e. IsLoading() / IsStoring()
#   ("vtable", obj)              vtable pointer loaded from object value `obj`
#   ("const", value)


def _render(val) -> Optional[str]:
    """Readable location for an address or loaded value."""
    if val is None:
        return None
    tag = val[0]
    if tag == "this":
        return "this"
    if tag == "const":
        return f"const {val[1]:#x}"
    if tag in ("ptr", "load"):
        base, disp = val[1], val[2]
        if base == "this":
            return f"this+{disp:#x}"
        if base == "stack":
            return "local"
        if base == "glob":
            return f"global {disp:#x}"
        if isinstance(base, tuple):
            inner = _render(base)
            return f"{inner}->{disp:#x}" if inner else None
    return None


def _gate_text(g) -> str:
    """Gates are ("mode", name) | ("or", (conj, conj)) | (operand, relation, imm)."""
    if g[0] == "mode":
        return g[1]
    if g[0] == "or":
        parts = []
        for conj in g[1]:
            inner = " and ".join(_gate_text(x) for x in conj)
            parts.append(f"({inner})" if len(conj) > 1 else inner)
        return " or ".join(parts)
    desc, rel, imm = g
    return f"{desc} {rel} {(imm or 0):#x}"


def _negate(g):
    if g == LOADING:
        return STORING
    if g == STORING:
        return LOADING
    if g[0] == "or":
        return None
    return (g[0], _NEG[g[1]], g[2])


def _atoms(g, out):
    if g[0] == "or":
        for conj in g[1]:
            for x in conj:
                _atoms(x, out)
    elif g[0] != "mode":
        out.append(g)
    return out


def _holds(g, env) -> bool:
    if g[0] == "mode":
        return env.get("__mode__", g[1]) == g[1]
    if g[0] == "or":
        return any(all(_holds(x, env) for x in conj) for conj in g[1])
    v, imm = env[g[0]], g[2] or 0
    return {"<": v < imm, ">=": v >= imm, "==": v == imm, "!=": v != imm,
            "<=": v <= imm, ">": v > imm}[g[1]]


def _is_tautology(conjs) -> bool:
    """True when the disjunction of the conjunctions holds for every operand value."""
    atoms = []
    for conj in conjs:
        for g in conj:
            _atoms(g, atoms)
    if any(g[0] == "mode" for conj in conjs for g in conj):
        return False
    samples: Dict[str, set] = {}
    for desc, _, imm in atoms:
        s = samples.setdefault(desc, {0, 1, -1, 0xFFFFFFFF})
        c = imm or 0
        s.update((c - 1, c, c + 1))
    names = list(samples)
    if not names:
        return False
    total = 1
    for n in names:
        total *= len(samples[n])
    if total > 20000:
        return False
    import itertools

    for combo in itertools.product(*(sorted(samples[n]) for n in names)):
        env = dict(zip(names, combo))
        if not any(all(_holds(g, env) for g in conj) for conj in conjs):
            return False
    return True


class _State:
    __slots__ = ("regs", "gates", "cmp", "pushes", "esp")

    def __init__(self, regs=None, gates=(), cmp=None, pushes=(), esp=0):
        self.regs: Dict[int, tuple] = dict(regs or {})
        self.gates: Tuple = tuple(gates)
        self.cmp = cmp
        self.pushes: Tuple = tuple(pushes)
        self.esp = esp

    def copy(self) -> "_State":
        return _State(self.regs, self.gates, self.cmp, self.pushes, self.esp)


def _merge_gates(states: List[_State]) -> Tuple:
    first = states[0].gates
    common = tuple(g for g in first if all(g in s.gates for s in states[1:]))
    extras = [[g for g in s.gates if g not in common] for s in states]
    if any(not e for e in extras) or len(states) != 2 or any(len(e) > 3 for e in extras):
        return common
    a, b = extras
    # (A) or (not A and B...) == A or (B...)
    if len(a) == 1 and _negate(a[0]) in b:
        b = [g for g in b if g != _negate(a[0])]
    elif len(b) == 1 and _negate(b[0]) in a:
        a = [g for g in a if g != _negate(b[0])]
    if not a or not b:
        return common
    if (LOADING in a and STORING in b) or (STORING in a and LOADING in b):
        a = [g for g in a if g not in (LOADING, STORING)]
        b = [g for g in b if g not in (LOADING, STORING)]
        if not a or not b:
            return common
    if _is_tautology((a, b)):
        return common
    return common + (("or", (tuple(a), tuple(b))),)


def _merge(states: List[_State]) -> _State:
    if len(states) == 1:
        return states[0]
    s0 = states[0]
    regs = {r: v for r, v in s0.regs.items() if all(s.regs.get(r) == v for s in states[1:])}
    pushes = s0.pushes if all(s.pushes == s0.pushes for s in states[1:]) else ()
    return _State(regs, _merge_gates(states), None, pushes, s0.esp)


@dataclass
class _Summary:
    ops: List[ArchiveOp]
    has_7fff: bool = False
    has_fffe: bool = False
    has_ffff: bool = False
    uses_cstring: bool = False
    returns_modebit: Optional[bool] = None  # inverted flag when the function returns mode&1
    returns_read: bool = False  # returns a value just read from the archive
    returns_ar: bool = False  # returns the archive itself (chained `ar << a << b`)
    n_insns: int = 0
    truncated: bool = False


class SerializeTracer:
    """Static Serialize() tracer bound to one PE image (results are memoised per helper)."""

    def __init__(self, source, report: Optional[msvc_class_recovery.ClassRecoveryReport] = None,
                 archive_flags: Optional[int] = 0):
        """`archive_flags`: value assumed for archive mode bits other than load/store (e.g.
        SOLIDWORKS' text/XML archive bit). The default 0 specialises traces to the plain
        binary format and prunes the alternate paths; None keeps them as gates."""
        self.archive_flags = archive_flags
        img = source if isinstance(source, binary_loader.BinaryImage) else binary_loader.load_binary(source)
        if img.format != "pe" or img.arch not in ("x86", "x86_64"):
            raise ValueError(f"Serialize tracing needs an x86/x64 PE image, got {img.format}/{img.arch}")
        self.img = img
        self.report = report if report is not None else msvc_class_recovery.recover_classes(img)
        self.view = msvc_class_recovery._View(img)
        self.mode = 64 if img.bits == 64 else 32
        self.ptr = img.bits // 8
        self.starts = sorted(set(img.function_starts))
        self.serialize_names: Dict[int, str] = {}
        for c in self.report.mfc_classes:
            if c.serialize:
                self.serialize_names.setdefault(c.serialize, c.name)
        self._memo: Dict[Tuple[int, int], _Summary] = {}
        self._active: set = set()

    # ---------------- decoding helpers ----------------

    @staticmethod
    def _reg_index(name: Optional[str]) -> Optional[int]:
        if name is None:
            return None
        for table in (x86_decode.REG64, x86_decode.REG32):
            if name in table:
                return table.index(name)
        return None

    def _import_name(self, va: int) -> Optional[str]:
        insn = msvc_class_recovery._decode_at(self.view, va)
        if insn is not None and insn.flow == "jmp_ind":
            return msvc_class_recovery._import_slot(self.view, insn)
        return None

    def _call_target(self, insn) -> Tuple[Optional[int], Optional[str]]:
        """(resolved VA, import name) for a direct call/jmp or `call [rip+IAT]`."""
        if insn.flow in ("call", "jmp") and insn.target is not None:
            va = msvc_class_recovery._follow_thunks(self.view, insn.target)
            return va, self._import_name(va)
        if insn.flow in ("call_ind", "jmp_ind") and insn.mem is not None:
            name = msvc_class_recovery._import_slot(self.view, insn)
            if name:
                return None, name
        return None, None

    def _bound(self, func: int) -> int:
        i = bisect.bisect_right(self.starts, func)
        end = self.starts[i] if i < len(self.starts) else func + 0x8000
        return min(end, func + 0x8000)

    def _instructions(self, func: int) -> Tuple[List[x86_decode.X86Insn], bool]:
        """Recursive-descent decode of one function, in address order."""
        end = self._bound(func)
        seen: Dict[int, x86_decode.X86Insn] = {}
        work = [func]
        truncated = False
        while work:
            va = work.pop()
            while func <= va < end and va not in seen:
                if len(seen) >= _MAX_INSNS:
                    truncated, work = True, []
                    break
                insn = msvc_class_recovery._decode_at(self.view, va)
                if insn is None:
                    break
                seen[va] = insn
                if insn.flow in ("ret", "halt", "jmp_ind", "int") or (insn.map == 0 and insn.opcode == 0xCC):
                    break
                if insn.flow in ("jcc", "loop") and insn.target is not None:
                    work.append(insn.target)
                if insn.flow == "jmp":
                    if insn.target is not None:
                        work.append(insn.target)
                    break
                va = insn.end
        return [seen[k] for k in sorted(seen)], truncated

    # ---------------- import classification ----------------

    @staticmethod
    def _classify_import(name: str) -> Optional[Tuple[str, str, Optional[int]]]:
        """(direction, kind, size) for an imported CArchive / CString archive method."""
        if "CArchive" not in name:
            return None
        if name.startswith("??5") or name.startswith("??6"):
            direction = "read" if name.startswith("??5") else "write"
            if "CStringT" in name or "CSimpleStringT" in name:
                return direction, "cstring", None
            if "CObject" in name:
                return direction, "object", None
            tail = ""
            for marker in ("@AEAV0@", "@AAV0@"):
                if marker in name:
                    tail = name.split(marker, 1)[1]
                    break
            for ref in ("AEA", "AA"):
                if tail.startswith(ref):
                    tail = tail[len(ref):]
                    break
            for code in sorted(_TYPE_CODES, key=len, reverse=True):
                if tail.startswith(code + "@") or tail.startswith(code + "Z") or tail == code:
                    kind, size = _TYPE_CODES[code]
                    return direction, kind, size
            return None
        if name.startswith("?Serialize@"):
            return "both", "serialize", None
        table = (("?ReadObject@", "read", "object"), ("?WriteObject@", "write", "object"),
                 ("?ReadClass@", "read", "class"), ("?WriteClass@", "write", "class"),
                 ("?ReadCount@", "read", "count"), ("?WriteCount@", "write", "count"),
                 ("?ReadString@", "read", "cstring"), ("?WriteString@", "write", "cstring"),
                 ("?Read@", "read", "bytes"), ("?Write@", "write", "bytes"))
        for prefix, direction, kind in table:
            if name.startswith(prefix):
                return direction, kind, None
        return None

    # ---------------- interprocedural summary ----------------

    def summarize(self, func: int, ar_arg: int, this_arg: Optional[int] = 0, depth: int = 0) -> _Summary:
        """Archive operations performed by `func` when argument #ar_arg is the archive."""
        key = (func, ar_arg)
        if key in self._memo:
            return self._memo[key]
        if key in self._active or depth > _MAX_DEPTH:
            return _Summary([])
        self._active.add(key)
        try:
            summ = self._trace(func, ar_arg, this_arg, depth)
        finally:
            self._active.discard(key)
        self._memo[key] = summ
        return summ

    def _val_of_mem(self, st: _State, mem) -> Optional[tuple]:
        """Abstract address of a memory operand."""
        if mem.rip_relative or (mem.base is None and mem.index is None):
            return ("ptr", "glob", mem.disp)
        if mem.index is not None:
            return None
        b = self._reg_index(mem.base)
        if b == 4 or (self.mode == 32 and b == 5):
            return ("ptr", "stack", mem.disp)
        bv = st.regs.get(b)
        if bv is None:
            return None
        if bv[0] == "this":
            return ("ptr", "this", mem.disp)
        if bv[0] == "ar":
            return ("ptr", "ar", mem.disp)
        if bv[0] == "cursor":
            return ("ptr", "cursor", bv[1], bv[2] + mem.disp)
        if bv[0] == "ptr" and bv[1] in ("this", "stack", "glob"):
            return ("ptr", bv[1], bv[2] + mem.disp)
        if bv[0] in ("load", "ptr"):
            return ("ptr", bv, mem.disp)
        return None

    def _trace(self, func: int, ar_arg: int, this_arg: Optional[int], depth: int) -> _Summary:
        insns, truncated = self._instructions(func)
        x64 = self.mode == 64
        entry = _State()
        stack_args: Dict[int, tuple] = {}  # x86: argument k (k >= 1) -> value
        if x64:
            if ar_arg < len(_ARGS64):
                entry.regs[_ARGS64[ar_arg]] = ("ar",)
            if this_arg is not None and this_arg != ar_arg and this_arg < len(_ARGS64):
                entry.regs[_ARGS64[this_arg]] = ("this",)
        else:  # __thiscall: arg 0 in ecx, the rest on the stack
            if ar_arg == 0:
                entry.regs[1] = ("ar",)
            else:
                stack_args[ar_arg] = ("ar",)
            if this_arg == 0 and ar_arg != 0:
                entry.regs[1] = ("this",)
        summ = _Summary([], n_insns=len(insns), truncated=truncated)
        pending_access: Dict[int, ArchiveOp] = {}  # cursor field -> access waiting for its advance
        volatile = _VOLATILE64 if x64 else _VOLATILE32
        bound = self._bound(func)
        pending: Dict[int, List[_State]] = {}
        prologue_regs: Dict[int, tuple] = {}  # callee-saved copies of ar/this made before any branch
        branched = False
        loops: List[Tuple[int, int]] = []  # back edges: (loop head, branch address)
        back_targets = {i.target for i in insns if i.flow in ("jcc", "loop", "jmp") and i.target is not None
                        and func <= i.target <= i.address}
        cur: Optional[_State] = entry

        for insn in insns:
            a = insn.address
            incoming = pending.pop(a, [])
            if cur is not None:
                incoming.append(cur)
            if incoming:
                cur = _merge(incoming)
            elif a in back_targets:  # loop entered only through its back edge: prologue state
                cur = _State({**entry.regs, **prologue_regs})
            else:
                continue  # unreachable (e.g. a pruned alternate-format path)
            st = cur
            op, mp, mem = insn.opcode, insn.map, insn.mem

            imm = insn.imm
            if imm is not None:
                if insn.operand_size == 2 and imm < 0:
                    imm &= 0xFFFF
                if imm == 0x7FFF:
                    summ.has_7fff = True
                elif imm == 0xFFFE:
                    summ.has_fffe = True
                elif imm == 0xFFFF:
                    summ.has_ffff = True

            # ---------------- control flow ----------------
            if insn.flow in ("jcc", "loop"):
                branched = True
                cond = self._branch_condition(insn, st)
                if cond is not None and cond[0] == "static":  # outcome known: prune the other path
                    st.cmp = None
                    if cond[1]:
                        if insn.target is not None and insn.target > a:
                            pending.setdefault(insn.target, []).append(st)
                        cur = None
                    else:
                        cur = st
                    continue
                taken, fall = st.copy(), st
                if cond is not None:
                    if cond not in st.gates:
                        taken.gates = st.gates + (cond,)
                    neg = _negate(cond)
                    fall = st.copy()
                    if neg is not None and neg not in st.gates:
                        fall.gates = st.gates + (neg,)
                taken.cmp = fall.cmp = None
                if insn.target is not None and insn.target > a:
                    pending.setdefault(insn.target, []).append(taken)
                elif insn.target is not None and insn.target >= func:
                    loops.append((insn.target, a))
                cur = fall
                continue
            if insn.flow == "jmp":
                branched = True
                if insn.target is not None and func <= insn.target < bound:
                    if insn.target > a:
                        pending.setdefault(insn.target, []).append(st)
                    else:
                        loops.append((insn.target, a))
                else:  # tail call
                    self._handle_call(insn, st, summ, depth, tail=True)
                cur = None
                continue
            if insn.flow in ("ret", "halt", "jmp_ind", "int") or (mp == 0 and op == 0xCC):
                if insn.flow == "ret":
                    rv = st.regs.get(0)
                    if rv is not None and rv[0] == "modebit" and summ.returns_modebit is None:
                        summ.returns_modebit = rv[1]
                    if rv is not None and rv[0] == "rv":
                        summ.returns_read = True
                    if rv == ("ar",):
                        summ.returns_ar = True
                elif insn.flow == "jmp_ind":
                    self._handle_call(insn, st, summ, depth, tail=True)
                cur = None
                continue
            if insn.flow in ("call", "call_ind"):
                # A buffer copy to/from the cursor (CArchive::Read/Write -> memcpy).
                args = self._args(st)
                for idx, direction in ((1, "read"), (0, "write")):
                    v = args[idx] if idx < len(args) else None
                    if v is not None and v[0] == "cursor":
                        pending_access.setdefault(v[1], ArchiveOp(a, direction, "bytes", None))
                ret = self._handle_call(insn, st, summ, depth)
                for r in volatile:
                    st.regs.pop(r, None)
                if ret is not None:
                    st.regs[0] = ret
                st.pushes = ()
                st.cmp = None
                continue

            # ---------------- compares (branch conditions) ----------------
            if mp == 0 and (op in (0x3C, 0x3D) or (op in (0x80, 0x81, 0x83) and (insn.reg & 7) == 7)):
                v = st.regs.get(0 if op in (0x3C, 0x3D) else insn.rm) if mem is None else None
                if v is not None and v[0] == "const" and imm is not None:
                    st.cmp = ("static", v[1], imm)
                else:
                    st.cmp = ("cmp", self._operand_desc(st, insn, 0 if op in (0x3C, 0x3D) else None), imm)
                continue
            if mp == 0 and op in (0x84, 0x85) and mem is None and insn.reg == insn.rm:  # test r, r
                v = st.regs.get(insn.rm)
                if v is not None and v[0] == "modebit":
                    st.cmp = ("modetest", v[1])
                elif v is not None and v[0] == "const":
                    st.cmp = ("static", v[1], 0)
                else:
                    st.cmp = ("cmp", self._operand_desc(st, insn, insn.rm), 0)
                continue
            if mp == 0 and (op == 0xA8 or (op in (0xF6, 0xF7) and (insn.reg & 7) == 0)):  # test r/m, imm
                if mem is not None:
                    loc = self._val_of_mem(st, mem)
                    if loc is not None and loc[:2] == ("ptr", "ar") and imm == 1:
                        st.cmp = ("modetest", False)
                    elif loc is not None and loc[:2] == ("ptr", "ar") and imm:
                        st.cmp = self._flag_test(loc[2], imm)
                    else:
                        st.cmp = None
                else:
                    v = st.regs.get(0 if op == 0xA8 else insn.rm)
                    if v is not None and v[0] == "arword" and imm == 1:
                        st.cmp = ("modetest", v[2])
                    elif v is not None and v[0] == "arword" and imm and not v[2]:
                        st.cmp = self._flag_test(v[1], imm)
                    elif v is not None and v[0] == "const" and imm is not None:
                        st.cmp = ("static", v[1] & imm, 0)
                    else:
                        st.cmp = None
                continue
            if mp == 0 and op in (0x38, 0x39, 0x3A, 0x3B, 0x84, 0x85):
                st.cmp = None
                if mem is not None:
                    self._cursor_access(st, insn, self._val_of_mem(st, mem), pending_access)
                continue

            # ---------------- archive cursor advance ----------------
            if mem is not None and mp == 0 and op in (0x83, 0x81, 0x01, 0xFF, 0x89) and insn.operand_size == self.ptr:
                loc = self._val_of_mem(st, mem)
                if loc is not None and loc[:2] == ("ptr", "ar"):
                    disp = loc[2]
                    n = "skip"
                    if op in (0x83, 0x81) and (insn.reg & 7) == 0 and imm is not None:
                        n = imm
                    elif op == 0xFF and (insn.reg & 7) == 0:
                        n = 1
                    elif op == 0x01:
                        n = None
                    elif op == 0x89:
                        src = st.regs.get(insn.reg)
                        if src is not None and src[0] == "cursor" and src[1] == disp and src[2] > 0:
                            n = src[2]
                    if n != "skip":
                        self._cursor_advance(st, summ, pending_access, disp, n)
                        continue

            # ---------------- x86 stack argument passing ----------------
            if mp == 0 and 0x50 <= op <= 0x57:
                st.pushes = st.pushes + (st.regs.get((op & 7) | ((insn.rex & 1) << 3)),)
                st.esp += self.ptr
                continue
            if mp == 0 and op in (0x68, 0x6A):
                st.pushes = st.pushes + (("const", imm),)
                st.esp += self.ptr
                continue
            if mp == 0 and 0x58 <= op <= 0x5F:
                st.regs.pop((op & 7) | ((insn.rex & 1) << 3), None)
                st.esp -= self.ptr
                continue
            if mp == 0 and op == 0xFF and mem is not None and (insn.reg & 7) == 6:  # push [mem]
                loc = self._val_of_mem(st, mem)
                st.pushes = st.pushes + ((("load",) + loc[1:3] + (self.ptr,)) if loc and loc[0] == "ptr" else None,)
                st.esp += self.ptr
                continue

            # ---------------- data movement ----------------
            if mp == 0 and 0xB8 <= op <= 0xBF:  # mov r, imm
                st.regs[(op & 7) | ((insn.rex & 1) << 3)] = ("const", imm)
                continue
            if mp == 0 and op in (0x31, 0x33) and mem is None and insn.reg == insn.rm:  # xor r, r
                st.regs[insn.reg] = ("const", 0)
                continue
            if mp == 0 and op == 0x8D and mem is not None:  # lea
                v = self._val_of_mem(st, mem)
                if v is not None and v[:2] == ("ptr", "cursor"):
                    v = ("cursor", v[2], v[3])
                elif v is not None and v[1] == "stack":
                    v = ("ptr", "stack", 0)
                self._set(st, insn.reg, v)
                continue
            if (mp == 0 and op in (0x8B, 0x8A, 0x63)) or (mp == 1 and op in (0xB6, 0xB7, 0xBE, 0xBF)):
                if mem is None:
                    self._set(st, insn.reg, ("ptr", "stack", 0) if insn.rm == 4 else st.regs.get(insn.rm))
                else:
                    self._set(st, insn.reg, self._load_value(st, insn, stack_args, pending_access))
                if not branched and insn.reg in (3, 5, 6, 7, 12, 13, 14, 15) and insn.reg in st.regs:
                    prologue_regs[insn.reg] = st.regs[insn.reg]
                continue
            if mp == 0 and op in (0x89, 0x88) and mem is None:  # mov r/m, r (register form)
                self._set(st, insn.rm, ("ptr", "stack", 0) if insn.reg == 4 else st.regs.get(insn.reg))
                if not branched and insn.rm in (3, 5, 6, 7, 12, 13, 14, 15) and insn.rm in st.regs:
                    prologue_regs[insn.rm] = st.regs[insn.rm]
                continue
            if mp == 0 and op in (0x83, 0x81) and mem is None and (insn.reg & 7) in (0, 5) and imm is not None:
                v = st.regs.get(insn.rm)  # add/sub r, imm
                if v is not None and v[0] == "cursor":
                    st.regs[insn.rm] = ("cursor", v[1], v[2] + (imm if (insn.reg & 7) == 0 else -imm))
                    continue
            if mp == 0 and op == 0xF7 and mem is None and (insn.reg & 7) == 2:  # not r
                v = st.regs.get(insn.rm)
                if v is not None and v[0] == "arword":
                    st.regs[insn.rm] = ("arword", v[1], not v[2])
                elif v is not None and v[0] == "modebit":
                    st.regs[insn.rm] = ("modebit", not v[1])
                else:
                    st.regs.pop(insn.rm, None)
                continue
            if mp == 0 and op in (0x83, 0x81) and mem is None and (insn.reg & 7) == 4 and imm == 1:  # and r, 1
                v = st.regs.get(insn.rm)
                self._set(st, insn.rm, ("modebit", v[2]) if v is not None and v[0] == "arword" else None)
                continue
            if mp == 0 and op == 0x24 and imm == 1:  # and al, 1
                v = st.regs.get(0)
                self._set(st, 0, ("modebit", v[2]) if v is not None and v[0] == "arword" else None)
                continue
            if mem is not None:
                loc = self._val_of_mem(st, mem)
                self._cursor_access(st, insn, loc, pending_access)
                if insn.is_memory_write() and loc is not None and loc[0] == "ptr" and insn.modrm is not None:
                    # Storing a value just read from the archive names that op's member.
                    src = st.regs.get(insn.reg) if op in (0x89, 0x88) or (mp == 1 and op in (0x11, 0x29, 0x7F, 0xD6)) else None
                    if src is not None and src[0] == "rv" and src[1].member is None:
                        src[1].member = _render(("ptr",) + tuple(loc[1:3])) if len(loc) == 3 else None
                    if op in (0x89, 0x88, 0xC7, 0xC6):
                        continue
            # Anything else: forget the register the instruction writes.
            if insn.modrm is not None:
                if mp == 1 and op in (0x10, 0x28, 0x6E, 0x7E) and mem is not None:
                    pass  # xmm loads do not touch general registers
                elif mp == 1 and op in (0x11, 0x29, 0x2E, 0x2F, 0xD6, 0x7F):
                    pass
                else:
                    if mem is None:
                        st.regs.pop(insn.rm, None)
                    # Group opcodes use ModRM.reg as an opcode extension, not a register.
                    if not (mp == 0 and op in (0x80, 0x81, 0x83, 0xC0, 0xC1, 0xC6, 0xC7, 0xD0, 0xD1, 0xD2, 0xD3,
                                               0xF6, 0xF7, 0xFE, 0xFF, 0x8F)) and \
                            not (mp == 1 and op in (0x00, 0x01, 0x18, 0x1F, 0xBA, 0xC7, 0xAE, 0x71, 0x72, 0x73)):
                        st.regs.pop(insn.reg, None)
            elif mp == 0 and 0x40 <= op <= 0x4F and self.mode == 32:
                st.regs.pop(op & 7, None)
            elif mp == 0 and op in (0x99, 0x98):
                st.regs.pop(0, None)
                st.regs.pop(2, None)
        if loops:
            body = self._natural_loops(func, insns, loops, bound)
            for o in summ.ops:
                if o.address in body:
                    o.repeat = True
        return summ

    @staticmethod
    def _natural_loops(func: int, insns, back_edges, bound: int) -> set:
        """Addresses inside natural loops (head dominates the back edge's source)."""
        succ: Dict[int, List[int]] = {}
        addrs = [i.address for i in insns]
        index = {a: k for k, a in enumerate(addrs)}
        for k, i in enumerate(insns):
            out = []
            stop = i.flow in ("ret", "halt", "jmp_ind", "int", "jmp") or (i.map == 0 and i.opcode == 0xCC)
            if not stop and k + 1 < len(insns) and addrs[k + 1] == i.end:
                out.append(i.end)
            if i.flow in ("jcc", "loop", "jmp") and i.target is not None and func <= i.target < bound \
                    and i.target in index:
                out.append(i.target)
            succ[i.address] = out
        pred: Dict[int, List[int]] = {a: [] for a in addrs}
        for a, outs in succ.items():
            for b in outs:
                pred[b].append(a)

        def closure(start: int, edges: Dict[int, List[int]]) -> set:
            seen, work = {start}, [start]
            while work:
                x = work.pop()
                for y in edges.get(x, ()):
                    if y not in seen:
                        seen.add(y)
                        work.append(y)
            return seen

        # A back edge tail -> head closes a cycle; its body is everything on a path
        # head ->* tail (this also covers rotated loops entered at their bottom test).
        body: set = set()
        for head, tail in back_edges:
            if head not in index or tail not in index:
                continue
            body |= closure(head, succ) & closure(tail, pred)
        return body

    # ---------------- per-instruction helpers ----------------

    @staticmethod
    def _set(st: _State, reg: int, val) -> None:
        if val is None:
            st.regs.pop(reg, None)
        else:
            st.regs[reg] = val

    def _load_value(self, st: _State, insn, stack_args, pending_access):
        mem = insn.mem
        loc = self._val_of_mem(st, mem)
        size = insn.memory_access_size() or self.ptr
        acc = self._cursor_access(st, insn, loc, pending_access)
        if acc is not None:
            return ("rv", acc)
        if loc is None:
            return None
        if loc[:2] == ("ptr", "ar"):
            if size == self.ptr:
                return ("cursor", loc[2], 0)
            return ("arword", loc[2], False)
        if loc[:2] == ("ptr", "stack") and self.mode == 32:
            base = mem.base
            k = (loc[2] - st.esp) // 4 if base == "esp" else (loc[2] - 4) // 4 if base == "ebp" else None
            return stack_args.get(k) if k is not None and k >= 1 else None
        b = self._reg_index(mem.base)
        if mem.disp == 0 and mem.index is None and b is not None and size == self.ptr:
            obj = st.regs.get(b)
            if obj is not None and obj[0] in ("this", "load", "ptr"):
                return ("vtable", obj)
        return ("load", loc[1], loc[2], size)

    def _cursor_access(self, st: _State, insn, loc, pending_access) -> Optional[ArchiveOp]:
        """A load/store through the archive buffer cursor: start a pending primitive op."""
        if not loc or loc[:2] != ("ptr", "cursor"):
            return None
        disp = loc[2]
        size = insn.memory_access_size()
        is_float = insn.map == 1 and insn.opcode in (0x10, 0x11) and insn.mandatory_prefix in (0xF2, 0xF3)
        if is_float:
            size = 8 if insn.mandatory_prefix == 0xF2 else 4
        direction = "write" if insn.is_memory_write() else "read"
        member = None
        if direction == "write" and insn.map == 0 and insn.opcode in (0x89, 0x88):
            member = _render(st.regs.get(insn.reg))
        elif direction == "write" and insn.imm is not None:
            member = f"const {insn.imm:#x}"
        prev = pending_access.get(disp)
        if prev is not None and prev.direction == direction:
            prev.size = None  # several accesses before one advance: size comes from the advance
            return prev
        op = ArchiveOp(insn.address, direction, "f64" if is_float and size == 8 else "f32" if is_float else "u",
                       size, member)
        pending_access[disp] = op
        return op

    def _cursor_advance(self, st: _State, summ: _Summary, pending_access, disp: int, n) -> None:
        """The cursor at [ar+disp] moved by n bytes: the pending access becomes an op."""
        op = pending_access.pop(disp, None)
        if op is None:
            return
        size = n if isinstance(n, int) and n > 0 else op.size
        if op.kind not in ("f32", "f64", "bytes"):
            op.kind = {1: "u8", 2: "u16", 4: "u32", 8: "u64"}.get(size or 0, "bytes")
        elif op.kind != "bytes" and size not in (4, 8):
            op.kind = "bytes"
        op.size = size
        self._emit(st, summ, op)

    def _emit(self, st: _State, summ: _Summary, op: ArchiveOp) -> None:
        gates = [_gate_text(g) for g in st.gates if g not in (LOADING, STORING)]
        if op.direction == "both":
            if LOADING in st.gates:
                op.direction = "read"
            elif STORING in st.gates:
                op.direction = "write"
        op.gates = gates + op.gates
        op.conditions = [g for g in st.gates if g not in (LOADING, STORING)] + op.conditions
        summ.ops.append(op)

    def _operand_desc(self, st: _State, insn, reg: Optional[int]) -> Optional[str]:
        if reg is None and insn.mem is not None:
            loc = self._val_of_mem(st, insn.mem)
            return _render(loc) if loc else None
        r = insn.rm if reg is None else reg
        v = st.regs.get(r)
        if v is not None:
            if v[0] == "load":
                return _render(v)
            if v[0] == "arword":
                return f"archive+{v[1]:#x}"
        return (x86_decode.REG64 if self.mode == 64 else x86_decode.REG32)[r]

    def _flag_test(self, disp: int, mask: int):
        """`test` of archive mode bits other than load/store."""
        if self.archive_flags is None:
            return ("cmp", f"archive[{disp:#x}]&{mask:#x}", 0)
        return ("static", self.archive_flags & mask, 0)

    def _branch_condition(self, insn, st: _State):
        """Condition that holds when the branch is taken, or None."""
        if st.cmp is None or insn.flow != "jcc":
            return None
        cc = insn.opcode & 0x0F
        if st.cmp[0] == "modetest":
            inverted = st.cmp[1]
            if cc not in (0x4, 0x5):
                return None
            bit_zero = cc == 0x4  # je: tested bit == 0
            loading = (not bit_zero) != inverted
            return LOADING if loading else STORING
        if st.cmp[0] == "static":
            rel = _JCC_REL.get(cc)
            if rel is None:
                return None
            lhs, rhs = st.cmp[1], st.cmp[2] or 0
            return ("static", {"<": lhs < rhs, ">=": lhs >= rhs, "==": lhs == rhs, "!=": lhs != rhs,
                               "<=": lhs <= rhs, ">": lhs > rhs}[rel])
        _, desc, imm = st.cmp
        rel = _JCC_REL.get(cc)
        if rel is None or desc is None:
            return None
        # Conditions on values of unknown origin (bare registers) and null checks of
        # locals (temporary pointers) carry no layout information.
        if desc in x86_decode.REG64 or desc in x86_decode.REG32:
            return None
        if desc == "local" and not imm and rel in ("==", "!="):
            return None
        return (desc, rel, imm)

    @staticmethod
    def _rebase(obj, member: Optional[str]) -> Optional[str]:
        """Express a callee's `this+X` member relative to the caller's object argument."""
        if member is None or not member.startswith("this"):
            return member
        if obj is None or obj == ("this",):
            return member
        if obj[:2] == ("ptr", "this") and len(obj) == 3:
            if member == "this":
                return f"this+{obj[2]:#x}"
            try:
                return f"this+{obj[2] + int(member[5:].split('-')[0], 16):#x}" + \
                    ("->" + member.split("->", 1)[1] if "->" in member else "")
            except ValueError:
                return member
        if obj[:2] == ("ptr", "stack"):
            return "local"
        outer = _render(obj)
        return f"{outer}->{member[5:] or '0x0'}" if outer else member

    def _args(self, st: _State) -> List[Optional[tuple]]:
        if self.mode == 64:
            return [st.regs.get(r) for r in _ARGS64]
        return [st.regs.get(1)] + list(reversed(st.pushes))

    def _handle_call(self, insn, st: _State, summ: _Summary, depth: int, tail: bool = False):
        """Emit archive ops for a call; returns the abstract return value, if known."""
        ret = self._handle_call_inner(insn, st, summ, depth, tail)
        if ret is not None or tail:
            return ret
        target, imported = self._call_target(insn)
        ar_pos = [i for i, v in enumerate(self._args(st)) if v is not None and v[0] == "ar"]
        if not ar_pos:
            return None
        if imported:  # MFC operator<< / operator>> return the archive
            return ("ar",) if imported.startswith(("??5", "??6")) and "CArchive" in imported else None
        sub = self._memo.get((target, ar_pos[0])) if target is not None else None
        return ("ar",) if sub is not None and sub.returns_ar else None

    def _handle_call_inner(self, insn, st: _State, summ: _Summary, depth: int, tail: bool = False):
        target, imported = self._call_target(insn)
        args = self._args(st)
        ar_pos = [i for i, v in enumerate(args) if v is not None and v[0] == "ar"]

        def emit(op: ArchiveOp) -> ArchiveOp:
            self._emit(st, summ, op)
            return op

        if imported:
            if "CStringT" in imported or "CSimpleStringT" in imported:
                summ.uses_cstring = True
            if not ar_pos:
                return None
            cls = self._classify_import(imported)
            if cls is None:
                return None
            direction, kind, size = cls
            if kind == "serialize":  # an imported base/member class's Serialize(CArchive&)
                if ar_pos[0] != 1:
                    return None
                obj = args[0]
                member = "base" if obj == ("this",) else _render(obj)
                emit(ArchiveOp(insn.address, "both", "serialize", None, member, _class_of_method(imported)))
                return None
            member = _render(args[1]) if ar_pos[0] == 0 and len(args) > 1 else None
            if kind == "bytes" and len(args) > 2 and args[2] is not None and args[2][0] == "const":
                size = args[2][1]
            emit(ArchiveOp(insn.address, direction, kind, size, member, imported))
            return None
        # Virtual call on an object with the archive as an argument: virtual Serialize.
        if target is None and insn.flow == "call_ind" and insn.mem is not None and ar_pos:
            b = self._reg_index(insn.mem.base)
            vt = st.regs.get(b) if b is not None else None
            # CObject slots 0/1 are GetRuntimeClass and the destructor, never serialisation.
            if vt is not None and vt[0] == "vtable" and insn.mem.disp // self.ptr >= 2:
                obj = vt[1]
                member = "base" if obj == ("this",) else _render(obj)
                if obj is not None and obj[0] == "load":
                    member = (member or "?") + "->"
                emit(ArchiveOp(insn.address, "both", "virtual_serialize", None, member,
                               f"slot {insn.mem.disp // self.ptr}"))
            return None
        if target is None:
            return None
        if not ar_pos:
            return None
        k = ar_pos[0]
        name = self.serialize_names.get(target)
        if name is not None and k == 1:
            obj = args[0]
            member = "base" if obj == ("this",) else _render(obj)
            emit(ArchiveOp(insn.address, "both", "serialize", None, member, name))
            return None
        if tail and any(g[0] not in ("mode", "or") and isinstance(g[0], str) and g[0].startswith("archive[")
                        and g[1] == "!=" for g in st.gates):
            return None  # alternate archive back-end (e.g. text/XML mode): not the binary format
        sub = self.summarize(target, k, 0 if k != 0 else None, depth + 1)
        if sub.returns_modebit is not None and not sub.ops:
            return ("modebit", sub.returns_modebit)
        if not sub.ops:
            return None
        member = None
        if k == 0 and len(args) > 1:
            member = _render(args[1])
        elif k == 1:
            member = _render(args[0])
        dirs = {o.direction for o in sub.ops if o.direction != "both"}
        direction = dirs.pop() if len(dirs) == 1 else "both"
        small = len(sub.ops) <= 10 and sub.n_insns <= 600
        kinds = {o.kind for o in sub.ops}
        # ReadClass/WriteClass own the 0x7FFF big-tag constant; ReadObject/WriteObject wrap
        # them together with the created object's own (virtual) Serialize call.
        if small and (sub.has_7fff or ("object" in kinds and kinds <= _OBJECT_INTERNAL)):
            emit(ArchiveOp(insn.address, direction, "object", None, member, hex(target)))
            return None
        # String length readers/writers use the 0xFFFE Unicode marker; string readers use
        # CStringT buffers around them.
        if small and ((sub.has_fffe and kinds <= _PRIMITIVES) or
                      (sub.uses_cstring and "cstring" in kinds and kinds <= {"cstring", "bytes"})):
            emit(ArchiveOp(insn.address, direction, "cstring", None, member, hex(target)))
            return None
        # MFC ReadCount/WriteCount: u16, escaping to u32 (and u64) when it is 0xFFFF.
        seq = [o.kind for o in sub.ops]
        if small and sub.has_ffff and len(seq) >= 2 and seq[0] == "u16" and set(seq) <= {"u16", "u32", "u64"}:
            op = emit(ArchiveOp(insn.address, direction, "count", None, member, hex(target)))
            return ("rv", op) if direction == "read" else None
        if len(sub.ops) == 1:
            o = sub.ops[0]
            op = emit(ArchiveOp(insn.address, o.direction, o.kind, o.size,
                                o.member and self._rebase(args[0] if k != 0 else None, o.member) or member,
                                o.callee, list(o.gates), [hex(target)] + o.via, o.repeat, list(o.conditions)))
            return ("rv", op) if sub.returns_read and op.direction == "read" else None
        obj = args[0] if k != 0 else None
        for o in sub.ops:
            emit(ArchiveOp(insn.address, o.direction, o.kind, o.size, self._rebase(obj, o.member), o.callee,
                           list(o.gates), [hex(target)] + o.via, o.repeat, list(o.conditions)))
        return None

    # ---------------- public ----------------

    def trace(self, func: int, class_name: Optional[str] = None, schema: Optional[int] = None) -> SerializeTrace:
        """Trace one Serialize(CArchive&) body (this = arg 0, archive = arg 1)."""
        summ = self.summarize(func, 1, 0)
        ops = _collapse_inline_strings(sorted(summ.ops, key=lambda o: o.address))
        return SerializeTrace(class_name, func, ops, schema, summ.truncated)

    def trace_classes(self, names: Optional[List[str]] = None) -> List[SerializeTrace]:
        out = []
        wanted = set(names) if names else None
        for c in self.report.mfc_classes:
            if not c.serializable or not c.serialize:
                continue
            if wanted is not None and c.name not in wanted:
                continue
            out.append(self.trace(c.serialize, c.name, c.schema & 0xFFFF))
        return out

    # ---------------- decode layouts ----------------

    def _class(self, name: Optional[str]):
        if not hasattr(self, "_mfc_by_name"):
            self._mfc_by_name = self.report.mfc_by_name()
            self._rtti_by_name = self.report.rtti_by_name()
            self._ops_cache: Dict[Tuple[int, str], List[ArchiveOp]] = {}
        return self._mfc_by_name.get(name) if name else None

    def _vtable_functions(self, cls) -> List[int]:
        rt = self._rtti_by_name.get(cls.name)
        if rt is not None:
            for vt in rt.vtables:
                if vt.address == cls.vtable:
                    return vt.functions
        funcs: List[int] = []
        va = cls.vtable
        while va and len(funcs) < 512:
            fn = self.view.pointer(va + len(funcs) * self.ptr)
            if not self.view.is_code(fn):
                break
            funcs.append(fn)
        return funcs

    def _ops_of(self, func: int, path: str) -> List[ArchiveOp]:
        key = (func, path)
        if key not in self._ops_cache:
            t = self.trace(func)
            self._ops_cache[key] = t.storing if path == "storing" else t.loading
        return self._ops_cache[key]

    @staticmethod
    def _inline(outer: ArchiveOp, inner: List[ArchiveOp]) -> List[ArchiveOp]:
        out = []
        for o in inner:
            out.append(ArchiveOp(o.address, o.direction, o.kind, o.size, o.member, o.callee,
                                 list(outer.gates) + list(o.gates), list(o.via), outer.repeat or o.repeat,
                                 list(outer.conditions) + list(o.conditions)))
        return out

    def class_layout(self, name: str, path: str = "storing",
                     others: Tuple["SerializeTracer", ...] = (), _depth: int = 0) -> Optional[List[ArchiveOp]]:
        """Fully expanded archive ops of one class, ready for mfc_archive.decode_stream.

        Base-class Serialize calls are inlined; virtual calls on `this` are resolved through
        the class's own vtable (the dynamic type is known while decoding that class); a
        Serialize inherited from another module (e.g. mfc140u's CStringArray::Serialize) is
        taken from `others`.
        """
        c = self._class(name)
        if c is None:
            for other in others:
                if other._class(name) is not None:
                    return other.class_layout(name, path, tuple(t for t in others if t is not other), _depth + 1)
            return None
        if c.serialize:
            return self._expand(self._ops_of(c.serialize, path), c, path, others, _depth,
                                self._typed_members(c.serialize, path))
        if c.serialize_external:
            return self.class_layout(_class_of_method(c.serialize_external), path, others, _depth + 1) \
                if _class_of_method(c.serialize_external) != name else None
        return None

    # ---------------- constructor analysis (embedded member types) ----------------

    def _vtable_owner(self) -> Dict[int, str]:
        if not hasattr(self, "_vt_owner"):
            self._vt_owner = {vt.address: c.name for c in self.report.rtti_classes for vt in c.vtables
                              if vt.offset_in_class == 0}
        return self._vt_owner

    def _linear(self, func: int, limit: int = 400) -> List[x86_decode.X86Insn]:
        out, va = [], func
        while len(out) < limit:
            insn = msvc_class_recovery._decode_at(self.view, va)
            if insn is None:
                break
            out.append(insn)
            if insn.flow in ("ret", "jmp", "jmp_ind", "halt") or (insn.map == 0 and insn.opcode == 0xCC):
                break
            va = insn.end
        return out

    def _vtable_stores(self, func: int, this_off: int, out: Dict[int, int], depth: int,
                       alloc_root: bool = False) -> None:
        """Record [this+off] = vtable stores made by a constructor (and the ctors it calls).

        With `alloc_root`, `func` is CreateObject(): `this` is the result of its first call
        (operator new), and the constructor may be inlined into it.
        """
        if depth > 4:
            return
        owners = self._vtable_owner()
        this_regs: Dict[int, int] = {} if alloc_root else {1: this_off}  # register -> offset
        consts: Dict[int, int] = {}
        seeded = not alloc_root
        for insn in self._linear(func):
            op, mp, mem = insn.opcode, insn.map, insn.mem
            if insn.flow == "call" and insn.target is not None:
                if 1 in this_regs:
                    self._vtable_stores(msvc_class_recovery._follow_thunks(self.view, insn.target),
                                        this_regs[1], out, depth + 1)
                for r in (0, 1, 2, 8, 9, 10, 11):
                    this_regs.pop(r, None)
                    consts.pop(r, None)
                if not seeded:  # rax = freshly allocated object
                    this_regs[0] = this_off
                    seeded = True
                continue
            if mp != 0:
                continue
            if op == 0x8D and mem is not None:  # lea
                if mem.rip_relative:
                    consts[insn.reg] = mem.effective_address(insn.end)
                    this_regs.pop(insn.reg, None)
                    continue
                b = self._reg_index(mem.base)
                if b in this_regs and mem.index is None:
                    this_regs[insn.reg] = this_regs[b] + mem.disp
                    consts.pop(insn.reg, None)
                    continue
            if op == 0x8B and mem is None:
                if insn.rm in this_regs:
                    this_regs[insn.reg] = this_regs[insn.rm]
                else:
                    this_regs.pop(insn.reg, None)
                if insn.rm in consts:
                    consts[insn.reg] = consts[insn.rm]
                continue
            if op == 0x89 and mem is not None and insn.reg in consts and consts[insn.reg] in owners:
                b = self._reg_index(mem.base)
                if b in this_regs and mem.index is None:
                    out[this_regs[b] + mem.disp] = consts[insn.reg]
                continue
            if op == 0xC7 and mem is not None:
                continue
            if insn.modrm is not None and mem is None:
                this_regs.pop(insn.reg, None)
                consts.pop(insn.reg, None)

    def member_types(self, cls) -> Dict[int, str]:
        """{offset: class} for embedded polymorphic members, from the class constructor."""
        if not hasattr(self, "_member_types"):
            self._member_types: Dict[str, Dict[int, str]] = {}
        if cls.name not in self._member_types:
            stores: Dict[int, int] = {}
            if cls.create_object:
                self._vtable_stores(msvc_class_recovery._follow_thunks(self.view, cls.create_object), 0, stores, 0,
                                    alloc_root=True)
            owners = self._vtable_owner()
            self._member_types[cls.name] = {off: owners[vt] for off, vt in stores.items() if off and vt in owners}
        return self._member_types[cls.name]

    def _typed_members(self, func: int, path: str) -> Dict[Tuple[str, ...], List[str]]:
        """Static types the *other* path gives to member Serialize calls, keyed by gates.

        Storing code often calls `m_p->Serialize(ar)` virtually while the loading code builds
        a concrete object (`X tmp; tmp.Serialize(ar)`) under the same version gates.
        """
        other = self._ops_of(func, "loading" if path == "storing" else "storing")
        typed: Dict[Tuple[str, ...], List[str]] = {}
        for o in other:
            if o.kind == "serialize" and o.member != "base" and o.callee:
                typed.setdefault(tuple(o.gates), []).append(o.callee)
        return typed

    def _expand(self, ops: List[ArchiveOp], dyn, path: str, others, depth: int,
                typed: Optional[Dict[Tuple[str, ...], List[str]]] = None) -> List[ArchiveOp]:
        out: List[ArchiveOp] = []
        for o in ops:
            sub = None
            if depth < 10 and o.kind == "virtual_serialize" and o.member != "base":
                member_cls = None
                cands = typed.get(tuple(o.gates)) if typed else None
                if cands and len(set(cands)) == 1:
                    member_cls = cands[0]
                elif dyn is not None and o.member and o.member.startswith("this+") and "->" not in o.member:
                    # Embedded member object: its vtable is installed by the constructor.
                    try:
                        member_cls = self.member_types(dyn).get(int(o.member[5:], 16))
                    except ValueError:
                        member_cls = None
                if member_cls:
                    sub = self.class_layout(member_cls, path, others, depth + 1)
            if sub is not None:
                out.extend(self._inline(o, sub))
                continue
            if depth < 10 and o.kind == "serialize" and o.callee:
                base = self._class(o.callee)
                if base is not None and base.serialize and o.member == "base":
                    sub = self._expand(self._ops_of(base.serialize, path), dyn, path, others, depth + 1)
                else:
                    sub = self.class_layout(o.callee, path, others, depth + 1)
            elif depth < 10 and o.kind == "virtual_serialize" and o.member == "base" and dyn is not None \
                    and dyn.vtable and o.callee and o.callee.startswith("slot "):
                funcs = self._vtable_functions(dyn)
                slot = int(o.callee.split()[1])
                if slot < len(funcs):
                    f = msvc_class_recovery._follow_thunks(self.view, funcs[slot])
                    if f != dyn.serialize:  # calling back into the class's own Serialize
                        sub = self._expand(self._ops_of(f, path), dyn, path, others, depth + 1)
            if sub is None:
                out.append(o)
            else:
                out.extend(self._inline(o, sub))
        return out

    def class_layouts(self, path: str = "storing", others: Tuple["SerializeTracer", ...] = (),
                      names: Optional[List[str]] = None) -> Dict[str, List[ArchiveOp]]:
        """class_layout() for every serializable class (optionally only `names`)."""
        self._class(None)
        out: Dict[str, List[ArchiveOp]] = {}
        for c in self.report.mfc_classes:
            if not c.serializable or (names and c.name not in names):
                continue
            ops = self.class_layout(c.name, path, others)
            if ops is not None:
                out[c.name] = ops
        return out


def _class_of_method(mangled: Optional[str]) -> Optional[str]:
    """`?Serialize@CStringArray@@UEAAX...` -> `CStringArray`."""
    if not mangled or not mangled.startswith("?"):
        return mangled
    parts = mangled[1:].split("@")
    return parts[1] if len(parts) > 2 and parts[1] else mangled


def _is_const(op: ArchiveOp, *values: int) -> bool:
    if not op.member or not op.member.startswith("const "):
        return False
    v = int(op.member[6:], 16)
    return any(v == x or v == x - (1 << (8 * (op.size or 1))) for x in values)


def _collapse_inline_strings(ops: List[ArchiveOp]) -> List[ArchiveOp]:
    """Fold MFC's inlined CString (de)serialisation into single `cstring` ops.

    Writing: `u8 0xFF, u16 0xFFFE` (Unicode marker) then the escaped length (u8/u16/u32/u64)
    and the character bytes. Reading: the length reader (already a `cstring` op) followed by
    the character-buffer read(s).
    """
    out: List[ArchiveOp] = []
    i = 0
    while i < len(ops):
        o = ops[i]
        nxt = ops[i + 1] if i + 1 < len(ops) else None
        if (o.direction == "write" and o.kind == "u8" and _is_const(o, 0xFF) and nxt is not None
                and nxt.kind == "u16" and _is_const(nxt, 0xFFFE)):
            j = i + 2
            while j < len(ops) and ops[j].direction == "write" and ops[j].kind in ("u8", "u16", "u32", "u64") \
                    and (ops[j].member is None or ops[j].member.startswith("const ")):
                j += 1
            while j < len(ops) and ops[j].direction == "write" and ops[j].kind == "bytes":
                j += 1
            out.append(ArchiveOp(o.address, "write", "cstring", None, None, None, list(o.gates), o.via,
                                 any(x.repeat for x in ops[i:j]), list(o.conditions)))
            i = j
            continue
        # Inlined WriteCount: [u16 n] / u16 0xFFFF then u32 (then u64).
        if (o.direction == "write" and o.kind == "u16" and _is_const(o, 0xFFFF) and nxt is not None
                and nxt.direction == "write" and nxt.kind in ("u32", "u64")):
            if out and out[-1].direction == "write" and out[-1].kind == "u16" and not _is_const(out[-1], 0xFFFF):
                prev = out.pop()
                o = prev
            j = i + 1
            while j < len(ops) and ops[j].direction == "write" and ops[j].kind in ("u32", "u64") \
                    and (ops[j].member is None or ops[j].member.startswith("const ")):
                j += 1
            out.append(ArchiveOp(o.address, "write", "count", None, o.member if not _is_const(o, 0xFFFF) else None,
                                 None, list(o.gates), o.via, any(x.repeat for x in ops[i:j]), list(o.conditions)))
            i = j
            continue
        if o.kind == "cstring":
            out.append(o)
            j = i + 1
            while j < len(ops) and ops[j].kind == "bytes" and ops[j].direction == o.direction \
                    and ops[j].member is None:
                j += 1
            i = j
            continue
        out.append(o)
        i += 1
    return out


def trace_serialize_functions(source, class_names: Optional[List[str]] = None) -> List[SerializeTrace]:
    """Convenience wrapper: recover classes and trace every (or the named) Serialize()."""
    return SerializeTracer(source).trace_classes(class_names)


if __name__ == "__main__":  # pragma: no cover
    import sys

    tracer = SerializeTracer(sys.argv[1])
    for t in tracer.trace_classes(sys.argv[2:] or None):
        print(f"== {t.class_name}  {t.function:#x}  mirrored={t.mirrored}")
        print("  load:")
        for o in t.loading:
            print("    ", o.describe())
        print("  store:")
        for o in t.storing:
            print("    ", o.describe())
