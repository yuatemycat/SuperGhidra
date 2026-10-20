"""
mfc_archive.py - read MFC CArchive streams (CObject::Serialize output), optionally driven by
field layouts recovered with serialize_trace.

The CArchive object format (MFC arcobj.cpp), which is what SOLIDWORKS, older Autodesk/Bentley
products and many MFC applications write:

    object   := tag payload
    tag      := u16 0x0000                     NULL
              | u16 n (< 0x7FFF)               reference to already-loaded object #n
              | u16 0x8000|n                   new object of already-loaded class #n
              | u16 0xFFFF schema:u16 len:u16 name[len]   new object of a new class
              | u16 0x7FFF u32 big             big tag (bit 31 = class) for maps > 0x7FFE
    payload  := whatever that class's Serialize(CArchive&) writes

Every new class and every new object takes the next index in the load map (index 0 is
NULL), in stream order, so the map stays consistent no matter how objects nest.

Strings (CString operator<<): u8 len; 0xFF -> u16 len; 0xFFFF -> u32; 0xFFFFFFFF -> u64.
A u16 0xFFFE after the first 0xFF marks UTF-16 text and the length is read again.
Counts (WriteCount): u16; 0xFFFF -> u32; 0xFFFFFFFF -> u64.

Usage:
    from mfc_archive import decode_stream, layouts_from_traces
    layouts = layouts_from_traces(serialize_trace.trace_serialize_functions("app.dll"))
    result = decode_stream(data, layouts, env={"local->0x780": 0})
"""

from __future__ import annotations

import math
import re
import struct
from dataclasses import dataclass, field
from typing import Callable, Dict, Iterable, List, Optional, Tuple

__all__ = [
    "ArchiveError",
    "ArchiveReader",
    "ArchiveObject",
    "Field",
    "LayoutOp",
    "NewClassTag",
    "scan_class_tags",
    "layouts_from_traces",
    "decode_stream",
    "calibrate",
    "evaluate_condition",
]

NULL_TAG = 0x0000
NEW_CLASS_TAG = 0xFFFF
CLASS_TAG = 0x8000
BIG_OBJECT_TAG = 0x7FFF
BIG_CLASS_TAG = 0x80000000
_NAME = re.compile(rb"[A-Za-z_][A-Za-z0-9_:]{0,63}")


class ArchiveError(ValueError):
    """Malformed or unexpected archive data."""


@dataclass
class Field:
    offset: int
    kind: str
    value: object
    member: Optional[str] = None
    size: int = 0

    def to_dict(self) -> Dict[str, object]:
        v = self.value
        if isinstance(v, ArchiveObject):
            v = v.to_dict()
        elif isinstance(v, list):
            v = [x.to_dict() if isinstance(x, ArchiveObject) else x for x in v]
        elif isinstance(v, bytes):
            v = v.hex()
        d = {"offset": self.offset, "kind": self.kind, "value": v, "size": self.size}
        if self.member:
            d["member"] = self.member
        if self.kind == "u64" and isinstance(self.value, int):
            f = _as_double(self.value)
            if f is not None:
                d["as_f64"] = f
        return d


@dataclass
class ArchiveObject:
    offset: int  # tag offset
    class_name: Optional[str]
    schema: Optional[int]
    map_index: Optional[int]  # this object's index in the load map
    kind: str = "object"  # object | null | reference
    ref_index: Optional[int] = None  # for references
    payload_offset: Optional[int] = None
    end: Optional[int] = None  # payload end when fully decoded
    status: str = "decoded"  # decoded | partial | opaque | reference | null
    fields: List[Field] = field(default_factory=list)
    note: Optional[str] = None
    assumed: List[str] = field(default_factory=list)  # gates decided by policy, not data

    def to_dict(self) -> Dict[str, object]:
        d: Dict[str, object] = {"offset": self.offset, "kind": self.kind, "class": self.class_name,
                                "status": self.status}
        if self.kind == "object":
            d.update(schema=self.schema, map_index=self.map_index, payload_offset=self.payload_offset,
                     end=self.end, fields=[f.to_dict() for f in self.fields])
        if self.ref_index is not None:
            d["ref_index"] = self.ref_index
        if self.note:
            d["note"] = self.note
        if self.assumed:
            d["assumed_gates"] = sorted(set(self.assumed))
        return d


@dataclass
class LayoutOp:
    kind: str
    size: Optional[int] = None
    repeat: bool = False
    member: Optional[str] = None
    callee: Optional[str] = None  # class for `serialize`
    conditions: List = field(default_factory=list)


@dataclass
class NewClassTag:
    offset: int
    schema: int
    name: str

    @property
    def payload_offset(self) -> int:
        return self.offset + 6 + len(self.name)


def _as_double(bits: int) -> Optional[float]:
    """Interpret a u64 as an IEEE double when that looks like a real-world number."""
    f = struct.unpack("<d", struct.pack("<Q", bits & 0xFFFFFFFFFFFFFFFF))[0]
    if bits == 0 or not math.isfinite(f):
        return None
    exp = (bits >> 52) & 0x7FF
    return f if 0x3B0 <= exp <= 0x450 else None  # roughly 1e-20 .. 1e21


def scan_class_tags(data: bytes, start: int = 0, end: Optional[int] = None) -> List[NewClassTag]:
    """Every plausible `0xFFFF schema len name` new-class tag (identifier names only)."""
    out = []
    end = len(data) if end is None else end
    pos = data.find(b"\xff\xff", start, end)
    while pos >= 0 and pos + 6 <= end:
        schema, ln = struct.unpack_from("<HH", data, pos + 2)
        name = data[pos + 6:pos + 6 + ln]
        if 1 <= ln <= 64 and len(name) == ln and _NAME.fullmatch(name):
            out.append(NewClassTag(pos, schema, name.decode("ascii")))
        pos = data.find(b"\xff\xff", pos + 1, end)
    return out


class ArchiveReader:
    """Sequential CArchive reader with MFC's load-map semantics."""

    def __init__(self, data: bytes, pos: int = 0, map_count: int = 1):
        self.data = data
        self.pos = pos
        # Load map: index -> ("class", name, schema) | ("object", ArchiveObject)
        self.map: Dict[int, tuple] = {}
        self.map_count = map_count
        self.map_reliable = True
        self.learned: Dict[int, str] = {}  # class indexes inferred from expected classes

    # ---------------- primitives ----------------

    def _take(self, n: int) -> bytes:
        if n < 0 or self.pos + n > len(self.data):
            raise ArchiveError(f"read of {n} bytes at {self.pos:#x} past end ({len(self.data):#x})")
        b = self.data[self.pos:self.pos + n]
        self.pos += n
        return b

    def u8(self) -> int:
        return self._take(1)[0]

    def u16(self) -> int:
        return struct.unpack("<H", self._take(2))[0]

    def u32(self) -> int:
        return struct.unpack("<I", self._take(4))[0]

    def u64(self) -> int:
        return struct.unpack("<Q", self._take(8))[0]

    def i8(self) -> int:
        return struct.unpack("<b", self._take(1))[0]

    def i16(self) -> int:
        return struct.unpack("<h", self._take(2))[0]

    def i32(self) -> int:
        return struct.unpack("<i", self._take(4))[0]

    def i64(self) -> int:
        return struct.unpack("<q", self._take(8))[0]

    def f32(self) -> float:
        return struct.unpack("<f", self._take(4))[0]

    def f64(self) -> float:
        return struct.unpack("<d", self._take(8))[0]

    def raw(self, n: int) -> bytes:
        return self._take(n)

    def count(self) -> int:
        """CArchive::ReadCount."""
        n = self.u16()
        if n != 0xFFFF:
            return n
        n = self.u32()
        if n != 0xFFFFFFFF:
            return n
        return self.u64()

    def string_length(self) -> Tuple[int, int]:
        """AfxReadStringLength: (characters, bytes per character)."""
        char_size = 1
        n = self.u8()
        if n < 0xFF:
            return n, char_size
        w = self.u16()
        if w == 0xFFFE:
            char_size = 2
            n = self.u8()
            if n < 0xFF:
                return n, char_size
            w = self.u16()
        if w < 0xFFFF:
            return w, char_size
        d = self.u32()
        if d < 0xFFFFFFFF:
            return d, char_size
        return self.u64(), char_size

    def cstring(self) -> str:
        n, cs = self.string_length()
        raw = self._take(n * cs)
        return raw.decode("utf-16-le" if cs == 2 else "latin-1", errors="replace")

    # ---------------- objects ----------------

    def read_tag(self, expected: Optional[str] = None) -> Tuple[str, Optional[int], Optional[str], Optional[int]]:
        """Read an object tag: ("null"|"ref"|"new_class"|"class_ref", index, class, schema).

        `expected` is the class the caller's code statically writes at this point (from
        `operator<<(CArchive&, X*)`). A class reference to an index this stream never
        defined - SOLIDWORKS shares one class map across several streams - is then taken
        to be that class and remembered for later references.
        """
        w = self.u16()
        if w == BIG_OBJECT_TAG:
            ob = self.u32()
        else:
            ob = ((w & CLASS_TAG) << 16) | (w & ~CLASS_TAG & 0xFFFF)
        if not ob & BIG_CLASS_TAG:
            return ("null", 0, None, None) if ob == 0 else ("ref", ob, None, None)
        if w == NEW_CLASS_TAG:
            schema, ln = self.u16(), self.u16()
            name = self._take(ln)
            if not _NAME.fullmatch(name):
                raise ArchiveError(f"bad class name {name!r} at {self.pos - ln:#x}")
            idx = self.map_count
            self.map[idx] = ("class", name.decode("ascii"), schema)
            self.map_count += 1
            return "new_class", idx, name.decode("ascii"), schema
        idx = ob & ~BIG_CLASS_TAG
        entry = self.map.get(idx)
        if entry is None and expected:
            entry = self.map[idx] = ("class", expected, None)
            self.learned[idx] = expected
        if entry is None or entry[0] != "class":
            raise ArchiveError(f"class reference #{idx} at {self.pos - 2:#x} does not name a loaded class")
        return "class_ref", idx, entry[1], entry[2]

    def register_object(self, obj: ArchiveObject) -> None:
        obj.map_index = self.map_count
        self.map[self.map_count] = ("object", obj)
        self.map_count += 1


# --------------------------------------------------------------------------------------
# Layouts from serialize_trace
# --------------------------------------------------------------------------------------


def layouts_from_traces(traces: Iterable, path: str = "storing") -> Dict[str, List[LayoutOp]]:
    """Per-class decode layouts from SerializeTrace objects.

    The storing path is used by default: it is exactly what this build writes (the loading
    path also contains branches for older file versions).
    """
    out: Dict[str, List[LayoutOp]] = {}
    if isinstance(traces, dict):  # SerializeTracer.class_layouts(): {class: [ArchiveOp]}
        items = traces.items()
    else:
        items = [(t.class_name, t.storing if path == "storing" else t.loading) for t in traces if t.class_name]
    for name, ops in items:
        out[name] = [LayoutOp(o.kind, o.size, o.repeat, o.member, _layout_callee(o),
                              list(getattr(o, "conditions", []) or [])) for o in ops]
    return out


def _layout_callee(op) -> Optional[str]:
    """Base class for `serialize`; the statically expected class for `object` ops written by
    `operator<<(CArchive&, X*)` (e.g. moNodeName_c), so an unseen class index can be learned."""
    if op.kind == "serialize":
        return op.callee
    if op.kind == "object" and op.callee and op.callee.startswith(("??5", "??6")):
        for marker in ("PEAV", "PAV", "PEBV", "PBV"):
            i = op.callee.rfind(marker)
            if i >= 0:
                return op.callee[i + len(marker):].split("@", 1)[0] or None
    return None


def _desc_value(desc: str, env: Dict[str, object], fields: Dict[str, object]):
    if desc in env:
        return env[desc]
    if desc.startswith("archive["):  # archive mode flags: a plain binary archive has none set
        return env.get("archive_flags", 0)
    return fields.get(desc)


def evaluate_condition(cond, env: Dict[str, object], fields: Optional[Dict[str, object]] = None) -> Optional[bool]:
    """True/False for a structured gate, or None when an operand value is unknown."""
    fields = fields or {}
    if cond[0] == "mode":
        return None
    if cond[0] == "or":
        results = []
        for conj in cond[1]:
            vals = [evaluate_condition(c, env, fields) for c in conj]
            if all(v is True for v in vals):
                return True
            results.append(None if any(v is None for v in vals) and not any(v is False for v in vals) else False)
        return None if any(r is None for r in results) else False
    desc, rel, imm = cond[0], cond[1], cond[2] or 0
    v = _desc_value(desc, env, fields)
    if not isinstance(v, (int, float)):
        return None
    return {"<": v < imm, ">=": v >= imm, "==": v == imm, "!=": v != imm, "<=": v <= imm, ">": v > imm}[rel]


_NEG_REL = {">=": "<", "<": ">=", ">": "<=", "<=": ">", "==": "!=", "!=": "=="}


def _is_pointer_null_test(cond) -> bool:
    """`this+0x60 != 0` / `this+0x60 == 0`: a test of a member pointer against NULL."""
    return (isinstance(cond, (list, tuple)) and len(cond) == 3 and isinstance(cond[0], str)
            and cond[0].startswith("this+") and "->" not in cond[0]
            and cond[1] in ("!=", "==") and not cond[2])


def _cond_key(cond):
    """Hashable form of a structured condition (lists from JSON become tuples)."""
    if cond is None:
        return None
    if isinstance(cond, (list, tuple)):
        return tuple(_cond_key(x) for x in cond)
    return cond


def _negate_cond(cond):
    if not cond or cond[0] in ("mode", "or") or len(cond) != 3 or cond[1] not in _NEG_REL:
        return None
    return (cond[0], _NEG_REL[cond[1]], cond[2])


def _cond_text(cond) -> str:
    try:
        from serialize_trace import _gate_text  # type: ignore
    except ImportError:  # pragma: no cover
        from .serialize_trace import _gate_text  # type: ignore
    return _gate_text(cond)


# --------------------------------------------------------------------------------------
# Decoder
# --------------------------------------------------------------------------------------


class _Stop(Exception):
    """Payload layout cannot be followed further (unknown class, virtual member, ...)."""


class _Decoder:
    def __init__(self, reader: ArchiveReader, layouts: Dict[str, List[LayoutOp]], env: Dict[str, object],
                 unknown_gates: str, max_depth: int = 64):
        self.r = reader
        self.layouts = layouts
        self.env = env
        self.unknown_gates = unknown_gates
        self.max_depth = max_depth

    def read_object(self, depth: int = 0, expected: Optional[str] = None) -> ArchiveObject:
        r = self.r
        start = r.pos
        kind, idx, name, schema = r.read_tag(expected)
        if kind == "null":
            return ArchiveObject(start, None, None, None, kind="null", status="null")
        if kind == "ref":
            entry = r.map.get(idx)
            cname = entry[1].class_name if entry and entry[0] == "object" else None
            if entry is not None and entry[0] != "object":
                raise ArchiveError(f"object reference #{idx} at {start:#x} names a class")
            if entry is None and r.map_reliable:
                raise ArchiveError(f"object reference #{idx} at {start:#x} is not loaded yet")
            return ArchiveObject(start, cname, None, None, kind="reference", ref_index=idx, status="reference")
        obj = ArchiveObject(start, name, schema, None, payload_offset=r.pos)
        r.register_object(obj)
        if depth > self.max_depth:
            raise ArchiveError("object nesting too deep")
        layout = self.layouts.get(name)
        if layout is None:
            obj.status = "opaque"
            obj.note = "no layout for this class"
            raise _StopWith(obj)
        try:
            self._run(layout, obj, depth, {})
        except _StopWith:
            obj.status = "partial"
            raise _StopWith(obj)
        except ArchiveError as exc:
            obj.status = "partial"
            obj.note = str(exc)
            raise _StopWith(obj)
        obj.end = r.pos
        return obj

    @staticmethod
    def _assumed(c, decided) -> Optional[bool]:
        """Value of condition `c` from earlier assumptions (directly or by negation)."""
        if isinstance(c, (list, tuple)) and c and c[0] == "or":
            results = []
            for conj in c[1]:
                vals = [_Decoder._assumed(x, decided) for x in conj]
                if all(v is True for v in vals):
                    return True
                results.append(False if any(v is False for v in vals) else None)
            return False if all(r is False for r in results) else None
        key, neg = _cond_key(c), _cond_key(_negate_cond(c))
        if key in decided:
            return decided[key]
        if neg is not None and neg in decided:
            return not decided[neg]
        return None

    def _gate_ok(self, op: LayoutOp, obj: ArchiveObject, values: Dict[str, object]) -> bool:
        decided = values.setdefault("__assumed__", {})  # per object: condition -> assumed value
        for c in op.conditions:
            v = evaluate_condition(c, self.env, values)
            if v is None and c and c[0] == "or":
                # Mix known values and earlier assumptions inside the disjunction.
                known = {}
                for conj in c[1]:
                    for x in conj:
                        kv = evaluate_condition(x, self.env, values)
                        if kv is not None:
                            known[_cond_key(x)] = kv
                v = self._assumed(c, {**decided, **known})
            if v is None and _is_pointer_null_test(c) and values.get("__last_flag__") is not None:
                # `ar << (long)(m_p != NULL); if (m_p) m_p->Serialize(ar);` - the presence
                # flag written just before stands in for the pointer.
                values[c[0]] = values["__last_flag__"]
                v = evaluate_condition(c, self.env, values)
            if v is None:
                key = _cond_key(c)
                neg = _cond_key(_negate_cond(c))
                if key in decided:
                    v = decided[key]
                elif neg is not None and neg in decided:
                    v = not decided[neg]  # stay consistent: `x != 0` assumed => `x == 0` is false
                else:
                    if self.unknown_gates == "stop":
                        obj.note = f"unknown gate {_cond_text(c)}"
                        raise _StopWith(obj)
                    v = self.unknown_gates == "true"
                    decided[key] = v
                    obj.assumed.append(f"{_cond_text(c)} -> {v}")
            if not v:
                return False
        return True

    def _run(self, layout: List[LayoutOp], obj: ArchiveObject, depth: int, values: Dict[str, object]) -> None:
        r = self.r
        i = 0
        last_count: Optional[int] = None
        while i < len(layout):
            op = layout[i]
            if op.repeat:
                group = []
                while i < len(layout) and layout[i].repeat:
                    group.append(layout[i])
                    i += 1
                n = last_count if last_count is not None else 0
                if last_count is None:
                    obj.assumed.append("repeat count unknown -> 0")
                if n > 1_000_000:
                    raise ArchiveError(f"implausible element count {n}")
                for _ in range(n):
                    for g in group:
                        self._one(g, obj, depth, values)
                continue
            v = self._one(op, obj, depth, values)
            if op.kind in ("count", "u16", "u32", "u64") and isinstance(v, int):
                last_count = v
            i += 1

    def _one(self, op: LayoutOp, obj: ArchiveObject, depth: int, values: Dict[str, object]):
        if not self._gate_ok(op, obj, values):
            return None
        r = self.r
        at = r.pos
        k = op.kind
        if k in ("u8", "u16", "u32", "u64", "i8", "i16", "i32", "i64", "f32", "f64"):
            v = getattr(r, k)()
        elif k == "bool":
            v = r.u8()
        elif k == "count":
            v = r.count()
        elif k == "cstring":
            v = r.cstring()
        elif k == "bytes":
            if not op.size:
                raise _StopWith(obj, f"byte block of unknown size at {at:#x}")
            v = r.raw(op.size)
        elif k == "object":
            try:
                v = self.read_object(depth + 1, op.callee)
            except _StopWith as stop:
                obj.fields.append(Field(at, k, stop.obj, op.member, r.pos - at))
                raise _StopWith(obj, f"nested {stop.obj.class_name} could not be decoded")
        elif k == "serialize":
            base = self.layouts.get(op.callee or "")
            if base is None:
                raise _StopWith(obj, f"no layout for {op.callee}::Serialize")
            self._run(base, obj, depth, values)
            return None
        elif k == "virtual_serialize":
            raise _StopWith(obj, f"virtual Serialize of {op.member or 'a member'} (dynamic type unknown)")
        else:
            raise _StopWith(obj, f"cannot decode `{k}`")
        obj.fields.append(Field(at, k, v, op.member, r.pos - at))
        if op.member and isinstance(v, (int, float)):
            values[op.member] = v
        # An unnamed integer may be a presence flag for the next `if (m_p)` gate.
        values["__last_flag__"] = v if (op.member is None and isinstance(v, int)
                                        and k in ("u8", "u16", "u32", "i8", "i16", "i32", "bool")) else None
        return v


class _StopWith(Exception):
    def __init__(self, obj: ArchiveObject, note: Optional[str] = None):
        super().__init__(note or obj.note)
        self.obj = obj
        if note and not obj.note:
            obj.note = note


def decode_stream(data: bytes, layouts: Optional[Dict[str, List[LayoutOp]]] = None, *, start: int = 0,
                  env: Optional[Dict[str, object]] = None, unknown_gates: str = "true",
                  map_count: int = 1, max_objects: int = 100000) -> Dict[str, object]:
    """Decode a stream of top-level CArchive objects.

    `layouts` maps class names to LayoutOps (see layouts_from_traces). Objects of classes
    without a layout are reported as `opaque`; decoding then resumes at the next new-class
    tag, and the load map is flagged unreliable because objects inside the skipped bytes
    were not counted. `env` supplies values for gate operands (e.g. a file version);
    `unknown_gates` is "true", "false" or "stop" for gates that cannot be evaluated.
    """
    layouts = layouts or {}
    env = env or {}
    reader = ArchiveReader(data, start, map_count)
    dec = _Decoder(reader, layouts, env, unknown_gates)
    tags = scan_class_tags(data, start)
    tag_offsets = [t.offset for t in tags]
    objects: List[ArchiveObject] = []
    gaps: List[Dict[str, int]] = []

    def resync(after: int) -> Optional[int]:
        import bisect

        k = bisect.bisect_right(tag_offsets, after)
        return tag_offsets[k] if k < len(tag_offsets) else None

    pos = start
    if tags and not _looks_like_tag(data, pos, reader):
        first = tags[0].offset
        if first > pos:
            gaps.append({"offset": pos, "length": first - pos, "reason": "prefix"})
            pos = first
    while pos < len(data) and len(objects) < max_objects:
        reader.pos = pos
        try:
            obj = dec.read_object()
            objects.append(obj)
            if obj.kind == "null" and reader.pos >= len(data) - 1:
                break
            pos = reader.pos
            continue
        except _StopWith as stop:
            objects.append(stop.obj)
        except ArchiveError as exc:  # malformed tag at this position (not just an unknown class)
            objects.append(ArchiveObject(pos, None, None, None, kind="object", status="error", note=str(exc)))
        nxt = resync(max(pos, reader.pos - 1) if reader.pos > pos else pos)
        if nxt is None:
            if reader.pos < len(data):
                gaps.append({"offset": reader.pos, "length": len(data) - reader.pos, "reason": "undecoded tail"})
            break
        if nxt > reader.pos:
            gaps.append({"offset": reader.pos, "length": nxt - reader.pos, "reason": "skipped (no layout)"})
        reader.map_reliable = False
        pos = nxt

    def count(objs):
        n = {"decoded": 0, "partial": 0, "opaque": 0, "error": 0}
        for o in objs:
            if o.status in n:
                n[o.status] += 1
            for f in o.fields:
                vals = f.value if isinstance(f.value, list) else [f.value]
                sub = [x for x in vals if isinstance(x, ArchiveObject)]
                for k, v in count(sub).items():
                    n[k] += v
        return n

    return {
        "length": len(data),
        "objects": [o.to_dict() for o in objects],
        "gaps": gaps,
        "map_reliable": reader.map_reliable,
        "classes": [{"index": i, "name": e[1], "schema": e[2]} for i, e in sorted(reader.map.items())
                    if e[0] == "class"],
        "stats": count(objects),
    }


def _field_bytes(o: Dict[str, object]) -> int:
    """Bytes covered by decoded primitive/string fields inside an object dict (recursive)."""
    total = 0
    for f in o.get("fields", []) or []:
        v = f["value"]
        if isinstance(v, dict):
            total += _field_bytes(v)
        else:
            total += f.get("size") or 0
    return total


def _furthest(o: Dict[str, object]) -> int:
    """Furthest stream offset reached inside a decoded/partial object dict."""
    best = o.get("end") or o.get("offset") or 0
    for f in o.get("fields", []) or []:
        v = f["value"]
        best = max(best, f["offset"] + 1)
        if isinstance(v, dict):
            best = max(best, _furthest(v))
    return best


def _gate_operands(conds, out: Dict[str, set]) -> None:
    for c in conds:
        if c[0] == "or":
            for conj in c[1]:
                _gate_operands(conj, out)
        elif c[0] != "mode" and isinstance(c[0], str) and not c[0].startswith("archive[") \
                and isinstance(c[2], int):
            out.setdefault(c[0], set()).add(c[2])


def calibrate(data: bytes, layouts: Dict[str, List[LayoutOp]], *, start: int = 0,
              variable: Optional[str] = None, max_candidates: int = 64) -> Dict[str, object]:
    """Infer the value of a gate operand (typically the file-format version) from the data.

    Files written by older application versions skip fields that newer code writes behind
    `version >= N` checks. The operand used by the most gates of classes present in the
    stream is tried at 0 ("current") and at every threshold it is compared with; the value
    that decodes the most objects completely wins.
    """
    present = {t.name for t in scan_class_tags(data, start)}
    operands: Dict[str, set] = {}
    uses: Dict[str, int] = {}
    for name in present:
        for op in layouts.get(name, []):
            found: Dict[str, set] = {}
            _gate_operands(op.conditions, found)
            for k, v in found.items():
                operands.setdefault(k, set()).update(v)
                uses[k] = uses.get(k, 0) + 1
    if variable is None:
        if not uses:
            return {"variable": None, "value": None, "trials": []}
        variable = max(uses, key=uses.get)
    thresholds = sorted(operands.get(variable, set()))
    candidates = [0] + sorted({t for t in thresholds} | {t - 1 for t in thresholds if t > 0})
    if len(candidates) > max_candidates:  # keep an even spread
        step = len(candidates) / max_candidates
        candidates = [0] + [candidates[int(i * step)] for i in range(1, max_candidates)]
    trials = []
    for value in candidates:
        res = decode_stream(data, layouts, start=start, env={variable: value}, unknown_gates="true")
        s = res["stats"]
        # Bytes explained by decoded fields at any nesting depth: a wrong version misaligns
        # the stream and stops decoding early, wherever the object boundaries are.
        decoded_bytes = sum(_field_bytes(o) for o in res["objects"])
        trials.append({"value": value, "decoded": s["decoded"], "partial": s["partial"], "opaque": s["opaque"],
                       "error": s["error"], "decoded_bytes": decoded_bytes, "progress": max((_furthest(o) for o in res["objects"]),
                                                                        default=0)})
    # A wrong value makes objects with known layouts fail part-way ("partial") or leaves
    # the stream misaligned ("error"); objects without a layout are skipped the same way
    # for every value, so they do not count.
    def score(t):
        return (-(t["partial"] + t["error"]), t["decoded_bytes"], t["progress"], t["decoded"])

    best = max(trials, key=lambda t: score(t) + (t["value"] == 0,))
    max_known = max(thresholds) if thresholds else None
    out = {"variable": variable, "value": best["value"], "max_known_threshold": max_known, "trials": trials}
    # The newest known version decodes as well as anything and decoding is still incomplete:
    # the data may come from a newer application version than the traced binaries.
    newest = [t for t in trials if max_known is not None and t["value"] == max_known]
    if newest and score(newest[0]) == score(best) and (best["partial"] or best["error"]):
        out["warning"] = (f"best value {best['value']} is at or above the highest version these layouts know "
                          f"({max_known}); the stream may have been written by a newer application version")
    return out


def _looks_like_tag(data: bytes, pos: int, reader: ArchiveReader) -> bool:
    if pos + 2 > len(data):
        return False
    w = struct.unpack_from("<H", data, pos)[0]
    if w == NEW_CLASS_TAG:
        return bool(scan_class_tags(data, pos, min(len(data), pos + 80))) and \
            scan_class_tags(data, pos, min(len(data), pos + 80))[0].offset == pos
    return False


if __name__ == "__main__":  # pragma: no cover
    import json
    import sys

    # usage: mfc_archive.py STREAM [MAIN.dll [EXTRA.dll ...]] [-e name=value ...]
    args = [a for a in sys.argv[1:]]
    env: Dict[str, object] = {}
    while "-e" in args:
        k = args.index("-e")
        name, _, value = args[k + 1].partition("=")
        env[name] = int(value, 0)
        del args[k:k + 2]
    blob = open(args[0], "rb").read()
    layouts: Dict[str, List[LayoutOp]] = {}
    if len(args) > 1:
        import serialize_trace

        tracers = [serialize_trace.SerializeTracer(p) for p in args[1:]]
        layouts = layouts_from_traces(tracers[0].class_layouts(others=tuple(tracers[1:])))
        for extra in tracers[1:]:
            for k, v in layouts_from_traces(extra.class_layouts()).items():
                layouts.setdefault(k, v)
    res = decode_stream(blob, layouts, env=env)
    print(json.dumps({k: res[k] for k in ("length", "stats", "map_reliable", "gaps")}, indent=1))
    print(json.dumps(res["objects"], indent=1, default=str)[:12000])
