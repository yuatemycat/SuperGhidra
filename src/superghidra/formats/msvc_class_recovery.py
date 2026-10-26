"""
msvc_class_recovery.py - recover C++ / MFC class metadata from Windows PE binaries.

Two independent sources, merged per class:

1. MSVC RTTI (x86 and x64)
   TypeDescriptor (".?AVName@@")  <-  CompleteObjectLocator  <-  vftable[-1]
   gives class names, every vftable (one per base sub-object), virtual function lists and
   the inheritance chain from the ClassHierarchyDescriptor.

2. MFC CRuntimeClass (DECLARE_DYNAMIC / DECLARE_DYNCREATE / DECLARE_SERIAL)
   { m_lpszClassName, m_nObjectSize, m_wSchema, m_pfnCreateObject,
     m_pBaseClass | m_pfnGetBaseClass, m_pNextClass, m_pClassInit }
   gives the CArchive class name, object size, schema version, factory and base class.

Linking them: CObject's first virtual function is GetRuntimeClass(), typically
`lea rax, [rip+classX] ; ret` (x64) or `mov eax, offset classX ; ret` (x86). Decoding
that stub ties a CRuntimeClass to its vftable, and CObject::Serialize is the third
virtual slot, so every serializable class gets the address of its Serialize(CArchive&)
function - the code that defines its on-disk field layout in CArchive streams such as
SolidWorks' Contents/Config-*-ResolvedFeatures.
"""

from __future__ import annotations

import os
import re
import struct
from dataclasses import asdict, dataclass, field
from typing import Dict, List, Optional, Tuple

from superghidra.formats import binary_loader
from superghidra.lifters import x86_decode

__all__ = [
    "VTable",
    "RttiClass",
    "MfcRuntimeClass",
    "ClassRecoveryReport",
    "demangle_rtti_name",
    "recover_classes",
    "RTTIClass",
    "RTTIBaseClass",
    "MemberVariable",
    "CRuntimeClassInfo",
]

# CObject vtable layout in release MFC (x86 and x64): 0 GetRuntimeClass, 1 deleting dtor,
# 2 Serialize. Debug MFC appends AssertValid/Dump after these, so the first three are stable.
MFC_SLOT_GET_RUNTIME_CLASS = 0
MFC_SLOT_SERIALIZE = 2
MFC_VERSIONABLE_SCHEMA = 0x80000000

_IDENT = re.compile(rb"[A-Za-z_][A-Za-z0-9_:<>]{1,200}\x00")


@dataclass
class VTable:
    address: int
    col_address: Optional[int]
    offset_in_class: int  # COL.offset: this pointer adjustment of the sub-object
    functions: List[int] = field(default_factory=list)


@dataclass
class RttiClass:
    name: str
    mangled: str
    type_descriptor: int
    vtables: List[VTable] = field(default_factory=list)
    bases: List[str] = field(default_factory=list)  # direct and indirect, nearest first
    multiple_inheritance: bool = False
    virtual_inheritance: bool = False
    object_size: Optional[int] = None


@dataclass
class MfcRuntimeClass:
    name: str
    address: int
    object_size: int
    schema: int  # 0xFFFF => not serializable; low 16 bits otherwise
    versionable: bool
    create_object: Optional[int]
    base_class: Optional[int]  # base CRuntimeClass VA (resolved through GetBaseClass stubs)
    base_name: Optional[str] = None
    vtable: Optional[int] = None
    get_runtime_class: Optional[int] = None
    serialize: Optional[int] = None  # body of Serialize(CArchive&), thunks/forwarders resolved
    serialize_slot: Optional[int] = None  # vtable slot holding that body (2 for plain MFC)
    serialize_external: Optional[str] = None  # imported Serialize the class inherits, if any

    @property
    def serializable(self) -> bool:
        return (self.schema & 0xFFFF) != 0xFFFF


@dataclass
class ClassRecoveryReport:
    binary: Optional[str]
    arch: str
    rtti_classes: List[RttiClass]
    mfc_classes: List[MfcRuntimeClass]

    def mfc_by_name(self) -> Dict[str, MfcRuntimeClass]:
        return {c.name: c for c in self.mfc_classes}

    def rtti_by_name(self) -> Dict[str, RttiClass]:
        return {c.name: c for c in self.rtti_classes}

    def to_dict(self) -> Dict[str, object]:
        def hx(v):
            return hex(v) if isinstance(v, int) else v

        mfc = []
        for c in self.mfc_classes:
            d = {k: hx(v) if k in ("address", "create_object", "base_class", "vtable",
                                   "get_runtime_class", "serialize") else v for k, v in asdict(c).items()}
            d["schema"] = c.schema & 0xFFFF
            d["serializable"] = c.serializable
            mfc.append(d)
        rtti = []
        for c in self.rtti_classes:
            rtti.append({
                "name": c.name, "mangled": c.mangled, "type_descriptor": hx(c.type_descriptor),
                "bases": c.bases, "multiple_inheritance": c.multiple_inheritance,
                "virtual_inheritance": c.virtual_inheritance, "object_size": c.object_size,
                "vtables": [{"address": hx(v.address), "offset_in_class": v.offset_in_class,
                             "functions": [hx(f) for f in v.functions]} for v in c.vtables],
            })
        return {"binary": self.binary, "arch": self.arch, "mfc_classes": mfc, "rtti_classes": rtti,
                "counts": {"mfc": len(mfc), "mfc_serializable": sum(1 for c in self.mfc_classes if c.serializable),
                           "rtti": len(rtti)}}


# --------------------------------------------------------------------------------------
# Name demangling (RTTI type names only)
# --------------------------------------------------------------------------------------


def demangle_rtti_name(mangled: str) -> str:
    """Best-effort readable name for an RTTI type descriptor name.

    ".?AVCWnd@@" -> "CWnd", ".?AVInner@Outer@ns@@" -> "ns::Outer::Inner",
    ".?AV?$CArray@VCPoint@@V1@@@" -> "CArray<...>".
    """
    s = mangled
    for prefix in (".?AV", ".?AU", ".?AW4", ".?AT"):
        if s.startswith(prefix):
            s = s[len(prefix):]
            break
    else:
        return mangled
    if s.endswith("@@"):
        s = s[:-2]
    if s.startswith("?$"):
        # Template: "?$Name@<args>@" then an optional scope. Arguments are not decoded; the
        # scope is only recoverable when the argument list ends with "@@@" (class-type args).
        tmpl = s[2:].split("@", 1)[0]
        parts = s.rsplit("@@@", 1)
        scope = [p for p in parts[1].split("@") if p] if len(parts) == 2 else []
        return "::".join(list(reversed(scope)) + [f"{tmpl}<...>"])
    parts = [p for p in s.split("@") if p]
    return "::".join(reversed(parts)) if parts else mangled


# --------------------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------------------


class _View:
    """Fast pointer/RVA reads over a BinaryImage."""

    def __init__(self, img: binary_loader.BinaryImage):
        self.img = img
        self.ptr = img.bits // 8
        self.pfmt = "<Q" if self.ptr == 8 else "<I"
        self.code = [(s.vaddr, s.vaddr + max(s.vsize, s.file_size)) for s in img.sections if s.executable]
        # Read-only data is often merged into .text (e.g. 32-bit Windows system DLLs), so
        # every section with file data is scanned except resources and relocations.
        self.data_secs = [s for s in img.sections if s.file_size and s.readable
                          and s.name.lower() not in (".rsrc", ".reloc", ".pdata", ".idata")]
        self.iat = {imp.address: imp for imp in img.imports if imp.address}

    def is_code(self, va: Optional[int]) -> bool:
        return va is not None and any(a <= va < b for a, b in self.code)

    def is_mapped(self, va: Optional[int]) -> bool:
        return va is not None and self.img.section_for_va(va) is not None

    def u32(self, va: int) -> Optional[int]:
        raw = self.img.read_va(va, 4)
        return struct.unpack("<I", raw)[0] if len(raw) == 4 else None

    def i32(self, va: int) -> Optional[int]:
        raw = self.img.read_va(va, 4)
        return struct.unpack("<i", raw)[0] if len(raw) == 4 else None

    def pointer(self, va: int) -> Optional[int]:
        raw = self.img.read_va(va, self.ptr)
        return struct.unpack(self.pfmt, raw)[0] if len(raw) == self.ptr else None

    def ref(self, va: int) -> Optional[int]:
        """RTTI reference: image-relative RVA on x64, absolute VA on x86."""
        if self.ptr == 8:
            rva = self.i32(va)
            return None if rva is None else self.img.image_base + rva
        return self.u32(va)

    def pointer_slots(self):
        """Yield (va, value) for every aligned pointer in readable data sections."""
        size, fmt = self.ptr, "<Q" if self.ptr == 8 else "<I"
        for sec in self.data_secs:
            blob = self.img.section_bytes(sec)
            start = (-sec.vaddr) % size
            for off in range(start, len(blob) - size + 1, size):
                yield sec.vaddr + off, struct.unpack_from(fmt, blob, off)[0]


def _decode_at(view: _View, va: int) -> Optional[x86_decode.X86Insn]:
    code = view.img.read_va(va, 16)
    if not code:
        return None
    insn = x86_decode.decode(code, 0, va, 64 if view.ptr == 8 else 32)
    return None if insn.invalid else insn


def _follow_thunks(view: _View, va: int, max_hops: int = 8) -> int:
    """Skip incremental-linking / ICF `jmp rel` thunks to the real function body."""
    for _ in range(max_hops):
        insn = _decode_at(view, va)
        if insn is None or insn.flow != "jmp" or insn.target is None or not view.is_code(insn.target):
            break
        va = insn.target
    return va


def _import_slot(view: _View, insn: x86_decode.X86Insn) -> Optional[str]:
    """Import name when `insn` reads an IAT slot (`mov rax,[rip+iat]` / `jmp [iat]`)."""
    if insn.mem is None:
        return None
    slot = insn.mem.effective_address(insn.end)
    imp = view.iat.get(slot) if slot is not None else None
    if imp is None:
        return None
    return imp.name or f"{imp.library or '?'}#{imp.ordinal}"


def _stub_value(view: _View, func_va: int) -> Tuple[Optional[int], Optional[str]]:
    """What a `return &classX;` stub returns: (address, None) or (None, imported symbol).

    Recognises `lea rax,[rip+X]; ret`, `mov eax, X; ret`, `mov rax,[rip+__imp_X]; ret`
    and the tail call `jmp [__imp_Base::GetThisClass]`, behind any number of jmp thunks.
    """
    va = _follow_thunks(view, func_va)
    insn = _decode_at(view, va)
    if insn is None or insn.map != 0:
        return None, None
    if insn.flow == "jmp_ind":
        return None, _import_slot(view, insn)
    value, imported = None, None
    if insn.opcode == 0x8D and insn.mem is not None and (insn.reg & 7) == 0:
        value = insn.mem.effective_address(insn.end)
    elif insn.opcode == 0xB8 and insn.imm is not None:  # mov eax, imm32
        value = insn.imm
    elif insn.opcode in (0x8B, 0xA1) and (insn.reg & 7) == 0:  # mov eax/rax, [mem]
        imported = _import_slot(view, insn)
        if imported is None:
            return None, None
    else:
        return None, None
    nxt = _decode_at(view, insn.end)
    if nxt is None or nxt.flow != "ret":
        return None, None
    return value, imported


def _returned_address(view: _View, func_va: int) -> Optional[int]:
    """Address returned by a `lea rax,[rip+X]; ret` / `mov eax, X; ret` style stub."""
    return _stub_value(view, func_va)[0]


def _virtual_forward_slot(view: _View, func_va: int) -> Optional[int]:
    """Slot index K when the function is `mov rax,[rcx]; jmp [rax+K*ptr]` (a virtual forwarder).

    Frameworks layered on MFC (e.g. SolidWorks' su_CObject) implement Serialize(CArchive&)
    this way and put the per-class body in a later virtual slot.
    """
    first = _decode_at(view, func_va)
    if (first is None or first.map != 0 or first.opcode != 0x8B or first.mem is None
            or first.mem.base not in ("rcx", "ecx") or first.mem.index or first.mem.disp
            or first.operand_size != view.ptr):
        return None
    reg = (x86_decode.REG64 if view.ptr == 8 else x86_decode.REG32)[first.reg]
    second = _decode_at(view, first.end)
    if (second is None or second.flow != "jmp_ind" or second.mem is None
            or second.mem.base != reg or second.mem.index or second.mem.disp % view.ptr):
        return None
    return second.mem.disp // view.ptr


def _demangle_mfc_import(name: Optional[str]) -> Optional[str]:
    """`?classCObject@CObject@@2UCRuntimeClass@@B` / `?GetThisClass@CDocument@@SA...` -> class."""
    if not name or not name.startswith("?"):
        return None
    parts = name[1:].split("@")
    return parts[1] if len(parts) > 2 and parts[1] else None


# --------------------------------------------------------------------------------------
# MSVC RTTI
# --------------------------------------------------------------------------------------


def _scan_rtti(view: _View) -> List[RttiClass]:
    img, ptr = view.img, view.ptr
    td_name_off = 2 * ptr  # TypeDescriptor: pVFTable, spare, name[]
    type_descs: Dict[int, str] = {}
    for sec in view.data_secs:
        blob = img.section_bytes(sec)
        for m in re.finditer(rb"\.\?A[VU][^\x00]{1,4000}?@@\x00", blob):
            td_va = sec.vaddr + m.start() - td_name_off
            if td_va % ptr:
                continue
            type_descs[td_va] = m.group()[:-1].decode("latin-1")
    if not type_descs:
        return []

    # Complete object locators referencing those type descriptors.
    cols: Dict[int, Tuple[int, int, int]] = {}  # col_va -> (td_va, offset, chd_va)
    col_size = 24 if ptr == 8 else 20
    for sec in view.data_secs:
        blob = img.section_bytes(sec)
        for off in range(0, len(blob) - col_size + 1, 4):
            sig = struct.unpack_from("<I", blob, off)[0]
            if sig != (1 if ptr == 8 else 0):
                continue
            col_va = sec.vaddr + off
            if ptr == 8:
                _, offset, cd_off, td_rva, chd_rva, self_rva = struct.unpack_from("<IIIiii", blob, off)
                if img.image_base + self_rva != col_va:
                    continue
                td_va, chd_va = img.image_base + td_rva, img.image_base + chd_rva
            else:
                _, offset, cd_off, td_va, chd_va = struct.unpack_from("<IIIII", blob, off)
            if td_va in type_descs and view.is_mapped(chd_va):
                cols[col_va] = (td_va, offset, chd_va)

    classes: Dict[int, RttiClass] = {}

    def get_class(td_va: int) -> RttiClass:
        if td_va not in classes:
            mangled = type_descs[td_va]
            classes[td_va] = RttiClass(demangle_rtti_name(mangled), mangled, td_va)
        return classes[td_va]

    # vftables: a pointer to a COL immediately precedes the first virtual function.
    for slot_va, value in view.pointer_slots():
        if value not in cols:
            continue
        td_va, offset, chd_va = cols[value]
        vt_va = slot_va + ptr
        funcs = []
        for k in range(4096):
            fn = view.pointer(vt_va + k * ptr)
            if k and fn in cols:
                break
            if not view.is_code(fn):
                break
            funcs.append(fn)
        if funcs:
            get_class(td_va).vtables.append(VTable(vt_va, value, offset, funcs))

    # Hierarchy (ClassHierarchyDescriptor -> BaseClassArray -> BaseClassDescriptors).
    for col_va, (td_va, _, chd_va) in cols.items():
        cls = get_class(td_va)
        if cls.bases:
            continue
        attrs = view.u32(chd_va + 4) or 0
        count = view.u32(chd_va + 8) or 0
        bca = view.ref(chd_va + 12)
        cls.multiple_inheritance = bool(attrs & 1)
        cls.virtual_inheritance = bool(attrs & 2)
        if not bca or count > 256:
            continue
        for k in range(1, count):  # entry 0 is the class itself
            bcd = view.ref(bca + 4 * k) if ptr == 8 else view.u32(bca + 4 * k)
            base_td = view.ref(bcd) if bcd else None
            if base_td in type_descs:
                cls.bases.append(demangle_rtti_name(type_descs[base_td]))

    # MSVC Exception Handling (CatchableType / CatchableTypeArray):
    # Recovers non-polymorphic / thrown exception classes, base hierarchies, and object sizes
    # even when RTTI is disabled (/GR-) or classes lack vtables.
    td_lookup = {(va - img.image_base if ptr == 8 else va): va for va in type_descs}
    catchable_types: Dict[int, Tuple[int, int]] = {}
    ct_rec_size = 28
    for sec in view.data_secs:
        blob = img.section_bytes(sec)
        for off in range(0, len(blob) - ct_rec_size + 1, 4):
            props, pType, mdisp, pdisp, vdisp, size, copy_fn = struct.unpack_from("<Iiiiiii", blob, off)
            if pType in td_lookup and 0 <= size <= 0x100000 and props < 0x20:
                ct_key = (sec.vaddr + off - img.image_base) if ptr == 8 else (sec.vaddr + off)
                catchable_types[ct_key] = (td_lookup[pType], size)

    for sec in view.data_secs:
        blob = img.section_bytes(sec)
        for off in range(0, len(blob) - 8, 4):
            count = struct.unpack_from("<i", blob, off)[0]
            if 1 <= count <= 32:
                rvas = struct.unpack_from(f"<{count}i", blob, off + 4)
                if all(r in catchable_types for r in rvas):
                    chain = [catchable_types[r] for r in rvas]
                    primary_td_va, obj_size = chain[0]
                    cls = get_class(primary_td_va)
                    if cls.object_size is None and obj_size > 0:
                        cls.object_size = obj_size
                    if not cls.bases and len(chain) > 1:
                        for base_td_va, _ in chain[1:]:
                            base_name = demangle_rtti_name(type_descs[base_td_va])
                            if base_name not in cls.bases and base_name != cls.name:
                                cls.bases.append(base_name)

    for cls in classes.values():
        cls.vtables.sort(key=lambda v: v.offset_in_class)
    return sorted(classes.values(), key=lambda c: c.name)


# --------------------------------------------------------------------------------------
# MFC CRuntimeClass
# --------------------------------------------------------------------------------------


def _scan_mfc(view: _View) -> List[MfcRuntimeClass]:
    img, ptr = view.img, view.ptr
    rec = 8 + 5 * ptr if ptr == 8 else 28  # x64: name, size+schema, 4 pointers / x86: 7 dwords
    name_cache: Dict[int, Optional[str]] = {}

    def class_name(va: int) -> Optional[str]:
        if va not in name_cache:
            raw = img.read_va(va, 202)
            m = _IDENT.match(raw) if raw else None
            name_cache[va] = m.group()[:-1].decode("ascii") if m else None
        return name_cache[va]

    found: Dict[int, MfcRuntimeClass] = {}
    for sec in view.data_secs:
        blob = img.section_bytes(sec)
        for off in range((-sec.vaddr) % ptr, len(blob) - rec + 1, ptr):
            if ptr == 8:
                name_p, size, schema, create, base, nxt, init = struct.unpack_from("<QiIQQQQ", blob, off)
            else:
                name_p, size, schema, create, base, nxt, init = struct.unpack_from("<IiIIIII", blob, off)
            if not (0 < size <= 0x100000):
                continue
            low = schema & 0xFFFF
            if schema & ~0x8000FFFF or (schema & MFC_VERSIONABLE_SCHEMA and low == 0xFFFF):
                continue
            if create and not view.is_code(create):
                continue
            if nxt and not view.is_mapped(nxt):
                continue
            if init and not view.is_mapped(init):
                continue
            if base and not view.is_mapped(base):
                continue
            if not view.is_mapped(name_p):
                continue
            name = class_name(name_p)
            if not name or (not base and name != "CObject"):  # only CObject is a root class
                continue
            va = sec.vaddr + off
            found[va] = MfcRuntimeClass(name, va, size, schema, bool(schema & MFC_VERSIONABLE_SCHEMA),
                                        create or None, base or None)

    # Base class: static builds store the CRuntimeClass*; _AFXDLL builds store a
    # GetBaseClass() function returning it.
    # A base CRuntimeClass in another module (e.g. mfc140u.dll) is only known by its
    # import name, so base_class stays None and base_name comes from the import.
    # 1. MFC linkage check: binary must either import an MFC library or define CObject
    has_mfc_linkage = any(
        imp.library and (imp.library.lower().startswith("mfc") or imp.library.lower().startswith("afx"))
        for imp in img.imports
    ) or any(c.name == "CObject" for c in found.values())

    if not has_mfc_linkage:
        return []

    imported_bases: Dict[int, str] = {}
    for cls in found.values():
        if cls.base_class and view.is_code(cls.base_class):
            resolved_base, imported = _stub_value(view, cls.base_class)
            cls.base_class = resolved_base
            if imported:
                imported_bases[cls.address] = imported
                cls.base_name = _demangle_mfc_import(imported)
        if cls.base_class in found:
            cls.base_name = found[cls.base_class].name

    # 2. Hierarchy validation: authentic MFC classes must trace to CObject or an imported MFC base
    def reaches_mfc_root(c: MfcRuntimeClass, visited: set) -> bool:
        if c.name == "CObject" or c.base_name is not None or c.address in imported_bases:
            return True
        if not c.base_class or c.base_class in visited:
            return False
        visited.add(c.base_class)
        parent = found.get(c.base_class)
        if parent is None:
            return False
        return reaches_mfc_root(parent, visited)

    valid_classes = [c for c in found.values() if reaches_mfc_root(c, set())]
    return sorted(valid_classes, key=lambda c: c.name)


_SIBLING_VIEWS: Dict[str, Optional[Tuple[_View, Dict[str, int]]]] = {}


def _sibling_view(view: _View, library: Optional[str]) -> Optional[Tuple[_View, Dict[str, int]]]:
    """(view, export map) of `library` loaded from the same folder as the image, or None."""
    if not library or not view.img.path:
        return None
    path = os.path.join(os.path.dirname(view.img.path), library)
    key = os.path.normcase(os.path.abspath(path))
    if key not in _SIBLING_VIEWS:
        loaded = None
        try:
            if os.path.isfile(path):
                img = binary_loader.load_binary(path)
                loaded = (_View(img), img.export_map())
        except (OSError, ValueError):
            pass
        _SIBLING_VIEWS[key] = loaded
    return _SIBLING_VIEWS[key]


def _imported_forward_slot(view: _View, insn: x86_decode.X86Insn) -> Optional[int]:
    """Slot K when an imported function (in a DLL next to the image) is a virtual forwarder.

    SolidWorks' main modules inherit `su_CObject::Serialize(CArchive&)` from swccu.dll,
    which is `mov rax,[rcx]; jmp [rax+0x28]`: the class's own body sits in slot 5.
    """
    if insn.mem is None:
        return None
    imp = view.iat.get(insn.mem.effective_address(insn.end))
    if imp is None or not imp.name:
        return None
    sibling = _sibling_view(view, imp.library)
    if sibling is None:
        return None
    other, exports = sibling
    target = exports.get(imp.name)
    if target is None:
        return None
    return _virtual_forward_slot(other, _follow_thunks(other, target))


def _resolve_serialize(view: _View, funcs: List[int]) -> Tuple[Optional[int], Optional[int], Optional[str]]:
    """(body VA, slot, imported name) for the Serialize virtual of a vftable."""
    slot = MFC_SLOT_SERIALIZE
    for _ in range(4):
        if slot >= len(funcs):
            return None, None, None
        body = _follow_thunks(view, funcs[slot])
        insn = _decode_at(view, body)
        if insn is not None and insn.flow == "jmp_ind":
            imported = _import_slot(view, insn)
            if imported:
                nxt = _imported_forward_slot(view, insn)
                if nxt is not None and nxt != slot and nxt < len(funcs):
                    slot = nxt
                    continue
                return None, slot, imported
        nxt = _virtual_forward_slot(view, body)
        if nxt is None or nxt == slot:
            return body, slot, None
        slot = nxt
    return None, None, None


def _link_mfc_to_vtables(view: _View, mfc: List[MfcRuntimeClass], rtti: List[RttiClass]) -> None:
    """Find each CRuntimeClass's vftable through its GetRuntimeClass() stub."""
    by_addr = {c.address: c for c in mfc}
    candidates: List[Tuple[int, List[int], Optional[str]]] = []
    for cls in rtti:
        for vt in cls.vtables:
            if vt.offset_in_class == 0:
                candidates.append((vt.address, vt.functions, cls.name))
    stub_cache: Dict[int, Optional[int]] = {}

    def runtime_class_of(fn: int) -> Optional[int]:
        if fn not in stub_cache:
            stub_cache[fn] = _returned_address(view, fn)
        return stub_cache[fn]

    # Without RTTI (/GR-), fall back to scanning data for pointer runs into code whose
    # first entry is a GetRuntimeClass stub.
    if not candidates:
        prev_va, run = None, []
        for slot_va, value in view.pointer_slots():
            if view.is_code(value) and prev_va is not None and slot_va == prev_va + view.ptr:
                run.append(value)
            else:
                if len(run) > MFC_SLOT_SERIALIZE:
                    candidates.append((prev_va - (len(run) - 1) * view.ptr, run, None))
                run = [value] if view.is_code(value) else []
            prev_va = slot_va

    # A class without its own DECLARE_DYNAMIC inherits its base's GetRuntimeClass, so
    # several vftables can report the same CRuntimeClass. Prefer the one whose RTTI name
    # matches; otherwise take the first.
    matches: Dict[int, List[Tuple[int, List[int], Optional[str]]]] = {}
    for vt_va, funcs, rtti_name in candidates:
        if len(funcs) <= MFC_SLOT_SERIALIZE:
            continue
        rc = runtime_class_of(funcs[MFC_SLOT_GET_RUNTIME_CLASS])
        if rc in by_addr:
            matches.setdefault(rc, []).append((vt_va, funcs, rtti_name))
    for rc, options in matches.items():
        cls = by_addr[rc]
        exact = [o for o in options if o[2] == cls.name]
        vt_va, funcs, _ = (exact or options)[0]
        cls.vtable = vt_va
        cls.get_runtime_class = _follow_thunks(view, funcs[MFC_SLOT_GET_RUNTIME_CLASS])
        if cls.serializable:
            cls.serialize, cls.serialize_slot, cls.serialize_external = _resolve_serialize(view, funcs)


def recover_classes(source, *, rtti: bool = True, mfc: bool = True,
                    symbol_dirs: Optional[List[str]] = None) -> ClassRecoveryReport:
    """Recover MSVC RTTI classes and MFC CRuntimeClass records from a PE file/bytes/image.

    ``symbol_dirs`` overrides where ordinal-name tables (``mfc140u.exports`` ...) are looked
    up; by default Ghidra's ``data/symbols`` directory is used when it can be found.
    """
    img = source if isinstance(source, binary_loader.BinaryImage) else binary_loader.load_binary(source)
    if img.format != "pe" or img.arch not in ("x86", "x86_64"):
        raise ValueError(f"MSVC class recovery needs an x86/x64 PE image, got {img.format}/{img.arch}")
    binary_loader.resolve_import_ordinals(img, symbol_dirs)  # MFC DLLs export by ordinal only
    view = _View(img)
    rtti_classes = _scan_rtti(view) if rtti else []
    mfc_classes = _scan_mfc(view) if mfc else []
    if mfc_classes:
        _link_mfc_to_vtables(view, mfc_classes, rtti_classes)
    return ClassRecoveryReport(img.path, img.arch, rtti_classes, mfc_classes)


if __name__ == "__main__":  # pragma: no cover
    import json
    import sys

    rep = recover_classes(sys.argv[1])
    d = rep.to_dict()
    print(json.dumps(d["counts"], indent=2))
    for c in d["mfc_classes"][:40]:
        print(f"{c['name']:40} size={c['object_size']:<6} schema={c['schema']:<6} base={c['base_name']} "
              f"vt={c['vtable']} serialize={c['serialize']}")

# Aliases for Public API freeze (SuperGhidra 0.4.0)
RTTIClass = RttiClass
RTTIBaseClass = VTable
CRuntimeClassInfo = MfcRuntimeClass

# Field alias for member recovery
from superghidra.formats.mfc_archive import Field as MemberVariable
