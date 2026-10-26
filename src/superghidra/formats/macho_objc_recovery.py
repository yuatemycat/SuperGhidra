"""
macho_objc_recovery.py
======================

Pure-Python Mach-O Objective-C runtime metadata recovery engine.
Recovers classes, metaclasses, superclasses, instance methods, class methods,
and ivars from 64-bit ARM64 / x86_64 Mach-O binaries without JVM or external tools.
Resolves GitHub Issue #28.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Tuple

from superghidra.formats.binary_loader import BinaryImage, load_binary


@dataclass
class ObjCMethod:
    name: str
    types: str | None = None
    imp: int = 0
    is_class_method: bool = False


@dataclass
class ObjCIvar:
    name: str
    type_encoding: str | None = None
    offset: int = 0
    size: int = 0


@dataclass
class ObjCClass:
    name: str
    address: int
    superclass: str | None = None
    instance_size: int = 0
    instance_methods: List[ObjCMethod] = field(default_factory=list)
    class_methods: List[ObjCMethod] = field(default_factory=list)
    ivars: List[ObjCIvar] = field(default_factory=list)


@dataclass
class ObjCRecoveryReport:
    classes: List[ObjCClass] = field(default_factory=list)
    counts: Dict[str, int] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "counts": self.counts,
            "classes": [
                {
                    "name": c.name,
                    "address": hex(c.address),
                    "superclass": c.superclass,
                    "instance_size": c.instance_size,
                    "instance_methods": [
                        {"name": m.name, "types": m.types, "imp": hex(m.imp)}
                        for m in c.instance_methods
                    ],
                    "class_methods": [
                        {"name": m.name, "types": m.types, "imp": hex(m.imp)}
                        for m in c.class_methods
                    ],
                    "ivars": [
                        {
                            "name": iv.name,
                            "type": iv.type_encoding,
                            "offset": iv.offset,
                            "size": iv.size,
                        }
                        for iv in c.ivars
                    ],
                }
                for c in self.classes
            ],
        }


def _strip_objc_symbol_prefix(sym_name: str) -> str:
    for prefix in ("_OBJC_CLASS_$_", "OBJC_CLASS_$_", "_OBJC_METACLASS_$_", "OBJC_METACLASS_$_"):
        if sym_name.startswith(prefix):
            return sym_name[len(prefix):]
    return sym_name


def _parse_method_list(img: BinaryImage, list_va: int, is_class_method: bool = False) -> List[ObjCMethod]:
    if not list_va:
        return []
    hdr = img.read_va(list_va, 8)
    if len(hdr) < 8:
        return []
    entsize_flags, count = struct.unpack("<II", hdr)
    entsize = entsize_flags & 0xFFFF
    if entsize < 24 or count > 10000:
        return []

    methods: List[ObjCMethod] = []
    for i in range(count):
        entry_va = list_va + 8 + i * entsize
        entry_data = img.read_va(entry_va, entsize)
        if len(entry_data) < 24:
            break
        name_va, types_va, imp = struct.unpack("<QQQ", entry_data[:24])
        name = img.read_c_string(name_va) or ""
        types = img.read_c_string(types_va)
        if name:
            methods.append(ObjCMethod(name=name, types=types, imp=imp, is_class_method=is_class_method))
    return methods


def _parse_ivar_list(img: BinaryImage, list_va: int) -> List[ObjCIvar]:
    if not list_va:
        return []
    hdr = img.read_va(list_va, 8)
    if len(hdr) < 8:
        return []
    entsize_flags, count = struct.unpack("<II", hdr)
    entsize = entsize_flags & 0xFFFF
    if entsize < 32 or count > 10000:
        return []

    ivars: List[ObjCIvar] = []
    for i in range(count):
        entry_va = list_va + 8 + i * entsize
        entry_data = img.read_va(entry_va, entsize)
        if len(entry_data) < 32:
            break
        off_va, name_va, type_va, align, size = struct.unpack("<QQQII", entry_data[:32])
        name = img.read_c_string(name_va) or ""
        type_enc = img.read_c_string(type_va)
        offset = 0
        if off_va:
            off_bytes = img.read_va(off_va, 4)
            if len(off_bytes) == 4:
                offset = struct.unpack("<I", off_bytes)[0]
        if name:
            ivars.append(ObjCIvar(name=name, type_encoding=type_enc, offset=offset, size=size))
    return ivars


def recover_objc_classes(binary_or_path: str | Path | bytes | BinaryImage) -> ObjCRecoveryReport:
    """
    Parses a 64-bit Mach-O binary and extracts Objective-C class definitions,
    method selectors, types, and ivar displacements without launching a JVM.
    """
    if isinstance(binary_or_path, BinaryImage):
        img = binary_or_path
    elif isinstance(binary_or_path, Path):
        img = load_binary(str(binary_or_path))
    else:
        img = load_binary(binary_or_path)

    if img.format != "macho":
        raise ValueError(f"recover_objc_classes expects a Mach-O binary; got format='{img.format}'")

    # Locate classlist sections (__objc_classlist in __DATA or __DATA_CONST)
    classlist_secs = [
        s for s in img.sections if s.name.endswith("__objc_classlist") or s.name.endswith("objc_classlist")
    ]
    if not classlist_secs:
        return ObjCRecoveryReport([], {"classes": 0, "instance_methods": 0, "class_methods": 0, "ivars": 0})

    # Collect class pointers
    class_vas: List[int] = []
    for sec in classlist_secs:
        sec_data = img.read_va(sec.vaddr, sec.file_size or sec.vsize)
        num_ptrs = len(sec_data) // 8
        for i in range(num_ptrs):
            c_va = struct.unpack_from("<Q", sec_data, i * 8)[0]
            if c_va and c_va not in class_vas:
                class_vas.append(c_va)

    # First pass: map class VA to class name for superclass resolution
    class_map: Dict[int, str] = {}
    class_ro_map: Dict[int, Tuple[int, int, str, int, int]] = {}  # class_va -> (ro_va, isa, name, super_va, size)

    for c_va in class_vas:
        c_raw = img.read_va(c_va, 40)
        if len(c_raw) < 40:
            continue
        isa, super_va, _, _, data_va = struct.unpack("<QQQQQ", c_raw)
        ro_va = data_va & ~7
        ro_raw = img.read_va(ro_va, 72)
        if len(ro_raw) < 72:
            continue
        _, _, instance_size, _, _, name_va, base_methods_va, _, ivars_va, _, _ = struct.unpack(
            "<IIIIQQQQQQQ", ro_raw[:72]
        )
        cname = img.read_c_string(name_va) or f"Class_{hex(c_va)}"
        class_map[c_va] = cname
        class_ro_map[c_va] = (ro_va, isa, cname, super_va, instance_size)

    # Second pass: construct full ObjCClass records
    classes: List[ObjCClass] = []
    for c_va in class_vas:
        if c_va not in class_ro_map:
            continue
        ro_va, isa, cname, super_va, instance_size = class_ro_map[c_va]
        ro_raw = img.read_va(ro_va, 72)
        _, _, _, _, _, _, base_methods_va, _, ivars_va, _, _ = struct.unpack(
            "<IIIIQQQQQQQ", ro_raw[:72]
        )

        # Resolve superclass name
        super_name: str | None = None
        if super_va:
            if super_va in class_map:
                super_name = class_map[super_va]
            else:
                # Check symbols / imports
                for sym in img.symbols:
                    if sym.address == super_va:
                        super_name = _strip_objc_symbol_prefix(sym.name)
                        break
                if not super_name:
                    # Check if super_va points to an external class with a class_ro_t
                    super_raw = img.read_va(super_va, 40)
                    if len(super_raw) == 40:
                        _, _, _, _, s_data_va = struct.unpack("<QQQQQ", super_raw)
                        s_ro_raw = img.read_va(s_data_va & ~7, 72)
                        if len(s_ro_raw) >= 72:
                            s_name_va = struct.unpack("<IIIIQQQQQQQ", s_ro_raw[:72])[5]
                            super_name = img.read_c_string(s_name_va)

        # Parse instance methods
        inst_methods = _parse_method_list(img, base_methods_va, is_class_method=False)

        # Parse ivars
        ivars = _parse_ivar_list(img, ivars_va)

        # Parse class methods from metaclass
        cls_methods: List[ObjCMethod] = []
        if isa and isa != c_va:
            meta_raw = img.read_va(isa, 40)
            if len(meta_raw) == 40:
                _, _, _, _, meta_data_va = struct.unpack("<QQQQQ", meta_raw)
                meta_ro_raw = img.read_va(meta_data_va & ~7, 72)
                if len(meta_ro_raw) >= 72:
                    meta_methods_va = struct.unpack("<IIIIQQQQQQQ", meta_ro_raw[:72])[6]
                    cls_methods = _parse_method_list(img, meta_methods_va, is_class_method=True)

        classes.append(
            ObjCClass(
                name=cname,
                address=c_va,
                superclass=super_name,
                instance_size=instance_size,
                instance_methods=inst_methods,
                class_methods=cls_methods,
                ivars=ivars,
            )
        )

    classes.sort(key=lambda c: c.name)
    counts = {
        "classes": len(classes),
        "instance_methods": sum(len(c.instance_methods) for c in classes),
        "class_methods": sum(len(c.class_methods) for c in classes),
        "ivars": sum(len(c.ivars) for c in classes),
    }

    return ObjCRecoveryReport(classes=classes, counts=counts)
