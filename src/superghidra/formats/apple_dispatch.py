"""
apple_dispatch.py
=================

Mach-O binary dispatch and runtime metadata recovery engine.
Decodes dyld chained fixups (including authenticated arm64e pointer chains),
legacy dyld info opcodes, Swift 5 nominal type descriptors and protocol
conformances, and Objective-C 64-bit runtime structures without starting Ghidra.
"""

from __future__ import annotations

import struct
import zlib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Set, Tuple

__all__ = [
    "ChainedFixupEntry",
    "ChainedFixupsReport",
    "Swift5Method",
    "Swift5TypeDescriptor",
    "Swift5ProtocolConformance",
    "Swift5Report",
    "ObjCMethod",
    "ObjCIvar",
    "ObjCCategory",
    "ObjCProtocol",
    "ObjCClass",
    "ObjCRecoveryReport",
    "AppleDispatchReport",
    "dispatch_apple_binary",
    "extract_macho_slice",
]

# -----------------------------------------------------------------------------
# Mach-O and Dyld Constants
# -----------------------------------------------------------------------------

FAT_MAGIC = 0xCAFEBABE
FAT_CIGAM = 0xBEBAFECA
FAT_MAGIC_64 = 0xCAFEBABF
FAT_CIGAM_64 = 0xBFBAFECA

MH_MAGIC = 0xFEEDFACE
MH_CIGAM = 0xCEFAEDFE
MH_MAGIC_64 = 0xFEEDFACF
MH_CIGAM_64 = 0xCFFAEDFE

CPU_TYPE_X86 = 7
CPU_TYPE_X86_64 = 0x01000007
CPU_TYPE_ARM = 12
CPU_TYPE_ARM64 = 0x0100000C
CPU_TYPE_ARM64_32 = 0x0200000C

CPU_SUBTYPE_ARM64_ALL = 0
CPU_SUBTYPE_ARM64_V8 = 1
CPU_SUBTYPE_ARM64E = 2
CPU_SUBTYPE_MASK = 0x00FFFFFF

LC_SEGMENT = 0x1
LC_SYMTAB = 0x2
LC_DYSYMTAB = 0xB
LC_LOAD_DYLIB = 0xC
LC_SEGMENT_64 = 0x19
LC_DYLD_INFO = 0x22
LC_DYLD_INFO_ONLY = 0x80000022
LC_LOAD_WEAK_DYLIB = 0x80000018
LC_REEXPORT_DYLIB = 0x8000001F
LC_DYLD_CHAINED_FIXUPS = 0x80000034
LC_DYLD_EXPORTS_TRIE = 0x80000033

# Chained pointer formats
DYLD_CHAINED_PTR_ARM64E = 1
DYLD_CHAINED_PTR_64 = 2
DYLD_CHAINED_PTR_32 = 3
DYLD_CHAINED_PTR_32_CACHE = 4
DYLD_CHAINED_PTR_32_FIRMWARE = 5
DYLD_CHAINED_PTR_64_OFFSET = 6
DYLD_CHAINED_PTR_ARM64E_KERNEL = 7
DYLD_CHAINED_PTR_64_KERNEL_CACHE = 8
DYLD_CHAINED_PTR_ARM64E_USERLAND = 9
DYLD_CHAINED_PTR_ARM64E_FIRMWARE = 10
DYLD_CHAINED_PTR_X86_64_KERNEL_CACHE = 11
DYLD_CHAINED_PTR_ARM64E_USERLAND24 = 12
DYLD_CHAINED_PTR_ARM64E_SHARED_CACHE = 13
DYLD_CHAINED_PTR_ARM64E_USERLAND2 = DYLD_CHAINED_PTR_ARM64E_USERLAND24

# Chained import formats
DYLD_CHAINED_IMPORT = 1
DYLD_CHAINED_IMPORT_ADDEND = 2
DYLD_CHAINED_IMPORT_ADDEND64 = 3

# Legacy dyld_info opcodes
REBASE_TYPE_POINTER = 1
REBASE_OPCODE_DONE = 0x00
REBASE_OPCODE_SET_TYPE_IMM = 0x10
REBASE_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB = 0x20
REBASE_OPCODE_ADD_ADDR_ULEB = 0x30
REBASE_OPCODE_ADD_ADDR_IMM_SCALED = 0x40
REBASE_OPCODE_DO_REBASE_IMM_TIMES = 0x50
REBASE_OPCODE_DO_REBASE_ULEB_TIMES = 0x60
REBASE_OPCODE_DO_REBASE_ADD_ADDR_ULEB = 0x70
REBASE_OPCODE_DO_REBASE_ULEB_TIMES_SKIPPING_ULEB = 0x80

BIND_TYPE_POINTER = 1
BIND_OPCODE_DONE = 0x00
BIND_OPCODE_SET_DYLIB_ORDINAL_IMM = 0x10
BIND_OPCODE_SET_DYLIB_ORDINAL_ULEB = 0x20
BIND_OPCODE_SET_DYLIB_SPECIAL_IMM = 0x30
BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM = 0x40
BIND_OPCODE_SET_TYPE_IMM = 0x50
BIND_OPCODE_SET_ADDEND_SLEB = 0x60
BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB = 0x70
BIND_OPCODE_ADD_ADDR_ULEB = 0x80
BIND_OPCODE_DO_BIND = 0x90
BIND_OPCODE_DO_BIND_ADD_ADDR_ULEB = 0xA0
BIND_OPCODE_DO_BIND_ADD_ADDR_IMM_SCALED = 0xB0
BIND_OPCODE_DO_BIND_ULEB_TIMES_SKIPPING_ULEB = 0xC0

DEFAULT_MAX_INPUT_BYTES = 67108864  # 64 MiB
MAX_ALLOWED_INPUT_BYTES = 1073741824  # 1 GiB


# -----------------------------------------------------------------------------
# Data Models & Dataclasses
# -----------------------------------------------------------------------------

@dataclass
class ChainedFixupEntry:
    offset: int
    address: int
    kind: str  # "rebase", "bind", "auth_rebase", "auth_bind"
    target: int = 0
    ordinal: int = 0
    symbol_name: str | None = None
    library: str | None = None
    addend: int = 0
    auth_key: str | None = None  # "IA", "IB", "DA", "DB"
    diversity: int = 0
    addr_diversity: bool = False

    def to_dict(self) -> Dict[str, Any]:
        res: Dict[str, Any] = {
            "offset": hex(self.offset),
            "address": hex(self.address),
            "kind": self.kind,
        }
        if "rebase" in self.kind:
            res["target"] = hex(self.target)
        if "bind" in self.kind:
            res["ordinal"] = self.ordinal
            if self.symbol_name is not None:
                res["symbol_name"] = self.symbol_name
            if self.library is not None:
                res["library"] = self.library
            if self.addend:
                res["addend"] = self.addend
        if "auth" in self.kind:
            res["auth_key"] = self.auth_key
            res["diversity"] = hex(self.diversity)
            res["addr_diversity"] = self.addr_diversity
        return res


@dataclass
class ChainedFixupsReport:
    fixups_version: int = 0
    pointer_format: int = 0
    starts_count: int = 0
    imports_count: int = 0
    entries: List[ChainedFixupEntry] = field(default_factory=list)
    imports: List[str] = field(default_factory=list)
    legacy_info_fallback: bool = False
    counts: Dict[str, int] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "fixups_version": self.fixups_version,
            "pointer_format": self.pointer_format,
            "starts_count": self.starts_count,
            "imports_count": self.imports_count,
            "legacy_info_fallback": self.legacy_info_fallback,
            "counts": self.counts,
            "imports": self.imports,
            "entries": [e.to_dict() for e in self.entries],
        }


@dataclass
class Swift5Method:
    address: int
    flags: int = 0
    name: str | None = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "address": hex(self.address),
            "flags": hex(self.flags),
            "name": self.name,
        }


@dataclass
class Swift5TypeDescriptor:
    name: str
    kind: str  # "class", "struct", "enum", "actor"
    address: int
    is_generic: bool = False
    fields: List[str] = field(default_factory=list)
    vtable_methods: List[Swift5Method] = field(default_factory=list)
    conformances: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "kind": self.kind,
            "address": hex(self.address),
            "is_generic": self.is_generic,
            "fields": self.fields,
            "vtable_methods": [m.to_dict() for m in self.vtable_methods],
            "conformances": self.conformances,
        }


@dataclass
class Swift5ProtocolConformance:
    protocol_name: str
    type_name: str
    type_binding: str | None = None
    address: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "protocol_name": self.protocol_name,
            "type_name": self.type_name,
            "type_binding": self.type_binding,
            "address": hex(self.address),
        }


@dataclass
class Swift5Report:
    types: List[Swift5TypeDescriptor] = field(default_factory=list)
    protocols: List[str] = field(default_factory=list)
    conformances: List[Swift5ProtocolConformance] = field(default_factory=list)
    counts: Dict[str, int] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "counts": self.counts,
            "protocols": self.protocols,
            "types": [t.to_dict() for t in self.types],
            "conformances": [c.to_dict() for c in self.conformances],
        }


@dataclass
class ObjCMethod:
    name: str
    types: str | None = None
    imp: int = 0
    is_class_method: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "types": self.types,
            "imp": hex(self.imp),
            "is_class_method": self.is_class_method,
        }


@dataclass
class ObjCIvar:
    name: str
    type_encoding: str | None = None
    offset: int = 0
    size: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "type": self.type_encoding,
            "offset": self.offset,
            "size": self.size,
        }


@dataclass
class ObjCCategory:
    name: str
    class_name: str
    address: int
    instance_methods: List[ObjCMethod] = field(default_factory=list)
    class_methods: List[ObjCMethod] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "class_name": self.class_name,
            "address": hex(self.address),
            "instance_methods": [m.to_dict() for m in self.instance_methods],
            "class_methods": [m.to_dict() for m in self.class_methods],
        }


@dataclass
class ObjCProtocol:
    name: str
    address: int
    instance_methods: List[ObjCMethod] = field(default_factory=list)
    class_methods: List[ObjCMethod] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "address": hex(self.address),
            "instance_methods": [m.to_dict() for m in self.instance_methods],
            "class_methods": [m.to_dict() for m in self.class_methods],
        }


@dataclass
class ObjCClass:
    name: str
    address: int
    superclass: str | None = None
    instance_size: int = 0
    instance_methods: List[ObjCMethod] = field(default_factory=list)
    class_methods: List[ObjCMethod] = field(default_factory=list)
    ivars: List[ObjCIvar] = field(default_factory=list)
    protocols: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "address": hex(self.address),
            "superclass": self.superclass,
            "instance_size": self.instance_size,
            "instance_methods": [m.to_dict() for m in self.instance_methods],
            "class_methods": [m.to_dict() for m in self.class_methods],
            "ivars": [iv.to_dict() for iv in self.ivars],
            "protocols": self.protocols,
        }


@dataclass
class ObjCRecoveryReport:
    classes: List[ObjCClass] = field(default_factory=list)
    categories: List[ObjCCategory] = field(default_factory=list)
    protocols: List[ObjCProtocol] = field(default_factory=list)
    counts: Dict[str, int] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "counts": self.counts,
            "classes": [c.to_dict() for c in self.classes],
            "categories": [cat.to_dict() for cat in self.categories],
            "protocols": [p.to_dict() for p in self.protocols],
        }


@dataclass
class AppleDispatchReport:
    arch: str
    bits: int
    image_base: int
    chained_fixups: ChainedFixupsReport
    swift5: Swift5Report
    objc: ObjCRecoveryReport
    counts: Dict[str, int] = field(default_factory=dict)
    limitations: List[str] = field(default_factory=list)
    epistemic_status: str = "observed"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "arch": self.arch,
            "bits": self.bits,
            "image_base": hex(self.image_base),
            "chained_fixups": self.chained_fixups.to_dict(),
            "swift5": self.swift5.to_dict(),
            "objc": self.objc.to_dict(),
            "counts": self.counts,
            "limitations": self.limitations,
            "epistemic_status": self.epistemic_status,
        }


# -----------------------------------------------------------------------------
# Internal Mach-O Slice & Parsing Helpers
# -----------------------------------------------------------------------------

@dataclass
class MachOSegment:
    segname: str
    vmaddr: int
    vmsize: int
    fileoff: int
    filesize: int
    maxprot: int
    initprot: int
    flags: int


@dataclass
class MachOSection:
    segname: str
    sectname: str
    addr: int
    size: int
    offset: int
    align: int
    reloff: int
    nreloc: int
    flags: int
    reserved1: int = 0


class MachOSlice:
    """Represents a single parsed thin Mach-O architecture slice."""

    def __init__(self, data: bytes, arch: str):
        self.data = data
        self.arch = arch
        self.segments: List[MachOSegment] = []
        self.sections: List[MachOSection] = []
        self.libraries: List[str] = []
        self.image_base: int = 0
        self._has_text_segment: bool = False
        self.chained_fixups_cmd: Tuple[int, int] | None = None  # (dataoff, datasize)
        self.dyld_info_cmd: Tuple[int, int, int, int, int, int, int, int, int, int] | None = None
        self.dysymtab_cmd: Tuple[int, ...] | None = None
        self.symtab_cmd: Tuple[int, int, int, int] | None = None  # symoff, nsyms, stroff, strsize

        self._parse_header_and_commands()

    def _parse_header_and_commands(self) -> None:
        if len(self.data) < 28:
            raise ValueError("Mach-O slice is too small to contain a header")

        magic_le = struct.unpack_from("<I", self.data, 0)[0]
        if magic_le in (MH_MAGIC, MH_MAGIC_64):
            e = "<"
            magic = magic_le
        else:
            e = ">"
            magic = struct.unpack_from(">I", self.data, 0)[0]

        if magic not in (MH_MAGIC, MH_CIGAM, MH_MAGIC_64, MH_CIGAM_64):
            raise ValueError(f"Invalid Mach-O magic: 0x{magic:08x}")

        self.bits = 64 if magic in (MH_MAGIC_64, MH_CIGAM_64) else 32
        self.endian = e

        cputype, cpusubtype, filetype, ncmds, sizeofcmds, flags = struct.unpack_from(
            e + "iiIIII", self.data, 4
        )
        self.cputype = cputype
        self.cpusubtype = cpusubtype
        self.filetype = filetype

        off = 32 if self.bits == 64 else 28
        for _ in range(ncmds):
            if off + 8 > len(self.data):
                break
            cmd, cmdsize = struct.unpack_from(e + "II", self.data, off)
            if cmdsize < 8 or off + cmdsize > len(self.data):
                break

            if cmd in (LC_SEGMENT, LC_SEGMENT_64):
                if cmd == LC_SEGMENT_64:
                    segname_raw = self.data[off + 8 : off + 24]
                    segname = segname_raw.rstrip(b"\x00").decode("latin-1", errors="replace")
                    vmaddr, vmsize, fileoff, filesize, maxprot, initprot, nsects, seg_flags = (
                        struct.unpack_from(e + "QQQQiiII", self.data, off + 24)
                    )
                    sect_off, sect_size = off + 72, 80
                else:
                    segname_raw = self.data[off + 8 : off + 24]
                    segname = segname_raw.rstrip(b"\x00").decode("latin-1", errors="replace")
                    vmaddr, vmsize, fileoff, filesize, maxprot, initprot, nsects, seg_flags = (
                        struct.unpack_from(e + "IIIIiiII", self.data, off + 24)
                    )
                    sect_off, sect_size = off + 56, 68

                seg = MachOSegment(
                    segname=segname,
                    vmaddr=vmaddr,
                    vmsize=vmsize,
                    fileoff=fileoff,
                    filesize=filesize,
                    maxprot=maxprot,
                    initprot=initprot,
                    flags=seg_flags,
                )
                self.segments.append(seg)
                if segname == "__TEXT":
                    self.image_base = vmaddr
                    self._has_text_segment = True
                elif not self._has_text_segment and segname != "__PAGEZERO":
                    self.image_base = vmaddr

                for s in range(nsects):
                    so = sect_off + s * sect_size
                    if so + sect_size > len(self.data):
                        break
                    sname_raw = self.data[so : so + 16]
                    sseg_raw = self.data[so + 16 : so + 32]
                    sname = sname_raw.rstrip(b"\x00").decode("latin-1", errors="replace")
                    sseg = sseg_raw.rstrip(b"\x00").decode("latin-1", errors="replace")

                    if cmd == LC_SEGMENT_64:
                        addr, size, offset, align, reloff, nreloc, sflags = (
                            struct.unpack_from(e + "QQIIIII", self.data, so + 32)
                        )
                        reserved1 = (
                            struct.unpack_from(e + "I", self.data, so + 68)[0]
                            if so + 72 <= len(self.data)
                            else 0
                        )
                    else:
                        addr, size, offset, align, reloff, nreloc, sflags = (
                            struct.unpack_from(e + "IIIIIII", self.data, so + 32)
                        )
                        reserved1 = (
                            struct.unpack_from(e + "I", self.data, so + 60)[0]
                            if so + 64 <= len(self.data)
                            else 0
                        )

                    self.sections.append(
                        MachOSection(
                            segname=sseg,
                            sectname=sname,
                            addr=addr,
                            size=size,
                            offset=offset,
                            align=align,
                            reloff=reloff,
                            nreloc=nreloc,
                            flags=sflags,
                            reserved1=reserved1,
                        )
                    )

            elif cmd == LC_DYLD_CHAINED_FIXUPS:
                dataoff, datasize = struct.unpack_from(e + "II", self.data, off + 8)
                self.chained_fixups_cmd = (dataoff, datasize)

            elif cmd in (LC_DYLD_INFO, LC_DYLD_INFO_ONLY):
                self.dyld_info_cmd = struct.unpack_from(e + "10I", self.data, off + 8)

            elif cmd == LC_DYSYMTAB:
                if off + 80 <= len(self.data):
                    self.dysymtab_cmd = struct.unpack_from(e + "18I", self.data, off + 8)

            elif cmd == LC_SYMTAB:
                self.symtab_cmd = struct.unpack_from(e + "4I", self.data, off + 8)

            elif cmd in (LC_LOAD_DYLIB, LC_LOAD_WEAK_DYLIB, LC_REEXPORT_DYLIB):
                name_off = struct.unpack_from(e + "I", self.data, off + 8)[0]
                if name_off < cmdsize:
                    dylib_str = self._read_cstr(self.data, off + name_off, cmdsize - name_off)
                    if dylib_str:
                        self.libraries.append(dylib_str)

            off += cmdsize

    @staticmethod
    def _read_cstr(buf: bytes, offset: int, max_len: int = 1024) -> str | None:
        if offset >= len(buf):
            return None
        sub = buf[offset : offset + max_len]
        idx = sub.find(b"\x00")
        if idx >= 0:
            return sub[:idx].decode("utf-8", errors="replace")
        return sub.decode("utf-8", errors="replace")

    def section_for_va(self, va: int) -> MachOSection | None:
        for sec in self.sections:
            if sec.addr <= va < sec.addr + max(sec.size, 1):
                return sec
        return None

    def va_to_offset(self, va: int) -> int | None:
        sec = self.section_for_va(va)
        if sec is not None:
            delta = va - sec.addr
            if delta < sec.size:
                return sec.offset + delta
        for seg in self.segments:
            if seg.vmaddr <= va < seg.vmaddr + max(seg.vmsize, seg.filesize):
                delta = va - seg.vmaddr
                if delta < seg.filesize:
                    return seg.fileoff + delta
        return None

    def offset_to_va(self, offset: int) -> int | None:
        for sec in self.sections:
            if sec.size and sec.offset <= offset < sec.offset + sec.size:
                return sec.addr + (offset - sec.offset)
        for seg in self.segments:
            if seg.filesize and seg.fileoff <= offset < seg.fileoff + seg.filesize:
                return seg.vmaddr + (offset - seg.fileoff)
        return None

    def read_va(self, va: int, size: int) -> bytes:
        off = self.va_to_offset(va)
        if off is None or off >= len(self.data):
            return b""
        avail = len(self.data) - off
        return self.data[off : off + min(size, avail)]

    def read_c_string(self, va: int, limit: int = 1024) -> str | None:
        raw = self.read_va(va, limit)
        if not raw:
            return None
        idx = raw.find(b"\x00")
        if idx >= 0:
            return raw[:idx].decode("utf-8", errors="replace")
        return raw.decode("utf-8", errors="replace")

    def read_c_string_at_offset(self, offset: int, limit: int = 1024) -> str | None:
        return self._read_cstr(self.data, offset, limit)

    def get_section(self, segname: str, sectname: str) -> MachOSection | None:
        for s in self.sections:
            if s.segname == segname and s.sectname == sectname:
                return s
        return None

    def get_sections_by_name(self, sectname: str) -> List[MachOSection]:
        return [
            s for s in self.sections
            if s.sectname == sectname or s.sectname.endswith(sectname)
        ]


def _read_uleb128(data: bytes, offset: int) -> Tuple[int, int]:
    result = 0
    shift = 0
    p = offset
    while p < len(data):
        byte = data[p]
        p += 1
        result |= (byte & 0x7F) << shift
        if (byte & 0x80) == 0:
            break
        shift += 7
    return result, p - offset


def _read_sleb128(data: bytes, offset: int) -> Tuple[int, int]:
    result = 0
    shift = 0
    p = offset
    byte = 0
    while p < len(data):
        byte = data[p]
        p += 1
        result |= (byte & 0x7F) << shift
        shift += 7
        if (byte & 0x80) == 0:
            break
    if shift < 64 and (byte & 0x40):
        result |= -(1 << shift)
    return result, p - offset


def _classify_arch(cputype: int, cpusubtype: int) -> str:
    cputype = cputype & 0xFFFFFFFF
    subtype = cpusubtype & CPU_SUBTYPE_MASK
    if cputype == CPU_TYPE_ARM64:
        if subtype == CPU_SUBTYPE_ARM64E:
            return "arm64e"
        return "arm64"
    elif cputype == CPU_TYPE_X86_64:
        return "x86_64"
    elif cputype == CPU_TYPE_ARM:
        return "arm"
    elif cputype == CPU_TYPE_X86:
        return "x86"
    return "unknown"


def extract_macho_slice(data: bytes, requested_arch: str = "arm64") -> Tuple[bytes, str]:
    """
    Selects and extracts a thin Mach-O slice from a raw binary or Universal FAT archive.
    """
    if len(data) < 4:
        raise ValueError("Binary buffer is too small to contain a Mach-O header")

    magic_be = struct.unpack_from(">I", data, 0)[0]
    magic_le = struct.unpack_from("<I", data, 0)[0]

    if magic_be in (FAT_MAGIC, FAT_CIGAM, FAT_MAGIC_64, FAT_CIGAM_64):
        endian = ">" if magic_be in (FAT_MAGIC, FAT_MAGIC_64) else "<"
        is64 = magic_be in (FAT_MAGIC_64, FAT_CIGAM_64)
        if len(data) < 8:
            raise ValueError("Truncated Universal FAT header")
        nfat = struct.unpack_from(endian + "I", data, 4)[0]

        slices: List[Tuple[str, int, int]] = []
        for i in range(nfat):
            if is64:
                entry_off = 8 + i * 32
                if entry_off + 32 > len(data):
                    break
                cputype, cpusubtype, off, sz = struct.unpack_from(endian + "iiQQ", data, entry_off)
            else:
                entry_off = 8 + i * 20
                if entry_off + 20 > len(data):
                    break
                cputype, cpusubtype, off, sz = struct.unpack_from(endian + "iiII", data, entry_off)

            arch_name = _classify_arch(cputype, cpusubtype)
            slices.append((arch_name, off, sz))

        if not slices:
            raise ValueError("Universal FAT binary has no valid architecture slices")

        preference = [requested_arch, "arm64e", "arm64", "x86_64", "arm", "x86"]

        def rank(s: Tuple[str, int, int]) -> int:
            name = s[0]
            if name in preference:
                return preference.index(name)
            return len(preference)

        slices.sort(key=rank)
        selected_arch, slice_off, slice_sz = slices[0]
        if slice_off + slice_sz > len(data):
            raise ValueError("FAT slice bounds exceed file length")
        return data[slice_off : slice_off + slice_sz], selected_arch

    elif magic_le in (MH_MAGIC, MH_MAGIC_64) or magic_be in (MH_MAGIC, MH_MAGIC_64):
        endian = "<" if magic_le in (MH_MAGIC, MH_MAGIC_64) else ">"
        if len(data) < 12:
            raise ValueError("Truncated thin Mach-O header")
        cputype, cpusubtype = struct.unpack_from(endian + "ii", data, 4)
        arch_name = _classify_arch(cputype, cpusubtype)
        return data, arch_name

    raise ValueError(f"Unrecognized binary format (magic=0x{magic_le:08x})")


# -----------------------------------------------------------------------------
# Dyld Chained Fixups & Legacy Dyld Info Decoders
# -----------------------------------------------------------------------------

def _decode_chained_fixups(slice_macho: MachOSlice, limitations: List[str]) -> ChainedFixupsReport:
    """Decodes dyld chained fixups table or falls back to legacy LC_DYLD_INFO opcodes."""
    if slice_macho.chained_fixups_cmd is None:
        if slice_macho.dyld_info_cmd is not None:
            legacy_rep = _decode_legacy_dyld_info(slice_macho, limitations)
            if legacy_rep.entries:
                return legacy_rep
        if slice_macho.dysymtab_cmd is not None:
            return _decode_dysymtab_fixups(slice_macho, limitations)
        return ChainedFixupsReport()

    dataoff, datasize = slice_macho.chained_fixups_cmd
    if dataoff + datasize > len(slice_macho.data) or datasize < 28:
        limitations.append("Malformed LC_DYLD_CHAINED_FIXUPS: payload boundary extends past slice")
        return ChainedFixupsReport()

    pointer_format: int = 0
    fixup_base = dataoff
    fixups_version, starts_offset, imports_offset, symbols_offset, imports_count, imports_format, symbols_format = (
        struct.unpack_from("<7I", slice_macho.data, fixup_base)
    )

    # 1. Decode imports table
    imports: List[str] = []
    symbols_base = fixup_base + symbols_offset
    symbols_pool: bytes = b""
    if symbols_offset < datasize:
        raw_symbols = slice_macho.data[symbols_base : fixup_base + datasize]
        if symbols_format == 1:
            try:
                symbols_pool = zlib.decompress(raw_symbols)
            except Exception as e:
                limitations.append(f"Failed to decompress chained fixup symbols: {e}")
                symbols_pool = raw_symbols
        else:
            symbols_pool = raw_symbols

    # Enforce admission check and upper bound on chained imports table
    entry_sz = 4
    if imports_format == DYLD_CHAINED_IMPORT_ADDEND:
        entry_sz = 8
    elif imports_format == DYLD_CHAINED_IMPORT_ADDEND64:
        entry_sz = 16
    max_possible = max(0, (datasize - imports_offset) // entry_sz) if imports_offset < datasize else 0
    max_chained_limit = 65536
    bounded_count = min(imports_count, max_chained_limit, max_possible)
    if imports_count > bounded_count:
        limitations.append(f"Chained fixups import count clamped from {imports_count} to {bounded_count}")

    for i in range(bounded_count):
        sym_name: str | None = None
        if imports_format == DYLD_CHAINED_IMPORT:
            imp_off = fixup_base + imports_offset + i * 4
            if imp_off + 4 <= len(slice_macho.data):
                val = struct.unpack_from("<I", slice_macho.data, imp_off)[0]
                name_offset = (val >> 9) & 0x7FFFFF
                sym_name = MachOSlice._read_cstr(symbols_pool, name_offset)
        elif imports_format == DYLD_CHAINED_IMPORT_ADDEND:
            imp_off = fixup_base + imports_offset + i * 8
            if imp_off + 8 <= len(slice_macho.data):
                val, _ = struct.unpack_from("<Ii", slice_macho.data, imp_off)
                name_offset = (val >> 9) & 0x7FFFFF
                sym_name = MachOSlice._read_cstr(symbols_pool, name_offset)
        elif imports_format == DYLD_CHAINED_IMPORT_ADDEND64:
            imp_off = fixup_base + imports_offset + i * 16
            if imp_off + 16 <= len(slice_macho.data):
                _meta, name_offset, _addend = struct.unpack_from("<IIq", slice_macho.data, imp_off)
                sym_name = MachOSlice._read_cstr(symbols_pool, name_offset)

        imports.append(sym_name or f"import_{i}")

    # 2. Decode starts in image
    entries: List[ChainedFixupEntry] = []
    starts_base = fixup_base + starts_offset
    if starts_offset < datasize and starts_base + 4 <= len(slice_macho.data):
        seg_count = struct.unpack_from("<I", slice_macho.data, starts_base)[0]
        for s in range(seg_count):
            off_ptr = starts_base + 4 + s * 4
            if off_ptr + 4 > len(slice_macho.data):
                break
            seg_info_offset = struct.unpack_from("<I", slice_macho.data, off_ptr)[0]
            if seg_info_offset == 0:
                continue

            seg_starts_base = starts_base + seg_info_offset
            if seg_starts_base + 22 > len(slice_macho.data):
                continue

            size, page_size, pointer_format, segment_offset, max_valid_pointer, page_count = (
                struct.unpack_from("<IHHQIH", slice_macho.data, seg_starts_base)
            )

            page_starts_offset = seg_starts_base + 22
            if page_starts_offset + page_count * 2 > len(slice_macho.data):
                continue
            page_starts = struct.unpack_from(
                f"<{page_count}H", slice_macho.data, page_starts_offset
            )

            target_seg: MachOSegment | None = None
            if s < len(slice_macho.segments):
                target_seg = slice_macho.segments[s]

            seg_fileoff = target_seg.fileoff if target_seg else segment_offset
            seg_vmaddr = target_seg.vmaddr if target_seg else (
                slice_macho.offset_to_va(seg_fileoff) or (slice_macho.image_base + seg_fileoff)
            )

            # Cycle breaker and traversal
            visited_offsets: Set[int] = set()
            for p in range(page_count):
                pstart = page_starts[p]
                if pstart == 0xFFFF:  # DYLD_CHAINED_PTR_START_NONE
                    continue
                offset_in_page = pstart & 0x7FFF
                chain_file_off = seg_fileoff + p * page_size + offset_in_page

                step_count = 0
                while True:
                    step_count += 1
                    if step_count > 100000:
                        limitations.append(f"Chain step limit exceeded at offset 0x{chain_file_off:x}")
                        break
                    if chain_file_off in visited_offsets:
                        limitations.append(f"Cycle detected in chained fixup table at offset 0x{chain_file_off:x}")
                        break
                    visited_offsets.add(chain_file_off)

                    if chain_file_off + 4 > len(slice_macho.data):
                        break

                    slot_va = seg_vmaddr + (chain_file_off - seg_fileoff)

                    # Pointer decoding by format
                    if pointer_format in (
                        DYLD_CHAINED_PTR_ARM64E,
                        DYLD_CHAINED_PTR_ARM64E_KERNEL,
                        DYLD_CHAINED_PTR_ARM64E_USERLAND,
                        DYLD_CHAINED_PTR_ARM64E_FIRMWARE,
                        DYLD_CHAINED_PTR_ARM64E_USERLAND24,
                        DYLD_CHAINED_PTR_ARM64E_SHARED_CACHE,
                    ):
                        if chain_file_off + 8 > len(slice_macho.data):
                            break
                        val = struct.unpack_from("<Q", slice_macho.data, chain_file_off)[0]
                        auth = (val >> 63) & 1
                        bind = (val >> 62) & 1
                        next_stride = ((val >> 51) & 0x7FF) * 8

                        if auth:
                            key_idx = (val >> 49) & 0x3
                            key_names = ["IA", "IB", "DA", "DB"]
                            auth_key = key_names[key_idx]
                            addr_div = bool((val >> 48) & 1)
                            diversity = (val >> 32) & 0xFFFF
                            if bind:
                                if pointer_format == DYLD_CHAINED_PTR_ARM64E_USERLAND24:
                                    ordinal = val & 0xFFFFFF
                                else:
                                    ordinal = val & 0xFFFF
                                sym_name = imports[ordinal] if ordinal < len(imports) else None
                                entries.append(
                                    ChainedFixupEntry(
                                        offset=chain_file_off,
                                        address=slot_va,
                                        kind="auth_bind",
                                        ordinal=ordinal,
                                        symbol_name=sym_name,
                                        auth_key=auth_key,
                                        diversity=diversity,
                                        addr_diversity=addr_div,
                                    )
                                )
                            else:
                                target = (slice_macho.image_base + (val & 0xFFFFFFFF)) & 0xFFFFFFFFFFFFFFFF
                                entries.append(
                                    ChainedFixupEntry(
                                        offset=chain_file_off,
                                        address=slot_va,
                                        kind="auth_rebase",
                                        target=target,
                                        auth_key=auth_key,
                                        diversity=diversity,
                                        addr_diversity=addr_div,
                                    )
                                )
                        else:
                            if bind:
                                if pointer_format == DYLD_CHAINED_PTR_ARM64E_USERLAND24:
                                    ordinal = val & 0xFFFFFF
                                else:
                                    ordinal = val & 0xFFFF
                                addend = (val >> 32) & 0x7FFFF
                                if addend & 0x40000:
                                    addend -= 0x80000
                                sym_name = imports[ordinal] if ordinal < len(imports) else None
                                entries.append(
                                    ChainedFixupEntry(
                                        offset=chain_file_off,
                                        address=slot_va,
                                        kind="bind",
                                        ordinal=ordinal,
                                        symbol_name=sym_name,
                                        addend=addend,
                                    )
                                )
                            else:
                                if pointer_format in (
                                    DYLD_CHAINED_PTR_ARM64E_USERLAND,
                                    DYLD_CHAINED_PTR_ARM64E_USERLAND24,
                                ):
                                    full_target = (slice_macho.image_base + (val & ((1 << 43) - 1))) & 0xFFFFFFFFFFFFFFFF
                                else:
                                    target = val & ((1 << 43) - 1)
                                    high8 = (val >> 43) & 0xFF
                                    full_target = (high8 << 56) | target
                                entries.append(
                                    ChainedFixupEntry(
                                        offset=chain_file_off,
                                        address=slot_va,
                                        kind="rebase",
                                        target=full_target,
                                    )
                                )

                    elif pointer_format in (
                        DYLD_CHAINED_PTR_64,
                        DYLD_CHAINED_PTR_64_OFFSET,
                        DYLD_CHAINED_PTR_64_KERNEL_CACHE,
                        DYLD_CHAINED_PTR_X86_64_KERNEL_CACHE,
                    ):
                        if chain_file_off + 8 > len(slice_macho.data):
                            break
                        val = struct.unpack_from("<Q", slice_macho.data, chain_file_off)[0]
                        bind = (val >> 63) & 1
                        next_stride = ((val >> 51) & 0xFFF) * 4
                        if bind:
                            ordinal = val & 0xFFFFFF
                            addend = (val >> 24) & 0xFF
                            if addend & 0x80:
                                addend -= 0x100
                            sym_name = imports[ordinal] if ordinal < len(imports) else None
                            entries.append(
                                ChainedFixupEntry(
                                    offset=chain_file_off,
                                    address=slot_va,
                                    kind="bind",
                                    ordinal=ordinal,
                                    symbol_name=sym_name,
                                    addend=addend,
                                )
                            )
                        else:
                            target = val & 0xFFFFFFFFF
                            high8 = (val >> 36) & 0xFF
                            if pointer_format == DYLD_CHAINED_PTR_64_OFFSET:
                                full_target = ((high8 << 56) | (slice_macho.image_base + target)) & 0xFFFFFFFFFFFFFFFF
                            else:
                                full_target = (high8 << 56) | target
                            entries.append(
                                ChainedFixupEntry(
                                    offset=chain_file_off,
                                    address=slot_va,
                                    kind="rebase",
                                    target=full_target,
                                )
                            )

                    elif pointer_format in (
                        DYLD_CHAINED_PTR_32,
                        DYLD_CHAINED_PTR_32_CACHE,
                        DYLD_CHAINED_PTR_32_FIRMWARE,
                    ):
                        if chain_file_off + 4 > len(slice_macho.data):
                            break
                        val32 = struct.unpack_from("<I", slice_macho.data, chain_file_off)[0]
                        bind = (val32 >> 31) & 1
                        next_stride = ((val32 >> 26) & 0x1F) * 4
                        if bind:
                            ordinal = val32 & 0xFFFFF
                            addend = (val32 >> 20) & 0x3F
                            if addend & 0x20:
                                addend -= 0x40
                            sym_name = imports[ordinal] if ordinal < len(imports) else None
                            entries.append(
                                ChainedFixupEntry(
                                    offset=chain_file_off,
                                    address=slot_va,
                                    kind="bind",
                                    ordinal=ordinal,
                                    symbol_name=sym_name,
                                    addend=addend,
                                )
                            )
                        else:
                            target = val32 & 0x3FFFFFF
                            entries.append(
                                ChainedFixupEntry(
                                    offset=chain_file_off,
                                    address=slot_va,
                                    kind="rebase",
                                    target=target,
                                )
                            )
                    else:
                        break

                    if next_stride == 0:
                        break
                    chain_file_off += next_stride

    counts = {
        "entries": len(entries),
        "imports": len(imports),
        "rebases": sum(1 for e in entries if "rebase" in e.kind),
        "binds": sum(1 for e in entries if "bind" in e.kind),
        "auth_entries": sum(1 for e in entries if "auth" in e.kind),
    }

    return ChainedFixupsReport(
        fixups_version=fixups_version,
        pointer_format=pointer_format if starts_offset < datasize else 0,
        starts_count=len(entries),
        imports_count=imports_count,
        entries=entries,
        imports=imports,
        legacy_info_fallback=False,
        counts=counts,
    )


def _decode_legacy_dyld_info(slice_macho: MachOSlice, limitations: List[str]) -> ChainedFixupsReport:
    """Decodes rebase and bind opcodes from legacy LC_DYLD_INFO commands."""
    if slice_macho.dyld_info_cmd is None:
        return ChainedFixupsReport()

    (
        rebase_off,
        rebase_size,
        bind_off,
        bind_size,
        weak_bind_off,
        weak_bind_size,
        lazy_bind_off,
        lazy_bind_size,
        export_off,
        export_size,
    ) = slice_macho.dyld_info_cmd
    entries: List[ChainedFixupEntry] = []
    imports_list: List[str] = []
    ptr_size = 8 if slice_macho.bits == 64 else 4

    def _read_rebase_target(off: int) -> int:
        if ptr_size == 8 and off + 8 <= len(slice_macho.data):
            return struct.unpack_from(slice_macho.endian + "Q", slice_macho.data, off)[0]
        elif ptr_size == 4 and off + 4 <= len(slice_macho.data):
            return struct.unpack_from(slice_macho.endian + "I", slice_macho.data, off)[0]
        return 0

    # 1. Parse rebase opcodes
    if rebase_size > 0 and rebase_off + rebase_size <= len(slice_macho.data):
        p = rebase_off
        end = rebase_off + rebase_size
        seg_idx = 0
        seg_offset = 0
        while p < end:
            b = slice_macho.data[p]
            p += 1
            op = b & 0xF0
            imm = b & 0x0F

            if op == REBASE_OPCODE_DONE:
                pass
            elif op == REBASE_OPCODE_SET_TYPE_IMM:
                pass
            elif op == REBASE_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB:
                seg_idx = imm
                val, n = _read_uleb128(slice_macho.data, p)
                p += n
                seg_offset = val
            elif op == REBASE_OPCODE_ADD_ADDR_ULEB:
                val, n = _read_uleb128(slice_macho.data, p)
                p += n
                seg_offset += val
            elif op == REBASE_OPCODE_ADD_ADDR_IMM_SCALED:
                seg_offset += imm * ptr_size
            elif op == REBASE_OPCODE_DO_REBASE_IMM_TIMES:
                for _ in range(imm):
                    seg = slice_macho.segments[seg_idx] if seg_idx < len(slice_macho.segments) else None
                    if seg:
                        va = seg.vmaddr + seg_offset
                        off = seg.fileoff + seg_offset
                        entries.append(
                            ChainedFixupEntry(
                                offset=off,
                                address=va,
                                kind="rebase",
                                target=_read_rebase_target(off),
                            )
                        )
                    seg_offset += ptr_size
            elif op == REBASE_OPCODE_DO_REBASE_ULEB_TIMES:
                count, n = _read_uleb128(slice_macho.data, p)
                p += n
                for _ in range(count):
                    seg = slice_macho.segments[seg_idx] if seg_idx < len(slice_macho.segments) else None
                    if seg:
                        va = seg.vmaddr + seg_offset
                        off = seg.fileoff + seg_offset
                        entries.append(
                            ChainedFixupEntry(
                                offset=off,
                                address=va,
                                kind="rebase",
                                target=_read_rebase_target(off),
                            )
                        )
                    seg_offset += ptr_size
            elif op == REBASE_OPCODE_DO_REBASE_ADD_ADDR_ULEB:
                seg = slice_macho.segments[seg_idx] if seg_idx < len(slice_macho.segments) else None
                if seg:
                    va = seg.vmaddr + seg_offset
                    off = seg.fileoff + seg_offset
                    entries.append(
                        ChainedFixupEntry(
                            offset=off,
                            address=va,
                            kind="rebase",
                            target=_read_rebase_target(off),
                        )
                    )
                val, n = _read_uleb128(slice_macho.data, p)
                p += n
                seg_offset += ptr_size + val
            elif op == REBASE_OPCODE_DO_REBASE_ULEB_TIMES_SKIPPING_ULEB:
                count, n = _read_uleb128(slice_macho.data, p)
                p += n
                skip, n2 = _read_uleb128(slice_macho.data, p)
                p += n2
                for _ in range(count):
                    seg = slice_macho.segments[seg_idx] if seg_idx < len(slice_macho.segments) else None
                    if seg:
                        va = seg.vmaddr + seg_offset
                        off = seg.fileoff + seg_offset
                        entries.append(
                            ChainedFixupEntry(
                                offset=off,
                                address=va,
                                kind="rebase",
                                target=_read_rebase_target(off),
                            )
                        )
                    seg_offset += ptr_size + skip
            else:
                break

    # 2. Parse bind, weak_bind, and lazy_bind opcodes
    bind_chunks = [
        (bind_off, bind_size, "bind"),
        (weak_bind_off, weak_bind_size, "bind"),
        (lazy_bind_off, lazy_bind_size, "bind"),
    ]

    for chunk_off, chunk_size, chunk_kind in bind_chunks:
        if chunk_size <= 0 or chunk_off + chunk_size > len(slice_macho.data):
            continue
        p = chunk_off
        end = chunk_off + chunk_size
        seg_idx = 0
        seg_offset = 0
        sym_name: str | None = None
        dylib_ord = 0
        addend = 0

        while p < end:
            b = slice_macho.data[p]
            p += 1
            op = b & 0xF0
            imm = b & 0x0F

            if op == BIND_OPCODE_DONE:
                pass
            elif op == BIND_OPCODE_SET_DYLIB_ORDINAL_IMM:
                dylib_ord = imm
            elif op == BIND_OPCODE_SET_DYLIB_ORDINAL_ULEB:
                dylib_ord, n = _read_uleb128(slice_macho.data, p)
                p += n
            elif op == BIND_OPCODE_SET_DYLIB_SPECIAL_IMM:
                if imm == 0:
                    dylib_ord = 0
                else:
                    dylib_ord = imm | ~0x0F
            elif op == BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM:
                idx = slice_macho.data.find(b"\x00", p, end)
                if idx >= p:
                    sym_name = slice_macho.data[p:idx].decode("utf-8", errors="replace")
                    p = idx + 1
                    if sym_name not in imports_list:
                        imports_list.append(sym_name)
                else:
                    sym_name = slice_macho.data[p:end].decode("utf-8", errors="replace")
                    p = end
                    if sym_name not in imports_list:
                        imports_list.append(sym_name)
            elif op == BIND_OPCODE_SET_TYPE_IMM:
                pass
            elif op == BIND_OPCODE_SET_ADDEND_SLEB:
                addend, n = _read_sleb128(slice_macho.data, p)
                p += n
            elif op == BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB:
                seg_idx = imm
                val, n = _read_uleb128(slice_macho.data, p)
                p += n
                seg_offset = val
            elif op == BIND_OPCODE_ADD_ADDR_ULEB:
                val, n = _read_uleb128(slice_macho.data, p)
                p += n
                seg_offset += val
            elif op == BIND_OPCODE_DO_BIND:
                seg = slice_macho.segments[seg_idx] if seg_idx < len(slice_macho.segments) else None
                if seg:
                    va = seg.vmaddr + seg_offset
                    off = seg.fileoff + seg_offset
                    entries.append(
                        ChainedFixupEntry(
                            offset=off,
                            address=va,
                            kind=chunk_kind,
                            ordinal=dylib_ord,
                            symbol_name=sym_name,
                            addend=addend,
                        )
                    )
                seg_offset += ptr_size
            elif op == BIND_OPCODE_DO_BIND_ADD_ADDR_ULEB:
                seg = slice_macho.segments[seg_idx] if seg_idx < len(slice_macho.segments) else None
                if seg:
                    va = seg.vmaddr + seg_offset
                    off = seg.fileoff + seg_offset
                    entries.append(
                        ChainedFixupEntry(
                            offset=off,
                            address=va,
                            kind=chunk_kind,
                            ordinal=dylib_ord,
                            symbol_name=sym_name,
                            addend=addend,
                        )
                    )
                val, n = _read_uleb128(slice_macho.data, p)
                p += n
                seg_offset += ptr_size + val
            elif op == BIND_OPCODE_DO_BIND_ADD_ADDR_IMM_SCALED:
                seg = slice_macho.segments[seg_idx] if seg_idx < len(slice_macho.segments) else None
                if seg:
                    va = seg.vmaddr + seg_offset
                    off = seg.fileoff + seg_offset
                    entries.append(
                        ChainedFixupEntry(
                            offset=off,
                            address=va,
                            kind=chunk_kind,
                            ordinal=dylib_ord,
                            symbol_name=sym_name,
                            addend=addend,
                        )
                    )
                seg_offset += ptr_size + imm * ptr_size
            elif op == BIND_OPCODE_DO_BIND_ULEB_TIMES_SKIPPING_ULEB:
                count, n = _read_uleb128(slice_macho.data, p)
                p += n
                skip, n2 = _read_uleb128(slice_macho.data, p)
                p += n2
                for _ in range(count):
                    seg = slice_macho.segments[seg_idx] if seg_idx < len(slice_macho.segments) else None
                    if seg:
                        va = seg.vmaddr + seg_offset
                        off = seg.fileoff + seg_offset
                        entries.append(
                            ChainedFixupEntry(
                                offset=off,
                                address=va,
                                kind=chunk_kind,
                                ordinal=dylib_ord,
                                symbol_name=sym_name,
                                addend=addend,
                            )
                        )
                    seg_offset += ptr_size + skip
            else:
                break

    counts = {
        "entries": len(entries),
        "imports": len(imports_list),
        "rebases": sum(1 for e in entries if e.kind == "rebase"),
        "binds": sum(1 for e in entries if "bind" in e.kind),
        "auth_entries": 0,
    }

    return ChainedFixupsReport(
        fixups_version=0,
        pointer_format=0,
        starts_count=len(entries),
        imports_count=len(imports_list),
        entries=entries,
        imports=imports_list,
        legacy_info_fallback=True,
        counts=counts,
    )


# -----------------------------------------------------------------------------
def _decode_dysymtab_fixups(slice_macho: MachOSlice, limitations: List[str]) -> ChainedFixupsReport:
    """Decodes indirect symbol table and pointer sections from LC_DYSYMTAB and LC_SYMTAB."""
    if slice_macho.dysymtab_cmd is None or slice_macho.symtab_cmd is None:
        return ChainedFixupsReport()

    (
        ilocalsym,
        nlocalsym,
        iextdefsym,
        nextdefsym,
        iundefsym,
        nundefsym,
        tocoff,
        ntoc,
        modtaboff,
        nmodtab,
        extrefsymoff,
        nextrefsyms,
        indirectsymoff,
        nindirectsyms,
        extreloff,
        nextrel,
        locreloff,
        nlocrel,
    ) = slice_macho.dysymtab_cmd

    symoff, nsyms, stroff, strsize = slice_macho.symtab_cmd
    entries: List[ChainedFixupEntry] = []
    imports_list: List[str] = []
    ptr_size = 8 if slice_macho.bits == 64 else 4

    # 1. Read symbol strings from LC_SYMTAB
    strtab = (
        slice_macho.data[stroff : stroff + strsize]
        if stroff + strsize <= len(slice_macho.data)
        else b""
    )
    symbols: List[str] = []
    nlist_sz = 16 if slice_macho.bits == 64 else 12
    nlist_fmt = slice_macho.endian + ("IBBHQ" if slice_macho.bits == 64 else "IBBHI")

    for s_i in range(nsyms):
        n_off = symoff + s_i * nlist_sz
        if n_off + nlist_sz > len(slice_macho.data):
            break
        n_strx = struct.unpack_from(nlist_fmt, slice_macho.data, n_off)[0]
        sym_name = MachOSlice._read_cstr(strtab, n_strx) if strtab else ""
        symbols.append(sym_name or f"sym_{s_i}")

    # 2. Read indirect symbol table indices
    indirect_syms: List[int] = []
    if (
        indirectsymoff > 0
        and nindirectsyms > 0
        and indirectsymoff + nindirectsyms * 4 <= len(slice_macho.data)
    ):
        indirect_syms = list(
            struct.unpack_from(
                f"{slice_macho.endian}{nindirectsyms}I",
                slice_macho.data,
                indirectsymoff,
            )
        )

    INDIRECT_SYMBOL_LOCAL = 0x80000000
    INDIRECT_SYMBOL_ABS = 0x40000000

    # 3. Locate symbol pointer sections (__la_symbol_ptr, __nl_symbol_ptr, __got)
    for sec in slice_macho.sections:
        stype = sec.flags & 0xFF
        is_ptr_sect = (stype in (6, 7)) or sec.sectname in (
            "__nl_symbol_ptr",
            "__la_symbol_ptr",
            "__got",
            "__auth_got",
            "__auth_ptr",
        )
        if not is_ptr_sect or sec.size <= 0:
            continue

        num_ptrs = sec.size // ptr_size
        start_idx = sec.reserved1

        for i in range(num_ptrs):
            indirect_idx = start_idx + i
            if indirect_idx < 0 or indirect_idx >= len(indirect_syms):
                continue
            sym_idx = indirect_syms[indirect_idx]
            slot_va = sec.addr + i * ptr_size
            slot_off = sec.offset + i * ptr_size

            if sym_idx in (INDIRECT_SYMBOL_LOCAL, INDIRECT_SYMBOL_ABS):
                target_val = 0
                if slot_off + ptr_size <= len(slice_macho.data):
                    target_val = struct.unpack_from(
                        slice_macho.endian + ("Q" if ptr_size == 8 else "I"),
                        slice_macho.data,
                        slot_off,
                    )[0]
                entries.append(
                    ChainedFixupEntry(
                        offset=slot_off,
                        address=slot_va,
                        kind="rebase",
                        target=target_val,
                    )
                )
            else:
                sym_name = (
                    symbols[sym_idx]
                    if sym_idx < len(symbols)
                    else f"import_{sym_idx}"
                )
                if sym_name not in imports_list:
                    imports_list.append(sym_name)
                entries.append(
                    ChainedFixupEntry(
                        offset=slot_off,
                        address=slot_va,
                        kind="bind",
                        ordinal=sym_idx,
                        symbol_name=sym_name,
                    )
                )

    counts = {
        "entries": len(entries),
        "imports": len(imports_list),
        "rebases": sum(1 for e in entries if e.kind == "rebase"),
        "binds": sum(1 for e in entries if e.kind == "bind"),
        "auth_entries": 0,
    }

    return ChainedFixupsReport(
        fixups_version=0,
        pointer_format=0,
        starts_count=len(entries),
        imports_count=len(imports_list),
        entries=entries,
        imports=imports_list,
        legacy_info_fallback=True,
        counts=counts,
    )


# -----------------------------------------------------------------------------
# Swift 5 Metadata Recovery
# -----------------------------------------------------------------------------

def _recover_swift5_metadata(slice_macho: MachOSlice, limitations: List[str]) -> Swift5Report:
    """Parses Swift 5 nominal types, fields, vtables, protocols, and conformances."""
    types: List[Swift5TypeDescriptor] = []
    protocols: List[str] = []
    conformances: List[Swift5ProtocolConformance] = []

    # 1. Parse __swift5_types
    type_sections = slice_macho.get_sections_by_name("__swift5_types")
    for sec in type_sections:
        count = sec.size // 4
        for i in range(count):
            entry_va = sec.addr + i * 4
            entry_off = sec.offset + i * 4
            if entry_off + 4 > len(slice_macho.data):
                break
            rel_ptr = struct.unpack_from("<i", slice_macho.data, entry_off)[0]
            desc_va = entry_va + rel_ptr

            desc_raw = slice_macho.read_va(desc_va, 24)
            if len(desc_raw) < 20:
                continue

            flags, parent_rel, name_rel, access_fn_rel, fields_rel = struct.unpack_from(
                "<Iiiii", desc_raw[:20]
            )

            kind_id = flags & 0x1F
            is_generic = bool(flags & 0x80)

            kind_map = {16: "class", 17: "struct", 18: "enum"}
            kind_str = kind_map.get(kind_id, "other")

            name_va = desc_va + 8 + name_rel
            tname = slice_macho.read_c_string(name_va) or f"SwiftType_{hex(desc_va)}"

            # Detect Actor
            if kind_id == 16:
                if (flags & 0x4000) or "Actor" in tname:
                    kind_str = "actor"

            # Parse fields
            fields: List[str] = []
            if fields_rel != 0:
                field_desc_va = desc_va + 16 + fields_rel
                fhdr = slice_macho.read_va(field_desc_va, 16)
                if len(fhdr) >= 16:
                    _, _, _, rec_size, num_fields = struct.unpack_from("<iihhI", fhdr)
                    if rec_size >= 12 and num_fields < 500:
                        for f in range(num_fields):
                            rec_va = field_desc_va + 16 + f * rec_size
                            rec_data = slice_macho.read_va(rec_va, 12)
                            if len(rec_data) >= 12:
                                _, _, fname_rel = struct.unpack_from("<Iii", rec_data)
                                fname_va = rec_va + 8 + fname_rel
                                fn = slice_macho.read_c_string(fname_va)
                                if fn:
                                    fields.append(fn)

            # Parse non-resilient vtable for class/actor
            vtable_methods: List[Swift5Method] = []
            if kind_id == 16:
                has_vtable = bool(flags & 0x80000000)
                if has_vtable:
                    vtable_hdr_va = desc_va + 44
                    vhdr = slice_macho.read_va(vtable_hdr_va, 8)
                    if len(vhdr) == 8:
                        vt_offset, vt_size = struct.unpack_from("<II", vhdr)
                        if vt_size < 1000:
                            for m in range(vt_size):
                                m_va = vtable_hdr_va + 8 + m * 8
                                m_data = slice_macho.read_va(m_va, 8)
                                if len(m_data) == 8:
                                    m_flags, m_impl_rel = struct.unpack_from("<Ii", m_data)
                                    impl_va = m_va + 4 + m_impl_rel
                                    vtable_methods.append(
                                        Swift5Method(address=impl_va, flags=m_flags)
                                    )

            types.append(
                Swift5TypeDescriptor(
                    name=tname,
                    kind=kind_str,
                    address=desc_va,
                    is_generic=is_generic,
                    fields=fields,
                    vtable_methods=vtable_methods,
                )
            )

    # 2. Parse __swift5_protos (Protocol Descriptors)
    proto_desc_sections = slice_macho.get_sections_by_name("__swift5_protos")
    for sec in proto_desc_sections:
        count = sec.size // 4
        for i in range(count):
            entry_va = sec.addr + i * 4
            entry_off = sec.offset + i * 4
            if entry_off + 4 > len(slice_macho.data):
                break
            rel_ptr = struct.unpack_from("<i", slice_macho.data, entry_off)[0]
            proto_desc_va = entry_va + rel_ptr

            p_raw = slice_macho.read_va(proto_desc_va, 16)
            if len(p_raw) >= 12:
                _, _, name_rel = struct.unpack_from("<Iii", p_raw[:12])
                pname = slice_macho.read_c_string(proto_desc_va + 8 + name_rel)
                if pname and pname not in protocols:
                    protocols.append(pname)

    # 3. Parse __swift5_proto (Protocol Conformances)
    conf_sections = slice_macho.get_sections_by_name("__swift5_proto")
    for sec in conf_sections:
        count = sec.size // 4
        for i in range(count):
            entry_va = sec.addr + i * 4
            entry_off = sec.offset + i * 4
            if entry_off + 4 > len(slice_macho.data):
                break
            rel_ptr = struct.unpack_from("<i", slice_macho.data, entry_off)[0]
            conf_va = entry_va + rel_ptr

            conf_raw = slice_macho.read_va(conf_va, 16)
            if len(conf_raw) < 16:
                continue

            proto_rel, type_rel, witness_rel, conf_flags = struct.unpack_from("<iiiI", conf_raw)

            # Protocol name
            proto_target_va = conf_va + proto_rel
            if proto_rel & 1:
                ptr_bytes = slice_macho.read_va(proto_target_va & ~1, 8)
                if len(ptr_bytes) == 8:
                    proto_target_va = struct.unpack_from("<Q", ptr_bytes)[0]

            p_hdr = slice_macho.read_va(proto_target_va, 16)
            pname = "UnknownProtocol"
            if len(p_hdr) >= 12:
                _, _, p_name_rel = struct.unpack_from("<Iii", p_hdr[:12])
                resolved_pname = slice_macho.read_c_string(proto_target_va + 8 + p_name_rel)
                if resolved_pname:
                    pname = resolved_pname
                    if pname not in protocols:
                        protocols.append(pname)

            # Type name / raw binding preservation
            type_target_va = conf_va + 4 + type_rel
            is_indirect = bool(type_rel & 1)
            raw_binding: str | None = None
            resolved_tname: str | None = None

            if is_indirect:
                ptr_bytes = slice_macho.read_va(type_target_va & ~1, 8)
                if len(ptr_bytes) == 8:
                    type_target_va = struct.unpack_from("<Q", ptr_bytes)[0]

            # Look up type by VA in already parsed types
            matched_type = next((t for t in types if t.address == type_target_va), None)
            if matched_type:
                resolved_tname = matched_type.name
                matched_type.conformances.append(pname)
            else:
                # Check if descriptor at type_target_va has a name
                td_raw = slice_macho.read_va(type_target_va, 16)
                if len(td_raw) >= 12:
                    _, _, td_name_rel = struct.unpack_from("<Iii", td_raw[:12])
                    td_name = slice_macho.read_c_string(type_target_va + 8 + td_name_rel)
                    if td_name and td_name.isprintable() and len(td_name) < 128:
                        resolved_tname = td_name

                # If external or unresolvable, preserve raw type binding rather than guessing
                if not resolved_tname:
                    # Check if target is a C-string or mangled symbol in slice
                    cand_str = slice_macho.read_c_string(type_target_va, limit=64)
                    if cand_str and (cand_str.startswith("$s") or cand_str.startswith("_")):
                        raw_binding = cand_str
                        resolved_tname = cand_str
                    else:
                        raw_binding = f"external_binding_{hex(type_target_va)}"
                        resolved_tname = f"ExternalType_{hex(type_target_va)}"

            conformances.append(
                Swift5ProtocolConformance(
                    protocol_name=pname,
                    type_name=resolved_tname or "UnknownType",
                    type_binding=raw_binding,
                    address=conf_va,
                )
            )

    counts = {
        "types": len(types),
        "protocols": len(protocols),
        "conformances": len(conformances),
        "classes": sum(1 for t in types if t.kind in ("class", "actor")),
        "structs": sum(1 for t in types if t.kind == "struct"),
        "enums": sum(1 for t in types if t.kind == "enum"),
    }

    return Swift5Report(
        types=types,
        protocols=protocols,
        conformances=conformances,
        counts=counts,
    )


# -----------------------------------------------------------------------------
# Objective-C 64-bit Recovery (Classes, Metaclasses, Categories, Protocols)
# -----------------------------------------------------------------------------

def _parse_objc_method_list(
    slice_macho: MachOSlice, list_va: int, is_class_method: bool = False
) -> List[ObjCMethod]:
    if not list_va:
        return []
    hdr = slice_macho.read_va(list_va, 8)
    if len(hdr) < 8:
        return []
    entsize_flags, count = struct.unpack("<II", hdr)
    entsize = entsize_flags & 0xFFFF
    if entsize < 24 or count > 10000:
        return []

    methods: List[ObjCMethod] = []
    for i in range(count):
        entry_va = list_va + 8 + i * entsize
        entry_data = slice_macho.read_va(entry_va, entsize)
        if len(entry_data) < 24:
            break
        name_va, types_va, imp = struct.unpack("<QQQ", entry_data[:24])
        name = slice_macho.read_c_string(name_va) or ""
        types = slice_macho.read_c_string(types_va)
        if name:
            methods.append(
                ObjCMethod(name=name, types=types, imp=imp, is_class_method=is_class_method)
            )
    return methods


def _parse_objc_ivar_list(slice_macho: MachOSlice, list_va: int) -> List[ObjCIvar]:
    if not list_va:
        return []
    hdr = slice_macho.read_va(list_va, 8)
    if len(hdr) < 8:
        return []
    entsize_flags, count = struct.unpack("<II", hdr)
    entsize = entsize_flags & 0xFFFF
    if entsize < 32 or count > 10000:
        return []

    ivars: List[ObjCIvar] = []
    for i in range(count):
        entry_va = list_va + 8 + i * entsize
        entry_data = slice_macho.read_va(entry_va, entsize)
        if len(entry_data) < 32:
            break
        off_va, name_va, type_va, align, size = struct.unpack("<QQQII", entry_data[:32])
        name = slice_macho.read_c_string(name_va) or ""
        type_enc = slice_macho.read_c_string(type_va)
        offset = 0
        if off_va:
            off_bytes = slice_macho.read_va(off_va, 4)
            if len(off_bytes) == 4:
                offset = struct.unpack("<I", off_bytes)[0]
        if name:
            ivars.append(ObjCIvar(name=name, type_encoding=type_enc, offset=offset, size=size))
    return ivars


def _recover_objc_metadata(slice_macho: MachOSlice, limitations: List[str]) -> ObjCRecoveryReport:
    """Recovers 64-bit Objective-C classes, metaclasses, categories, and protocols."""
    classes: List[ObjCClass] = []
    categories: List[ObjCCategory] = []
    protocols: List[ObjCProtocol] = []

    # 1. Recover Classes (__objc_classlist)
    classlist_secs = slice_macho.get_sections_by_name("objc_classlist")
    class_vas: List[int] = []
    for sec in classlist_secs:
        sec_data = slice_macho.read_va(sec.addr, sec.size)
        num_ptrs = len(sec_data) // 8
        for i in range(num_ptrs):
            c_va = struct.unpack_from("<Q", sec_data, i * 8)[0]
            if c_va and c_va not in class_vas:
                class_vas.append(c_va)

    class_map: Dict[int, str] = {}
    class_ro_map: Dict[int, Tuple[int, int, str, int, int]] = {}

    for c_va in class_vas:
        c_raw = slice_macho.read_va(c_va, 40)
        if len(c_raw) < 40:
            continue
        isa, super_va, _, _, data_va = struct.unpack("<QQQQQ", c_raw)
        ro_va = data_va & ~7
        ro_raw = slice_macho.read_va(ro_va, 72)
        if len(ro_raw) < 72:
            continue
        _, _, instance_size, _, _, name_va, base_methods_va, _, ivars_va, _, _ = struct.unpack(
            "<IIIIQQQQQQQ", ro_raw[:72]
        )
        cname = slice_macho.read_c_string(name_va) or f"Class_{hex(c_va)}"
        class_map[c_va] = cname
        class_ro_map[c_va] = (ro_va, isa, cname, super_va, instance_size)

    for c_va in class_vas:
        if c_va not in class_ro_map:
            continue
        ro_va, isa, cname, super_va, instance_size = class_ro_map[c_va]
        ro_raw = slice_macho.read_va(ro_va, 72)
        _, _, _, _, _, _, base_methods_va, _, ivars_va, _, _ = struct.unpack(
            "<IIIIQQQQQQQ", ro_raw[:72]
        )

        super_name: str | None = None
        if super_va:
            if super_va in class_map:
                super_name = class_map[super_va]
            else:
                super_raw = slice_macho.read_va(super_va, 40)
                if len(super_raw) == 40:
                    _, _, _, _, s_data_va = struct.unpack("<QQQQQ", super_raw)
                    s_ro_raw = slice_macho.read_va(s_data_va & ~7, 72)
                    if len(s_ro_raw) >= 72:
                        s_name_va = struct.unpack("<IIIIQQQQQQQ", s_ro_raw[:72])[5]
                        super_name = slice_macho.read_c_string(s_name_va)

        inst_methods = _parse_objc_method_list(slice_macho, base_methods_va, is_class_method=False)
        ivars = _parse_objc_ivar_list(slice_macho, ivars_va)

        cls_methods: List[ObjCMethod] = []
        if isa and isa != c_va:
            meta_raw = slice_macho.read_va(isa, 40)
            if len(meta_raw) == 40:
                _, _, _, _, meta_data_va = struct.unpack("<QQQQQ", meta_raw)
                meta_ro_raw = slice_macho.read_va(meta_data_va & ~7, 72)
                if len(meta_ro_raw) >= 72:
                    meta_methods_va = struct.unpack("<IIIIQQQQQQQ", meta_ro_raw[:72])[6]
                    cls_methods = _parse_objc_method_list(
                        slice_macho, meta_methods_va, is_class_method=True
                    )

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

    # 2. Recover Categories (__objc_catlist)
    catlist_secs = slice_macho.get_sections_by_name("objc_catlist")
    for sec in catlist_secs:
        sec_data = slice_macho.read_va(sec.addr, sec.size)
        num_ptrs = len(sec_data) // 8
        for i in range(num_ptrs):
            cat_va = struct.unpack_from("<Q", sec_data, i * 8)[0]
            if not cat_va:
                continue
            cat_raw = slice_macho.read_va(cat_va, 48)
            if len(cat_raw) < 32:
                continue
            name_va, cls_va, inst_meths_va, cls_meths_va = struct.unpack("<QQQQ", cat_raw[:32])
            cat_name = slice_macho.read_c_string(name_va) or f"Category_{hex(cat_va)}"
            target_class_name = class_map.get(cls_va)
            if not target_class_name:
                c_cand = slice_macho.read_c_string(cls_va)
                target_class_name = c_cand or f"Class_{hex(cls_va)}"

            cat_inst_methods = _parse_objc_method_list(
                slice_macho, inst_meths_va, is_class_method=False
            )
            cat_cls_methods = _parse_objc_method_list(
                slice_macho, cls_meths_va, is_class_method=True
            )

            categories.append(
                ObjCCategory(
                    name=cat_name,
                    class_name=target_class_name,
                    address=cat_va,
                    instance_methods=cat_inst_methods,
                    class_methods=cat_cls_methods,
                )
            )

    # 3. Recover Protocols (__objc_protolist)
    protolist_secs = slice_macho.get_sections_by_name("objc_protolist")
    for sec in protolist_secs:
        sec_data = slice_macho.read_va(sec.addr, sec.size)
        num_ptrs = len(sec_data) // 8
        for i in range(num_ptrs):
            p_va = struct.unpack_from("<Q", sec_data, i * 8)[0]
            if not p_va:
                continue
            p_raw = slice_macho.read_va(p_va, 40)
            if len(p_raw) < 40:
                continue
            isa, name_va, protos_va, inst_meths_va, cls_meths_va = struct.unpack(
                "<QQQQQ", p_raw[:40]
            )
            pname = slice_macho.read_c_string(name_va) or f"Protocol_{hex(p_va)}"
            p_inst_methods = _parse_objc_method_list(
                slice_macho, inst_meths_va, is_class_method=False
            )
            p_cls_methods = _parse_objc_method_list(
                slice_macho, cls_meths_va, is_class_method=True
            )

            protocols.append(
                ObjCProtocol(
                    name=pname,
                    address=p_va,
                    instance_methods=p_inst_methods,
                    class_methods=p_cls_methods,
                )
            )

    classes.sort(key=lambda c: c.name)
    categories.sort(key=lambda cat: cat.name)
    protocols.sort(key=lambda p: p.name)

    counts = {
        "classes": len(classes),
        "categories": len(categories),
        "protocols": len(protocols),
        "instance_methods": sum(len(c.instance_methods) for c in classes)
        + sum(len(cat.instance_methods) for cat in categories),
        "class_methods": sum(len(c.class_methods) for c in classes)
        + sum(len(cat.class_methods) for cat in categories),
        "ivars": sum(len(c.ivars) for c in classes),
    }

    return ObjCRecoveryReport(
        classes=classes, categories=categories, protocols=protocols, counts=counts
    )


# -----------------------------------------------------------------------------
# Main Public Entrypoint
# -----------------------------------------------------------------------------

def dispatch_apple_binary(
    binary_path_or_bytes: str | Path | bytes,
    arch: str = "arm64",
    max_input_bytes: int = DEFAULT_MAX_INPUT_BYTES,
) -> AppleDispatchReport:
    """
    Parses a macOS/iOS Mach-O binary (thin or Universal FAT), extracting dyld chained
    fixups, Objective-C classes/categories/protocols, and Swift 5 nominal types/vtables.

    Enforces a strict byte admission budget to prevent memory exhaustion on untrusted files.
    """
    if max_input_bytes > MAX_ALLOWED_INPUT_BYTES:
        max_input_bytes = MAX_ALLOWED_INPUT_BYTES

    if isinstance(binary_path_or_bytes, (str, Path)):
        p = Path(binary_path_or_bytes)
        if not p.is_file():
            raise FileNotFoundError(f"Binary file not found: {p}")
        file_sz = p.stat().st_size
        if file_sz > max_input_bytes:
            raise ValueError(
                f"Binary size {file_sz} exceeds admission budget of {max_input_bytes} bytes"
            )
        data = p.read_bytes()
    elif isinstance(binary_path_or_bytes, (bytes, bytearray)):
        data = bytes(binary_path_or_bytes)
        if len(data) > max_input_bytes:
            raise ValueError(
                f"Binary buffer size {len(data)} exceeds admission budget of {max_input_bytes} bytes"
            )
    else:
        raise TypeError(
            f"Expected binary path or bytes, got {type(binary_path_or_bytes).__name__}"
        )

    # Extract matching slice
    slice_bytes, resolved_arch = extract_macho_slice(data, requested_arch=arch)

    slice_macho = MachOSlice(slice_bytes, resolved_arch)
    limitations: List[str] = []

    # 1. Decode Dyld Chained Fixups
    chained_fixups = _decode_chained_fixups(slice_macho, limitations)

    # 2. Recover Swift 5 Metadata
    swift5 = _recover_swift5_metadata(slice_macho, limitations)

    # 3. Recover Objective-C Metadata
    objc = _recover_objc_metadata(slice_macho, limitations)

    counts = {
        "chained_fixups": len(chained_fixups.entries),
        "chained_imports": len(chained_fixups.imports),
        "swift5_types": len(swift5.types),
        "swift5_protocols": len(swift5.protocols),
        "swift5_conformances": len(swift5.conformances),
        "objc_classes": len(objc.classes),
        "objc_categories": len(objc.categories),
        "objc_protocols": len(objc.protocols),
    }

    return AppleDispatchReport(
        arch=resolved_arch,
        bits=slice_macho.bits,
        image_base=slice_macho.image_base,
        chained_fixups=chained_fixups,
        swift5=swift5,
        objc=objc,
        counts=counts,
        limitations=limitations,
        epistemic_status="observed",
    )


parse_apple_dispatch = dispatch_apple_binary
