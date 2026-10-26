"""
binary_loader.py - one format/architecture loader for every SuperGhidra module.

Parses, with no third-party dependencies:
  * ELF   - 32/64-bit, little/big endian (x86, x86-64, ARM, AArch64, MIPS, RISC-V, PPC, ...)
  * PE    - PE32 / PE32+ executables and DLLs (x86, x86-64, ARM/Thumb-2, ARM64),
            including exports (ordinals, forwarders), imports (by name/ordinal, IAT),
            delay imports, .pdata function starts, CodeView PDB path, .NET (CLR) flag
  * Mach-O - 32/64-bit thin binaries and universal ("fat") binaries
            (exports trie, undefined imports, LC_FUNCTION_STARTS, LC_MAIN)
  * raw   - anything else (treated as one executable blob)

Usage:
    img = load_binary("liquidwork.dll")          # or bytes
    img.arch, img.bits, img.format, img.is_library
    for sec in img.executable_sections(): ...
    img.read_va(img.entry, 16)
"""

from __future__ import annotations

import os
import struct
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Tuple

__all__ = [
    "BinaryFormatError",
    "Section",
    "Symbol",
    "Import",
    "Relocation",
    "BinaryImage",
    "load_binary",
    "detect_format",
    "resolve_import_ordinals",
]


class BinaryFormatError(ValueError):
    """Raised when a binary is recognised but structurally invalid."""


# --------------------------------------------------------------------------------------
# Data model
# --------------------------------------------------------------------------------------


@dataclass
class Section:
    name: str
    vaddr: int
    vsize: int
    file_offset: int
    file_size: int
    executable: bool = False
    writable: bool = False
    readable: bool = True
    mapped: bool = True  # False for ELF non-SHF_ALLOC sections (.symtab, .comment, ...)

    def contains_va(self, va: int) -> bool:
        return self.vaddr <= va < self.vaddr + max(self.vsize, self.file_size)


@dataclass
class Symbol:
    name: str
    address: int
    size: int = 0
    kind: str = "func"  # func | object | other
    ordinal: int | None = None
    forwarder: str | None = None  # PE forwarded export, e.g. "NTDLL.RtlAllocateHeap"


@dataclass
class Import:
    library: str | None
    name: str | None
    ordinal: int | None = None
    address: int | None = None  # IAT / GOT slot VA when known
    delay_loaded: bool = False


@dataclass
class Relocation:
    offset: int
    symbol: str | None = None
    type: int = 0
    addend: int = 0


@dataclass
class BinaryImage:
    format: str  # elf | pe | macho | raw
    arch: str  # x86 | x86_64 | arm | arm64 | mips | mips64 | riscv32 | riscv64 | ppc | ppc64 | unknown
    bits: int
    endian: str  # little | big
    image_base: int
    entry: int | None
    is_library: bool
    data: bytes = field(repr=False)
    sections: List[Section] = field(default_factory=list)
    segments: List[Section] = field(default_factory=list)  # ELF PT_LOAD; fallback when sections are stripped
    exports: List[Symbol] = field(default_factory=list)
    imports: List[Import] = field(default_factory=list)
    symbols: List[Symbol] = field(default_factory=list)
    function_starts: List[int] = field(default_factory=list)
    libraries: List[str] = field(default_factory=list)
    pdb_path: str | None = None
    is_dotnet: bool = False
    thumb_entry: bool = False  # ARM32: entry/function addresses with bit 0 set run in Thumb mode
    machine: int = 0  # raw machine / cputype value
    path: str | None = None

    # ---------------- address translation ----------------

    def section_for_va(self, va: int) -> Section | None:
        for sec in self.sections:
            if sec.mapped and (sec.vsize or sec.file_size) and sec.contains_va(va):
                return sec
        for seg in self.segments:  # stripped/forged section tables (e.g. protected Android libs)
            if seg.contains_va(va):
                return seg
        return None

    def va_to_offset(self, va: int) -> int | None:
        sec = self.section_for_va(va)
        if sec is None:
            return None
        delta = va - sec.vaddr
        if delta >= sec.file_size:
            return None  # inside .bss-like zero-fill
        return sec.file_offset + delta

    def offset_to_va(self, offset: int) -> int | None:
        for sec in self.sections:
            if sec.file_size and sec.file_offset <= offset < sec.file_offset + sec.file_size:
                return sec.vaddr + (offset - sec.file_offset)
        return None

    def rva_to_va(self, rva: int) -> int:
        return self.image_base + rva

    def va_to_rva(self, va: int) -> int:
        return va - self.image_base

    def read_va(self, va: int, size: int) -> bytes:
        off = self.va_to_offset(va)
        if off is None:
            return b""
        sec = self.section_for_va(va)
        avail = sec.file_offset + sec.file_size - off if sec else 0
        return self.data[off : off + max(0, min(size, avail))]

    def read_c_string(self, va: int, limit: int = 1024) -> str | None:
        raw = self.read_va(va, limit)
        if not raw:
            return None
        end = raw.find(b"\x00")
        if end < 0:
            return None
        return raw[:end].decode("latin-1")

    def read_pointer(self, va: int) -> int | None:
        size = self.bits // 8
        raw = self.read_va(va, size)
        if len(raw) != size:
            return None
        fmt = ("<" if self.endian == "little" else ">") + ("Q" if size == 8 else "I")
        return struct.unpack(fmt, raw)[0]

    # ---------------- convenience ----------------

    def executable_sections(self) -> List[Section]:
        secs = [s for s in self.sections if s.executable and s.file_size > 0]
        if not secs:
            secs = [s for s in self.segments if s.executable and s.file_size > 0]
        return secs

    def section(self, name: str) -> Section | None:
        for s in self.sections:
            if s.name == name:
                return s
        return None

    def section_bytes(self, sec: Section) -> bytes:
        return self.data[sec.file_offset : sec.file_offset + sec.file_size]

    def code_regions(self) -> List[Tuple[int, bytes]]:
        """(start VA, bytes) for each executable section; the whole blob for raw images."""
        return [(s.vaddr, self.section_bytes(s)) for s in self.executable_sections()]

    def export_map(self) -> Dict[str, int]:
        return {e.name: e.address for e in self.exports if e.name and e.forwarder is None}

    def summary(self) -> Dict[str, object]:
        return {
            "format": self.format,
            "arch": self.arch,
            "bits": self.bits,
            "endian": self.endian,
            "image_base": hex(self.image_base),
            "entry": hex(self.entry) if self.entry is not None else None,
            "is_library": self.is_library,
            "is_dotnet": self.is_dotnet,
            "sections": len(self.sections),
            "executable_sections": [s.name for s in self.executable_sections()],
            "exports": len(self.exports),
            "imports": len(self.imports),
            "symbols": len(self.symbols),
            "function_starts": len(self.function_starts),
            "libraries": list(self.libraries),
            "pdb_path": self.pdb_path,
        }


# --------------------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------------------


def _cstr(buf: bytes, off: int, limit: int = 4096) -> str:
    if off < 0 or off >= len(buf):
        return ""
    end = buf.find(b"\x00", off, off + limit)
    if end < 0:
        end = min(len(buf), off + limit)
    return buf[off:end].decode("latin-1")


def _uleb(buf: bytes, off: int) -> Tuple[int, int]:
    result = shift = 0
    while off < len(buf):
        b = buf[off]
        off += 1
        result |= (b & 0x7F) << shift
        shift += 7
        if not b & 0x80:
            break
    return result, off


def detect_format(data: bytes) -> str:
    if data[:4] == b"\x7fELF":
        return "elf"
    if data[:2] == b"MZ" and len(data) >= 0x40:
        e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
        if data[e_lfanew : e_lfanew + 4] == b"PE\x00\x00":
            return "pe"
    magic_le = struct.unpack_from("<I", data, 0)[0] if len(data) >= 4 else 0
    magic_be = struct.unpack_from(">I", data, 0)[0] if len(data) >= 4 else 0
    if magic_le in (0xFEEDFACE, 0xFEEDFACF) or magic_be in (0xFEEDFACE, 0xFEEDFACF):
        return "macho"
    if magic_be in (0xCAFEBABE, 0xCAFEBABF) and len(data) >= 8:
        nfat = struct.unpack_from(">I", data, 4)[0]
        if 0 < nfat < 32:  # Java class files share the magic but have a version here
            return "macho-fat"
    return "raw"


# --------------------------------------------------------------------------------------
# ELF
# --------------------------------------------------------------------------------------

_ELF_MACHINES = {
    3: ("x86", 32),
    0x3E: ("x86_64", 64),
    0x28: ("arm", 32),
    0xB7: ("arm64", 64),
    8: ("mips", 32),
    0x14: ("ppc", 32),
    0x15: ("ppc64", 64),
    0xF3: ("riscv", 0),  # width from EI_CLASS
}


def _load_elf(data: bytes) -> BinaryImage:
    if len(data) < 52:
        raise BinaryFormatError("truncated ELF header")
    ei_class, ei_data = data[4], data[5]
    if ei_class not in (1, 2) or ei_data not in (1, 2):
        raise BinaryFormatError("bad ELF class/data")
    bits = 32 if ei_class == 1 else 64
    e = "<" if ei_data == 1 else ">"
    endian = "little" if ei_data == 1 else "big"

    if bits == 64:
        (e_type, e_machine, _, e_entry, e_phoff, e_shoff, e_flags, _, e_phentsize, e_phnum,
         e_shentsize, e_shnum, e_shstrndx) = struct.unpack_from(e + "HHIQQQIHHHHHH", data, 16)
    else:
        (e_type, e_machine, _, e_entry, e_phoff, e_shoff, e_flags, _, e_phentsize, e_phnum,
         e_shentsize, e_shnum, e_shstrndx) = struct.unpack_from(e + "HHIIIIIHHHHHH", data, 16)

    arch, _ = _ELF_MACHINES.get(e_machine, ("unknown", bits))
    if arch == "riscv":
        arch = "riscv64" if bits == 64 else "riscv32"
    if arch == "mips" and bits == 64:
        arch = "mips64"

    # Program headers (segments) - used for image base, interpreter and as a fallback map.
    segments: List[Section] = []
    has_interp = False
    dynamic_off = dynamic_size = None
    for i in range(e_phnum if e_phoff else 0):
        off = e_phoff + i * e_phentsize
        if off + e_phentsize > len(data):
            break
        if bits == 64:
            p_type, p_flags, p_offset, p_vaddr, _, p_filesz, p_memsz, _ = struct.unpack_from(e + "IIQQQQQQ", data, off)
        else:
            p_type, p_offset, p_vaddr, _, p_filesz, p_memsz, p_flags, _ = struct.unpack_from(e + "IIIIIIII", data, off)
        if p_type == 1:  # PT_LOAD
            segments.append(Section(f"LOAD{len(segments)}", p_vaddr, p_memsz, p_offset, p_filesz,
                                    executable=bool(p_flags & 1), writable=bool(p_flags & 2),
                                    readable=bool(p_flags & 4)))
        elif p_type == 3:
            has_interp = True
        elif p_type == 2:
            dynamic_off, dynamic_size = p_offset, p_filesz

    # Section headers.
    sections: List[Section] = []
    raw_shdrs = []
    if e_shoff and e_shnum and e_shoff + e_shnum * e_shentsize <= len(data):
        for i in range(e_shnum):
            off = e_shoff + i * e_shentsize
            if bits == 64:
                sh = struct.unpack_from(e + "IIQQQQIIQQ", data, off)
            else:
                sh = struct.unpack_from(e + "IIIIIIIIII", data, off)
            raw_shdrs.append(sh)
        names = b""
        if e_shstrndx < len(raw_shdrs):
            sh = raw_shdrs[e_shstrndx]
            names = data[sh[4] : sh[4] + sh[5]]
        for sh in raw_shdrs:
            sh_name, sh_type, sh_flags, sh_addr, sh_offset, sh_size = sh[:6]
            if sh_type == 0:
                continue
            nobits = sh_type == 8
            alloc = bool(sh_flags & 2)
            sections.append(Section(
                _cstr(names, sh_name), sh_addr, sh_size, sh_offset, 0 if nobits else sh_size,
                executable=bool(sh_flags & 4), writable=bool(sh_flags & 1),
                readable=alloc, mapped=alloc,
            ))
    image_base = min((s.vaddr - (s.vaddr % 0x1000) for s in segments), default=0)
    is_library = e_type == 3 and not has_interp  # ET_DYN without PT_INTERP => shared object
    img = BinaryImage("elf", arch, bits, endian, image_base, e_entry or None, is_library, data,
                      sections=sections, segments=segments, machine=e_machine)
    if arch == "arm" and e_entry & 1:
        img.thumb_entry = True

    sym_size = 24 if bits == 64 else 16
    seen: set[Tuple[Any, ...]] = set()

    def parse_symbols(sym_off: int, count: int, strtab: bytes, dynamic: bool) -> None:
        for j in range(1, count):
            so = sym_off + j * sym_size
            if so + sym_size > len(data):
                break
            if bits == 64:
                st_name, st_info, st_other, st_shndx, st_value, st_size = struct.unpack_from(e + "IBBHQQ", data, so)
            else:
                st_name, st_value, st_size, st_info, st_other, st_shndx = struct.unpack_from(e + "IIIBBH", data, so)
            name = _cstr(strtab, st_name)
            if not name:
                continue
            st_type, st_bind = st_info & 0xF, st_info >> 4
            kind = "func" if st_type == 2 else "object" if st_type == 1 else "other"
            if st_shndx == 0:  # undefined => import
                if dynamic and (name, "imp") not in seen:
                    seen.add((name, "imp"))
                    img.imports.append(Import(None, name))
                continue
            sym = Symbol(name, st_value, st_size, kind)
            if (name, st_value) not in seen:
                seen.add((name, st_value))
                img.symbols.append(sym)
            if dynamic and st_bind in (1, 2) and st_other & 3 == 0:  # GLOBAL/WEAK, default visibility
                if (name, st_value, "exp") not in seen:
                    seen.add((name, st_value, "exp"))
                    img.exports.append(sym)
            if kind == "func" and st_value:
                img.function_starts.append(st_value & ~1 if arch == "arm" else st_value)

    # 1) Section-header symbol tables (.symtab, .dynsym).
    have_dynsym = False
    for sh in raw_shdrs:
        sh_type = sh[1]
        if sh_type not in (2, 11) or sh[6] >= len(raw_shdrs):  # SHT_SYMTAB, SHT_DYNSYM
            continue
        strtab_hdr = raw_shdrs[sh[6]]
        parse_symbols(sh[4], sh[5] // sym_size, data[strtab_hdr[4] : strtab_hdr[4] + strtab_hdr[5]], sh_type == 11)
        have_dynsym |= sh_type == 11

    # 2) PT_DYNAMIC: DT_NEEDED, and the dynamic symbol table when the section table
    #    is stripped or forged (common in protected Android libraries).
    if dynamic_off is not None and dynamic_size is not None:
        dyn_size = 16 if bits == 64 else 8
        tags: Dict[int, int] = {}
        needed: List[int] = []
        for k in range(dynamic_size // dyn_size):
            o = dynamic_off + k * dyn_size
            if o + dyn_size > len(data):
                break
            tag, val = struct.unpack_from(e + ("qQ" if bits == 64 else "iI"), data, o)
            if tag == 0:
                break
            if tag == 1:
                needed.append(val)
            else:
                tags.setdefault(tag, val)
        str_off = img.va_to_offset(tags[5]) if 5 in tags else None
        strtab = data[str_off : str_off + tags.get(10, 0x100000)] if str_off is not None else b""
        img.libraries = [_cstr(strtab, n) for n in needed] if strtab else []

        sym_off = img.va_to_offset(tags[6]) if 6 in tags else None
        if not have_dynsym and sym_off is not None and strtab:
            count = 0
            hash_off = img.va_to_offset(tags[4]) if 4 in tags else None
            gnu_off = img.va_to_offset(tags[0x6FFFFEF5]) if 0x6FFFFEF5 in tags else None
            if hash_off is not None:  # DT_HASH: nchain == number of symbols
                count = struct.unpack_from(e + "I", data, hash_off + 4)[0]
            elif gnu_off is not None:  # DT_GNU_HASH: highest bucket chain end
                nbuckets, symoffset, bloom_size, _ = struct.unpack_from(e + "IIII", data, gnu_off)
                buckets_off = gnu_off + 16 + bloom_size * (bits // 8)
                chains_off = buckets_off + 4 * nbuckets
                last = max(struct.unpack_from(e + f"{nbuckets}I", data, buckets_off), default=0)
                if last >= symoffset:
                    while chains_off + 4 * (last - symoffset) + 4 <= len(data):
                        if struct.unpack_from(e + "I", data, chains_off + 4 * (last - symoffset))[0] & 1:
                            break
                        last += 1
                    count = last + 1
                else:
                    count = symoffset
            elif str_off is not None and str_off > sym_off:  # .dynsym usually precedes .dynstr
                count = (str_off - sym_off) // sym_size
            parse_symbols(sym_off, min(count, 0x200000), strtab, True)

    img.function_starts = sorted(set(img.function_starts))
    return img


# --------------------------------------------------------------------------------------
# PE / COFF
# --------------------------------------------------------------------------------------

_PE_MACHINES = {
    0x014C: ("x86", 32),
    0x8664: ("x86_64", 64),
    0xAA64: ("arm64", 64),
    0xA641: ("arm64", 64),  # ARM64EC
    0x01C0: ("arm", 32),
    0x01C2: ("arm", 32),  # Thumb
    0x01C4: ("arm", 32),  # ARMNT (Thumb-2)
}


def _load_pe(data: bytes) -> BinaryImage:
    e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
    coff = e_lfanew + 4
    if coff + 20 > len(data):
        raise BinaryFormatError("truncated COFF header")
    machine, nsect, _, _, _, opt_size, characteristics = struct.unpack_from("<HHIIIHH", data, coff)
    opt = coff + 20
    magic = struct.unpack_from("<H", data, opt)[0]
    if magic == 0x20B:
        bits = 64
        entry_rva = struct.unpack_from("<I", data, opt + 16)[0]
        image_base = struct.unpack_from("<Q", data, opt + 24)[0]
        ndirs_off, dirs_off = opt + 108, opt + 112
    elif magic == 0x10B:
        bits = 32
        entry_rva = struct.unpack_from("<I", data, opt + 16)[0]
        image_base = struct.unpack_from("<I", data, opt + 28)[0]
        ndirs_off, dirs_off = opt + 92, opt + 96
    else:
        raise BinaryFormatError(f"unknown PE optional header magic 0x{magic:X}")
    arch, _ = _PE_MACHINES.get(machine, ("unknown", bits))
    ndirs = min(struct.unpack_from("<I", data, ndirs_off)[0], 16)
    dirs = [struct.unpack_from("<II", data, dirs_off + 8 * i) for i in range(ndirs)]

    sections = []
    sec_off = opt + opt_size
    for i in range(nsect):
        o = sec_off + 40 * i
        if o + 40 > len(data):
            break
        name = data[o : o + 8].rstrip(b"\x00").decode("latin-1")
        vsize, vaddr, raw_size, raw_ptr = struct.unpack_from("<IIII", data, o + 8)
        chars = struct.unpack_from("<I", data, o + 36)[0]
        file_size = min(raw_size, vsize) if vsize else raw_size
        file_size = max(0, min(file_size, len(data) - raw_ptr))
        sections.append(Section(
            name, image_base + vaddr, vsize or raw_size, raw_ptr, file_size,
            executable=bool(chars & 0x20000000) or bool(chars & 0x20),
            writable=bool(chars & 0x80000000), readable=bool(chars & 0x40000000),
        ))

    is_library = bool(characteristics & 0x2000)
    img = BinaryImage("pe", arch, bits, "little", image_base,
                      image_base + entry_rva if entry_rva else None, is_library, data,
                      sections=sections, machine=machine)
    if arch == "arm" and machine in (0x01C2, 0x01C4):
        img.thumb_entry = True

    def rva_off(rva: int) -> int | None:
        return img.va_to_offset(image_base + rva)

    def rva_str(rva: int) -> str:
        o = rva_off(rva)
        return _cstr(data, o) if o is not None else ""

    def directory(idx: int) -> Tuple[int, int]:
        return dirs[idx] if idx < len(dirs) else (0, 0)

    # Exports.
    exp_rva, exp_size = directory(0)
    eo = rva_off(exp_rva) if exp_rva else None
    if eo is not None and eo + 40 <= len(data):
        (_, _, _, _, _, ord_base, n_funcs, n_names, funcs_rva, names_rva, ords_rva) = struct.unpack_from("<IIHHIIIIIII", data, eo)
        fo, no, oo = rva_off(funcs_rva), rva_off(names_rva), rva_off(ords_rva)
        names_by_index: Dict[int, str] = {}
        if no is not None and oo is not None:
            for k in range(min(n_names, 0x100000)):
                if no + 4 * k + 4 > len(data) or oo + 2 * k + 2 > len(data):
                    break
                nrva = struct.unpack_from("<I", data, no + 4 * k)[0]
                idx = struct.unpack_from("<H", data, oo + 2 * k)[0]
                names_by_index[idx] = rva_str(nrva)
        if fo is not None:
            for idx in range(min(n_funcs, 0x100000)):
                if fo + 4 * idx + 4 > len(data):
                    break
                frva = struct.unpack_from("<I", data, fo + 4 * idx)[0]
                if not frva:
                    continue
                name = names_by_index.get(idx, "")
                forwarder = rva_str(frva) if exp_rva <= frva < exp_rva + exp_size else None
                img.exports.append(Symbol(name or f"ord_{ord_base + idx}", image_base + frva, 0,
                                          "func", ordinal=ord_base + idx, forwarder=forwarder))
                if forwarder is None:
                    img.function_starts.append(image_base + frva)

    # Imports (normal and delay-load).
    thunk_size, ord_flag = (8, 1 << 63) if bits == 64 else (4, 1 << 31)
    thunk_fmt = "<Q" if bits == 64 else "<I"

    def walk_thunks(lookup_rva: int, iat_rva: int, lib: str, delay: bool) -> None:
        lo = rva_off(lookup_rva or iat_rva)
        if lo is None:
            return
        for k in range(0x10000):
            p = lo + k * thunk_size
            if p + thunk_size > len(data):
                break
            val = struct.unpack_from(thunk_fmt, data, p)[0]
            if not val:
                break
            slot = image_base + iat_rva + k * thunk_size
            if val & ord_flag:
                img.imports.append(Import(lib, None, val & 0xFFFF, slot, delay))
            else:
                img.imports.append(Import(lib, rva_str((val & 0x7FFFFFFF) + 2), None, slot, delay))

    imp_rva, _ = directory(1)
    io_ = rva_off(imp_rva) if imp_rva else None
    while io_ is not None and io_ + 20 <= len(data):
        ilt, _, _, name_rva, iat = struct.unpack_from("<IIIII", data, io_)
        if not (ilt or name_rva or iat):
            break
        lib = rva_str(name_rva)
        img.libraries.append(lib)
        walk_thunks(ilt, iat, lib, False)
        io_ += 20

    dl_rva, _ = directory(13)
    do = rva_off(dl_rva) if dl_rva else None
    while do is not None and do + 32 <= len(data):
        attrs, name_rva, _, iat, int_rva = struct.unpack_from("<IIIII", data, do)
        if not (name_rva or iat):
            break
        if not attrs & 1:  # pre-VC7 delay tables store VAs, not RVAs
            name_rva, iat, int_rva = name_rva - image_base, iat - image_base, int_rva - image_base
        lib = rva_str(name_rva)
        if lib and lib not in img.libraries:
            img.libraries.append(lib)
        walk_thunks(int_rva, iat, lib, True)
        do += 32

    # Exception directory (.pdata) => reliable function starts on x64/ARM64/ARM.
    pd_rva, pd_size = directory(3)
    po = rva_off(pd_rva) if pd_rva else None
    if po is not None:
        entry_size = 12 if arch == "x86_64" else 8
        for k in range(pd_size // entry_size):
            p = po + k * entry_size
            if p + entry_size > len(data):
                break
            begin = struct.unpack_from("<I", data, p)[0]
            if not begin:
                continue
            if arch == "x86_64":
                # Chained unwind info (UNW_FLAG_CHAININFO) marks a fragment of the previous
                # function (shrink-wrapped or split code), not a function of its own.
                uo = rva_off(struct.unpack_from("<I", data, p + 8)[0])
                if uo is not None and uo < len(data) and (data[uo] >> 3) & 0x4:
                    continue
            img.function_starts.append(image_base + (begin & ~1 if arch == "arm" else begin))

    # Debug directory => CodeView RSDS PDB path.
    dbg_rva, dbg_size = directory(6)
    dbo = rva_off(dbg_rva) if dbg_rva else None
    if dbo is not None:
        for k in range(dbg_size // 28):
            p = dbo + 28 * k
            if p + 28 > len(data):
                break
            dtype, size_of, _, raw_ptr = struct.unpack_from("<IIII", data, p + 12)
            if dtype == 2 and raw_ptr + 24 <= len(data) and data[raw_ptr : raw_ptr + 4] == b"RSDS":
                img.pdb_path = _cstr(data, raw_ptr + 24, 512)
                break

    clr_rva, _ = directory(14)
    img.is_dotnet = bool(clr_rva)
    img.function_starts = sorted(set(img.function_starts))
    return img


# --------------------------------------------------------------------------------------
# Mach-O
# --------------------------------------------------------------------------------------

_MACHO_CPU = {
    7: ("x86", 32),
    0x01000007: ("x86_64", 64),
    12: ("arm", 32),
    0x0100000C: ("arm64", 64),
    0x0200000C: ("arm64", 64),  # arm64_32
    18: ("ppc", 32),
    0x01000012: ("ppc64", 64),
}

_FAT_PREFERENCE = ["arm64", "x86_64", "arm", "x86"]


def _load_macho_fat(data: bytes, prefer: str | None) -> BinaryImage:
    magic, nfat = struct.unpack_from(">II", data, 0)
    is64 = magic == 0xCAFEBABF
    slices = []
    for i in range(nfat):
        if is64:
            cputype, _, offset, size, _, _ = struct.unpack_from(">iiQQII", data, 8 + 32 * i)
        else:
            cputype, _, offset, size, _ = struct.unpack_from(">iiIII", data, 8 + 20 * i)
        arch = _MACHO_CPU.get(cputype & 0xFFFFFFFF, ("unknown", 0))[0]
        slices.append((arch, offset, size))
    if not slices:
        raise BinaryFormatError("empty universal binary")
    order = ([prefer] if prefer else []) + _FAT_PREFERENCE
    slices.sort(key=lambda s: order.index(s[0]) if s[0] in order else len(order))
    arch, offset, size = slices[0]
    return _load_macho(data[offset : offset + size])


def _load_macho(data: bytes) -> BinaryImage:
    magic_le = struct.unpack_from("<I", data, 0)[0]
    if magic_le in (0xFEEDFACE, 0xFEEDFACF):
        e = "<"
    else:
        e = ">"
    magic = struct.unpack_from(e + "I", data, 0)[0]
    bits = 64 if magic == 0xFEEDFACF else 32
    cputype, _, filetype, ncmds, _, _ = struct.unpack_from(e + "iIIIII", data, 4)
    arch = _MACHO_CPU.get(cputype & 0xFFFFFFFF, ("unknown", bits))[0]
    off = 32 if bits == 64 else 28
    img = BinaryImage("macho", arch, bits, "little" if e == "<" else "big", 0, None,
                      filetype in (6, 8), data, machine=cputype & 0xFFFFFFFF)

    text_vmaddr = None
    symtab = None
    func_starts = None
    export_trie = None
    main_entryoff = None
    for _ in range(ncmds):
        if off + 8 > len(data):
            break
        cmd, cmdsize = struct.unpack_from(e + "II", data, off)
        if cmdsize < 8:
            break
        if cmd in (0x1, 0x19):  # LC_SEGMENT / LC_SEGMENT_64
            if cmd == 0x19:
                segname = data[off + 8 : off + 24].rstrip(b"\x00").decode("latin-1")
                vmaddr, vmsize, fileoff, filesize, _, initprot, nsects, _ = struct.unpack_from(e + "QQQQiiII", data, off + 24)
                sect_off, sect_size = off + 72, 80
            else:
                segname = data[off + 8 : off + 24].rstrip(b"\x00").decode("latin-1")
                vmaddr, vmsize, fileoff, filesize, _, initprot, nsects, _ = struct.unpack_from(e + "IIIIiiII", data, off + 24)
                sect_off, sect_size = off + 56, 68
            if segname == "__TEXT":
                text_vmaddr = vmaddr
                img.image_base = vmaddr
            for s in range(nsects):
                so = sect_off + s * sect_size
                sectname = data[so : so + 16].rstrip(b"\x00").decode("latin-1")
                if cmd == 0x19:
                    addr, size, offset = struct.unpack_from(e + "QQI", data, so + 32)
                    flags = struct.unpack_from(e + "I", data, so + 64)[0]
                else:
                    addr, size, offset = struct.unpack_from(e + "III", data, so + 32)
                    flags = struct.unpack_from(e + "I", data, so + 56)[0]
                zerofill = (flags & 0xFF) in (1, 0xC, 0x12)
                img.sections.append(Section(
                    f"{segname},{sectname}", addr, size, offset, 0 if zerofill else size,
                    # S_ATTR_PURE_INSTRUCTIONS | S_ATTR_SOME_INSTRUCTIONS; segment prot alone
                    # would also mark __TEXT,__cstring executable.
                    executable=bool(flags & 0x80000400),
                    writable=bool(initprot & 2), readable=bool(initprot & 1),
                ))
        elif cmd == 0x2:  # LC_SYMTAB
            symtab = struct.unpack_from(e + "IIII", data, off + 8)
        elif cmd == 0x26:  # LC_FUNCTION_STARTS
            func_starts = struct.unpack_from(e + "II", data, off + 8)
        elif cmd in (0x22, 0x80000022):  # LC_DYLD_INFO(_ONLY)
            exp_off, exp_size = struct.unpack_from(e + "II", data, off + 40)
            if exp_size:
                export_trie = (exp_off, exp_size)
        elif cmd == 0x80000033:  # LC_DYLD_EXPORTS_TRIE
            export_trie = struct.unpack_from(e + "II", data, off + 8)
        elif cmd == 0x80000028:  # LC_MAIN
            main_entryoff = struct.unpack_from(e + "Q", data, off + 8)[0]
        elif cmd in (0xC, 0x80000018, 0x8000001F, 0x20, 0x80000023):  # LOAD / WEAK / REEXPORT / LAZY / UPWARD dylib
            name_off = struct.unpack_from(e + "I", data, off + 8)[0]
            img.libraries.append(_cstr(data, off + name_off, cmdsize))
        off += cmdsize

    base = text_vmaddr or 0
    if main_entryoff is not None:
        img.entry = base + main_entryoff

    if symtab:
        symoff, nsyms, stroff, strsize = symtab
        strtab = data[stroff : stroff + strsize]
        nl_size = 16 if bits == 64 else 12
        for k in range(nsyms):
            p = symoff + k * nl_size
            if p + nl_size > len(data):
                break
            if bits == 64:
                n_strx, n_type, n_sect, n_desc, n_value = struct.unpack_from(e + "IBBHQ", data, p)
            else:
                n_strx, n_type, n_sect, n_desc, n_value = struct.unpack_from(e + "IBBhI", data, p)
            if n_type & 0xE0:  # stab
                continue
            name = _cstr(strtab, n_strx)
            if not name:
                continue
            if (n_type & 0x0E) == 0 and n_type & 0x01:  # N_UNDF | N_EXT => import
                lib_ord = (n_desc >> 8) & 0xFF
                lib = img.libraries[lib_ord - 1] if 0 < lib_ord <= len(img.libraries) else None
                img.imports.append(Import(lib, name))
            elif (n_type & 0x0E) == 0x0E:  # N_SECT
                sym = Symbol(name, n_value, 0, "func")
                img.symbols.append(sym)
                if n_type & 0x01 and not export_trie:
                    img.exports.append(sym)

    if export_trie:
        t_off, t_size = export_trie
        trie = data[t_off : t_off + t_size]

        def walk(node: int, prefix: str, depth: int) -> None:
            if node >= len(trie) or depth > 128:
                return
            term_size, p = _uleb(trie, node)
            if term_size:
                flags, q = _uleb(trie, p)
                if not flags & 0x08:  # not re-export
                    addr, _ = _uleb(trie, q)
                    img.exports.append(Symbol(prefix, base + addr, 0, "func"))
            p += term_size
            if p >= len(trie):
                return
            nchild = trie[p]
            p += 1
            for _ in range(nchild):
                end = trie.find(b"\x00", p)
                if end < 0:
                    return
                edge = trie[p:end].decode("latin-1")
                child, p = _uleb(trie, end + 1)
                walk(child, prefix + edge, depth + 1)

        walk(0, "", 0)

    if func_starts:
        fs_off, fs_size = func_starts
        blob = data[fs_off : fs_off + fs_size]
        addr, p = base, 0
        while p < len(blob):
            delta, p = _uleb(blob, p)
            if delta == 0:
                break
            addr += delta
            img.function_starts.append(addr & ~1 if arch == "arm" else addr)
    img.function_starts = sorted(set(img.function_starts))
    return img


# --------------------------------------------------------------------------------------
# Entry point
# --------------------------------------------------------------------------------------


def load_binary(source: str | bytes | bytearray | memoryview, *,
                prefer_arch: str | None = None,
                raw_arch: str = "unknown", raw_base: int = 0) -> BinaryImage:
    """Parse an ELF / PE / Mach-O / raw file path or buffer into a BinaryImage.

    prefer_arch picks the slice of a universal Mach-O. raw_arch/raw_base describe
    blobs that have no recognised header.
    """
    path = None
    if isinstance(source, (str, os.PathLike)):
        path = os.fspath(source)
        with open(path, "rb") as f:
            data = f.read()
    else:
        data = bytes(source)
    if not data:
        raise BinaryFormatError("empty input")

    fmt = detect_format(data)
    try:
        if fmt == "elf":
            img = _load_elf(data)
        elif fmt == "pe":
            img = _load_pe(data)
        elif fmt == "macho":
            img = _load_macho(data)
        elif fmt == "macho-fat":
            img = _load_macho_fat(data, prefer_arch)
        else:
            bits = 64 if raw_arch in ("arm64", "x86_64", "riscv64", "mips64", "ppc64") else 32
            img = BinaryImage("raw", raw_arch, bits, "little", raw_base, raw_base, False, data,
                              sections=[Section("raw", raw_base, len(data), 0, len(data), executable=True,
                                                writable=False)])
    except struct.error as exc:
        raise BinaryFormatError(f"truncated or corrupt {fmt} file: {exc}") from exc
    img.path = path
    return img


def iter_code(img: BinaryImage) -> Iterable[Tuple[int, bytes]]:
    """Yield (start VA, bytes) for each executable region."""
    yield from img.code_regions()


_ORDINAL_TABLES: Dict[str, Dict[int, str]] = {}


def _ghidra_symbol_dirs(bits: int) -> List[str]:
    sub = "win64" if bits == 64 else "win32"
    root = os.environ.get("GHIDRA_INSTALL_DIR")
    return [os.path.join(root, "Ghidra", "Features", "Base", "data", "symbols", sub)] if root else []


def _ordinal_table(path: str) -> Dict[int, str]:
    if path not in _ORDINAL_TABLES:
        import re

        table: Dict[int, str] = {}
        try:
            with open(path, encoding="utf-8", errors="replace") as f:
                for m in re.finditer(r'ORDINAL="(\d+)"\s+NAME="([^"]+)"', f.read()):
                    table[int(m.group(1))] = m.group(2)
        except OSError:
            pass
        _ORDINAL_TABLES[path] = table
    return _ORDINAL_TABLES[path]


def resolve_import_ordinals(img: BinaryImage, symbol_dirs: List[str] | None = None) -> int:
    """Name PE imports that are by ordinal only (e.g. every mfc140u.dll import).

    Uses Ghidra's ``data/symbols/win32|win64/<dll>.exports`` tables (from
    ``GHIDRA_INSTALL_DIR``) or ``symbol_dirs``. Returns how many imports were named; does
    nothing when no table is found.
    """
    if img.format != "pe":
        return 0
    dirs = symbol_dirs if symbol_dirs is not None else _ghidra_symbol_dirs(img.bits)
    named = 0
    for imp in img.imports:
        if imp.name or imp.ordinal is None or not imp.library:
            continue
        base = os.path.splitext(imp.library.lower())[0]
        for d in dirs:
            path = os.path.join(d, base + ".exports")
            if os.path.isfile(path):
                name = _ordinal_table(path).get(imp.ordinal)
                if name:
                    imp.name = name
                    named += 1
                break
    return named


if __name__ == "__main__":  # pragma: no cover - manual inspection helper
    import json
    import sys

    for arg in sys.argv[1:]:
        print(arg)
        print(json.dumps(load_binary(arg).summary(), indent=2))
