"""
apk_jni_cross_referencer.py
===========================
SuperGhidra Unified Android APK DEX + Native NDK (.so) JNI Cross-Referencer.

Implements Section 5.1 of GHIDRA_REFORMATION_ARCHITECTURAL_SPEC.md:
- Extracts and cross-references Java/Kotlin native method declarations against ELF .so binaries.
- Resolves static JNI export symbols:
    Java_<package>_<class>_<method>
    Java_<package>_<class>_<method>__<signature> (overloaded)
- Discovers and decodes dynamic `RegisterNatives` dispatch tables:
    JNINativeMethod {
        const char *name;      // method name
        const char *signature; // JNI type signature, e.g. "(Ljava/lang/String;)I"
        void       *fnPtr;     // target function pointer in .text
    }
- Direct binary parsing for ELF (64-bit & 32-bit: .dynsym, .symtab, .rodata, RegisterNatives).
- Direct binary parsing for Android DEX (classes.dex, string/type/proto/method/class_def tables).
- Unified archive loader for APK/ZIP containers (classes*.dex + lib/**/*.so).
- Exports unified JNI cross-reference manifests (JSON) and Ghidra Python/Java import scripts.
"""

from __future__ import annotations

import dataclasses
import hashlib
import json
import logging
import re
import struct
import zipfile
import zlib
from typing import Any, Dict, List, Set, Tuple

logger = logging.getLogger("apk_jni_cross_referencer")


# ==============================================================================
# JNI Type & Symbol Name Encoding Helpers
# ==============================================================================

def mangle_jni_identifier(ident: str) -> str:
    """
    Mangles a Java class/package or method identifier into standard JNI symbol format.
    Rules:
      _  -> _1
      ;  -> _2
      [  -> _3
      /  -> _
      $  -> _00024 (or _ for inner classes in short form)
      Unicode -> _0xxxx
    """
    out = []
    for ch in ident:
        if ch == '/':
            out.append('_')
        elif ch == '_':
            out.append('_1')
        elif ch == ';':
            out.append('_2')
        elif ch == '[':
            out.append('_3')
        elif ch == '$':
            out.append('_00024')
        elif ch.isalnum():
            out.append(ch)
        else:
            out.append(f"_0{ord(ch):04x}")
    return "".join(out)


def construct_static_jni_symbol(
    package_class: str,
    method_name: str,
    signature: str | None = None,
    is_overloaded: bool = False
) -> str:
    """
    Constructs canonical static JNI export symbol:
      Short: Java_<mangled_class>_<mangled_method>
      Long:  Java_<mangled_class>_<mangled_method>__<mangled_signature>
    """
    norm_pkg = package_class.replace('.', '/')
    mangled_class = mangle_jni_identifier(norm_pkg)
    mangled_method = mangle_jni_identifier(method_name)
    base = f"Java_{mangled_class}_{mangled_method}"
    if is_overloaded and signature:
        # Extract parameter types inside parentheses (args)
        match = re.search(r'\((.*?)\)', signature)
        arg_part = match.group(1) if match else signature
        mangled_sig = mangle_jni_identifier(arg_part)
        return f"{base}__{mangled_sig}"
    return base


# ==============================================================================
# Data Models
# ==============================================================================

@dataclasses.dataclass
class JavaNativeMethod:
    """Represents a declared native method in DEX bytecode."""
    class_name: str         # e.g. "com.example.app.NativeDialog"
    method_name: str        # e.g. "onDialogDismissed"
    signature: str          # e.g. "(ILjava/lang/String;)V"
    is_static: bool = True
    is_overloaded: bool = False
    source_file: str | None = None
    line_number: int | None = None

    @property
    def static_symbol_short(self) -> str:
        return construct_static_jni_symbol(self.class_name, self.method_name)

    @property
    def static_symbol_long(self) -> str:
        return construct_static_jni_symbol(self.class_name, self.method_name, self.signature, is_overloaded=True)


@dataclasses.dataclass
class JNIRegisteredNative:
    """Represents an entry in a JNINativeMethod array passed to RegisterNatives."""
    table_address: int      # Virtual address of JNINativeMethod array entry
    slot_index: int         # Index in the array
    method_name: str        # Method name string
    signature: str          # Signature string
    fn_ptr: int             # Target native function address in .text
    class_context: str | None = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "table_address": hex(self.table_address),
            "slot_index": self.slot_index,
            "method_name": self.method_name,
            "signature": self.signature,
            "fn_ptr": hex(self.fn_ptr),
            "class_context": self.class_context,
        }


@dataclasses.dataclass
class JNICrossReferenceMatch:
    """Represents a resolved cross-reference between Java DEX and Native .so."""
    java_method: JavaNativeMethod
    binding_type: str       # "STATIC_EXPORT" or "REGISTER_NATIVES"
    symbol_name: str
    target_address: int     # Native VA
    target_rva: int         # Target RVA relative to ELF image base
    confidence: float       # 0.0 to 1.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "class_name": self.java_method.class_name,
            "method_name": self.java_method.method_name,
            "signature": self.java_method.signature,
            "binding_type": self.binding_type,
            "symbol_name": self.symbol_name,
            "target_address": hex(self.target_address),
            "target_rva": hex(self.target_rva),
            "confidence": self.confidence,
        }


# ==============================================================================
# JNI Cross-Referencer Engine
# ==============================================================================

class APKJNICrossReferencer:
    """
    Parses Java DEX native methods, scans ELF exports and RegisterNatives tables,
    and produces verified cross-reference maps.
    """

    def __init__(self, image_base: int = 0x100000, is_64bit: bool = True):
        self.image_base = image_base
        self.is_64bit = is_64bit
        self.ptr_size = 8 if is_64bit else 4
        self.ptr_format = "<Q" if is_64bit else "<I"

        self.native_methods: List[JavaNativeMethod] = []
        self.elf_exports: Dict[str, int] = {}  # Symbol -> VA
        self.registered_natives: List[JNIRegisteredNative] = []
        self.matches: List[JNICrossReferenceMatch] = []

    def add_java_method(
        self,
        class_name: str,
        method_name: str,
        signature: str,
        is_static: bool = True,
        is_overloaded: bool = False
    ) -> JavaNativeMethod:
        """Registers a Java native method extracted from DEX / JADX output."""
        m = JavaNativeMethod(
            class_name=class_name,
            method_name=method_name,
            signature=signature,
            is_static=is_static,
            is_overloaded=is_overloaded
        )
        self.native_methods.append(m)
        return m

    def load_dex_methods_from_json(self, json_str: str) -> int:
        """Loads Java native method declarations from a structured JSON dump."""
        data = json.loads(json_str)
        count = 0
        for item in data:
            self.add_java_method(
                class_name=item["class_name"],
                method_name=item["method_name"],
                signature=item["signature"],
                is_static=item.get("is_static", True),
                is_overloaded=item.get("is_overloaded", False)
            )
            count += 1
        return count

    def add_elf_export(self, symbol_name: str, address: int) -> None:
        """Registers an exported dynamic symbol (.dynsym) from the ELF library."""
        self.elf_exports[symbol_name] = address

    def load_elf_exports(self, exports_dict: Dict[str, int]) -> None:
        """Loads a dictionary of exported symbol -> VA pairs."""
        self.elf_exports.update(exports_dict)

    def scan_register_natives_table(
        self,
        rodata_bytes: bytes,
        rodata_vaddr: int,
        string_table: Dict[int, str],
        text_vaddr_start: int,
        text_vaddr_end: int,
        class_context: str | None = None
    ) -> List[JNIRegisteredNative]:
        """
        Scans a memory buffer (.rodata or .data.rel.ro) for arrays of JNINativeMethod.
        JNINativeMethod layout:
          32-bit: [name_ptr: uint32, sig_ptr: uint32, fn_ptr: uint32] -> 12 bytes
          64-bit: [name_ptr: uint64, sig_ptr: uint64, fn_ptr: uint64] -> 24 bytes
        """
        discovered = []
        entry_size = self.ptr_size * 3
        total_len = len(rodata_bytes)

        # Align to pointer boundary
        for offset in range(0, total_len - entry_size + 1, self.ptr_size):
            chunk = rodata_bytes[offset:offset + entry_size]
            if len(chunk) < entry_size:
                break

            if self.is_64bit:
                name_ptr, sig_ptr, fn_ptr = struct.unpack("<QQQ", chunk)
            else:
                name_ptr, sig_ptr, fn_ptr = struct.unpack("<III", chunk)

            # Verification heuristic:
            # 1. name_ptr must resolve to a valid method name in string_table
            # 2. sig_ptr must resolve to a valid JNI signature (starts with '(')
            # 3. fn_ptr must fall within executable .text segment bounds
            if name_ptr in string_table and sig_ptr in string_table:
                method_name = string_table[name_ptr]
                sig = string_table[sig_ptr]

                if sig.startswith("(") and text_vaddr_start <= fn_ptr < text_vaddr_end:
                    entry = JNIRegisteredNative(
                        table_address=rodata_vaddr + offset,
                        slot_index=len(discovered),
                        method_name=method_name,
                        signature=sig,
                        fn_ptr=fn_ptr,
                        class_context=class_context
                    )
                    discovered.append(entry)
                    self.registered_natives.append(entry)

        return discovered

    def load_from_elf_bytes(self, elf_bytes: bytes, class_context: str | None = None) -> Dict[str, Any]:
        """
        Zero-dependency binary ELF parser supporting 64-bit and 32-bit ELF binaries.
        Extracts dynamic exports (.dynsym) and scans .rodata/.data.rel.ro/.data for JNINativeMethod tables.
        """
        if len(elf_bytes) < 52 or not elf_bytes.startswith(b"\x7fELF"):
            raise ValueError("Not a valid ELF binary")

        ei_class = elf_bytes[4]
        is_64bit = (ei_class == 2)
        self.is_64bit = is_64bit
        self.ptr_size = 8 if is_64bit else 4
        self.ptr_format = "<Q" if is_64bit else "<I"

        # Unpack ELF Header coordinates
        if is_64bit:
            (
                e_ident, e_type, e_machine, e_version, e_entry,
                e_phoff, e_shoff, e_flags, e_ehsize, e_phentsize,
                e_phnum, e_shentsize, e_shnum, e_shstrndx
            ) = struct.unpack_from("<16sHHIQQQIHHHHHH", elf_bytes, 0)
        else:
            (
                e_ident, e_type, e_machine, e_version, e_entry,
                e_phoff, e_shoff, e_flags, e_ehsize, e_phentsize,
                e_phnum, e_shentsize, e_shnum, e_shstrndx
            ) = struct.unpack_from("<16sHHIIIIIHHHHHH", elf_bytes, 0)

        if e_shoff == 0 or e_shnum == 0 or e_shstrndx >= e_shnum:
            return {"exports_loaded": 0, "strings_indexed": 0, "registered_natives_found": 0}

        def _get_shdr(idx: int) -> Tuple[int, int, int, int, int, int, int, int, int, int]:
            off = e_shoff + idx * e_shentsize
            if is_64bit:
                return struct.unpack_from("<IIQQQQIIQQ", elf_bytes, off)
            else:
                return struct.unpack_from("<IIIIIIIIII", elf_bytes, off)

        # Read section header string table (.shstrtab)
        shstrtab_hdr = _get_shdr(e_shstrndx)
        shstrtab_off, shstrtab_size = shstrtab_hdr[4], shstrtab_hdr[5]
        shstrtab = elf_bytes[shstrtab_off : shstrtab_off + shstrtab_size]

        def _get_sh_name(name_idx: int) -> str:
            if name_idx >= len(shstrtab):
                return ""
            end = shstrtab.find(b"\x00", name_idx)
            if end == -1:
                end = len(shstrtab)
            return shstrtab[name_idx:end].decode("utf-8", errors="replace")

        # Map all section coordinates
        sections: Dict[str, Dict[str, Any]] = {}
        for i in range(e_shnum):
            sh = _get_shdr(i)
            name = _get_sh_name(sh[0])
            if name:
                sections[name] = {
                    "sh_type": sh[1],
                    "sh_flags": sh[2],
                    "sh_addr": sh[3],
                    "sh_offset": sh[4],
                    "sh_size": sh[5],
                    "sh_link": sh[6],
                    "sh_info": sh[7],
                    "sh_entsize": sh[9],
                }

        exports_count = 0

        # Helper to parse symbol tables (.dynsym / .symtab)
        def _parse_symbols(sym_sec_name: str):
            nonlocal exports_count
            if sym_sec_name not in sections:
                return
            sym_sec = sections[sym_sec_name]
            link_idx = sym_sec["sh_link"]
            if link_idx >= e_shnum:
                return
            str_hdr = _get_shdr(link_idx)
            str_data = elf_bytes[str_hdr[4] : str_hdr[4] + str_hdr[5]]

            def _get_sym_name(off: int) -> str:
                if off >= len(str_data):
                    return ""
                end = str_data.find(b"\x00", off)
                if end == -1:
                    end = len(str_data)
                return str_data[off:end].decode("utf-8", errors="replace")

            sym_offset = sym_sec["sh_offset"]
            sym_size = sym_sec["sh_size"]
            entry_size = 24 if is_64bit else 16
            num_syms = sym_size // entry_size

            for j in range(num_syms):
                entry_off = sym_offset + j * entry_size
                if is_64bit:
                    st_name, st_info, st_other, st_shndx, st_value, st_size = struct.unpack_from("<IBBHQQ", elf_bytes, entry_off)
                else:
                    st_name, st_value, st_size, st_info, st_other, st_shndx = struct.unpack_from("<IIIBBH", elf_bytes, entry_off)

                if st_name != 0 and st_value != 0:
                    s_name = _get_sym_name(st_name)
                    if s_name:
                        va = st_value if st_value >= self.image_base else st_value + self.image_base
                        self.add_elf_export(s_name, va)
                        exports_count += 1

        _parse_symbols(".dynsym")
        _parse_symbols(".symtab")

        # Build virtual-address-indexed string_table from .rodata, .data.rel.ro, .dynstr
        string_table: Dict[int, str] = {}

        def _scan_strings(data: bytes, sec_vaddr: int):
            i = 0
            n = len(data)
            while i < n:
                if 0x20 <= data[i] <= 0x7E:
                    start = i
                    while i < n and 0x20 <= data[i] <= 0x7E:
                        i += 1
                    if i < n and data[i] == 0:
                        s = data[start:i].decode("ascii", errors="replace")
                        if s:
                            va = sec_vaddr + start
                            string_table[va] = s
                            if sec_vaddr < self.image_base:
                                string_table[self.image_base + va] = s
                    i += 1
                else:
                    i += 1

        for sname in [".rodata", ".data.rel.ro", ".dynstr"]:
            if sname in sections:
                sec = sections[sname]
                s_off = sec["sh_offset"]
                s_sz = sec["sh_size"]
                s_addr = sec["sh_addr"] if sec["sh_addr"] > 0 else s_off
                _scan_strings(elf_bytes[s_off : s_off + s_sz], s_addr)

        # Determine .text segment bounds
        text_vaddr_start = 0
        text_vaddr_end = 0xFFFFFFFFFFFFFFFF
        if ".text" in sections:
            t_sec = sections[".text"]
            t_addr = t_sec["sh_addr"] if t_sec["sh_addr"] > 0 else t_sec["sh_offset"]
            t_size = t_sec["sh_size"]
            text_vaddr_start = t_addr if t_addr >= self.image_base else self.image_base + t_addr
            text_vaddr_end = text_vaddr_start + t_size

        # Scan .rodata, .data.rel.ro, and .data for RegisterNatives
        total_discovered = 0
        for sname in [".rodata", ".data.rel.ro", ".data"]:
            if sname in sections:
                sec = sections[sname]
                s_off = sec["sh_offset"]
                s_sz = sec["sh_size"]
                s_addr = sec["sh_addr"] if sec["sh_addr"] > 0 else s_off
                sec_vaddr = s_addr if s_addr >= self.image_base else self.image_base + s_addr
                sec_bytes = elf_bytes[s_off : s_off + s_sz]

                # Scan with normalized virtual addresses
                found = self.scan_register_natives_table(
                    rodata_bytes=sec_bytes,
                    rodata_vaddr=sec_vaddr,
                    string_table=string_table,
                    text_vaddr_start=text_vaddr_start,
                    text_vaddr_end=text_vaddr_end,
                    class_context=class_context
                )
                if not found and s_addr < self.image_base:
                    # Fallback check with raw RVA bounds if table stores RVAs
                    found = self.scan_register_natives_table(
                        rodata_bytes=sec_bytes,
                        rodata_vaddr=s_addr,
                        string_table=string_table,
                        text_vaddr_start=s_addr,
                        text_vaddr_end=s_addr + sec["sh_size"],
                        class_context=class_context
                    )
                total_discovered += len(found)

        return {
            "exports_loaded": exports_count,
            "strings_indexed": len(string_table),
            "registered_natives_found": total_discovered,
        }

    def load_from_elf_file(self, elf_path: str, class_context: str | None = None) -> Dict[str, Any]:
        """Loads an ELF binary from disk and extracts exports and RegisterNatives tables."""
        with open(elf_path, "rb") as f:
            elf_bytes = f.read()
        return self.load_from_elf_bytes(elf_bytes, class_context=class_context)

    def load_from_dex_bytes(self, dex_bytes: bytes) -> int:
        """
        Parses an Android DEX bytecode binary (classes.dex) and registers all native method declarations.
        Automatically marks overloaded native methods sharing the same class and method name.
        """
        if len(dex_bytes) < 112 or not dex_bytes.startswith(b"dex\n"):
            raise ValueError("Not a valid DEX binary")

        # Unpack DEX header tables (offset 56..104: 12 uint32s)
        (
            string_ids_size, string_ids_off,
            type_ids_size, type_ids_off,
            proto_ids_size, proto_ids_off,
            field_ids_size, field_ids_off,
            method_ids_size, method_ids_off,
            class_defs_size, class_defs_off,
        ) = struct.unpack_from("<IIIIIIIIIIII", dex_bytes, 56)

        def _read_uleb128(data: bytes, offset: int) -> Tuple[int, int]:
            result = 0
            shift = 0
            while True:
                byte = data[offset]
                offset += 1
                result |= (byte & 0x7F) << shift
                if (byte & 0x80) == 0:
                    break
                shift += 7
            return result, offset

        # 1. Read String Table
        strings: List[str] = []
        for i in range(string_ids_size):
            str_data_off = struct.unpack_from("<I", dex_bytes, string_ids_off + i * 4)[0]
            _, off = _read_uleb128(dex_bytes, str_data_off)
            end = dex_bytes.find(b"\x00", off)
            if end == -1:
                end = len(dex_bytes)
            strings.append(dex_bytes[off:end].decode("utf-8", errors="replace"))

        # 2. Read Type Table
        types: List[str] = []
        for i in range(type_ids_size):
            desc_idx = struct.unpack_from("<I", dex_bytes, type_ids_off + i * 4)[0]
            types.append(strings[desc_idx] if desc_idx < len(strings) else "")

        # 3. Read Proto Table
        protos: List[str] = []
        for i in range(proto_ids_size):
            shorty_idx, return_type_idx, parameters_off = struct.unpack_from("<III", dex_bytes, proto_ids_off + i * 12)
            ret_type = types[return_type_idx] if return_type_idx < len(types) else "V"
            if parameters_off != 0 and parameters_off < len(dex_bytes):
                param_count = struct.unpack_from("<I", dex_bytes, parameters_off)[0]
                param_indices = struct.unpack_from(f"<{param_count}H", dex_bytes, parameters_off + 4)
                param_types = [types[idx] for idx in param_indices if idx < len(types)]
                proto_sig = f"({''.join(param_types)}){ret_type}"
            else:
                proto_sig = f"(){ret_type}"
            protos.append(proto_sig)

        # 4. Read Method Table
        methods: List[Tuple[str, str, str]] = []
        for i in range(method_ids_size):
            class_idx, proto_idx, name_idx = struct.unpack_from("<HHI", dex_bytes, method_ids_off + i * 8)
            c_desc = types[class_idx] if class_idx < len(types) else ""
            p_sig = protos[proto_idx] if proto_idx < len(protos) else "()V"
            m_name = strings[name_idx] if name_idx < len(strings) else ""
            methods.append((c_desc, m_name, p_sig))

        native_count = 0

        # 5. Read Class Definitions
        for i in range(class_defs_size):
            entry_off = class_defs_off + i * 32
            (
                class_idx, access_flags, superclass_idx,
                interfaces_off, source_file_idx, annotations_off,
                class_data_off, static_values_off
            ) = struct.unpack_from("<IIIIIIII", dex_bytes, entry_off)

            if class_data_off == 0 or class_data_off >= len(dex_bytes):
                continue

            off = class_data_off
            static_fields_size, off = _read_uleb128(dex_bytes, off)
            instance_fields_size, off = _read_uleb128(dex_bytes, off)
            direct_methods_size, off = _read_uleb128(dex_bytes, off)
            virtual_methods_size, off = _read_uleb128(dex_bytes, off)

            # Skip fields
            for _ in range(static_fields_size):
                _, off = _read_uleb128(dex_bytes, off)
                _, off = _read_uleb128(dex_bytes, off)
            for _ in range(instance_fields_size):
                _, off = _read_uleb128(dex_bytes, off)
                _, off = _read_uleb128(dex_bytes, off)

            # Process direct methods
            m_idx = 0
            for _ in range(direct_methods_size):
                diff, off = _read_uleb128(dex_bytes, off)
                m_idx += diff
                m_flags, off = _read_uleb128(dex_bytes, off)
                code_off, off = _read_uleb128(dex_bytes, off)

                if (m_flags & 0x0100) != 0 and m_idx < len(methods):  # ACC_NATIVE
                    c_desc, m_name, sig = methods[m_idx]
                    if c_desc.startswith("L") and c_desc.endswith(";"):
                        class_name = c_desc[1:-1].replace("/", ".")
                    else:
                        class_name = c_desc.replace("/", ".")
                    self.add_java_method(
                        class_name=class_name,
                        method_name=m_name,
                        signature=sig,
                        is_static=bool(m_flags & 0x0008)
                    )
                    native_count += 1

            # Process virtual methods
            m_idx = 0
            for _ in range(virtual_methods_size):
                diff, off = _read_uleb128(dex_bytes, off)
                m_idx += diff
                m_flags, off = _read_uleb128(dex_bytes, off)
                code_off, off = _read_uleb128(dex_bytes, off)

                if (m_flags & 0x0100) != 0 and m_idx < len(methods):  # ACC_NATIVE
                    c_desc, m_name, sig = methods[m_idx]
                    if c_desc.startswith("L") and c_desc.endswith(";"):
                        class_name = c_desc[1:-1].replace("/", ".")
                    else:
                        class_name = c_desc.replace("/", ".")
                    self.add_java_method(
                        class_name=class_name,
                        method_name=m_name,
                        signature=sig,
                        is_static=bool(m_flags & 0x0008)
                    )
                    native_count += 1

        # Automatically mark overloaded native methods
        name_counts: Dict[Tuple[str, str], int] = {}
        for m in self.native_methods:
            key = (m.class_name, m.method_name)
            name_counts[key] = name_counts.get(key, 0) + 1

        for m in self.native_methods:
            if name_counts.get((m.class_name, m.method_name), 0) > 1:
                m.is_overloaded = True

        return native_count

    def load_from_apk_or_dex(self, path: str) -> Dict[str, int]:
        """
        Parses an Android APK package or DEX file.
        If path is a ZIP/APK archive, extracts and analyzes all classes*.dex and native lib/**/*.so files.
        If path is a standalone DEX or ELF file, analyzes its declarations directly.
        """
        stats = {"dex_methods": 0, "elf_exports": 0, "registered_natives": 0}

        if zipfile.is_zipfile(path):
            with zipfile.ZipFile(path, "r") as zf:
                for name in zf.namelist():
                    if re.match(r"^classes\d*\.dex$", name) or name.endswith(".dex"):
                        dex_data = zf.read(name)
                        count = self.load_from_dex_bytes(dex_data)
                        stats["dex_methods"] += count
                    elif name.endswith(".so"):
                        elf_data = zf.read(name)
                        res = self.load_from_elf_bytes(elf_data)
                        stats["elf_exports"] += res.get("exports_loaded", 0)
                        stats["registered_natives"] += res.get("registered_natives_found", 0)
            return stats

        with open(path, "rb") as f:
            data = f.read()

        if data.startswith(b"dex\n"):
            count = self.load_from_dex_bytes(data)
            stats["dex_methods"] = count
        elif data.startswith(b"\x7fELF"):
            res = self.load_from_elf_bytes(data)
            stats["elf_exports"] = res.get("exports_loaded", 0)
            stats["registered_natives"] = res.get("registered_natives_found", 0)

        return stats

    @staticmethod
    def build_synthetic_dex_bytes(native_methods: List[Tuple[str, str, str, int]]) -> bytes:
        """
        Synthesizes a minimal valid Android DEX binary (dex\\n035\\0) encoding the provided native methods.
        native_methods: list of (class_name, method_name, signature, access_flags)
        """
        def _encode_uleb(val: int) -> bytes:
            out = bytearray()
            while True:
                b = val & 0x7F
                val >>= 7
                if val != 0:
                    b |= 0x80
                out.append(b)
                if val == 0:
                    break
            return bytes(out)

        def _split_params(sig: str) -> List[str]:
            if "(" not in sig or ")" not in sig:
                return []
            p_str = sig[sig.index("(") + 1 : sig.index(")")]
            types = []
            i = 0
            n = len(p_str)
            while i < n:
                c = p_str[i]
                if c in "ZBCSIJFD":
                    types.append(c)
                    i += 1
                elif c == "[":
                    start = i
                    while i < n and p_str[i] == "[":
                        i += 1
                    if i < n and p_str[i] == "L":
                        end = p_str.index(";", i)
                        types.append(p_str[start : end + 1])
                        i = end + 1
                    elif i < n:
                        types.append(p_str[start : i + 1])
                        i += 1
                elif c == "L":
                    end = p_str.index(";", i)
                    types.append(p_str[i : end + 1])
                    i = end + 1
                else:
                    i += 1
            return types

        def _shorty_for_type(t: str) -> str:
            if not t:
                return "V"
            if t[0] in "VZBCSIJFD":
                return t[0]
            return "L"

        # Collect unique classes, strings, types, protos
        str_set: Set[str] = {"Ljava/lang/Object;", "V"}
        class_methods: Dict[str, List[Tuple[str, str, int]]] = {}

        for c_name, m_name, sig, flags in native_methods:
            c_desc = f"L{c_name.replace('.', '/')};"
            str_set.add(c_desc)
            str_set.add(m_name)
            p_types = _split_params(sig)
            for pt in p_types:
                str_set.add(pt)
            ret_type = sig[sig.index(")") + 1 :] if ")" in sig else "V"
            str_set.add(ret_type)
            shorty = _shorty_for_type(ret_type) + "".join(_shorty_for_type(pt) for pt in p_types)
            str_set.add(shorty)

            class_methods.setdefault(c_desc, []).append((m_name, sig, flags))

        strings_list = sorted(list(str_set))
        str_map = {s: idx for idx, s in enumerate(strings_list)}

        type_set = set()
        for s in strings_list:
            if s.startswith("L") and s.endswith(";"):
                type_set.add(s)
            elif s in "VZBCSIJFD" or s.startswith("["):
                type_set.add(s)
        types_list = sorted(list(type_set))
        type_map = {t: idx for idx, t in enumerate(types_list)}

        # Build protos
        proto_set = set()
        for _, m_name, sig, _ in native_methods:
            p_types = tuple(_split_params(sig))
            ret_type = sig[sig.index(")") + 1 :] if ")" in sig else "V"
            shorty = _shorty_for_type(ret_type) + "".join(_shorty_for_type(pt) for pt in p_types)
            proto_set.add((shorty, ret_type, p_types))
        protos_list = sorted(list(proto_set))
        proto_map = {p: idx for idx, p in enumerate(protos_list)}

        # Build methods
        method_set = set()
        for c_desc, meths in class_methods.items():
            for m_name, sig, _ in meths:
                p_types = tuple(_split_params(sig))
                ret_type = sig[sig.index(")") + 1 :] if ")" in sig else "V"
                shorty = _shorty_for_type(ret_type) + "".join(_shorty_for_type(pt) for pt in p_types)
                method_set.add((c_desc, (shorty, ret_type, p_types), m_name))

        # DEX methods must be sorted by (class_idx, name_idx, proto_idx)
        methods_list = sorted(
            list(method_set),
            key=lambda m: (type_map[m[0]], str_map[m[2]], proto_map[m[1]])
        )
        method_map = {m: idx for idx, m in enumerate(methods_list)}

        # Layout and data buffers
        string_ids_size = len(strings_list)
        type_ids_size = len(types_list)
        proto_ids_size = len(protos_list)
        method_ids_size = len(methods_list)
        class_defs_size = len(class_methods)

        string_ids_off = 112
        type_ids_off = string_ids_off + string_ids_size * 4
        proto_ids_off = type_ids_off + type_ids_size * 4
        field_ids_off = 0
        field_ids_size = 0
        method_ids_off = proto_ids_off + proto_ids_size * 12
        class_defs_off = method_ids_off + method_ids_size * 8
        data_start_off = class_defs_off + class_defs_size * 32

        data_buf = bytearray()

        # 1. Type lists for protos with parameters
        proto_params_off: Dict[Tuple, int] = {}
        for p in protos_list:
            p_types = p[2]
            if p_types:
                pad = (4 - (len(data_buf) % 4)) % 4
                data_buf.extend(b"\x00" * pad)
                cur_off = data_start_off + len(data_buf)
                proto_params_off[p] = cur_off
                data_buf.extend(struct.pack("<I", len(p_types)))
                for pt in p_types:
                    data_buf.extend(struct.pack("<H", type_map[pt]))
            else:
                proto_params_off[p] = 0

        # 2. String data
        str_data_offsets = []
        for s in strings_list:
            s_bytes = s.encode("utf-8")
            cur_off = data_start_off + len(data_buf)
            str_data_offsets.append(cur_off)
            data_buf.extend(_encode_uleb(len(s)))
            data_buf.extend(s_bytes)
            data_buf.append(0)

        # 3. Class data
        class_data_offsets: Dict[str, int] = {}
        sorted_classes = sorted(list(class_methods.keys()), key=lambda c: type_map[c])

        for c_desc in sorted_classes:
            meths = class_methods[c_desc]
            direct_m = []
            virtual_m = []
            for m_name, sig, flags in meths:
                p_types = tuple(_split_params(sig))
                ret_type = sig[sig.index(")") + 1 :] if ")" in sig else "V"
                shorty = _shorty_for_type(ret_type) + "".join(_shorty_for_type(pt) for pt in p_types)
                m_tuple = (c_desc, (shorty, ret_type, p_types), m_name)
                m_idx = method_map[m_tuple]
                if flags & 0x0008 or flags & 0x0002:
                    direct_m.append((m_idx, flags))
                else:
                    virtual_m.append((m_idx, flags))

            direct_m.sort(key=lambda x: x[0])
            virtual_m.sort(key=lambda x: x[0])

            cur_off = data_start_off + len(data_buf)
            class_data_offsets[c_desc] = cur_off
            data_buf.extend(_encode_uleb(0))  # static_fields_size
            data_buf.extend(_encode_uleb(0))  # instance_fields_size
            data_buf.extend(_encode_uleb(len(direct_m)))
            data_buf.extend(_encode_uleb(len(virtual_m)))

            last_idx = 0
            for m_idx, flags in direct_m:
                diff = m_idx - last_idx
                last_idx = m_idx
                data_buf.extend(_encode_uleb(diff))
                data_buf.extend(_encode_uleb(flags))
                data_buf.extend(_encode_uleb(0))  # code_off = 0 for native

            last_idx = 0
            for m_idx, flags in virtual_m:
                diff = m_idx - last_idx
                last_idx = m_idx
                data_buf.extend(_encode_uleb(diff))
                data_buf.extend(_encode_uleb(flags))
                data_buf.extend(_encode_uleb(0))  # code_off = 0 for native

        # Build tables
        string_ids_data = struct.pack(f"<{string_ids_size}I", *str_data_offsets)
        type_ids_data = struct.pack(f"<{type_ids_size}I", *[str_map[t] for t in types_list])
        proto_ids_data = bytearray()
        for p in protos_list:
            shorty, ret_type, p_types = p
            proto_ids_data.extend(struct.pack(
                "<III",
                str_map[shorty],
                type_map[ret_type],
                proto_params_off[p]
            ))
        method_ids_data = bytearray()
        for m in methods_list:
            c_desc, p_tuple, m_name = m
            method_ids_data.extend(struct.pack(
                "<HHI",
                type_map[c_desc],
                proto_map[p_tuple],
                str_map[m_name]
            ))
        class_defs_data = bytearray()
        for c_desc in sorted_classes:
            class_defs_data.extend(struct.pack(
                "<IIIIIIII",
                type_map[c_desc],
                0x0001,  # ACC_PUBLIC
                type_map.get("Ljava/lang/Object;", 0),
                0, 0, 0,
                class_data_offsets[c_desc],
                0
            ))

        total_file_size = data_start_off + len(data_buf)

        header_tail = struct.pack(
            "<IIIIIIIIIIIIIIIIII",
            total_file_size,
            112,
            0x12345678,
            0, 0,  # link
            0,     # map_off
            string_ids_size, string_ids_off,
            type_ids_size, type_ids_off,
            proto_ids_size, proto_ids_off,
            field_ids_size, field_ids_off,
            method_ids_size, method_ids_off,
            class_defs_size, class_defs_off,
        ) + struct.pack("<II", len(data_buf), data_start_off)

        body = (
            string_ids_data
            + type_ids_data
            + bytes(proto_ids_data)
            + bytes(method_ids_data)
            + bytes(class_defs_data)
            + bytes(data_buf)
        )

        signed_part = header_tail + body
        sig = hashlib.sha1(signed_part).digest()
        checksum = zlib.adler32(sig + signed_part) & 0xFFFFFFFF

        header = b"dex\n035\x00" + struct.pack("<I", checksum) + sig + header_tail
        return header + body

    @staticmethod
    def build_synthetic_jni_elf_bytes(
        exports: Dict[str, int],
        registered_natives: List[Tuple[str, str, int]] | None = None,
        image_base: int = 0x100000,
        is_64bit: bool = True
    ) -> bytes:
        """
        Synthesizes a minimal valid 64-bit (or 32-bit) ELF binary containing:
        - Exported dynamic symbols in .dynsym / .dynstr (Java_* exports)
        - .rodata section with strings and JNINativeMethod arrays for RegisterNatives
        - .text section with executable code
        """
        registered_natives = registered_natives or []
        ptr_size = 8 if is_64bit else 4
        ptr_fmt = "<Q" if is_64bit else "<I"

        text_vaddr = image_base + 0x1000
        text_size = 0x1000
        text_bytes = b"\xc0\x03\x5f\xd6" * (text_size // 4)

        rodata_vaddr = image_base + 0x2000
        rodata_buf = bytearray()
        string_offsets: Dict[str, int] = {}

        # String constants in .rodata
        for m_name, m_sig, _ in registered_natives:
            if m_name not in string_offsets:
                string_offsets[m_name] = rodata_vaddr + len(rodata_buf)
                rodata_buf.extend(m_name.encode("ascii") + b"\x00")
            if m_sig not in string_offsets:
                string_offsets[m_sig] = rodata_vaddr + len(rodata_buf)
                rodata_buf.extend(m_sig.encode("ascii") + b"\x00")

        # Align to pointer boundary
        pad = (ptr_size - (len(rodata_buf) % ptr_size)) % ptr_size
        rodata_buf.extend(b"\x00" * pad)

        # Append JNINativeMethod array entries
        for m_name, m_sig, fn_ptr in registered_natives:
            name_ptr = string_offsets[m_name]
            sig_ptr = string_offsets[m_sig]
            rodata_buf.extend(struct.pack(ptr_fmt, name_ptr))
            rodata_buf.extend(struct.pack(ptr_fmt, sig_ptr))
            rodata_buf.extend(struct.pack(ptr_fmt, fn_ptr))

        if not rodata_buf:
            rodata_buf.extend(b"SuperGhidraRODATA\x00")

        rodata_size = len(rodata_buf)
        rodata_bytes = bytes(rodata_buf)

        # .dynstr section: contains export symbol names
        dynstr_buf = bytearray(b"\x00")
        sym_name_offsets: Dict[str, int] = {}
        for sym_name in exports.keys():
            sym_name_offsets[sym_name] = len(dynstr_buf)
            dynstr_buf.extend(sym_name.encode("ascii") + b"\x00")
        dynstr_bytes = bytes(dynstr_buf)
        dynstr_size = len(dynstr_bytes)
        dynstr_vaddr = image_base + 0x3000

        # .dynsym section
        dynsym_buf = bytearray()
        if is_64bit:
            dynsym_buf.extend(struct.pack("<IBBHQQ", 0, 0, 0, 0, 0, 0))
            for sym_name, va in exports.items():
                name_off = sym_name_offsets[sym_name]
                dynsym_buf.extend(struct.pack("<IBBHQQ", name_off, 0x12, 0, 1, va, 16))
        else:
            dynsym_buf.extend(struct.pack("<IIIBBH", 0, 0, 0, 0, 0, 0))
            for sym_name, va in exports.items():
                name_off = sym_name_offsets[sym_name]
                dynsym_buf.extend(struct.pack("<IIIBBH", name_off, va, 16, 0x12, 0, 1))

        dynsym_bytes = bytes(dynsym_buf)
        dynsym_size = len(dynsym_bytes)
        dynsym_vaddr = image_base + 0x4000

        # .shstrtab section
        shstrtab = b"\x00.text\x00.rodata\x00.dynsym\x00.dynstr\x00.shstrtab\x00"
        shstrtab_size = len(shstrtab)

        hdr_size = 64 if is_64bit else 52
        cur_off = hdr_size

        text_offset = cur_off
        cur_off += text_size

        rodata_offset = cur_off
        cur_off += rodata_size

        dynsym_offset = cur_off
        cur_off += dynsym_size

        dynstr_offset = cur_off
        cur_off += dynstr_size

        shstrtab_offset = cur_off
        cur_off += shstrtab_size

        shdr_offset = (cur_off + 7) & ~7

        shdrs = []
        if is_64bit:
            shdrs.append(struct.pack("<IIQQQQIIQQ", 0, 0, 0, 0, 0, 0, 0, 0, 0, 0))
            shdrs.append(struct.pack("<IIQQQQIIQQ", 1, 1, 6, text_vaddr, text_offset, text_size, 0, 0, 16, 0))
            shdrs.append(struct.pack("<IIQQQQIIQQ", 7, 1, 2, rodata_vaddr, rodata_offset, rodata_size, 0, 0, 8, 0))
            shdrs.append(struct.pack("<IIQQQQIIQQ", 15, 11, 2, dynsym_vaddr, dynsym_offset, dynsym_size, 4, 1, 8, 24))
            shdrs.append(struct.pack("<IIQQQQIIQQ", 23, 3, 2, dynstr_vaddr, dynstr_offset, dynstr_size, 0, 0, 1, 0))
            shdrs.append(struct.pack("<IIQQQQIIQQ", 31, 3, 0, 0, shstrtab_offset, shstrtab_size, 0, 0, 1, 0))
            shnum = len(shdrs)
            shdr_bytes = b"".join(shdrs)

            e_ident = b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 8
            ehdr = struct.pack(
                "<16sHHIQQQIHHHHHH",
                e_ident, 2, 183, 1, text_vaddr, 0, shdr_offset, 0, 64, 0, 0, 64, shnum, 5
            )
        else:
            shdrs.append(struct.pack("<IIIIIIIIII", 0, 0, 0, 0, 0, 0, 0, 0, 0, 0))
            shdrs.append(struct.pack("<IIIIIIIIII", 1, 1, 6, text_vaddr, text_offset, text_size, 0, 0, 16, 0))
            shdrs.append(struct.pack("<IIIIIIIIII", 7, 1, 2, rodata_vaddr, rodata_offset, rodata_size, 0, 0, 8, 0))
            shdrs.append(struct.pack("<IIIIIIIIII", 15, 11, 2, dynsym_vaddr, dynsym_offset, dynsym_size, 4, 1, 4, 16))
            shdrs.append(struct.pack("<IIIIIIIIII", 23, 3, 2, dynstr_vaddr, dynstr_offset, dynstr_size, 0, 0, 1, 0))
            shdrs.append(struct.pack("<IIIIIIIIII", 31, 3, 0, 0, shstrtab_offset, shstrtab_size, 0, 0, 1, 0))
            shnum = len(shdrs)
            shdr_bytes = b"".join(shdrs)

            e_ident = b"\x7fELF\x01\x01\x01\x00" + b"\x00" * 8
            ehdr = struct.pack(
                "<16sHHIIIIIHHHHHH",
                e_ident, 2, 40, 1, text_vaddr, 0, shdr_offset, 0, 52, 0, 0, 40, shnum, 5
            )

        pad = b"\x00" * (shdr_offset - cur_off)
        return ehdr + text_bytes + rodata_bytes + dynsym_bytes + dynstr_bytes + shstrtab + pad + shdr_bytes

    def resolve_cross_references(self) -> List[JNICrossReferenceMatch]:
        """
        Correlates Java DEX native methods against ELF static exports and RegisterNatives tables.
        """
        self.matches.clear()

        dyn_map: Dict[Tuple[str, str], JNIRegisteredNative] = {}
        for reg in self.registered_natives:
            dyn_map[(reg.method_name, reg.signature)] = reg

        for jm in self.native_methods:
            # 1. Check dynamic RegisterNatives table
            key = (jm.method_name, jm.signature)
            if key in dyn_map:
                reg_entry = dyn_map[key]
                match = JNICrossReferenceMatch(
                    java_method=jm,
                    binding_type="REGISTER_NATIVES",
                    symbol_name=f"{jm.class_name}.{jm.method_name}",
                    target_address=reg_entry.fn_ptr,
                    target_rva=reg_entry.fn_ptr - self.image_base,
                    confidence=1.0
                )
                self.matches.append(match)
                continue

            # 2. Check Static Short JNI Export
            short_sym = jm.static_symbol_short
            if short_sym in self.elf_exports:
                va = self.elf_exports[short_sym]
                match = JNICrossReferenceMatch(
                    java_method=jm,
                    binding_type="STATIC_EXPORT",
                    symbol_name=short_sym,
                    target_address=va,
                    target_rva=va - self.image_base,
                    confidence=0.98 if not jm.is_overloaded else 0.85
                )
                self.matches.append(match)
                continue

            # 3. Check Static Long (Overloaded) JNI Export
            long_sym = jm.static_symbol_long
            if long_sym in self.elf_exports:
                va = self.elf_exports[long_sym]
                match = JNICrossReferenceMatch(
                    java_method=jm,
                    binding_type="STATIC_EXPORT",
                    symbol_name=long_sym,
                    target_address=va,
                    target_rva=va - self.image_base,
                    confidence=1.0
                )
                self.matches.append(match)
                continue

        return self.matches

    def export_ghidra_python_script(self) -> str:
        """
        Generates a Ghidra Python postScript that labels all resolved JNI functions
        and adds parameter/signature comments in the CodeBrowser.
        """
        lines = [
            "# Auto-generated SuperGhidra JNI Cross-Reference Script",
            "# Applies symbols and comments to JNI function endpoints.",
            "from ghidra.program.model.symbol import SourceType",
            "",
            "prog = currentProgram",
            "tx = prog.startTransaction('Apply JNI Symbols')",
            "try:",
        ]

        for m in self.matches:
            target_va_hex = hex(m.target_address)
            clean_name = f"JNI_{m.java_method.class_name.split('.')[-1]}_{m.java_method.method_name}"
            comment = f"JNI [{m.binding_type}] {m.java_method.class_name}.{m.java_method.method_name}{m.java_method.signature} (RVA: {hex(m.target_rva)})"
            lines.append(f"    addr = toAddr({target_va_hex})")
            lines.append("    if addr is not None:")
            lines.append(f"        createLabel(addr, '{clean_name}', True, SourceType.USER_DEFINED)")
            lines.append(f"        setPlateComment(addr, '{comment}')")

        lines.extend([
            "finally:",
            "    prog.endTransaction(tx, True)",
            "print('Successfully applied JNI cross-reference symbols.')",
        ])
        return "\n".join(lines)

    def to_json(self) -> str:
        """Exports all resolved cross references to structured JSON."""
        return json.dumps([m.to_dict() for m in self.matches], indent=2)
