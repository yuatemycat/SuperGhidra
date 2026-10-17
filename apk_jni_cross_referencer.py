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
- Exports unified JNI cross-reference manifests (JSON) and Ghidra Python/Java import scripts.
"""

from __future__ import annotations

import dataclasses
import json
import logging
import re
import struct
from typing import Any, Dict, List, Optional, Set, Tuple

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
    signature: Optional[str] = None,
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
    class_name: str         # e.g. "com.supercell.titan.NativeDialog"
    method_name: str        # e.g. "onDialogDismissed"
    signature: str          # e.g. "(ILjava/lang/String;)V"
    is_static: bool = True
    is_overloaded: bool = False
    source_file: Optional[str] = None
    line_number: Optional[int] = None

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
    class_context: Optional[str] = None

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
        class_context: Optional[str] = None
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
                    # Valid candidate
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

    def resolve_cross_references(self) -> List[JNICrossReferenceMatch]:
        """
        Correlates Java DEX native methods against ELF static exports and RegisterNatives tables.
        """
        self.matches.clear()

        # Build dynamic lookup map from registered natives: (method_name, signature) -> entry
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
            lines.append(f"    if addr is not None:")
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
