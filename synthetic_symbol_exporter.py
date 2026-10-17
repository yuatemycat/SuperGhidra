"""
synthetic_symbol_exporter.py
============================
SuperGhidra Standalone Synthetic DWARF 5, PDB, .sym, and .map Symbol Exporter.

Frontier 1 of SuperGhidra Reformation:
- Reads ReconstructionObligationLedger (evidence_ledger.py), function symbols
  (_ghidra_names.json or Python dicts), and struct definitions.
- Generates fully compliant symbol containers loadable by external reverse engineering
  tools (IDA Pro, LLDB, Ghidra, x64dbg, Cheat Engine):
    1. DWARF 5 ELF64 Container (.debug_info, .debug_abbrev, .debug_str, .debug_line, .symtab)
    2. Microsoft Multi-Stream File (MSF 7.0 / PDB) Container with S_PUB32 CodeView records
    3. Multi-tool .sym Container (Google Breakpad + x64dbg / Cheat Engine compatible)
    4. Linker .map File (Publics by Name & Value, Section mappings, Struct layout comments)
- High-throughput batch export API: export_from_ledger(...) and standalone CLI.
"""

from __future__ import annotations

import argparse
import dataclasses
import datetime
import enum
import io
import json
import os
import struct
import sys
import uuid
from typing import Any, Dict, List, Optional, Set, Tuple, Union

# Attempt to import from local workspace
try:
    from evidence_ledger import (
        ObligationStatus,
        ObligationType,
        ProofObligation,
        ReconstructionObligationLedger,
    )
except ImportError:
    # If run standalone outside package root
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    from evidence_ledger import (  # type: ignore
        ObligationStatus,
        ObligationType,
        ProofObligation,
        ReconstructionObligationLedger,
    )


# ==============================================================================
# Intermediate Representation Models
# ==============================================================================

@dataclasses.dataclass
class ExportSymbol:
    """Represents a symbol to export (function, global variable, or label)."""
    name: str
    address: int
    size: int = 0
    section: str = ".text"
    symbol_type: str = "FUNC"  # "FUNC", "OBJECT", "LABEL"
    demangled_name: Optional[str] = None
    source_file: Optional[str] = "reconstructed.cpp"
    source_line: Optional[int] = 1

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "address": hex(self.address),
            "size": self.size,
            "section": self.section,
            "symbol_type": self.symbol_type,
            "demangled_name": self.demangled_name,
            "source_file": self.source_file,
            "source_line": self.source_line,
        }


@dataclasses.dataclass
class ExportField:
    """Represents a member field in a reconstructed structure."""
    name: str
    offset: int
    size: int
    type_name: str = "uint32_t"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "offset": hex(self.offset),
            "size": self.size,
            "type_name": self.type_name,
        }


@dataclasses.dataclass
class ExportStruct:
    """Represents a reconstructed structure definition."""
    name: str
    size: int
    fields: List[ExportField] = dataclasses.field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "size": self.size,
            "fields": [f.to_dict() for f in self.fields],
        }


# ==============================================================================
# Helper LEB128 Encoders
# ==============================================================================

def encode_uleb128(val: int) -> bytes:
    """Encodes an unsigned integer into ULEB128 bytes."""
    res = bytearray()
    while True:
        byte = val & 0x7F
        val >>= 7
        if val != 0:
            byte |= 0x80
        res.append(byte)
        if val == 0:
            break
    return bytes(res)


def encode_sleb128(val: int) -> bytes:
    """Encodes a signed integer into SLEB128 bytes."""
    res = bytearray()
    more = True
    while more:
        byte = val & 0x7F
        val >>= 7
        sign_bit_set = (byte & 0x40) != 0
        if (val == 0 and not sign_bit_set) or (val == -1 and sign_bit_set):
            more = False
        else:
            byte |= 0x80
        res.append(byte)
    return bytes(res)


# ==============================================================================
# 1. DWARF 5 ELF64 Container Exporter
# ==============================================================================

class DWARF5Exporter:
    """
    Constructs a valid ELF64 relocatable/executable container with DWARF 5 debug sections:
      - .debug_str: string table for DWARF names
      - .debug_abbrev: DWARF 5 abbreviation declarations
      - .debug_info: DWARF 5 compilation unit with DW_TAG_subprogram and DW_TAG_structure_type
      - .debug_line: DWARF 5 line number program
      - .symtab / .strtab: standard ELF symbol tables
    Loadable by IDA Pro, LLDB, Ghidra, and readelf.
    """

    DW_TAG_compile_unit = 0x11
    DW_TAG_structure_type = 0x13
    DW_TAG_member = 0x0D
    DW_TAG_subprogram = 0x2E
    DW_TAG_base_type = 0x24

    DW_CHILDREN_no = 0x00
    DW_CHILDREN_yes = 0x01

    DW_AT_name = 0x03
    DW_AT_byte_size = 0x0B
    DW_AT_stmt_list = 0x10
    DW_AT_low_pc = 0x11
    DW_AT_high_pc = 0x12
    DW_AT_language = 0x13
    DW_AT_producer = 0x25
    DW_AT_data_member_location = 0x38
    DW_AT_type = 0x49

    DW_FORM_addr = 0x01
    DW_FORM_data2 = 0x05
    DW_FORM_data4 = 0x06
    DW_FORM_data8 = 0x07
    DW_FORM_string = 0x08
    DW_FORM_strp = 0x0E
    DW_FORM_udata = 0x0F
    DW_FORM_sec_offset = 0x17

    DW_UT_compile = 0x01
    DW_LANG_C_plus_plus = 0x0004

    def __init__(self, symbols: List[ExportSymbol], structs: List[ExportStruct], base_address: int = 0x100000000):
        self.symbols = sorted(symbols, key=lambda s: s.address)
        self.structs = structs
        self.base_address = base_address

    def build_elf(self) -> bytes:
        """Constructs and returns the full binary ELF64 container with DWARF 5 sections."""
        # 1. Build .debug_str (string pool)
        debug_str = bytearray(b"\x00")  # Offset 0 is empty string
        str_cache: Dict[str, int] = {"": 0}

        def add_debug_str(s: str) -> int:
            if s not in str_cache:
                offset = len(debug_str)
                debug_str.extend(s.encode("utf-8") + b"\x00")
                str_cache[s] = offset
            return str_cache[s]

        producer_offset = add_debug_str("SuperGhidra Synthetic DWARF 5 Exporter v1.0")
        cu_name_offset = add_debug_str("reconstructed_cu.cpp")

        # 2. Build .debug_abbrev (DWARF 5 abbreviation table)
        abbrev = bytearray()
        # Abbrev 1: DW_TAG_compile_unit
        abbrev.extend(encode_uleb128(1))
        abbrev.extend(encode_uleb128(self.DW_TAG_compile_unit))
        abbrev.append(self.DW_CHILDREN_yes)
        abbrev.extend(encode_uleb128(self.DW_AT_producer) + encode_uleb128(self.DW_FORM_strp))
        abbrev.extend(encode_uleb128(self.DW_AT_language) + encode_uleb128(self.DW_FORM_data2))
        abbrev.extend(encode_uleb128(self.DW_AT_name) + encode_uleb128(self.DW_FORM_strp))
        abbrev.extend(encode_uleb128(self.DW_AT_low_pc) + encode_uleb128(self.DW_FORM_addr))
        abbrev.extend(encode_uleb128(self.DW_AT_high_pc) + encode_uleb128(self.DW_FORM_data8))
        abbrev.extend(encode_uleb128(self.DW_AT_stmt_list) + encode_uleb128(self.DW_FORM_sec_offset))
        abbrev.extend(b"\x00\x00")  # Terminator

        # Abbrev 2: DW_TAG_subprogram
        abbrev.extend(encode_uleb128(2))
        abbrev.extend(encode_uleb128(self.DW_TAG_subprogram))
        abbrev.append(self.DW_CHILDREN_no)
        abbrev.extend(encode_uleb128(self.DW_AT_name) + encode_uleb128(self.DW_FORM_strp))
        abbrev.extend(encode_uleb128(self.DW_AT_low_pc) + encode_uleb128(self.DW_FORM_addr))
        abbrev.extend(encode_uleb128(self.DW_AT_high_pc) + encode_uleb128(self.DW_FORM_data8))
        abbrev.extend(b"\x00\x00")

        # Abbrev 3: DW_TAG_structure_type
        abbrev.extend(encode_uleb128(3))
        abbrev.extend(encode_uleb128(self.DW_TAG_structure_type))
        abbrev.append(self.DW_CHILDREN_yes)
        abbrev.extend(encode_uleb128(self.DW_AT_name) + encode_uleb128(self.DW_FORM_strp))
        abbrev.extend(encode_uleb128(self.DW_AT_byte_size) + encode_uleb128(self.DW_FORM_udata))
        abbrev.extend(b"\x00\x00")

        # Abbrev 4: DW_TAG_member
        abbrev.extend(encode_uleb128(4))
        abbrev.extend(encode_uleb128(self.DW_TAG_member))
        abbrev.append(self.DW_CHILDREN_no)
        abbrev.extend(encode_uleb128(self.DW_AT_name) + encode_uleb128(self.DW_FORM_strp))
        abbrev.extend(encode_uleb128(self.DW_AT_data_member_location) + encode_uleb128(self.DW_FORM_udata))
        abbrev.extend(encode_uleb128(self.DW_AT_byte_size) + encode_uleb128(self.DW_FORM_udata))
        abbrev.extend(b"\x00\x00")

        # End of abbreviation table
        abbrev.append(0x00)

        # 3. Build .debug_info
        # Minimum address and maximum span
        if self.symbols:
            low_pc = self.symbols[0].address
            high_pc_delta = max((s.address + max(s.size, 4)) - low_pc for s in self.symbols)
        else:
            low_pc = self.base_address
            high_pc_delta = 0x10000

        cu_body = bytearray()
        # Root DIE: DW_TAG_compile_unit (abbrev 1)
        cu_body.extend(encode_uleb128(1))
        cu_body.extend(struct.pack("<I", producer_offset))
        cu_body.extend(struct.pack("<H", self.DW_LANG_C_plus_plus))
        cu_body.extend(struct.pack("<I", cu_name_offset))
        cu_body.extend(struct.pack("<Q", low_pc))
        cu_body.extend(struct.pack("<Q", high_pc_delta))
        cu_body.extend(struct.pack("<I", 0))  # stmt_list = 0 (.debug_line offset)

        # Children: Functions
        for sym in self.symbols:
            name_offset = add_debug_str(sym.name)
            func_size = max(sym.size, 4)
            cu_body.extend(encode_uleb128(2))  # abbrev 2
            cu_body.extend(struct.pack("<I", name_offset))
            cu_body.extend(struct.pack("<Q", sym.address))
            cu_body.extend(struct.pack("<Q", func_size))

        # Children: Structs
        for st in self.structs:
            st_name_offset = add_debug_str(st.name)
            cu_body.extend(encode_uleb128(3))  # abbrev 3: struct
            cu_body.extend(struct.pack("<I", st_name_offset))
            cu_body.extend(encode_uleb128(st.size))
            for f in st.fields:
                f_name_offset = add_debug_str(f.name)
                cu_body.extend(encode_uleb128(4))  # abbrev 4: member
                cu_body.extend(struct.pack("<I", f_name_offset))
                cu_body.extend(encode_uleb128(f.offset))
                cu_body.extend(encode_uleb128(f.size))
            cu_body.append(0x00)  # End of struct members

        # End of compile unit children
        cu_body.append(0x00)

        # Prepend DWARF 5 CU Header
        # unit_length (4 bytes) + version (2 bytes, =5) + unit_type (1 byte, =1) +
        # address_size (1 byte, =8) + debug_abbrev_offset (4 bytes, =0)
        cu_header_fields = struct.pack("<HBBI", 5, self.DW_UT_compile, 8, 0)
        total_cu_len = len(cu_header_fields) + len(cu_body)
        debug_info = struct.pack("<I", total_cu_len) + cu_header_fields + bytes(cu_body)

        # 4. Build .debug_line (DWARF 5 line table)
        debug_line = self._build_debug_line(low_pc)

        # 5. Build .symtab and .strtab (Standard ELF symbol table)
        symtab, strtab = self._build_symtab()

        # 6. Build dummy .text section
        text_size = max(high_pc_delta, 0x100)
        text_data = b"\x90" * min(text_size, 0x4000)  # NOPs or small slice

        # 7. Assemble ELF64 binary container
        return self._assemble_elf64(
            text_data=text_data,
            symtab_data=symtab,
            strtab_data=strtab,
            debug_str=bytes(debug_str),
            debug_abbrev=bytes(abbrev),
            debug_info=debug_info,
            debug_line=debug_line,
            low_pc=low_pc,
        )

    def _build_debug_line(self, low_pc: int) -> bytes:
        """Constructs a compliant DWARF 5 line number section."""
        # DWARF 5 line table header:
        # unit_length: 4B
        # version: 2B (5)
        # address_size: 1B (8)
        # segment_selector_size: 1B (0)
        # header_length: 4B
        # min_inst_length: 1B (1)
        # max_ops_per_inst: 1B (1)
        # default_is_stmt: 1B (1)
        # line_base: 1B (-5)
        # line_range: 1B (14)
        # opcode_base: 1B (13)
        # standard_opcode_lengths: 12 bytes
        std_opcodes = bytes([0, 1, 1, 1, 1, 0, 0, 0, 1, 0, 0, 1])

        # Directories table: format count, format (DW_LNCT_path=1, DW_FORM_string=8), dir count, dir
        dir_table = bytearray()
        dir_table.append(1)  # 1 format
        dir_table.extend(encode_uleb128(1) + encode_uleb128(self.DW_FORM_string))  # path, string
        dir_table.extend(encode_uleb128(1))  # 1 directory
        dir_table.extend(b".\x00")

        # Files table: format count (path, dir_idx), file count, entries
        file_table = bytearray()
        file_table.append(2)  # 2 formats
        file_table.extend(encode_uleb128(1) + encode_uleb128(self.DW_FORM_string))  # path, string
        file_table.extend(encode_uleb128(2) + encode_uleb128(self.DW_FORM_udata))   # directory_index, udata
        file_table.extend(encode_uleb128(1))  # 1 file
        file_table.extend(b"reconstructed.cpp\x00" + encode_uleb128(0))

        header_content = (
            struct.pack("<BBBBBB", 1, 1, 1, 251, 14, 13)  # min_inst, max_ops, is_stmt, line_base(-5), range, opcode_base
            + std_opcodes
            + dir_table
            + file_table
        )
        header_len = len(header_content)

        # Line number program opcodes
        program = bytearray()
        # Extended opcode: DW_LNE_set_address
        program.extend(b"\x00" + encode_uleb128(9) + b"\x02" + struct.pack("<Q", low_pc))
        # DW_LNS_advance_line (+1)
        program.extend(b"\x03" + encode_sleb128(1))
        # DW_LNS_copy
        program.append(0x01)
        # DW_LNE_end_sequence
        program.extend(b"\x00" + encode_uleb128(1) + b"\x01")

        total_body = (
            struct.pack("<HBB", 5, 8, 0)
            + struct.pack("<I", header_len)
            + header_content
            + bytes(program)
        )
        return struct.pack("<I", len(total_body)) + total_body

    def _build_symtab(self) -> Tuple[bytes, bytes]:
        """Builds standard ELF64 .symtab and .strtab entries."""
        strtab = bytearray(b"\x00")
        str_map: Dict[str, int] = {"": 0}

        def get_str(name: str) -> int:
            if name not in str_map:
                offset = len(strtab)
                strtab.extend(name.encode("utf-8") + b"\x00")
                str_map[name] = offset
            return str_map[name]

        # Null symbol (index 0)
        symtab = bytearray(b"\x00" * 24)

        # Add symbols
        for sym in self.symbols:
            name_idx = get_str(sym.name)
            st_info = (1 << 4) | (2 if sym.symbol_type == "FUNC" else 1)  # STB_GLOBAL | STT_FUNC/OBJECT
            st_other = 0
            st_shndx = 1  # .text section
            st_value = sym.address
            st_size = max(sym.size, 4)
            symtab.extend(struct.pack("<IBBHQQ", name_idx, st_info, st_other, st_shndx, st_value, st_size))

        return bytes(symtab), bytes(strtab)

    def _assemble_elf64(
        self,
        text_data: bytes,
        symtab_data: bytes,
        strtab_data: bytes,
        debug_str: bytes,
        debug_abbrev: bytes,
        debug_info: bytes,
        debug_line: bytes,
        low_pc: int,
    ) -> bytes:
        """Assembles section contents into a fully compliant 64-bit ELF file."""
        # Section names string table (.shstrtab)
        shstrtab = bytearray(b"\x00")
        shstr_map: Dict[str, int] = {}

        def get_shstr(name: str) -> int:
            if name not in shstr_map:
                idx = len(shstrtab)
                shstrtab.extend(name.encode("utf-8") + b"\x00")
                shstr_map[name] = idx
            return shstr_map[name]

        # Register section names
        for sec in [".text", ".symtab", ".strtab", ".shstrtab", ".debug_str", ".debug_abbrev", ".debug_info", ".debug_line"]:
            get_shstr(sec)

        # Section definitions: (name, type, flags, addr, offset, size, link, info, addralign, entsize)
        # SHT_NULL=0, SHT_PROGBITS=1, SHT_SYMTAB=2, SHT_STRTAB=3
        # SHF_WRITE=1, SHF_ALLOC=2, SHF_EXECINSTR=4
        sections_payload = [
            (b"", 0, 0, 0, 0, 0, 0),                              # 0: null
            (text_data, 1, 6, low_pc, 0, 0, 16),                 # 1: .text (SHF_ALLOC | SHF_EXEC)
            (symtab_data, 2, 2, 0, 3, len(self.symbols) + 1, 8), # 2: .symtab (link to .strtab, entsize 24)
            (strtab_data, 3, 2, 0, 0, 0, 1),                     # 3: .strtab
            (debug_str, 1, 0, 0, 0, 0, 1),                       # 4: .debug_str
            (debug_abbrev, 1, 0, 0, 0, 0, 1),                    # 5: .debug_abbrev
            (debug_info, 1, 0, 0, 0, 0, 1),                      # 6: .debug_info
            (debug_line, 1, 0, 0, 0, 0, 1),                      # 7: .debug_line
        ]

        # ELF Header (64 bytes) + 1 Program Header (56 bytes) = 120 bytes
        # Align sections to 16 bytes
        header_size = 64 + 56
        current_offset = (header_size + 15) & ~15

        section_offsets: List[int] = []
        for payload, _, _, _, _, _, align in sections_payload:
            if len(payload) == 0 and len(section_offsets) == 0:
                section_offsets.append(0)
                continue
            align_mask = max(align - 1, 0)
            current_offset = (current_offset + align_mask) & ~align_mask
            section_offsets.append(current_offset)
            current_offset += len(payload)

        # Finally, append .shstrtab
        shstr_align = 1
        current_offset = (current_offset + 0) & ~0
        shstrtab_offset = current_offset
        shstrtab_bytes = bytes(shstrtab)
        current_offset += len(shstrtab_bytes)

        # Section header table offset (aligned to 8 bytes)
        sh_offset = (current_offset + 7) & ~7
        num_sections = len(sections_payload) + 1  # including .shstrtab
        shstrtab_section_idx = num_sections - 1

        # Construct ELF Header
        elf_header = bytearray(64)
        elf_header[0:4] = b"\x7fELF"
        elf_header[4] = 2   # ELFCLASS64
        elf_header[5] = 1   # ELFDATA2LSB
        elf_header[6] = 1   # EV_CURRENT
        elf_header[7] = 0   # ELFOSABI_NONE
        struct.pack_into("<H", elf_header, 16, 2)            # e_type = ET_EXEC
        struct.pack_into("<H", elf_header, 18, 0x3E)         # e_machine = EM_X86_64
        struct.pack_into("<I", elf_header, 20, 1)            # e_version = 1
        struct.pack_into("<Q", elf_header, 24, low_pc)       # e_entry
        struct.pack_into("<Q", elf_header, 32, 64)           # e_phoff = 64
        struct.pack_into("<Q", elf_header, 40, sh_offset)    # e_shoff
        struct.pack_into("<I", elf_header, 48, 0)            # e_flags
        struct.pack_into("<H", elf_header, 52, 64)           # e_ehsize = 64
        struct.pack_into("<H", elf_header, 54, 56)           # e_phentsize = 56
        struct.pack_into("<H", elf_header, 56, 1)            # e_phnum = 1
        struct.pack_into("<H", elf_header, 58, 64)           # e_shentsize = 64
        struct.pack_into("<H", elf_header, 60, num_sections) # e_shnum
        struct.pack_into("<H", elf_header, 62, shstrtab_section_idx) # e_shstrndx

        # Program Header (PT_LOAD for .text)
        ph = bytearray(56)
        struct.pack_into("<I", ph, 0, 1)                     # p_type = PT_LOAD
        struct.pack_into("<I", ph, 4, 5)                     # p_flags = PF_R | PF_X
        struct.pack_into("<Q", ph, 8, section_offsets[1])    # p_offset = .text offset
        struct.pack_into("<Q", ph, 16, low_pc)               # p_vaddr
        struct.pack_into("<Q", ph, 24, low_pc)               # p_paddr
        struct.pack_into("<Q", ph, 32, len(text_data))       # p_filesz
        struct.pack_into("<Q", ph, 40, len(text_data))       # p_memsz
        struct.pack_into("<Q", ph, 48, 0x1000)               # p_align

        # Assemble full binary buffer
        buf = bytearray(elf_header + ph)

        # Pad to first section
        sec_names = ["", ".text", ".symtab", ".strtab", ".debug_str", ".debug_abbrev", ".debug_info", ".debug_line"]
        for idx, (payload, _, _, _, _, _, _) in enumerate(sections_payload):
            if idx == 0:
                continue
            off = section_offsets[idx]
            if len(buf) < off:
                buf.extend(b"\x00" * (off - len(buf)))
            buf.extend(payload)

        # Pad to .shstrtab
        if len(buf) < shstrtab_offset:
            buf.extend(b"\x00" * (shstrtab_offset - len(buf)))
        buf.extend(shstrtab_bytes)

        # Pad to section header table
        if len(buf) < sh_offset:
            buf.extend(b"\x00" * (sh_offset - len(buf)))

        # Write Section Headers (Elf64_Shdr is 64 bytes)
        # Elf64_Shdr: sh_name (4), sh_type (4), sh_flags (8), sh_addr (8), sh_offset (8),
        #             sh_size (8), sh_link (4), sh_info (4), sh_addralign (8), sh_entsize (8)
        for idx in range(num_sections):
            sh = bytearray(64)
            if idx == 0:
                pass  # NULL section
            elif idx < len(sections_payload):
                payload, s_type, s_flags, s_addr, s_link, s_info, s_align = sections_payload[idx]
                name_idx = get_shstr(sec_names[idx])
                entsize = 24 if idx == 2 else 0
                struct.pack_into("<I", sh, 0, name_idx)
                struct.pack_into("<I", sh, 4, s_type)
                struct.pack_into("<Q", sh, 8, s_flags)
                struct.pack_into("<Q", sh, 16, s_addr)
                struct.pack_into("<Q", sh, 24, section_offsets[idx])
                struct.pack_into("<Q", sh, 32, len(payload))
                struct.pack_into("<I", sh, 40, s_link)
                struct.pack_into("<I", sh, 44, s_info)
                struct.pack_into("<Q", sh, 48, s_align)
                struct.pack_into("<Q", sh, 56, entsize)
            else:
                # .shstrtab section header
                name_idx = get_shstr(".shstrtab")
                struct.pack_into("<I", sh, 0, name_idx)
                struct.pack_into("<I", sh, 4, 3)  # SHT_STRTAB
                struct.pack_into("<Q", sh, 8, 0)
                struct.pack_into("<Q", sh, 16, 0)
                struct.pack_into("<Q", sh, 24, shstrtab_offset)
                struct.pack_into("<Q", sh, 32, len(shstrtab_bytes))
                struct.pack_into("<I", sh, 40, 0)
                struct.pack_into("<I", sh, 44, 0)
                struct.pack_into("<Q", sh, 48, 1)
                struct.pack_into("<Q", sh, 56, 0)
            buf.extend(sh)

        return bytes(buf)


# ==============================================================================
# 2. Microsoft CodeView / PDB (MSF 7.0) Container Exporter
# ==============================================================================

class PDBExporter:
    """
    Synthesizes a valid Microsoft Compound File (MSF 7.0 / PDB) with Public Symbol Stream (S_PUB32).
    Supported directly by x64dbg, LLDB, and symbol visualizers.
    """

    MSF_MAGIC = b"Microsoft C/C++ MSF 7.00\r\n\x1a\x44\x53\x00\x00\x00"
    BLOCK_SIZE = 4096

    def __init__(self, symbols: List[ExportSymbol], structs: List[ExportStruct], base_address: int = 0x140000000):
        self.symbols = sorted(symbols, key=lambda s: s.address)
        self.structs = structs
        self.base_address = base_address

    def build_pdb(self) -> bytes:
        """Constructs an MSF 7.0 multi-stream container containing PDB, DBI, and Public streams."""
        # 1. Stream 1: PDB Info Stream
        pdb_stream = self._build_pdb_stream()

        # 2. Stream 2: TPI Stream (minimal valid header)
        tpi_stream = self._build_tpi_stream()

        # 3. Stream 5: Public Symbol Stream (S_PUB32 records)
        public_stream = self._build_public_stream()

        # 4. Stream 3: DBI Stream (Debug Info Stream)
        dbi_stream = self._build_dbi_stream(public_stream_len=len(public_stream))

        # Stream directory streams list:
        # Stream 0: Root directory (reserved)
        # Stream 1: PDB Stream
        # Stream 2: TPI Stream
        # Stream 3: DBI Stream
        # Stream 4: IPI Stream (empty or minimal)
        # Stream 5: Public Symbol Stream
        ipi_stream = tpi_stream
        streams: List[bytes] = [
            b"",            # Stream 0
            pdb_stream,     # Stream 1
            tpi_stream,     # Stream 2
            dbi_stream,     # Stream 3
            ipi_stream,     # Stream 4
            public_stream,  # Stream 5
        ]

        return self._pack_msf(streams)

    def _build_pdb_stream(self) -> bytes:
        """Builds PDB info stream with GUID, signature, and named streams table."""
        # Version = 20000404 (VC70), Signature = 0x53504442 ('SPDB'), Age = 1, GUID (16 bytes)
        guid_bytes = uuid.uuid4().bytes
        header = struct.pack("<IIII16s", 20000404, 0x53504442, 1, 0, guid_bytes)
        # Named stream table length = 0
        names_table = struct.pack("<I", 0)
        return header + names_table

    def _build_tpi_stream(self) -> bytes:
        """Builds minimal TPI type stream header."""
        # version = 20040203 (V80), header_size = 56, ti_min = 0x1000, ti_max = 0x1000, records_len = 0
        tpi_hdr = bytearray(56)
        struct.pack_into("<IIIII", tpi_hdr, 0, 20040203, 56, 0x1000, 0x1000, 0)
        return bytes(tpi_hdr)

    def _build_dbi_stream(self, public_stream_len: int) -> bytes:
        """Builds DBI stream referencing the Public Symbol stream."""
        # DBI Header (64 bytes):
        # signature: -1 (0xFFFFFFFF)
        # version: 19990903 (V70)
        # age: 1
        # global_stream_index: 0xFFFF
        # toolchain_version: 0x0000
        # public_stream_index: 5 (Stream 5)
        # ... sizes of sub-streams ...
        dbi_hdr = bytearray(64)
        struct.pack_into("<IiIIHH", dbi_hdr, 0, 0xFFFFFFFF, 19990903, 1, 0xFFFF, 0x0000, 5)
        # mod_info_size (offset 20) = 0
        # sec_conpr_size (offset 24) = 0
        # sec_map_size (offset 28) = 0
        # filenam_size (offset 32) = 0
        # ec_info_size (offset 36) = 0
        # dbghdr_size (offset 40) = 0
        return bytes(dbi_hdr)

    def _build_public_stream(self) -> bytes:
        """Builds CodeView S_PUB32 (0x110e) records for all public symbols."""
        records = bytearray()
        for sym in self.symbols:
            # RVA relative to base address
            rva = max(sym.address - self.base_address, 0x1000)
            name_bytes = sym.name.encode("utf-8") + b"\x00"
            rec_type = 0x110E  # S_PUB32
            pub_flags = 2 if sym.symbol_type == "FUNC" else 0  # Function flag
            rec_content = struct.pack("<HIIH", rec_type, pub_flags, rva, 1) + name_bytes
            # Align record content to 4 bytes
            pad_len = (4 - (len(rec_content) % 4)) % 4
            rec_content += b"\x00" * pad_len
            # Prepend record length (length excludes the 2-byte length field itself)
            rec_len = len(rec_content)
            records.extend(struct.pack("<H", rec_len) + rec_content)

        # Public stream header:
        # sym_hash = 0, addr_hash = 0, num_sym_bytes = len(records)
        hdr = struct.pack("<III", 0, 0, len(records))
        return hdr + bytes(records)

    def _pack_msf(self, streams: List[bytes]) -> bytes:
        """Packs multiple streams into a standard MSF 7.0 block-aligned file."""
        bs = self.BLOCK_SIZE
        # Block 0: MSF Header
        # Block 1..: Stream data blocks
        blocks: List[bytes] = []

        # Reserve Block 0 for Header
        blocks.append(b"\x00" * bs)

        # Lay out stream data
        stream_block_lists: List[List[int]] = []
        for s_idx, data in enumerate(streams):
            b_list: List[int] = []
            if len(data) > 0:
                for off in range(0, len(data), bs):
                    chunk = data[off:off + bs]
                    if len(chunk) < bs:
                        chunk += b"\x00" * (bs - len(chunk))
                    b_list.append(len(blocks))
                    blocks.append(chunk)
            stream_block_lists.append(b_list)

        # Lay out Stream Directory
        # Directory contains:
        #   uint32 num_streams
        #   uint32 stream_sizes[num_streams]
        #   for each stream: uint32 stream_blocks[...]
        dir_bytes = bytearray()
        dir_bytes.extend(struct.pack("<I", len(streams)))
        for s in streams:
            dir_bytes.extend(struct.pack("<I", len(s)))
        for b_list in stream_block_lists:
            for b in b_list:
                dir_bytes.extend(struct.pack("<I", b))

        # Write Directory into blocks
        dir_block_nums: List[int] = []
        for off in range(0, len(dir_bytes), bs):
            chunk = dir_bytes[off:off + bs]
            if len(chunk) < bs:
                chunk += b"\x00" * (bs - len(chunk))
            dir_block_nums.append(len(blocks))
            blocks.append(chunk)

        # Write Block Map (holds the block numbers of the directory blocks)
        map_bytes = bytearray()
        for b in dir_block_nums:
            map_bytes.extend(struct.pack("<I", b))
        map_block_addr = len(blocks)
        if len(map_bytes) < bs:
            map_bytes += b"\x00" * (bs - len(map_bytes))
        blocks.append(bytes(map_bytes))

        # Fill Block 0 (MSF Header)
        total_blocks = len(blocks)
        msf_hdr = bytearray(bs)
        msf_hdr[0:32] = self.MSF_MAGIC
        struct.pack_into("<I", msf_hdr, 32, bs)                 # block_size
        struct.pack_into("<I", msf_hdr, 36, 1)                  # free_block_map_block
        struct.pack_into("<I", msf_hdr, 40, total_blocks)       # num_blocks
        struct.pack_into("<I", msf_hdr, 44, len(dir_bytes))     # num_directory_bytes
        struct.pack_into("<I", msf_hdr, 48, 0)                  # reserved
        struct.pack_into("<I", msf_hdr, 52, map_block_addr)     # block_map_addr
        blocks[0] = bytes(msf_hdr)

        return b"".join(blocks)


# ==============================================================================
# 3. .map Symbol File Exporter
# ==============================================================================

class MapFileExporter:
    """
    Exports a standard linker MAP file supported by IDA Pro (File -> Load file -> MAP file),
    x64dbg, Cheat Engine, and Ghidra MapLoader.
    """

    def __init__(self, symbols: List[ExportSymbol], structs: List[ExportStruct], base_address: int = 0x140000000):
        self.symbols = sorted(symbols, key=lambda s: s.address)
        self.structs = structs
        self.base_address = base_address

    def export(self) -> str:
        """Formats symbols and struct layouts into a standard MAP file text."""
        lines: List[str] = []
        lines.append(f" SuperGhidra Reconstructed Map File")
        lines.append(f" Timestamp: {datetime.datetime.now(datetime.timezone.utc).isoformat()}")
        lines.append(f" Preferred load address is {self.base_address:016X}")
        lines.append("")
        lines.append(" Start         Length     Name                   Class")
        lines.append(" 0001:00000000 00100000H .text                   CODE")
        lines.append(" 0002:00000000 00080000H .rdata                  DATA")
        lines.append(" 0003:00000000 00040000H .data                   DATA")
        lines.append("")
        lines.append("  Address         Publics by Value              Rva+Base               Lib:Object")

        for sym in self.symbols:
            rva = max(sym.address - self.base_address, 0)
            sec_idx = 1 if sym.symbol_type == "FUNC" else 2
            flag = "f" if sym.symbol_type == "FUNC" else " "
            obj_name = sym.source_file or "reconstructed.obj"
            lines.append(
                f" {sec_idx:04X}:{rva:08X}   {sym.name:<28}  {sym.address:016X} {flag}     {obj_name}"
            )

        lines.append("")
        lines.append("  Address         Publics by Name               Rva+Base               Lib:Object")
        by_name = sorted(self.symbols, key=lambda s: s.name.lower())
        for sym in by_name:
            rva = max(sym.address - self.base_address, 0)
            sec_idx = 1 if sym.symbol_type == "FUNC" else 2
            flag = "f" if sym.symbol_type == "FUNC" else " "
            obj_name = sym.source_file or "reconstructed.obj"
            lines.append(
                f" {sec_idx:04X}:{rva:08X}   {sym.name:<28}  {sym.address:016X} {flag}     {obj_name}"
            )

        if self.structs:
            lines.append("")
            lines.append(" ; --- Reconstructed Struct Definitions ---")
            for st in self.structs:
                lines.append(f" ; struct {st.name} (sizeof=0x{st.size:X}):")
                for f in st.fields:
                    lines.append(f" ;   +0x{f.offset:04X} {f.name:<24} : {f.type_name} ({f.size}B)")

        return "\n".join(lines) + "\n"


# ==============================================================================
# 4. Multi-Tool .sym File Exporter
# ==============================================================================

class SymFileExporter:
    """
    Exports a hybrid .sym container combining Google Breakpad symbol format
    (for LLDB/Crashpad) and x64dbg / Cheat Engine simple symbol tables.
    """

    def __init__(self, symbols: List[ExportSymbol], module_name: str = "reconstructed.exe"):
        self.symbols = sorted(symbols, key=lambda s: s.address)
        self.module_name = module_name

    def export(self) -> str:
        """Formats symbols into multi-tool .sym string."""
        lines: List[str] = []
        mod_id = uuid.uuid4().hex.upper()
        lines.append(f"MODULE windows x86_64 {mod_id}0 {self.module_name}")
        lines.append("INFO CODE_ID 00000000")
        lines.append("FILE 1 reconstructed.cpp")

        # Breakpad FUNC / PUBLIC records
        for sym in self.symbols:
            sz = max(sym.size, 4)
            if sym.symbol_type == "FUNC":
                lines.append(f"FUNC {sym.address:x} {sz:x} 0 {sym.name}")
                lines.append(f"{sym.address:x} {sz:x} 1 1")
            else:
                lines.append(f"PUBLIC {sym.address:x} 0 {sym.name}")

        # x64dbg / Cheat Engine Symbol Lines
        lines.append("")
        lines.append("# --- x64dbg & Cheat Engine Flat Symbols ---")
        for sym in self.symbols:
            lines.append(f"0x{sym.address:08X} {sym.name}")

        return "\n".join(lines) + "\n"


# ==============================================================================
# Symbol & Ledger Ingestion Engine
# ==============================================================================

class SymbolLedgerIngestor:
    """Ingests symbols and struct models from EvidenceLedger or raw dicts/files."""

    @classmethod
    def from_ledger(
        cls,
        ledger: ReconstructionObligationLedger,
        status_filter: Optional[Set[ObligationStatus]] = None,
    ) -> Tuple[List[ExportSymbol], List[ExportStruct]]:
        """Extracts verified symbols and structs from ReconstructionObligationLedger."""
        if status_filter is None:
            # By default include VERIFIED and COMMITTED obligations
            status_filter = {ObligationStatus.VERIFIED, ObligationStatus.COMMITTED}

        symbols: List[ExportSymbol] = []
        struct_map: Dict[str, ExportStruct] = {}

        for obl in ledger.list_obligations():
            if obl.status not in status_filter:
                continue

            # Functions / Hooks
            if obl.obligation_type in (ObligationType.FUNCTION_HOOK, ObligationType.FUNCTION_RENAME):
                addr = obl.target_address
                if addr is not None:
                    name = obl.proposed_name or obl.target_name
                    size = obl.evidence.get("function_size", 0x20)
                    symbols.append(ExportSymbol(
                        name=name,
                        address=addr,
                        size=size,
                        symbol_type="FUNC",
                    ))

            # Struct definitions and field renames
            if obl.obligation_type in (ObligationType.STRUCT_DEFINITION, ObligationType.STRUCT_RENAME, ObligationType.STRUCT_FIELD_RENAME):
                st_name = obl.proposed_name or obl.target_name
                st_size = obl.evidence.get("struct_size", 0x100)
                if st_name not in struct_map:
                    struct_map[st_name] = ExportStruct(name=st_name, size=st_size)

                fields = obl.evidence.get("field_displacements", [])
                for f in fields:
                    f_name = f.get("name", "field")
                    f_offset = f.get("offset", 0)
                    f_size = f.get("access_size", 4)
                    f_type = f.get("type", "uint32_t")
                    struct_map[st_name].fields.append(
                        ExportField(name=f_name, offset=f_offset, size=f_size, type_name=f_type)
                    )

        return symbols, list(struct_map.values())

    @classmethod
    def from_dict(
        cls,
        raw_symbols: Union[Dict[str, Any], List[Dict[str, Any]]],
    ) -> List[ExportSymbol]:
        """Parses symbols from flexible dictionary formats (e.g. _ghidra_names.json)."""
        symbols: List[ExportSymbol] = []

        if isinstance(raw_symbols, list):
            for item in raw_symbols:
                name = item.get("name")
                addr = item.get("address") or item.get("addr")
                if isinstance(addr, str) and addr.startswith("0x"):
                    addr = int(addr, 16)
                if name and addr is not None:
                    symbols.append(ExportSymbol(
                        name=name,
                        address=int(addr),
                        size=int(item.get("size", 0x20)),
                        symbol_type=item.get("type", "FUNC"),
                    ))
        elif isinstance(raw_symbols, dict):
            for k, v in raw_symbols.items():
                if isinstance(v, (int, float)):
                    # {"sub_10045A820": 0x10045A820}
                    symbols.append(ExportSymbol(name=k, address=int(v)))
                elif isinstance(v, str):
                    # {"0x10045A820": "Player__TakeDamage"} or {"sub_10045A820": "Player__TakeDamage"}
                    addr = int(k, 16) if k.startswith("0x") else 0
                    symbols.append(ExportSymbol(name=v, address=addr))
                elif isinstance(v, dict):
                    addr = v.get("address") or (int(k, 16) if k.startswith("0x") else 0)
                    name = v.get("name", k)
                    symbols.append(ExportSymbol(name=name, address=int(addr), size=int(v.get("size", 0x20))))

        return symbols


# ==============================================================================
# Fast Batch Export API
# ==============================================================================

def export_from_ledger(
    ledger_source: Union[str, ReconstructionObligationLedger],
    output_base: str,
    formats: Optional[List[str]] = None,
    additional_symbols: Optional[Union[Dict[str, Any], List[Dict[str, Any]]]] = None,
    additional_structs: Optional[List[Dict[str, Any]]] = None,
    base_address: int = 0x100400000,
) -> Dict[str, str]:
    """
    High-throughput batch export API.
    Exports symbols into DWARF, PDB, .sym, and .map containers.

    Args:
        ledger_source: Path to evidence_ledger.json or instantiated ReconstructionObligationLedger.
        output_base: Base output path (without extension).
        formats: List of formats to emit: ['dwarf', 'pdb', 'sym', 'map']. Defaults to all 4.
        additional_symbols: Extra symbols to merge.
        additional_structs: Extra structs to merge.
        base_address: Preferred virtual base address.

    Returns:
        Dict mapping format name to absolute path of generated file.
    """
    if formats is None:
        formats = ["dwarf", "pdb", "sym", "map"]

    # 1. Load Ledger
    if isinstance(ledger_source, str):
        ledger = ReconstructionObligationLedger(ledger_source)
    else:
        ledger = ledger_source

    symbols, structs = SymbolLedgerIngestor.from_ledger(ledger)

    # 2. Merge additional symbols & structs
    if additional_symbols:
        extra_syms = SymbolLedgerIngestor.from_dict(additional_symbols)
        symbols.extend(extra_syms)

    if additional_structs:
        for st_dict in additional_structs:
            st = ExportStruct(
                name=st_dict["name"],
                size=st_dict.get("size", 0x100),
                fields=[
                    ExportField(
                        name=f["name"],
                        offset=f["offset"],
                        size=f.get("size", 4),
                        type_name=f.get("type", "uint32_t"),
                    )
                    for f in st_dict.get("fields", [])
                ],
            )
            structs.append(st)

    # Deduplicate symbols by address (preferring non-generic names)
    sym_by_addr: Dict[int, ExportSymbol] = {}
    for s in symbols:
        if s.address not in sym_by_addr or (sym_by_addr[s.address].name.startswith("sub_") and not s.name.startswith("sub_")):
            sym_by_addr[s.address] = s
    symbols = sorted(sym_by_addr.values(), key=lambda s: s.address)

    os.makedirs(os.path.dirname(os.path.abspath(output_base)), exist_ok=True)
    exported_files: Dict[str, str] = {}

    # Format 1: DWARF 5 ELF64 Container (.dwarf / .elf)
    if "dwarf" in formats:
        dwarf_path = f"{output_base}.dwarf"
        dwarf_gen = DWARF5Exporter(symbols=symbols, structs=structs, base_address=base_address)
        elf_bytes = dwarf_gen.build_elf()
        with open(dwarf_path, "wb") as f:
            f.write(elf_bytes)
        exported_files["dwarf"] = os.path.abspath(dwarf_path)

    # Format 2: Microsoft CodeView / PDB Container (.pdb)
    if "pdb" in formats:
        pdb_path = f"{output_base}.pdb"
        pdb_gen = PDBExporter(symbols=symbols, structs=structs, base_address=base_address)
        pdb_bytes = pdb_gen.build_pdb()
        with open(pdb_path, "wb") as f:
            f.write(pdb_bytes)
        exported_files["pdb"] = os.path.abspath(pdb_path)

    # Format 3: Linker .map File (.map)
    if "map" in formats:
        map_path = f"{output_base}.map"
        map_gen = MapFileExporter(symbols=symbols, structs=structs, base_address=base_address)
        map_text = map_gen.export()
        with open(map_path, "w", encoding="utf-8") as f:
            f.write(map_text)
        exported_files["map"] = os.path.abspath(map_path)

    # Format 4: Breakpad / x64dbg / Cheat Engine .sym File (.sym)
    if "sym" in formats:
        sym_path = f"{output_base}.sym"
        sym_gen = SymFileExporter(symbols=symbols, module_name=os.path.basename(output_base) + ".exe")
        sym_text = sym_gen.export()
        with open(sym_path, "w", encoding="utf-8") as f:
            f.write(sym_text)
        exported_files["sym"] = os.path.abspath(sym_path)

    return exported_files


# ==============================================================================
# CLI Entry Point
# ==============================================================================

def main() -> None:
    parser = argparse.ArgumentParser(
        description="SuperGhidra Standalone Synthetic DWARF 5, PDB, .sym, and .map Exporter"
    )
    parser.add_argument("--ledger", required=True, help="Path to evidence_ledger.json")
    parser.add_argument("--output", required=True, help="Output base file path (without extension)")
    parser.add_argument(
        "--formats",
        nargs="+",
        default=["dwarf", "pdb", "sym", "map"],
        choices=["dwarf", "pdb", "sym", "map"],
        help="Target symbol container formats to export",
    )
    parser.add_argument("--names-json", help="Optional extra function names JSON (_ghidra_names.json)")
    parser.add_argument("--base-address", type=lambda x: int(x, 0), default=0x100400000, help="Base address")

    args = parser.parse_args()

    extra_symbols = None
    if args.names_json and os.path.exists(args.names_json):
        with open(args.names_json, "r", encoding="utf-8") as f:
            extra_symbols = json.load(f)

    print(f"Exporting symbols from '{args.ledger}' -> '{args.output}.*' (formats: {args.formats})...")
    res = export_from_ledger(
        ledger_source=args.ledger,
        output_base=args.output,
        formats=args.formats,
        additional_symbols=extra_symbols,
        base_address=args.base_address,
    )
    print("Export completed successfully:")
    for fmt, p in res.items():
        sz = os.path.getsize(p)
        print(f"  [{fmt.upper()}] {p} ({sz:,} bytes)")


if __name__ == "__main__":
    main()
