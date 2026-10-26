#!/usr/bin/env python3
"""Generates redistributable sample binaries for SuperGhidra CI and integration tests.

Outputs:
- tests/fixtures/binaries/sample_arm64.so (ELF64 ARM64 shared library)
- tests/fixtures/binaries/sample_x64.dll  (PE32+ x86_64 dynamic link library)

All binaries are self-contained and generated synthetically without external tool dependencies.
"""

from __future__ import annotations

import os
import struct
from pathlib import Path
from typing import Dict, List, Tuple

BASE_DIR = Path(__file__).resolve().parent
OUT_DIR = BASE_DIR / "binaries"
OUT_DIR.mkdir(parents=True, exist_ok=True)


def generate_pe64_dll(out_path: Path) -> None:
    """Generates a valid PE32+ (x86_64) DLL with .text, .rdata, and export table."""
    image_base = 0x180000000
    e_lfanew = 0x80
    headers_size = 0x400
    machine = 0x8664  # AMD64
    opt_size = 240

    # 1. Code in .text (RVA 0x1000)
    # mov rax, [rcx + 0x18] ; mov [rcx + 0x20], rax ; mov edx, [rcx + 0x08]
    # mov rax, rbx ; mov rcx, rax ; mov rdx, rcx ; ret (dataflow chain + type lattice displacements)
    # 48 8B 41 18 ; 48 89 41 20 ; 8B 51 08 ; 48 89 D8 ; 48 89 C1 ; 48 89 CA ; C3
    code = bytearray()
    # FUN at 0x1000
    code.extend(bytes.fromhex("488B4118 48894120 8B5108 4889D8 4889C1 4889CA C3"))
    # Padding
    code.extend(b"\x90" * 8)
    # FUN at 0x101C: add and xor chain
    code.extend(bytes.fromhex("4801D8 4831C9 C3"))
    # Pad to at least 16 KB so chunk compression tests work
    code.extend(b"\x90" * (16384 - len(code)))

    # 2. .rdata (RVA 0x5000) containing export directory
    # Export directory structure:
    # 0x00: Characteristics (4)
    # 0x04: TimeDateStamp (4)
    # 0x08: Major/MinorVersion (4)
    # 0x0C: Name RVA (4) -> points to "sample_x64.dll"
    # 0x10: OrdinalBase (4) -> 1
    # 0x14: NumberOfFunctions (4) -> 2
    # 0x18: NumberOfNames (4) -> 2
    # 0x1C: AddressOfFunctions RVA (4)
    # 0x20: AddressOfNames RVA (4)
    # 0x24: AddressOfNameOrdinals RVA (4)
    rdata_rva = 0x5000
    rdata = bytearray(0x1000)

    exp_dir_rva = rdata_rva
    dll_name = b"sample_x64.dll\x00"
    dll_name_rva = rdata_rva + 0x40
    rdata[0x40 : 0x40 + len(dll_name)] = dll_name

    func_table_rva = rdata_rva + 0x60
    name_table_rva = rdata_rva + 0x70
    ord_table_rva = rdata_rva + 0x80

    f1_name = b"SampleFunction\x00"
    f2_name = b"DataflowFunction\x00"
    f1_rva = rdata_rva + 0x90
    f2_rva = f1_rva + len(f1_name)
    rdata[0x90 : 0x90 + len(f1_name)] = f1_name
    rdata[0x90 + len(f1_name) : 0x90 + len(f1_name) + len(f2_name)] = f2_name

    # AddressOfFunctions: [0x1000, 0x1010]
    struct.pack_into("<II", rdata, 0x60, 0x1000, 0x1010)
    # AddressOfNames: [f1_rva, f2_rva]
    struct.pack_into("<II", rdata, 0x70, f1_rva, f2_rva)
    # AddressOfNameOrdinals: [0, 1]
    struct.pack_into("<HH", rdata, 0x80, 0, 1)

    # Pack Export Directory Header
    struct.pack_into(
        "<IIIIIIIIII",
        rdata,
        0,
        0, 0, 0,
        dll_name_rva,
        1,  # OrdinalBase
        2,  # NumberOfFunctions
        2,  # NumberOfNames
        func_table_rva,
        name_table_rva,
        ord_table_rva,
    )

    sections = [
        (b".text\x00\x00\x00", 0x1000, bytes(code), 0x60000020),  # Code, Execute, Read
        (b".rdata\x00\x00", rdata_rva, bytes(rdata), 0x40000040),  # Initialized data, Read
    ]

    # Build PE Header
    hdr = bytearray(headers_size)
    hdr[0:2] = b"MZ"
    struct.pack_into("<I", hdr, 0x3C, e_lfanew)
    hdr[e_lfanew : e_lfanew + 4] = b"PE\x00\x00"
    struct.pack_into(
        "<HHIIIHH",
        hdr,
        e_lfanew + 4,
        machine,
        len(sections),
        0, 0, 0,
        opt_size,
        0x2022,  # EXECUTABLE_IMAGE | LARGE_ADDRESS_AWARE | DLL
    )
    opt = e_lfanew + 24
    struct.pack_into("<HQ", hdr, opt, 0x20B, 0)  # PE32+
    struct.pack_into("<Q", hdr, opt + 24, image_base)
    struct.pack_into("<I", hdr, opt + 32, 0x1000)  # SectionAlignment
    struct.pack_into("<I", hdr, opt + 36, 0x200)   # FileAlignment
    struct.pack_into("<I", hdr, opt + 56, 0x7000)  # SizeOfImage
    struct.pack_into("<I", hdr, opt + 60, headers_size)  # SizeOfHeaders
    struct.pack_into("<H", hdr, opt + 68, 0x2160)  # DllCharacteristics
    struct.pack_into("<I", hdr, opt + 108, 16)     # NumberOfRvaAndSizes

    # Export Data Directory (index 0)
    dirs_off = opt + 112
    struct.pack_into("<II", hdr, dirs_off + 8 * 0, exp_dir_rva, 0x100)

    raw = bytearray(hdr)
    for i, (name, rva, blob, ch) in enumerate(sections):
        file_align = (len(blob) + 0x1FF) & ~0x1FF
        padded_blob = blob.ljust(file_align, b"\x00")
        raw_offset = len(raw)
        struct.pack_into(
            "<8sIIIIIIHHI",
            raw,
            opt + opt_size + 40 * i,
            name,
            len(blob),
            rva,
            len(padded_blob),
            raw_offset,
            0, 0, 0, 0,
            ch,
        )
        raw += padded_blob

    out_path.write_bytes(bytes(raw))


def generate_arm64_elf_so(out_path: Path) -> None:
    """Generates a valid ELF64 ARM64 shared object with .text, .rodata, and symbol table."""
    # Build ARM64 instructions:
    # Pair 1: ADRP x0, #0 ; LDR x1, [x0, #16] ; RET
    # Pair 2: ADRP x1, #0 ; LDR x1, [x1, #32] ; RET
    # Pair 3: ADRP x2, #0 ; ADD x2, x2, #32   ; RET
    insns = [
        0x90000000,
        0xF9400801,
        0xD65F03C0,
        0x90000001,
        0xF9401021,
        0xD65F03C0,
        0x90000002,
        0x91008042,
        0xD65F03C0,
        0xD65F03C0,  # extra ret
    ]
    text_data = bytearray()
    for insn in insns:
        text_data.extend(struct.pack("<I", insn))

    # Pad to 16 KB for buffer file tests
    text_data.extend(b"\x00" * (16384 - len(text_data)))

    rodata = b"SuperGhidra ARM64 Test Shared Object\x00"
    rodata = rodata.ljust(0x100, b"\x00")

    shstrtab = bytearray(b"\x00.text\x00.rodata\x00.symtab\x00.strtab\x00.shstrtab\x00")
    strtab = bytearray(b"\x00sample_func\x00sample_adrp_func\x00target_data\x00")

    # Symbols in symtab:
    # 0: NULL
    # 1: sample_func (STB_GLOBAL | STT_FUNC) @ 0x1000
    # 2: sample_adrp_func (STB_GLOBAL | STT_FUNC) @ 0x100C
    # 3: target_data (STB_GLOBAL | STT_OBJECT) @ 0x5000
    symtab = bytearray(24 * 4)
    # Sym 1: sample_func
    struct.pack_into("<IBBHQQ", symtab, 24 * 1, 1, 0x12, 0, 1, 0x1000, 12)
    # Sym 2: sample_adrp_func
    struct.pack_into("<IBBHQQ", symtab, 24 * 2, 13, 0x12, 0, 1, 0x100C, 12)
    # Sym 3: target_data
    struct.pack_into("<IBBHQQ", symtab, 24 * 3, 30, 0x11, 0, 2, 0x5000, len(rodata))

    ehdr_size = 64
    phdr_size = 56
    shdr_size = 64
    num_phdrs = 2
    num_shdrs = 6

    # File layout:
    # 0x0000: EHDR (64)
    # 0x0040: PHDRs (2 * 56 = 112)
    # Align to 0x1000: .text
    # Align to 0x5000: .rodata
    # Align: .symtab, .strtab, .shstrtab, SHDRs
    off_text = 0x1000
    off_rodata = off_text + len(text_data)
    off_symtab = off_rodata + len(rodata)
    off_strtab = off_symtab + len(symtab)
    off_shstrtab = off_strtab + len(strtab)
    off_shdrs = (off_shstrtab + len(shstrtab) + 7) & ~7

    total_file_size = off_shdrs + num_shdrs * shdr_size
    raw = bytearray(total_file_size)

    # 1. ELF Header
    raw[0:4] = b"\x7fELF"
    raw[4] = 2   # ELFCLASS64
    raw[5] = 1   # ELFDATA2LSB
    raw[6] = 1   # EV_CURRENT
    raw[7] = 0   # ELFOSABI_NONE
    struct.pack_into(
        "<HHIQQQIHHHHHH",
        raw,
        16,
        3,          # ET_DYN
        183,        # EM_AARCH64
        1,          # EV_CURRENT
        0x1000,     # e_entry
        ehdr_size,  # e_phoff
        off_shdrs,  # e_shoff
        0,          # e_flags
        ehdr_size,
        phdr_size,
        num_phdrs,
        shdr_size,
        num_shdrs,
        5,          # e_shstrndx (.shstrtab is section 5)
    )

    # 2. Program Headers
    # PHDR 0: LOAD .text (R+X)
    struct.pack_into(
        "<IIQQQQQQ",
        raw,
        ehdr_size,
        1,          # PT_LOAD
        5,          # PF_R | PF_X
        off_text,
        0x1000,     # p_vaddr
        0x1000,     # p_paddr
        len(text_data),
        len(text_data),
        0x1000,     # p_align
    )
    # PHDR 1: LOAD .rodata (R)
    struct.pack_into(
        "<IIQQQQQQ",
        raw,
        ehdr_size + phdr_size,
        1,          # PT_LOAD
        4,          # PF_R
        off_rodata,
        0x5000,     # p_vaddr
        0x5000,     # p_paddr
        len(rodata),
        len(rodata),
        0x1000,     # p_align
    )

    # Write payload data
    raw[off_text : off_text + len(text_data)] = text_data
    raw[off_rodata : off_rodata + len(rodata)] = rodata
    raw[off_symtab : off_symtab + len(symtab)] = symtab
    raw[off_strtab : off_strtab + len(strtab)] = strtab
    raw[off_shstrtab : off_shstrtab + len(shstrtab)] = shstrtab

    # 3. Section Headers
    # Sec 0: NULL
    # Sec 1: .text (shstrtab off 1)
    struct.pack_into(
        "<IIQQQQIIQQ",
        raw,
        off_shdrs + shdr_size * 1,
        1, 1, 6, 0x1000, off_text, len(text_data), 0, 0, 16, 0
    )
    # Sec 2: .rodata (shstrtab off 7)
    struct.pack_into(
        "<IIQQQQIIQQ",
        raw,
        off_shdrs + shdr_size * 2,
        7, 1, 2, 0x5000, off_rodata, len(rodata), 0, 0, 8, 0
    )
    # Sec 3: .symtab (shstrtab off 15)
    struct.pack_into(
        "<IIQQQQIIQQ",
        raw,
        off_shdrs + shdr_size * 3,
        15, 2, 0, 0, off_symtab, len(symtab), 4, 1, 8, 24
    )
    # Sec 4: .strtab (shstrtab off 23)
    struct.pack_into(
        "<IIQQQQIIQQ",
        raw,
        off_shdrs + shdr_size * 4,
        23, 3, 0, 0, off_strtab, len(strtab), 0, 0, 1, 0
    )
    # Sec 5: .shstrtab (shstrtab off 31)
    struct.pack_into(
        "<IIQQQQIIQQ",
        raw,
        off_shdrs + shdr_size * 5,
        31, 3, 0, 0, off_shstrtab, len(shstrtab), 0, 0, 1, 0
    )

    out_path.write_bytes(bytes(raw))


def main() -> None:
    pe_target = OUT_DIR / "sample_x64.dll"
    elf_target = OUT_DIR / "sample_arm64.so"

    generate_pe64_dll(pe_target)
    print(f"[+] Generated PE64: {pe_target} ({pe_target.stat().st_size} bytes)")

    generate_arm64_elf_so(elf_target)
    print(f"[+] Generated ELF64 ARM64: {elf_target} ({elf_target.stat().st_size} bytes)")


if __name__ == "__main__":
    main()
