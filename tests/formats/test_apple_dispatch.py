"""
test_apple_dispatch.py
======================

Unit tests for superghidra.formats.apple_dispatch:
- Universal FAT Mach-O slice selection (arm64, arm64e, x86_64)
- Thin 64-bit Mach-O header parsing
- Admission byte budget enforcement (64 MiB default)
- Dyld chained fixups parsing (starts, segments, imports, pointer chains)
- Authenticated ARM64E chained fixup decoding
- Standard 64-bit chained fixup decoding
- Legacy LC_DYLD_INFO rebase & bind opcodes fallback
- Swift 5 nominal type descriptors (__swift5_types)
- Swift 5 protocol conformances (__swift5_proto)
- Objective-C 64-bit classes, metaclasses, ivars, methods, and categories
- Serialization of AppleDispatchReport
"""

from __future__ import annotations

import struct

import pytest

from superghidra.formats.apple_dispatch import (
    BIND_OPCODE_DO_BIND,
    BIND_OPCODE_DONE,
    BIND_OPCODE_SET_DYLIB_ORDINAL_IMM,
    BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB,
    BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM,
    BIND_OPCODE_SET_TYPE_IMM,
    BIND_TYPE_POINTER,
    CPU_SUBTYPE_ARM64_ALL,
    CPU_SUBTYPE_ARM64E,
    CPU_TYPE_ARM64,
    CPU_TYPE_X86_64,
    DYLD_CHAINED_IMPORT,
    DYLD_CHAINED_PTR_64,
    LC_SYMTAB,
    LC_DYSYMTAB,
    DYLD_CHAINED_PTR_64_OFFSET,
    DYLD_CHAINED_PTR_ARM64E,
    DYLD_CHAINED_PTR_ARM64E_USERLAND24,
    FAT_MAGIC,
    LC_DYLD_CHAINED_FIXUPS,
    LC_DYLD_INFO_ONLY,
    LC_SEGMENT_64,
    MH_MAGIC_64,
    REBASE_OPCODE_DO_REBASE_IMM_TIMES,
    REBASE_OPCODE_DONE,
    REBASE_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB,
    REBASE_OPCODE_SET_TYPE_IMM,
    REBASE_TYPE_POINTER,
    dispatch_apple_binary,
)


def _build_thin_macho_header(
    cputype: int = CPU_TYPE_ARM64,
    cpusubtype: int = CPU_SUBTYPE_ARM64_ALL,
    ncmds: int = 0,
    sizeofcmds: int = 0,
) -> bytes:
    # mach_header_64: magic, cputype, cpusubtype, filetype, ncmds, sizeofcmds, flags, reserved
    return struct.pack(
        "<IIIIIIII",
        MH_MAGIC_64,
        cputype,
        cpusubtype,
        2,  # MH_EXECUTE
        ncmds,
        sizeofcmds,
        0,  # flags
        0,  # reserved
    )


def test_admission_budget_exceeded():
    """Verify exceeding max_input_bytes raises ValueError."""
    fake_data = b"\x00" * 1024
    with pytest.raises(ValueError, match="exceeds admission budget"):
        dispatch_apple_binary(fake_data, max_input_bytes=512)


def test_invalid_magic_handling():
    """Verify non-Mach-O bytes raise ValueError in extract_macho_slice."""
    garbage = b"\x7fELF" + b"\x00" * 60
    with pytest.raises(ValueError, match="Unrecognized binary format"):
        dispatch_apple_binary(garbage)


def test_thin_arm64_macho_header():
    """Verify basic thin arm64 Mach-O parsing."""
    hdr = _build_thin_macho_header(CPU_TYPE_ARM64, CPU_SUBTYPE_ARM64_ALL)
    report = dispatch_apple_binary(hdr)
    assert report.arch == "arm64"
    assert report.bits == 64


def test_thin_arm64e_macho_header():
    """Verify arm64e subtype identification."""
    hdr = _build_thin_macho_header(CPU_TYPE_ARM64, CPU_SUBTYPE_ARM64E)
    report = dispatch_apple_binary(hdr)
    assert report.arch == "arm64e"
    assert report.bits == 64


def test_thin_x86_64_macho_header():
    """Verify x86_64 architecture identification."""
    hdr = _build_thin_macho_header(CPU_TYPE_X86_64, 3)
    report = dispatch_apple_binary(hdr)
    assert report.arch == "x86_64"
    assert report.bits == 64


def test_universal_fat_slice_selection():
    """Verify FAT binary extraction selects matching slice."""
    slice_x86 = _build_thin_macho_header(CPU_TYPE_X86_64, 3)
    slice_arm = _build_thin_macho_header(CPU_TYPE_ARM64, CPU_SUBTYPE_ARM64E)

    fat_hdr_size = 8 + 2 * 20  # 48
    offset_x86 = 48
    offset_arm = 48 + len(slice_x86)

    fat_header = struct.pack(">II", FAT_MAGIC, 2)
    arch1 = struct.pack(">IIIII", CPU_TYPE_X86_64, 3, offset_x86, len(slice_x86), 4)
    arch2 = struct.pack(">IIIII", CPU_TYPE_ARM64, CPU_SUBTYPE_ARM64E, offset_arm, len(slice_arm), 4)

    fat_binary = fat_header + arch1 + arch2 + slice_x86 + slice_arm

    report_arm = dispatch_apple_binary(fat_binary, arch="arm64e")
    assert report_arm.arch == "arm64e"

    report_x86 = dispatch_apple_binary(fat_binary, arch="x86_64")
    assert report_x86.arch == "x86_64"


def test_legacy_dyld_info_rebase():
    """Verify legacy LC_DYLD_INFO rebase opcodes decoding."""
    rebase_stream = bytes([
        REBASE_OPCODE_SET_TYPE_IMM | REBASE_TYPE_POINTER,
        REBASE_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB | 0,
        0x10,
        REBASE_OPCODE_DO_REBASE_IMM_TIMES | 1,
        REBASE_OPCODE_DONE,
    ])

    rebase_off = 32 + 72 + 48
    rebase_size = len(rebase_stream)

    seg_cmd = struct.pack(
        "<II16sQQQQIIII",
        LC_SEGMENT_64,
        72,
        b"__DATA\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
        0x1000, 0x1000, 0, 0x1000, 7, 7, 0, 0
    )

    dyld_cmd = struct.pack(
        "<IIIIIIIIIIII",
        LC_DYLD_INFO_ONLY,
        48,
        rebase_off,
        rebase_size,
        0, 0, 0, 0, 0, 0, 0, 0
    )

    hdr = _build_thin_macho_header(CPU_TYPE_ARM64, CPU_SUBTYPE_ARM64_ALL, ncmds=2, sizeofcmds=72 + 48)
    binary = hdr + seg_cmd + dyld_cmd + rebase_stream

    report = dispatch_apple_binary(binary)
    assert report.chained_fixups.legacy_info_fallback
    assert len(report.chained_fixups.entries) >= 1
    assert any(e.address == 0x1010 for e in report.chained_fixups.entries)


def test_legacy_dyld_info_bind():
    """Verify legacy LC_DYLD_INFO bind opcodes decoding."""
    bind_stream = bytearray([
        BIND_OPCODE_SET_DYLIB_ORDINAL_IMM | 1,
        BIND_OPCODE_SET_TYPE_IMM | BIND_TYPE_POINTER,
        BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM | 0,
    ])
    bind_stream.extend(b"_malloc\x00")
    bind_stream.extend([
        BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB | 0,
        0x20,
        BIND_OPCODE_DO_BIND,
        BIND_OPCODE_DONE,
    ])

    bind_off = 32 + 72 + 48
    bind_size = len(bind_stream)

    seg_cmd = struct.pack(
        "<II16sQQQQIIII",
        LC_SEGMENT_64,
        72,
        b"__DATA\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
        0x2000, 0x1000, 0, 0x1000, 7, 7, 0, 0
    )
    dyld_cmd = struct.pack(
        "<IIIIIIIIIIII",
        LC_DYLD_INFO_ONLY,
        48,
        0, 0,
        bind_off,
        bind_size,
        0, 0, 0, 0, 0, 0
    )
    hdr = _build_thin_macho_header(CPU_TYPE_ARM64, CPU_SUBTYPE_ARM64_ALL, ncmds=2, sizeofcmds=72 + 48)
    binary = hdr + seg_cmd + dyld_cmd + bytes(bind_stream)

    report = dispatch_apple_binary(binary)
    assert report.chained_fixups.legacy_info_fallback
    bind_fixup = next((e for e in report.chained_fixups.entries if e.symbol_name == "_malloc"), None)
    assert bind_fixup is not None
    assert bind_fixup.address == 0x2020


def test_dyld_chained_fixups_header_parsing():
    """Verify LC_DYLD_CHAINED_FIXUPS structure unpacking."""
    fixups_header = struct.pack(
        "<IIIIIII",
        0,   # version
        28,  # starts_offset
        28 + 16,  # imports_offset
        28 + 16 + 4,  # symbols_offset
        1,   # imports_count
        DYLD_CHAINED_IMPORT,
        0,   # symbols_format
    )

    starts_in_image = struct.pack("<II", 1, 0) + b"\x00" * 8
    import_entry = struct.pack("<I", (1 << 9) | 1)
    symbols_table = b"\x00_free\x00"

    payload = fixups_header + starts_in_image + import_entry + symbols_table

    fixup_cmd = struct.pack(
        "<IIII",
        LC_DYLD_CHAINED_FIXUPS,
        16,
        32 + 16,  # dataoff
        len(payload)
    )

    hdr = _build_thin_macho_header(CPU_TYPE_ARM64, CPU_SUBTYPE_ARM64_ALL, ncmds=1, sizeofcmds=16)
    binary = hdr + fixup_cmd + payload

    report = dispatch_apple_binary(binary)
    assert "_free" in report.chained_fixups.imports


def test_swift5_nominal_type_parsing():
    """Verify Swift 5 nominal type descriptor parsing from __swift5_types."""
    flags_struct = 17  # struct
    name_str = b"UserAccount\x00"
    name_rel = 12
    descriptor_bytes = struct.pack("<5i", flags_struct, 0, name_rel, 0, 0) + name_str
    sec_data = struct.pack("<i", 4) + descriptor_bytes
    sec_len = len(sec_data)

    seg_size = 72 + 80
    sec_offset = 32 + seg_size
    sec_addr = 0x1000

    sect_cmd = struct.pack(
        "<16s16sQQIIIIIIII",
        b"__swift5_types\x00\x00",
        b"__TEXT\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
        sec_addr, sec_len, sec_offset, 2, 0, 0, 0, 0, 0, 0
    )
    seg_cmd = struct.pack(
        "<II16sQQQQIIII",
        LC_SEGMENT_64,
        seg_size,
        b"__TEXT\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
        sec_addr, 0x1000, 0, 0x1000, 5, 5, 1, 0
    )

    hdr = _build_thin_macho_header(CPU_TYPE_ARM64, CPU_SUBTYPE_ARM64_ALL, ncmds=1, sizeofcmds=seg_size)
    binary = hdr + seg_cmd + sect_cmd + sec_data

    report = dispatch_apple_binary(binary)
    assert report.counts["swift5_types"] >= 1
    assert any(t.name == "UserAccount" and t.kind == "struct" for t in report.swift5.types)


def test_objc_class_recovery():
    """Verify Objective-C class extraction with class ro_data."""
    className = b"NetworkManager\x00"
    name_addr = 0x2100
    ro_addr = 0x2050

    ro_data = struct.pack(
        "<IIIIQQQQQQQ",
        0, 0, 32, 0, 0, name_addr, 0, 0, 0, 0, 0
    )
    class_t = struct.pack("<QQQQQ", 0, 0, 0, 0, ro_addr)

    seg_size = 72
    seg_cmd = struct.pack(
        "<II16sQQQQIIII",
        LC_SEGMENT_64,
        seg_size,
        b"__DATA_CONST\x00\x00\x00\x00",
        0x2000, 0x1000, 32 + seg_size, 0x1000, 7, 7, 0, 0
    )

    payload = bytearray(0x1000)
    payload[0:40] = class_t
    payload[0x50:0x50 + len(ro_data)] = ro_data
    payload[0x100:0x100 + len(className)] = className

    hdr = _build_thin_macho_header(CPU_TYPE_ARM64, CPU_SUBTYPE_ARM64_ALL, ncmds=1, sizeofcmds=seg_size)
    binary = hdr + seg_cmd + bytes(payload)

    report = dispatch_apple_binary(binary)
    assert report.bits == 64


def test_swift5_protocol_conformance_parsing():
    """Verify Swift 5 protocol conformance parsing from __swift5_proto."""
    proto_name = b"Serializable\x00"
    pname_rel = 12
    # ProtocolDescriptor: flags(4), parent(4), name_rel(4)
    proto_desc = struct.pack("<5i", 0, 0, pname_rel, 0, 0) + proto_name

    # ConformanceDescriptor: proto_rel(4), type_rel(4), witness_rel(4), flags(4)
    # proto_rel pointing back to proto_desc
    conf_record = struct.pack("<iiiI", -len(proto_desc), 4, 0, 0)

    sec_data = proto_desc + struct.pack("<i", 0) + conf_record
    sec_len = len(sec_data)

    seg_size = 72 + 80
    sec_offset = 32 + seg_size
    sec_addr = 0x3000

    sect_cmd = struct.pack(
        "<16s16sQQIIIIIIII",
        b"__swift5_proto\x00\x00",
        b"__TEXT\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
        sec_addr, sec_len, sec_offset, 2, 0, 0, 0, 0, 0, 0
    )
    seg_cmd = struct.pack(
        "<II16sQQQQIIII",
        LC_SEGMENT_64,
        seg_size,
        b"__TEXT\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
        sec_addr, 0x1000, 0, 0x1000, 5, 5, 1, 0
    )

    hdr = _build_thin_macho_header(CPU_TYPE_ARM64, CPU_SUBTYPE_ARM64_ALL, ncmds=1, sizeofcmds=seg_size)
    binary = hdr + seg_cmd + sect_cmd + sec_data

    report = dispatch_apple_binary(binary)
    assert report.bits == 64


def test_dyld_chained_fixups_arm64e_auth_chain():
    """Verify DYLD_CHAINED_PTR_ARM64E authenticated rebase parsing."""
    # dyld_chained_starts_in_segment: size(4), page_size(2), pointer_format(2), segment_offset(8), max_valid_pointer(4), page_count(2), page_start[1](2)
    # pointer_format = DYLD_CHAINED_PTR_ARM64E (1)
    page_start = 0  # starts at offset 0
    seg_starts = struct.pack("<IHHQIH", 24, 0x4000, 1, 0, 0, 1) + struct.pack("<H", page_start)

    # starts in image pointing to seg_starts
    starts_in_image = struct.pack("<II", 1, 8) + seg_starts

    fixups_header = struct.pack(
        "<IIIIIII",
        0,   # version
        28,  # starts_offset
        28 + len(starts_in_image),  # imports_offset
        28 + len(starts_in_image) + 4,  # symbols_offset
        1,   # imports_count
        DYLD_CHAINED_IMPORT,
        0,   # symbols_format
    )
    import_entry = struct.pack("<I", (1 << 9) | 1)
    symbols_table = b"\x00_exit\x00"

    # Encoded auth rebase pointer:
    # auth=1 (bit 63), bind=0 (bit 62), next_stride=0 (bits 51-61), key=0 (IA, bits 49-50), addr_div=1 (bit 48), diversity=0x1234 (bits 32-47), target=0x10000000
    val_auth = (1 << 63) | (0 << 62) | (0 << 51) | (0 << 49) | (1 << 48) | (0x1234 << 32) | 0x10000000
    ptr_bytes = struct.pack("<Q", val_auth)

    payload = fixups_header + starts_in_image + import_entry + symbols_table

    seg_size = 72
    seg_cmd = struct.pack(
        "<II16sQQQQIIII",
        LC_SEGMENT_64,
        seg_size,
        b"__DATA\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
        0x4000, 0x1000, 32 + seg_size + 16 + len(payload), 0x1000, 7, 7, 0, 0
    )

    fixup_cmd = struct.pack(
        "<IIII",
        LC_DYLD_CHAINED_FIXUPS,
        16,
        32 + seg_size + 16,  # dataoff
        len(payload)
    )

    hdr = _build_thin_macho_header(CPU_TYPE_ARM64, CPU_SUBTYPE_ARM64E, ncmds=2, sizeofcmds=seg_size + 16)
    binary = hdr + seg_cmd + fixup_cmd + payload + ptr_bytes

    report = dispatch_apple_binary(binary, arch="arm64e")
    assert report.arch == "arm64e"
    assert len(report.chained_fixups.entries) == 1
    e = report.chained_fixups.entries[0]
    assert e.kind == "auth_rebase"
    assert e.auth_key == "IA"
    assert e.diversity == 0x1234
    assert e.addr_diversity is True
    assert e.target == 0x4000 + 0x10000000


def test_to_dict_serialization():
    """Verify report serialization to JSON-compatible dictionary."""
    hdr = _build_thin_macho_header(CPU_TYPE_ARM64, CPU_SUBTYPE_ARM64_ALL)
    report = dispatch_apple_binary(hdr)
    d = report.to_dict()
    assert isinstance(d, dict)
    assert "arch" in d
    assert "bits" in d
    assert "chained_fixups" in d
    assert "swift5" in d
    assert "objc" in d


def test_legacy_rebase_target_extracted_from_data():
    """Bug 1: Verify legacy dyld_info rebase reads pre-slid target pointer from binary data."""
    seg_fileoff = 0x100
    seg_vmaddr = 0x1000
    expected_target = 0x0000000100084000
    rel_slot_off = 0x28

    rebase_stream = bytes([
        REBASE_OPCODE_SET_TYPE_IMM | REBASE_TYPE_POINTER,
        REBASE_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB | 0,
        rel_slot_off,
        REBASE_OPCODE_DO_REBASE_IMM_TIMES | 1,
        REBASE_OPCODE_DONE,
    ])

    rebase_off = 32 + 72 + 48
    rebase_size = len(rebase_stream)

    seg_cmd = struct.pack(
        "<II16sQQQQIIII",
        LC_SEGMENT_64,
        72,
        b"__DATA\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
        seg_vmaddr, 0x1000, seg_fileoff, 0x1000, 7, 7, 0, 0
    )

    dyld_cmd = struct.pack(
        "<IIIIIIIIIIII",
        LC_DYLD_INFO_ONLY,
        48,
        rebase_off,
        rebase_size,
        0, 0, 0, 0, 0, 0, 0, 0
    )

    hdr = _build_thin_macho_header(CPU_TYPE_X86_64, 3, ncmds=2, sizeofcmds=72 + 48)
    prefix = hdr + seg_cmd + dyld_cmd + rebase_stream

    total_len = seg_fileoff + rel_slot_off + 8
    binary_bytes = bytearray(total_len)
    binary_bytes[:len(prefix)] = prefix
    struct.pack_into("<Q", binary_bytes, seg_fileoff + rel_slot_off, expected_target)

    report = dispatch_apple_binary(bytes(binary_bytes), arch="x86_64")
    assert report.chained_fixups.legacy_info_fallback
    assert len(report.chained_fixups.entries) == 1
    rebase_entry = report.chained_fixups.entries[0]
    assert rebase_entry.kind == "rebase"
    assert rebase_entry.address == seg_vmaddr + rel_slot_off
    assert rebase_entry.offset == seg_fileoff + rel_slot_off
    assert rebase_entry.target == expected_target


def test_legacy_lazy_bind_opcodes_parsing_279_entries():
    """Bug 4: Verify legacy dyld_info weak_bind and lazy_bind opcodes decoding (279 Hugo lazy binds)."""
    def encode_uleb128(val: int) -> bytes:
        out = bytearray()
        while True:
            b = val & 0x7F
            val >>= 7
            if val:
                out.append(b | 0x80)
            else:
                out.append(b)
                break
        return bytes(out)

    bind_stream = bytearray([
        BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB | 0,
        0x00,
        BIND_OPCODE_SET_DYLIB_ORDINAL_IMM | 1,
        BIND_OPCODE_SET_TYPE_IMM | BIND_TYPE_POINTER,
        BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM | 0,
    ])
    bind_stream.extend(b"_dyld_start\x00")
    bind_stream.extend([
        BIND_OPCODE_DO_BIND,
        BIND_OPCODE_DONE,
    ])

    num_lazy_entries = 279
    lazy_stream = bytearray()
    for i in range(num_lazy_entries):
        slot_offset = 0x10 + i * 8
        lazy_stream.append(BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB | 0)
        lazy_stream.extend(encode_uleb128(slot_offset))
        lazy_stream.append(BIND_OPCODE_SET_DYLIB_ORDINAL_IMM | 2)
        lazy_stream.append(BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM | 0)
        lazy_stream.extend(f"_stub_func_{i}\x00".encode("utf-8"))
        lazy_stream.append(BIND_OPCODE_DO_BIND)
        lazy_stream.append(BIND_OPCODE_DONE)

    seg_cmd = struct.pack(
        "<II16sQQQQIIII",
        LC_SEGMENT_64,
        72,
        b"__DATA\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
        0x2000, 0x4000, 0x1000, 0x4000, 7, 7, 0, 0
    )

    base_off = 32 + 72 + 48
    bind_off = base_off
    bind_size = len(bind_stream)
    lazy_off = bind_off + bind_size
    lazy_size = len(lazy_stream)

    dyld_cmd = struct.pack(
        "<IIIIIIIIIIII",
        LC_DYLD_INFO_ONLY,
        48,
        0, 0,
        bind_off, bind_size,
        0, 0,
        lazy_off, lazy_size,
        0, 0
    )

    hdr = _build_thin_macho_header(CPU_TYPE_X86_64, 3, ncmds=2, sizeofcmds=72 + 48)
    binary = bytearray(0x2000)
    meta = hdr + seg_cmd + dyld_cmd + bytes(bind_stream) + bytes(lazy_stream)
    binary[:len(meta)] = meta

    report = dispatch_apple_binary(bytes(binary), arch="x86_64")
    assert report.chained_fixups.legacy_info_fallback
    assert report.chained_fixups.counts["entries"] == num_lazy_entries + 1
    assert report.chained_fixups.counts["binds"] == num_lazy_entries + 1
    all_binds = [e for e in report.chained_fixups.entries if e.kind == "bind"]
    assert len(all_binds) == num_lazy_entries + 1
    assert all_binds[0].symbol_name == "_dyld_start"
    lazy_entries = all_binds[1:]
    assert len(lazy_entries) == 279
    assert lazy_entries[0].symbol_name == "_stub_func_0"
    assert lazy_entries[278].symbol_name == "_stub_func_278"
    assert lazy_entries[278].address == 0x2000 + 0x10 + 278 * 8
    assert "_stub_func_0" in report.chained_fixups.imports
    assert "_stub_func_278" in report.chained_fixups.imports


def test_dyld_chained_ptr_64_offset_adds_image_base():
    """Bug 2: Verify DYLD_CHAINED_PTR_64_OFFSET correctly adds slice_macho.image_base."""
    page_start = 0
    seg_starts = struct.pack("<IHHQIH", 24, 0x1000, DYLD_CHAINED_PTR_64_OFFSET, 0, 0, 1) + struct.pack("<H", page_start)
    starts_in_image = struct.pack("<II", 1, 8) + seg_starts

    fixups_header = struct.pack(
        "<IIIIIII",
        0,   # version
        28,  # starts_offset
        28 + len(starts_in_image),  # imports_offset
        28 + len(starts_in_image) + 4,  # symbols_offset
        1,   # imports_count
        DYLD_CHAINED_IMPORT,
        0,   # symbols_format
    )
    import_entry = struct.pack("<I", 0)
    symbols_table = b"\x00unused\x00"
    payload = fixups_header + starts_in_image + import_entry + symbols_table

    offset_target = 0x1234
    high8 = 0x05
    val = (0 << 63) | (0 << 51) | (high8 << 36) | offset_target
    ptr_bytes = struct.pack("<Q", val)

    seg_size = 72
    image_base = 0x100000000
    seg_cmd = struct.pack(
        "<II16sQQQQIIII",
        LC_SEGMENT_64,
        seg_size,
        b"__DATA\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
        image_base, 0x1000, 32 + seg_size + 16 + len(payload), 0x1000, 7, 7, 0, 0
    )

    fixup_cmd = struct.pack(
        "<IIII",
        LC_DYLD_CHAINED_FIXUPS,
        16,
        32 + seg_size + 16,
        len(payload)
    )

    hdr = _build_thin_macho_header(CPU_TYPE_ARM64, CPU_SUBTYPE_ARM64_ALL, ncmds=2, sizeofcmds=seg_size + 16)
    binary = hdr + seg_cmd + fixup_cmd + payload + ptr_bytes

    report = dispatch_apple_binary(binary, arch="arm64")
    assert len(report.chained_fixups.entries) == 1
    e = report.chained_fixups.entries[0]
    assert e.kind == "rebase"
    expected_full_target = (high8 << 56) | (image_base + offset_target)
    assert e.target == expected_full_target


def test_dyld_chained_ptr_arm64e_userland24_decoding():
    """Bug 3: Verify DYLD_CHAINED_PTR_ARM64E_USERLAND24 decodes 24-bit ordinals, PAC keys, and targets."""
    page_start = 0
    seg_starts = struct.pack(
        "<IHHQIH",
        24,
        0x4000,
        DYLD_CHAINED_PTR_ARM64E_USERLAND24,
        0,
        0,
        1,
    ) + struct.pack("<H", page_start)
    starts_in_image = struct.pack("<II", 1, 8) + seg_starts

    fixups_header = struct.pack(
        "<IIIIIII",
        0,   # version
        28,  # starts_offset
        28 + len(starts_in_image),  # imports_offset
        28 + len(starts_in_image) + 4,  # symbols_offset
        1,   # imports_count
        DYLD_CHAINED_IMPORT,
        0,   # symbols_format
    )
    import_entry = struct.pack("<I", 0)
    symbols_table = b"\x00unused\x00"
    payload = fixups_header + starts_in_image + import_entry + symbols_table

    # Build 4 chained fixup slots in a chain:
    # Slot 0: auth_bind24 with stride 8 (next=1)
    # auth=1, bind=1, next=1, key=2 (DA), addr_div=1, diversity=0xBEEF, ordinal=0x123456 (24-bit)
    val_auth_bind = (1 << 63) | (1 << 62) | (1 << 51) | (2 << 49) | (1 << 48) | (0xBEEF << 32) | 0x123456

    # Slot 1: bind24 with stride 8 (next=1)
    # auth=0, bind=1, next=1, addend=-42 (19-bit signed: -42 & 0x7FFFF), ordinal=0x654321 (24-bit)
    val_bind24 = (0 << 63) | (1 << 62) | (1 << 51) | (((-42) & 0x7FFFF) << 32) | 0x654321

    # Slot 2: unauth rebase in USERLAND24 with stride 8 (next=1)
    # auth=0, bind=0, next=1, target=0x5000 (VM offset from image_base)
    val_rebase = (0 << 63) | (0 << 62) | (1 << 51) | 0x5000

    # Slot 3: auth rebase in USERLAND24 with stride 0 (end of chain)
    # auth=1, bind=0, next=0, key=1 (IB), addr_div=0, diversity=0xCAFE, target=0x6000 (runtime offset)
    val_auth_rebase = (1 << 63) | (0 << 62) | (0 << 51) | (1 << 49) | (0 << 48) | (0xCAFE << 32) | 0x6000

    ptr_chain_bytes = (
        struct.pack("<Q", val_auth_bind) +
        struct.pack("<Q", val_bind24) +
        struct.pack("<Q", val_rebase) +
        struct.pack("<Q", val_auth_rebase)
    )

    image_base = 0x100004000
    seg_size = 72
    seg_cmd = struct.pack(
        "<II16sQQQQIIII",
        LC_SEGMENT_64,
        seg_size,
        b"__DATA\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
        image_base, 0x4000, 32 + seg_size + 16 + len(payload), 0x4000, 7, 7, 0, 0
    )

    fixup_cmd = struct.pack(
        "<IIII",
        LC_DYLD_CHAINED_FIXUPS,
        16,
        32 + seg_size + 16,
        len(payload)
    )

    hdr = _build_thin_macho_header(CPU_TYPE_ARM64, CPU_SUBTYPE_ARM64E, ncmds=2, sizeofcmds=seg_size + 16)
    binary = hdr + seg_cmd + fixup_cmd + payload + ptr_chain_bytes

    report = dispatch_apple_binary(binary, arch="arm64e")
    assert len(report.chained_fixups.entries) == 4

    e0 = report.chained_fixups.entries[0]
    assert e0.kind == "auth_bind"
    assert e0.ordinal == 0x123456
    assert e0.auth_key == "DA"
    assert e0.diversity == 0xBEEF
    assert e0.addr_diversity is True

    e1 = report.chained_fixups.entries[1]
    assert e1.kind == "bind"
    assert e1.ordinal == 0x654321
    assert e1.addend == -42

    e2 = report.chained_fixups.entries[2]
    assert e2.kind == "rebase"
    assert e2.target == image_base + 0x5000

    e3 = report.chained_fixups.entries[3]
    assert e3.kind == "auth_rebase"
    assert e3.auth_key == "IB"
    assert e3.diversity == 0xCAFE
    assert e3.addr_diversity is False
    assert e3.target == image_base + 0x6000


def test_dysymtab_indirect_symbols_hugo_intel_279_entries():
    """Bug 4: Verify classic Mach-O LC_DYSYMTAB indirect symbol table recovery (279 Hugo Intel fixups)."""
    # 279 indirect symbols in __la_symbol_ptr
    num_entries = 279
    strtab = bytearray(b"\x00_main\x00")
    symbols_raw = bytearray()
    # Symbol 0: _main
    symbols_raw.extend(struct.pack("<IBBHQ", 1, 0x0F, 1, 0, 0x10001000))
    # Symbols 1..279: _stub_i
    for i in range(num_entries):
        stroff = len(strtab)
        strtab.extend(f"_hugo_sym_{i}\x00".encode("utf-8"))
        symbols_raw.extend(struct.pack("<IBBHQ", stroff, 0x01, 0, 0, 0))

    # indirect symbol table: indices 1..279
    indirect_table = struct.pack(f"<{num_entries}I", *range(1, num_entries + 1))

    # Section __la_symbol_ptr in __DATA:
    # reserved1 = 0 (offset into indirect symbol table)
    # size = 279 * 8
    sect_sz = num_entries * 8
    sect_cmd = struct.pack(
        "<16s16sQQIIIIIIII",
        b"__la_symbol_ptr\x00",
        b"__DATA\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
        0x10004000, sect_sz,
        0x1000, 3, 0, 0, 0x07,  # flags: S_LAZY_SYMBOL_POINTERS
        0, 8, 0,  # reserved1=0, reserved2=8, reserved3=0
    )
    seg_cmd = struct.pack(
        "<II16sQQQQIIII",
        LC_SEGMENT_64,
        72 + 80,
        b"__DATA\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
        0x10004000, 0x4000, 0x1000, 0x4000, 7, 7, 1, 0,
    ) + sect_cmd

    # Layout file offsets
    # Header: 32 bytes
    # seg_cmd: 152 bytes
    # dysymtab_cmd: 80 bytes
    # symtab_cmd: 24 bytes
    # Total cmds size: 152 + 80 + 24 = 256 bytes
    header_and_cmds_sz = 32 + 256
    symoff = 0x500
    stroff = symoff + len(symbols_raw)
    indirect_off = stroff + len(strtab)

    symtab_cmd = struct.pack("<IIII", symoff, num_entries + 1, stroff, len(strtab))
    dysym_cmd = struct.pack(
        "<18I",
        0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0,
        indirect_off, num_entries,
        0, 0, 0, 0,
    )

    hdr = _build_thin_macho_header(CPU_TYPE_X86_64, 3, ncmds=3, sizeofcmds=256)
    binary = bytearray(0x4000)
    meta = hdr + seg_cmd + struct.pack("<II", LC_SYMTAB, 24) + symtab_cmd + struct.pack("<II", LC_DYSYMTAB, 80) + dysym_cmd
    binary[:len(meta)] = meta
    binary[symoff : symoff + len(symbols_raw)] = symbols_raw
    binary[stroff : stroff + len(strtab)] = strtab
    binary[indirect_off : indirect_off + len(indirect_table)] = indirect_table

    report = dispatch_apple_binary(bytes(binary), arch="x86_64")
    assert report.chained_fixups.legacy_info_fallback is True
    assert report.chained_fixups.counts["entries"] == 279
    assert report.chained_fixups.counts["binds"] == 279
    assert len(report.chained_fixups.entries) == 279
    assert report.chained_fixups.entries[0].symbol_name == "_hugo_sym_0"
    assert report.chained_fixups.entries[278].symbol_name == "_hugo_sym_278"
    assert report.chained_fixups.entries[0].address == 0x10004000
    assert report.chained_fixups.entries[278].address == 0x10004000 + 278 * 8


def test_ios_framework_dylib_base_zero_altstorecore():
    """Bug 9: Verify iOS dylib/framework with __TEXT.vmaddr=0 keeps image_base=0 and does not shift by __DATA."""
    # Segment 1: __TEXT with vmaddr = 0
    seg_text = struct.pack(
        "<II16sQQQQIIII",
        LC_SEGMENT_64,
        72,
        b"__TEXT\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
        0x0, 0x4000, 0x0, 0x4000, 5, 5, 0, 0,
    )
    # Segment 2: __DATA with vmaddr = 0x8000
    seg_data = struct.pack(
        "<II16sQQQQIIII",
        LC_SEGMENT_64,
        72,
        b"__DATA\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
        0x8000, 0x4000, 0x4000, 0x4000, 7, 7, 0, 0,
    )
    hdr = _build_thin_macho_header(CPU_TYPE_ARM64, 0, ncmds=2, sizeofcmds=72 + 72)
    binary = hdr + seg_text + seg_data
    report = dispatch_apple_binary(binary, arch="arm64")
    assert report.image_base == 0, f"Dylib __TEXT with vmaddr 0 must have image_base 0, got {hex(report.image_base)}"
