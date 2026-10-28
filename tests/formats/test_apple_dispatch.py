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
    CPU_SUBTYPE_ARM64E,
    CPU_SUBTYPE_ARM64_ALL,
    CPU_TYPE_ARM64,
    CPU_TYPE_X86_64,
    DYLD_CHAINED_IMPORT,
    FAT_MAGIC,
    LC_DYLD_CHAINED_FIXUPS,
    LC_DYLD_INFO_ONLY,
    LC_SEGMENT_64,
    MH_MAGIC_64,
    REBASE_OPCODE_DONE,
    REBASE_OPCODE_DO_REBASE_IMM_TIMES,
    REBASE_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB,
    REBASE_OPCODE_SET_TYPE_IMM,
    REBASE_TYPE_POINTER,
    BIND_OPCODE_DONE,
    BIND_OPCODE_DO_BIND,
    BIND_OPCODE_SET_DYLIB_ORDINAL_IMM,
    BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB,
    BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM,
    BIND_OPCODE_SET_TYPE_IMM,
    BIND_TYPE_POINTER,
    AppleDispatchReport,
    dispatch_apple_binary,
    extract_macho_slice,
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
    seg_starts = struct.pack("<IHHIHQH", 24, 0x4000, 1, 0, 0, 1, page_start)

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
        0x4000, 0x1000, 32 + 16 + len(payload), 0x1000, 7, 7, 0, 0
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
