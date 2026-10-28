"""
test_il2cpp_metadata.py
=======================

Unit tests for superghidra.formats.il2cpp_metadata:
- Header magic verification (0xFAB11BAF)
- Encrypted/corrupted header rejection
- Admission budget enforcement
- Unity metadata versions 24, 27, 29, 31, and 39
- Assemblies/Images recovery
- Types and field definitions extraction
- Methods and parameter lists extraction
- String literal pool extraction
- Native binary method pointer correlation (inferred RVA)
- Report serialization
"""

from __future__ import annotations

import struct
from pathlib import Path

import pytest

from superghidra.formats.il2cpp_metadata import (
    IL2CPP_METADATA_MAGIC,
    SUPPORTED_VERSIONS,
    Il2CppMetadataReport,
    recover_il2cpp_metadata,
)


def _build_mock_metadata(
    version: int = 29,
    assemblies: list[tuple[str, int, int]] | None = None,
    types: list[tuple[str, str, int, int]] | None = None,
    methods: list[tuple[str, int]] | None = None,
    strings: list[str] | None = None,
) -> bytes:
    """Helper to synthesize a valid global-metadata.dat buffer for testing."""
    if assemblies is None:
        assemblies = [("Assembly-CSharp.dll", 0, 1)]
    if types is None:
        types = [("GameController", "UnityEngine", 0, 1)]  # name, ns, field_count, method_count
    if methods is None:
        methods = [("Start", 0)]  # name, param_count
    if strings is None:
        strings = ["Dummy"]

    # Build string pool
    str_pool = bytearray(b"\x00")
    str_map: dict[str, int] = {}
    for s in ["Assembly-CSharp.dll", "GameController", "UnityEngine", "Start", "health"] + strings:
        if s not in str_map:
            str_map[s] = len(str_pool)
            str_pool.extend(s.encode("utf-8") + b"\x00")

    # Header is 264 bytes
    header_size = 264
    curr_offset = header_size

    # Strings section
    str_off = curr_offset
    str_sz = len(str_pool)
    curr_offset += str_sz

    # String literals section: 1 literal
    lit_data = b"Hello Unity World!\x00"
    lit_data_off = curr_offset
    lit_data_sz = len(lit_data)
    curr_offset += lit_data_sz

    lit_entry = struct.pack("<II", len(lit_data) - 1, 0)
    lit_off = curr_offset
    lit_sz = len(lit_entry)
    curr_offset += lit_sz

    # Parameters: 0 params
    params_off = curr_offset
    params_sz = 0

    # Fields: 1 field
    field_entry = struct.pack("<III", str_map.get("health", 0), 0, 0x04000001)
    fields_off = curr_offset
    fields_sz = len(field_entry)
    curr_offset += fields_sz

    # Methods:
    method_struct_size = 40 if version >= 27 else 36
    method_bytes = bytearray()
    for idx, (mname, pcount) in enumerate(methods):
        name_idx = str_map.get(mname, 0)
        if version >= 27:
            # name(4), decl_type(4), ret_type(4), param_start(4), gen_cont(4), token(4), flags(4), slot(2), param_count(2), ...
            mdata = struct.pack("<IIIIIIIHHII", name_idx, 0, 0, 0, 0, 0x06000001 + idx, 0, 0, pcount, 0, 0)
            method_bytes.extend(mdata[:40])
        else:
            mdata = struct.pack("<IIIIIIIHH", name_idx, 0, 0, 0, 0, 0x06000001 + idx, 0, 0, pcount)
            method_bytes.extend(mdata[:36])
    methods_off = curr_offset
    methods_sz = len(method_bytes)
    curr_offset += methods_sz

    # Type definitions:
    type_struct_size = 96 if version >= 27 else 88
    type_bytes = bytearray()
    for idx, (tname, tns, fcount, mcount) in enumerate(types):
        tname_idx = str_map.get(tname, 0)
        ns_idx = str_map.get(tns, 0)
        tdata = bytearray(type_struct_size)
        struct.pack_into("<II", tdata, 0, tname_idx, ns_idx)
        struct.pack_into("<II", tdata, 40, 0x00100000, 0)  # flags, field_start
        struct.pack_into("<I", tdata, 48, 0)  # method_start
        struct.pack_into("<HH", tdata, 72, mcount, fcount)  # method_count, field_count
        if version >= 27:
            struct.pack_into("<I", tdata, 88, 0x02000001 + idx)  # token
        type_bytes.extend(tdata)
    type_defs_off = curr_offset
    type_defs_sz = len(type_bytes)
    curr_offset += type_defs_sz

    # Assemblies / Images:
    image_struct_size = 40 if version >= 27 else 36
    image_bytes = bytearray()
    for idx, (img_name, tstart, tcount) in enumerate(assemblies):
        name_idx = str_map.get(img_name, 0)
        idata = bytearray(image_struct_size)
        struct.pack_into("<IIIII", idata, 0, name_idx, idx, tstart, tcount, 0)
        struct.pack_into("<I", idata, 20, 0x01000001 + idx)
        image_bytes.extend(idata)
    images_off = curr_offset
    images_sz = len(image_bytes)
    curr_offset += images_sz

    # Build Header:
    header = bytearray(264)
    struct.pack_into("<I", header, 0, IL2CPP_METADATA_MAGIC)
    struct.pack_into("<i", header, 4, version)
    struct.pack_into("<ii", header, 8, lit_off, lit_sz)
    struct.pack_into("<ii", header, 16, lit_data_off, lit_data_sz)
    struct.pack_into("<ii", header, 24, str_off, str_sz)
    struct.pack_into("<ii", header, 48, methods_off, methods_sz)
    struct.pack_into("<ii", header, 88, params_off, params_sz)
    struct.pack_into("<ii", header, 96, fields_off, fields_sz)
    struct.pack_into("<ii", header, 152, type_defs_off, type_defs_sz)
    struct.pack_into("<ii", header, 160, images_off, images_sz)

    return bytes(header + str_pool + lit_data + lit_entry + field_entry + method_bytes + type_bytes + image_bytes)


def test_admission_budget_exceeded():
    """Verify exceeding max_input_bytes raises ValueError."""
    fake_data = b"\x00" * 1024
    with pytest.raises(ValueError, match="exceeds admission budget"):
        recover_il2cpp_metadata(fake_data, max_input_bytes=512)


def test_buffer_too_small():
    """Verify buffer under 264 bytes returns invalid report."""
    report = recover_il2cpp_metadata(b"\x00" * 100)
    assert not report.is_valid
    assert report.epistemic_status == "unknown"
    assert "too small" in report.limitations[0].lower()


def test_invalid_magic_handling():
    """Verify non-0xFAB11BAF magic returns invalid report with limitations."""
    bad_header = bytearray(300)
    struct.pack_into("<I", bad_header, 0, 0xDEADBEEF)
    struct.pack_into("<i", bad_header, 4, 29)
    report = recover_il2cpp_metadata(bytes(bad_header))
    assert not report.is_valid
    assert report.epistemic_status == "unknown"
    assert "magic" in report.limitations[0].lower()


@pytest.mark.parametrize("ver", [24, 27, 29, 31, 39])
def test_supported_versions_parsing(ver: int):
    """Verify metadata versions 24, 27, 29, 31, and 39 parse cleanly."""
    buf = _build_mock_metadata(version=ver)
    report = recover_il2cpp_metadata(buf)
    assert report.is_valid
    assert report.version == ver
    assert len(report.assemblies) >= 1
    assert report.assemblies[0].name == "Assembly-CSharp.dll"
    assert len(report.types) >= 1
    assert report.types[0].fullname == "UnityEngine.GameController"
    assert len(report.types[0].methods) >= 1
    assert report.types[0].methods[0].name == "Start"


def test_string_literal_extraction():
    """Verify string literals pool extraction."""
    buf = _build_mock_metadata(version=29)
    report = recover_il2cpp_metadata(buf)
    assert report.is_valid
    assert len(report.string_literals) >= 1
    assert "Hello Unity World!" in report.string_literals


def test_native_binary_rva_correlation():
    """Verify joining metadata method indices to native code pointer table."""
    buf = _build_mock_metadata(version=29)
    # Synthesize native ELF binary with IL2CPP_METHOD_POINTERS table
    # IL2CPP_METHOD_POINTERS + [rva_0 (8 bytes: 0x140001000)]
    elf_hdr = b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 56
    marker = b"IL2CPP_METHOD_POINTERS"
    rva_entry = struct.pack("<Q", 0x140001000)
    fake_native_so = elf_hdr + marker + rva_entry

    report = recover_il2cpp_metadata(buf, binary_path_or_bytes=fake_native_so)
    assert report.is_valid
    start_method = report.types[0].methods[0]
    assert start_method.native_rva == 0x140001000
    assert start_method.epistemic_status == "inferred"


def test_corrupted_offsets_do_not_crash():
    """Verify that corrupt out-of-bounds offsets do not raise unhandled exceptions."""
    header = bytearray(300)
    struct.pack_into("<I", header, 0, IL2CPP_METADATA_MAGIC)
    struct.pack_into("<i", header, 4, 29)
    # Put offsets way beyond file length
    struct.pack_into("<ii", header, 24, 0x7FFFFFFF, 100)
    struct.pack_into("<ii", header, 152, 0x7FFFFFFF, 100)
    report = recover_il2cpp_metadata(bytes(header))
    assert report.is_valid
    assert len(report.types) == 0


def test_to_dict_serialization():
    """Verify report serialization to JSON-compatible dict."""
    buf = _build_mock_metadata(version=29)
    report = recover_il2cpp_metadata(buf)
    d = report.to_dict()
    assert isinstance(d, dict)
    assert d["is_valid"] is True
    assert d["version"] == 29
    assert "assemblies" in d
    assert "types" in d
    assert "counts" in d
