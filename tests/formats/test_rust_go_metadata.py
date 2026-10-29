"""
test_rust_go_metadata.py
========================

Unit tests for superghidra.formats.rust_go_metadata:
- Admission budget enforcement
- Rust .dep-v0 zlib JSON dependency DAG recovery
- Rust /rustc/<hash>/ commit hash extraction
- Epistemic status: observed_absence when metadata is missing
- Corrupted zlib stream handling
- Go .go.buildinfo signature and module lines parsing
- Go pclntab header detection across versions (1.16, 1.18, 1.20+)
- Multi-format section discovery (ELF, PE, Mach-O)
- Report serialization
"""

from __future__ import annotations

import json
import struct
import zlib

import pytest

from superghidra.formats.rust_go_metadata import (
    GO_BUILDINFO_MAGIC,
    PCLNTAB_MAGIC_116,
    PCLNTAB_MAGIC_118,
    PCLNTAB_MAGIC_120,
    audit_rust_go_binary,
)


def _build_mock_dep_v0() -> bytes:
    """Helper to synthesize a cargo-auditable .dep-v0 compressed payload."""
    payload = {
        "packages": [
            {
                "name": "superghidra",
                "version": "0.5.0",
                "root": True,
                "features": ["smt", "gpu"],
                "dependencies": [1, 2],
            },
            {
                "name": "z3-solver",
                "version": "4.13.0",
                "source": "registry+https://github.com/rust-lang/crates.io-index",
                "features": ["default"],
                "dependencies": [],
            },
            {
                "name": "wgpu",
                "version": "0.19.0",
                "source": "registry+https://github.com/rust-lang/crates.io-index",
                "features": ["vulkan", "dx12"],
                "dependencies": [],
            },
        ]
    }
    raw_json = json.dumps(payload).encode("utf-8")
    return zlib.compress(raw_json)


def _build_mock_go_buildinfo() -> bytes:
    """Helper to synthesize a Go buildinfo signature and module table."""
    magic = GO_BUILDINFO_MAGIC  # 14 bytes
    flags = b"\x02\x00"  # 16 bytes total
    ver_str = b"go1.22.4\x00"

    mod_text = (
        b"path\tgithub.com/yuatemycat/superghidra-daemon\n"
        b"mod\tgithub.com/yuatemycat/superghidra-daemon\tv0.5.0\th1:abc123hash=\n"
        b"dep\tgithub.com/google/uuid\tv1.6.0\th1:6CjpWyG...\n"
        b"=>\tgithub.com/forked/uuid\n"
        b"build\t-compiler=gc\n"
        b"build\tCGO_ENABLED=1\n"
        b"build\tvcs.revision=034ca64859a85fec\n\x00"
    )

    return magic + flags + ver_str + mod_text


def test_admission_budget_exceeded():
    """Verify exceeding max_input_bytes raises ValueError."""
    fake_data = b"\x00" * 1024
    with pytest.raises(ValueError, match="exceeds admission budget"):
        audit_rust_go_binary(fake_data, max_input_bytes=512)


def test_rust_dep_v0_parsing():
    """Verify recovering Rust crate DAG from synthetic ELF with .dep-v0 section."""
    dep_v0_bytes = _build_mock_dep_v0()

    # Build synthetic ELF with .dep-v0 section in shstrtab
    # shstrtab: \x00.shstrtab\x00.dep-v0\x00
    shstrtab = b"\x00.shstrtab\x00.dep-v0\x00"
    dep_name_idx = shstrtab.find(b".dep-v0")
    shstr_name_idx = shstrtab.find(b".shstrtab")

    # ELF64 header (64 bytes)
    # e_shoff = 64, e_shentsize = 64, e_shnum = 3, e_shstrndx = 1
    # section 0: NULL
    # section 1: .shstrtab
    # section 2: .dep-v0
    elf_hdr = bytearray(64)
    struct.pack_into("<4sBBBBB", elf_hdr, 0, b"\x7fELF", 2, 1, 1, 0, 0)
    struct.pack_into("<H", elf_hdr, 16, 2)  # ET_EXEC
    struct.pack_into("<H", elf_hdr, 18, 62)  # EM_X86_64
    struct.pack_into("<Q", elf_hdr, 40, 64)  # e_shoff
    struct.pack_into("<H", elf_hdr, 58, 64)  # e_shentsize
    struct.pack_into("<H", elf_hdr, 60, 3)   # e_shnum
    struct.pack_into("<H", elf_hdr, 62, 1)   # e_shstrndx

    sh_data_start = 64 + 3 * 64
    shstrtab_off = sh_data_start
    shstrtab_sz = len(shstrtab)
    dep_off = shstrtab_off + shstrtab_sz
    dep_sz = len(dep_v0_bytes)

    sec0 = bytes(64)
    sec1 = bytearray(64)
    struct.pack_into("<I", sec1, 0, shstr_name_idx)
    struct.pack_into("<QQ", sec1, 24, shstrtab_off, shstrtab_sz)

    sec2 = bytearray(64)
    struct.pack_into("<I", sec2, 0, dep_name_idx)
    struct.pack_into("<QQ", sec2, 24, dep_off, dep_sz)

    full_binary = elf_hdr + sec0 + sec1 + sec2 + shstrtab + dep_v0_bytes

    report = audit_rust_go_binary(full_binary)
    assert report.binary_format == "ELF"
    assert report.rust.has_audit_data is True
    assert report.rust.package_name == "superghidra"
    assert report.rust.package_version == "0.5.0"
    assert len(report.rust.crates) == 3
    crate_names = [c.name for c in report.rust.crates]
    assert "z3-solver" in crate_names
    assert "wgpu" in crate_names


def test_rustc_commit_hash_extraction():
    """Verify extraction of /rustc/<40-hex>/ commit hashes."""
    commit_hex = "a8314ef7d0ec7b75c336af2c9857bfaf43002bfc"
    dummy_data = b"SomeCode\x00/rustc/" + commit_hex.encode("ascii") + b"/library/core\x00"

    report = audit_rust_go_binary(dummy_data)
    assert report.rust.rustc_commit == commit_hex


def test_missing_metadata_reports_observed_absence():
    """Verify that absent sections report epistemic status observed_absence."""
    plain_binary = b"\x7fELF" + b"\x00" * 128
    report = audit_rust_go_binary(plain_binary)
    assert report.rust.has_audit_data is False
    assert report.rust.epistemic_status == "observed_absence"
    assert report.go.has_buildinfo is False
    assert report.go.epistemic_status == "observed_absence"


def test_corrupted_zlib_stream_handled_cleanly():
    """Verify corrupted zlib data does not raise unhandled exception."""
    shstrtab = b"\x00.shstrtab\x00.dep-v0\x00"
    dep_name_idx = shstrtab.find(b".dep-v0")
    shstr_name_idx = shstrtab.find(b".shstrtab")

    elf_hdr = bytearray(64)
    struct.pack_into("<4sBBBBB", elf_hdr, 0, b"\x7fELF", 2, 1, 1, 0, 0)
    struct.pack_into("<Q", elf_hdr, 40, 64)
    struct.pack_into("<H", elf_hdr, 58, 64)
    struct.pack_into("<H", elf_hdr, 60, 3)
    struct.pack_into("<H", elf_hdr, 62, 1)

    corrupt_zlib = b"\x78\x9c\xff\xff\x00\x00CorruptZlibPayload"
    sh_data_start = 64 + 3 * 64
    shstrtab_off = sh_data_start
    shstrtab_sz = len(shstrtab)
    dep_off = shstrtab_off + shstrtab_sz
    dep_sz = len(corrupt_zlib)

    sec0 = bytes(64)
    sec1 = bytearray(64)
    struct.pack_into("<I", sec1, 0, shstr_name_idx)
    struct.pack_into("<QQ", sec1, 24, shstrtab_off, shstrtab_sz)

    sec2 = bytearray(64)
    struct.pack_into("<I", sec2, 0, dep_name_idx)
    struct.pack_into("<QQ", sec2, 24, dep_off, dep_sz)

    full_binary = elf_hdr + sec0 + sec1 + sec2 + shstrtab + corrupt_zlib

    report = audit_rust_go_binary(full_binary)
    assert report.rust.has_audit_data is False
    assert any("dep-v0" in lim.lower() for lim in report.limitations)


def test_go_buildinfo_parsing():
    """Verify parsing of Go buildinfo magic signature and module lines."""
    go_buf = _build_mock_go_buildinfo()
    report = audit_rust_go_binary(go_buf)
    assert report.go.has_buildinfo is True
    assert report.go.go_version == "go1.22.4"
    assert report.go.main_path == "github.com/yuatemycat/superghidra-daemon"
    assert report.go.main_module is not None
    assert report.go.main_module.version == "v0.5.0"
    assert len(report.go.dependencies) >= 1
    assert report.go.dependencies[0].path == "github.com/google/uuid"
    assert report.go.dependencies[0].replacement == "github.com/forked/uuid"
    assert len(report.go.build_settings) >= 2
    settings_dict = {b.key: b.value for b in report.go.build_settings}
    assert settings_dict.get("-compiler") == "gc"
    assert settings_dict.get("vcs.revision") == "034ca64859a85fec"


@pytest.mark.parametrize("magic,expected_ver", [
    (PCLNTAB_MAGIC_116, "Go 1.16-1.17"),
    (PCLNTAB_MAGIC_118, "Go 1.18-1.19"),
    (PCLNTAB_MAGIC_120, "Go 1.20+"),
])
def test_go_pclntab_version_detection(magic: int, expected_ver: str):
    """Verify pclntab header parsing detects Go versions correctly."""
    # pclntab: magic(4), pad1(1), pad2(1), minLC(1), ptrSize(1), nfunc(4)
    pcln_hdr = struct.pack("<IBBBBI", magic, 0, 0, 1, 8, 42)
    dummy_data = b"DUMMY_CODE" + pcln_hdr + b"\x00" * 64

    report = audit_rust_go_binary(dummy_data)
    assert report.go.pclntab_version == expected_ver
    assert report.go.function_count == 42


def test_pe_binary_format_detection():
    """Verify PE header detection."""
    pe_hdr = bytearray(256)
    pe_hdr[0:2] = b"MZ"
    struct.pack_into("<I", pe_hdr, 0x3C, 0x80)
    pe_hdr[0x80:0x84] = b"PE\x00\x00"

    report = audit_rust_go_binary(bytes(pe_hdr))
    assert report.binary_format == "PE"


def test_macho_binary_format_detection():
    """Verify Mach-O header detection."""
    # MH_MAGIC_64 little endian
    hdr = struct.pack("<IIIIIIII", 0xFEEDFACF, 0x0100000C, 0, 2, 0, 0, 0, 0)
    report = audit_rust_go_binary(hdr)
    assert report.binary_format == "Mach-O"
    assert report.is_64bit is True


def test_to_dict_serialization():
    """Verify report serialization to JSON-compatible dictionary."""
    report = audit_rust_go_binary(b"\x00" * 64)
    d = report.to_dict()
    assert isinstance(d, dict)
    assert "binary_format" in d
    assert "rust" in d
    assert "go" in d
    assert "counts" in d["rust"]
    assert "counts" in d["go"]
