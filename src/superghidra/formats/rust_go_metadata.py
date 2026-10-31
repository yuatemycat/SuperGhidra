"""
rust_go_metadata.py
===================

Pure-Python Rust and Go static binary metadata recovery engine.
Recovers:
1. Rust crate dependency graphs, versions, and features from cargo-auditable
   .dep-v0 zlib-compressed JSON sections, plus /rustc/<hash>/ commit hashes.
2. Go compiler versions, module paths, dependency replacements, and VCS build
   settings from .go.buildinfo (\\xff Go buildinf:) signatures and pclntab headers.

Operates across ELF, PE, and Mach-O binaries without starting Ghidra.
"""

from __future__ import annotations

import json
import re
import struct
import zlib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Tuple

__all__ = [
    "RustCrateInfo",
    "CrateAuditReport",
    "GoModuleInfo",
    "GoBuildSetting",
    "GoBuildInfoReport",
    "RustGoReport",
    "audit_rust_go_binary",
]

DEFAULT_MAX_INPUT_BYTES = 64 * 1024 * 1024  # 64 MiB
MAX_ALLOWED_INPUT_BYTES = 1024 * 1024 * 1024  # 1 GiB

GO_BUILDINFO_MAGIC = b"\xff Go buildinf:"
PCLNTAB_MAGIC_115 = 0xFFFFFFFB
PCLNTAB_MAGIC_116 = 0xFFFFFFFA
PCLNTAB_MAGIC_118 = 0xFFFFFFF0
PCLNTAB_MAGIC_120 = 0xFFFFFFF1


@dataclass
class RustCrateInfo:
    name: str
    version: str
    source: str | None = None
    features: List[str] = field(default_factory=list)
    dependencies: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "version": self.version,
            "source": self.source,
            "features": self.features,
            "dependencies": self.dependencies,
        }


@dataclass
class CrateAuditReport:
    has_audit_data: bool
    package_name: str | None = None
    package_version: str | None = None
    rustc_commit: str | None = None
    crates: List[RustCrateInfo] = field(default_factory=list)
    counts: Dict[str, int] = field(default_factory=dict)
    epistemic_status: str = "observed"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "has_audit_data": self.has_audit_data,
            "package_name": self.package_name,
            "package_version": self.package_version,
            "rustc_commit": self.rustc_commit,
            "counts": self.counts,
            "crates": [c.to_dict() for c in self.crates],
            "epistemic_status": self.epistemic_status,
        }


@dataclass
class GoModuleInfo:
    path: str
    version: str | None = None
    sum: str | None = None
    replacement: str | None = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "path": self.path,
            "version": self.version,
            "sum": self.sum,
            "replacement": self.replacement,
        }


@dataclass
class GoBuildSetting:
    key: str
    value: str

    def to_dict(self) -> Dict[str, Any]:
        return {"key": self.key, "value": self.value}


@dataclass
class GoBuildInfoReport:
    has_buildinfo: bool
    go_version: str | None = None
    main_path: str | None = None
    main_module: GoModuleInfo | None = None
    dependencies: List[GoModuleInfo] = field(default_factory=list)
    build_settings: List[GoBuildSetting] = field(default_factory=list)
    pclntab_version: str | None = None
    function_count: int = 0
    counts: Dict[str, int] = field(default_factory=dict)
    epistemic_status: str = "observed"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "has_buildinfo": self.has_buildinfo,
            "go_version": self.go_version,
            "main_path": self.main_path,
            "main_module": self.main_module.to_dict() if self.main_module else None,
            "dependencies": [d.to_dict() for d in self.dependencies],
            "build_settings": [b.to_dict() for b in self.build_settings],
            "pclntab_version": self.pclntab_version,
            "function_count": self.function_count,
            "counts": self.counts,
            "epistemic_status": self.epistemic_status,
        }


@dataclass
class RustGoReport:
    binary_format: str  # "ELF", "PE", "Mach-O", "unknown"
    is_64bit: bool
    rust: CrateAuditReport
    go: GoBuildInfoReport
    limitations: List[str] = field(default_factory=list)
    epistemic_status: str = "observed"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "binary_format": self.binary_format,
            "is_64bit": self.is_64bit,
            "rust": self.rust.to_dict(),
            "go": self.go.to_dict(),
            "limitations": self.limitations,
            "epistemic_status": self.epistemic_status,
        }


# -----------------------------------------------------------------------------
# Binary Loader Helper (ELF, PE, Mach-O Section Finder)
# -----------------------------------------------------------------------------

def _find_sections(data: bytes) -> Dict[str, bytes]:
    """Finds named sections from ELF, PE, or Mach-O without starting Ghidra."""
    sections: Dict[str, bytes] = {}

    # 1. ELF
    if data.startswith(b"\x7fELF") and len(data) >= 64:
        is_64 = data[4] == 2
        endian = "<" if data[5] == 1 else ">"
        try:
            if is_64:
                shoff = struct.unpack_from(endian + "Q", data, 40)[0]
                shentsize = struct.unpack_from(endian + "H", data, 58)[0]
                shnum = struct.unpack_from(endian + "H", data, 60)[0]
                shstrndx = struct.unpack_from(endian + "H", data, 62)[0]
            else:
                shoff = struct.unpack_from(endian + "I", data, 32)[0]
                shentsize = struct.unpack_from(endian + "H", data, 46)[0]
                shnum = struct.unpack_from(endian + "H", data, 48)[0]
                shstrndx = struct.unpack_from(endian + "H", data, 50)[0]

            if shstrndx < shnum and shoff + (shstrndx + 1) * shentsize <= len(data):
                str_hdr_off = shoff + shstrndx * shentsize
                if is_64:
                    str_file_off, str_file_sz = struct.unpack_from(endian + "QQ", data, str_hdr_off + 24)
                else:
                    str_file_off, str_file_sz = struct.unpack_from(endian + "II", data, str_hdr_off + 16)
                shstrtab = data[str_file_off : str_file_off + str_file_sz]

                for i in range(shnum):
                    e_off = shoff + i * shentsize
                    if e_off + shentsize > len(data):
                        break
                    name_idx = struct.unpack_from(endian + "I", data, e_off)[0]
                    if is_64:
                        s_off, s_sz = struct.unpack_from(endian + "QQ", data, e_off + 24)
                    else:
                        s_off, s_sz = struct.unpack_from(endian + "II", data, e_off + 16)
                    if s_off + s_sz <= len(data):
                        # read cstr from shstrtab
                        end = shstrtab.find(b"\x00", name_idx)
                        sname = shstrtab[name_idx:end].decode("utf-8", errors="replace") if end != -1 else ""
                        if sname:
                            sections[sname] = data[s_off : s_off + s_sz]
        except Exception:
            pass

    # 2. PE
    elif data.startswith(b"MZ") and len(data) >= 64:
        try:
            pe_off = struct.unpack_from("<I", data, 0x3C)[0]
            if pe_off + 24 <= len(data) and data[pe_off : pe_off + 4] == b"PE\x00\x00":
                num_sects = struct.unpack_from("<H", data, pe_off + 6)[0]
                opt_hdr_sz = struct.unpack_from("<H", data, pe_off + 20)[0]
                sect_tbl_off = pe_off + 24 + opt_hdr_sz
                for i in range(min(num_sects, 96)):
                    s_off = sect_tbl_off + i * 40
                    if s_off + 40 > len(data):
                        break
                    sname_raw = data[s_off : s_off + 8].rstrip(b"\x00")
                    sname = sname_raw.decode("utf-8", errors="replace")
                    raw_data_sz, raw_data_ptr = struct.unpack_from("<II", data, s_off + 16)
                    if raw_data_ptr + raw_data_sz <= len(data):
                        sections[sname] = data[raw_data_ptr : raw_data_ptr + raw_data_sz]
        except Exception:
            pass

    # 3. Mach-O
    elif data[:4] in (b"\xfe\xed\xfa\xcf", b"\xcf\xfa\xed\xfe", b"\xfe\xed\xfa\xce", b"\xce\xfa\xed\xfe"):
        try:
            is_64 = data[:4] in (b"\xfe\xed\xfa\xcf", b"\xcf\xfa\xed\xfe")
            endian = "<" if data[:4] in (b"\xcf\xfa\xed\xfe", b"\xce\xfa\xed\xfe") else ">"
            ncmds = struct.unpack_from(endian + "I", data, 16)[0]
            hdr_sz = 32 if is_64 else 28
            curr_cmd = hdr_sz
            for _ in range(min(ncmds, 128)):
                if curr_cmd + 8 > len(data):
                    break
                cmd, cmdsz = struct.unpack_from(endian + "II", data, curr_cmd)
                if cmd in (1, 0x19):  # LC_SEGMENT or LC_SEGMENT_64
                    nsects = struct.unpack_from(endian + "I", data, curr_cmd + 64 if is_64 else curr_cmd + 48)[0]
                    sect_off = curr_cmd + (72 if is_64 else 56)
                    s_stride = 80 if is_64 else 68
                    for _ in range(min(nsects, 64)):
                        if sect_off + s_stride > len(data):
                            break
                        sec_name = data[sect_off : sect_off + 16].rstrip(b"\x00").decode("utf-8", errors="replace")
                        if is_64:
                            s_sz = struct.unpack_from(endian + "Q", data, sect_off + 40)[0]
                            f_off = struct.unpack_from(endian + "I", data, sect_off + 48)[0]
                        else:
                            s_sz = struct.unpack_from(endian + "I", data, sect_off + 36)[0]
                            f_off = struct.unpack_from(endian + "I", data, sect_off + 40)[0]
                        if f_off + s_sz <= len(data):
                            sec_bytes = data[f_off : f_off + s_sz]
                            sections[sec_name] = sec_bytes
                            if sec_name.startswith("__"):
                                norm_name = "." + sec_name[2:]
                                sections[norm_name] = sec_bytes
                                if "_" in norm_name:
                                    sections[norm_name.replace("_", ".")] = sec_bytes
                        sect_off += s_stride
                curr_cmd += cmdsz
        except Exception:
            pass

    return sections


# -----------------------------------------------------------------------------
# Rust Crate Recovery (.dep-v0 / cargo-auditable)
# -----------------------------------------------------------------------------

def _recover_rust_metadata(data: bytes, sections: Dict[str, bytes], limitations: List[str]) -> CrateAuditReport:
    """Parses .dep-v0 section and extracts Rust toolchain commit hashes."""
    dep_section: bytes | None = None
    for sname in (".dep-v0", ".dep_v0", "dep-v0", "rust_metadata", "__dep_v0"):
        if sname in sections:
            dep_section = sections[sname]
            break

    # If section not found via headers, search for zlib header pattern or embedded marker
    if dep_section is None:
        idx = data.find(b"cargo-auditable")
        if idx != -1:
            # Check for zlib stream near cargo-auditable
            # Or scan .rodata
            pass

    has_audit = False
    pkg_name: str | None = None
    pkg_ver: str | None = None
    crates: List[RustCrateInfo] = []

    if dep_section is not None and len(dep_section) > 0:
        try:
            # decompress zlib
            decomp = zlib.decompress(dep_section)
            payload = json.loads(decomp.decode("utf-8", errors="replace"))
            has_audit = True

            # cargo-auditable schema: {"packages": [...]}
            pkgs = payload.get("packages", [])
            for p in pkgs:
                name = p.get("name", "")
                version = p.get("version", "")
                source = p.get("source")
                features = p.get("features", [])
                dependencies = [str(d) for d in p.get("dependencies", [])]

                if p.get("root", False):
                    pkg_name = name
                    pkg_ver = version

                crates.append(
                    RustCrateInfo(
                        name=name,
                        version=version,
                        source=source,
                        features=features,
                        dependencies=dependencies,
                    )
                )
            if not pkg_name and crates:
                pkg_name = crates[0].name
                pkg_ver = crates[0].version
        except Exception as e:
            limitations.append(f"Failed to decode .dep-v0 payload: {e}")

    # Extract rustc commit hash from string tables or rodata: /rustc/<40-hex>/
    rustc_commit: str | None = None
    rustc_match = re.search(rb"/rustc/([0-9a-fA-F]{40})/", data)
    if rustc_match:
        rustc_commit = rustc_match.group(1).decode("ascii")

    counts = {
        "crates_count": len(crates),
        "has_audit_data": 1 if has_audit else 0,
    }

    # If .dep-v0 was missing, mark observed_absence (epistemic status)
    epistemic = "observed" if has_audit else "observed_absence"

    return CrateAuditReport(
        has_audit_data=has_audit,
        package_name=pkg_name,
        package_version=pkg_ver,
        rustc_commit=rustc_commit,
        crates=crates,
        counts=counts,
        epistemic_status=epistemic,
    )


# -----------------------------------------------------------------------------
# Go Metadata Recovery (.go.buildinfo & pclntab)
# -----------------------------------------------------------------------------

PCLNTAB_MAGIC_VERSIONS = {
    PCLNTAB_MAGIC_115: "Go 1.2-1.15",
    PCLNTAB_MAGIC_116: "Go 1.16-1.17",
    PCLNTAB_MAGIC_118: "Go 1.18-1.19",
    PCLNTAB_MAGIC_120: "Go 1.20+",
}


def _parse_pclntab_header(candidate: bytes) -> Tuple[str, int] | None:
    """
    Validates candidate bytes against the Go pcHeader contract:
    - magic (4 bytes): must be in PCLNTAB_MAGIC_VERSIONS
    - pad1 (byte 4): must be 0
    - pad2 (byte 5): must be 0
    - minLC (byte 6): must be in (1, 2, 4)
    - ptrSize (byte 7): must be in (4, 8)
    - nfunc (offset 8): uint64 if ptrSize == 8, uint32 if ptrSize == 4
    - nfunc range: 1 <= nfunc < 2_000_000

    Returns (version_string, function_count) if valid, or None if rejected.
    """
    if len(candidate) < 12:
        return None

    for endian in ("<", ">"):
        magic = struct.unpack_from(endian + "I", candidate, 0)[0]
        if magic not in PCLNTAB_MAGIC_VERSIONS:
            continue

        pad1 = candidate[4]
        pad2 = candidate[5]
        if pad1 != 0 or pad2 != 0:
            continue

        min_lc = candidate[6]
        if min_lc not in (1, 2, 4):
            continue

        ptr_size = candidate[7]
        if ptr_size not in (4, 8):
            continue

        if ptr_size == 8:
            if len(candidate) < 16:
                continue
            nfunc = struct.unpack_from(endian + "Q", candidate, 8)[0]
        else:
            nfunc = struct.unpack_from(endian + "I", candidate, 8)[0]

        if not (1 <= nfunc < 2_000_000):
            continue

        return PCLNTAB_MAGIC_VERSIONS[magic], nfunc

    return None


def _parse_go_modinfo(raw_text: str) -> Tuple[str | None, GoModuleInfo | None, List[GoModuleInfo], List[GoBuildSetting]]:
    """Parses standard Go buildinfo key-value module lines."""
    main_path: str | None = None
    main_mod: GoModuleInfo | None = None
    deps: List[GoModuleInfo] = []
    settings: List[GoBuildSetting] = []

    for line in raw_text.splitlines():
        line = line.strip()
        if not line:
            continue
        parts = line.split(maxsplit=3)
        tag = parts[0]
        if tag == "path" and len(parts) >= 2:
            main_path = parts[1]
        elif tag == "mod" and len(parts) >= 2:
            mpath = parts[1]
            mver = parts[2] if len(parts) >= 3 else None
            msum = parts[3] if len(parts) >= 4 else None
            main_mod = GoModuleInfo(path=mpath, version=mver, sum=msum)
        elif tag == "dep" and len(parts) >= 2:
            dpath = parts[1]
            dver = parts[2] if len(parts) >= 3 else None
            dsum = parts[3] if len(parts) >= 4 else None
            deps.append(GoModuleInfo(path=dpath, version=dver, sum=dsum))
        elif tag == "=>" and deps:
            # replacement for preceding dependency
            deps[-1].replacement = parts[1]
        elif tag == "build" and len(parts) >= 2:
            key_val = parts[1]
            if "=" in key_val:
                k, v = key_val.split("=", 1)
                settings.append(GoBuildSetting(key=k, value=v))
            else:
                settings.append(GoBuildSetting(key=key_val, value=""))

    return main_path, main_mod, deps, settings


def _recover_go_metadata(data: bytes, sections: Dict[str, bytes], limitations: List[str]) -> GoBuildInfoReport:
    """Locates and parses Go buildinfo signature and pclntab headers."""
    has_buildinfo = False
    go_version: str | None = None
    main_path: str | None = None
    main_mod: GoModuleInfo | None = None
    deps: List[GoModuleInfo] = []
    settings: List[GoBuildSetting] = []
    pclntab_ver: str | None = None
    func_count: int = 0

    # 1. Search for \xff Go buildinf:
    pos = data.find(GO_BUILDINFO_MAGIC)
    if pos != -1 and pos + 32 <= len(data):
        has_buildinfo = True
        flags = data[pos + 14]
        endian = ">" if (flags & 2) != 0 else "<"
        ptr_size = 4 if (flags & 1) == 0 else 8

        # After magic (14 bytes) and flags (2 bytes) = 16 bytes:
        # Go 1.18+ build info contains inline length-prefixed strings or pointers
        # In standard Go runtime:
        # [0:14] Magic: "\xff Go buildinf:"
        # [14] ptrSize/flags
        # [16:16+ptrSize] ptr to version
        # [16+ptrSize:16+2*ptrSize] ptr to modinfo
        #
        # If the binary has .go.buildinfo section or contiguous string data:
        # Search forward for "\x00go1." or "\xff"
        v_idx = data.find(b"go1.", pos)
        if v_idx != -1 and v_idx - pos < 512:
            candidate_chunk = data[v_idx : min(len(data), v_idx + 64)]
            # Go version pattern: e.g. go1.21.3, go1.22rc1, go1.18-devel
            m = re.match(rb"^(go[0-9]+(?:\.[0-9]+)+(?:(?:rc|beta|alpha)[0-9]+|-[a-zA-Z0-9.:_-]+)?)", candidate_chunk)
            if m:
                ver_cand = m.group(1).decode("ascii", errors="replace").rstrip(".-_")
                if len(ver_cand) <= 64:
                    go_version = ver_cand
            else:
                # Check for 0x00 termination within 32 bytes max
                end_v = candidate_chunk.find(b"\x00")
                if 0 < end_v <= 32:
                    ver_cand = candidate_chunk[:end_v].decode("ascii", errors="replace").rstrip(".-_")
                    if re.match(r"^go[0-9]+", ver_cand) and len(ver_cand) <= 64:
                        go_version = ver_cand

        # Search for module text "\xff" or "path\t"
        mod_start = data.find(b"path\t", pos)
        if mod_start == -1:
            mod_start = data.find(b"path ", pos)

        if mod_start != -1 and mod_start - pos < 4096:
            # Terminated by 0x00 or \xff
            mod_end = data.find(b"\x00", mod_start)
            if mod_end == -1 or mod_end - mod_start > 32768:
                mod_end = min(len(data), mod_start + 8192)
            raw_text = data[mod_start:mod_end].decode("utf-8", errors="replace")
            main_path, main_mod, deps, settings = _parse_go_modinfo(raw_text)

    # 2. Check for pclntab header in sections (.gopclntab, pclntab, __gopclntab)
    pcln_bytes = (
        sections.get(".gopclntab")
        or sections.get("pclntab")
        or sections.get("__gopclntab")
    )
    if pcln_bytes is not None and len(pcln_bytes) >= 12:
        parsed = _parse_pclntab_header(pcln_bytes)
        if parsed is not None:
            pclntab_ver, func_count = parsed

    # If not found or invalid in sections, scan raw data for valid pcHeader
    if pclntab_ver is None:
        for magic_val in (PCLNTAB_MAGIC_120, PCLNTAB_MAGIC_118, PCLNTAB_MAGIC_116, PCLNTAB_MAGIC_115):
            for endian in ("<", ">"):
                magic_bytes = struct.pack(endian + "I", magic_val)
                pos_scan = 0
                while True:
                    p_idx = data.find(magic_bytes, pos_scan)
                    if p_idx == -1:
                        break
                    if p_idx + 12 <= len(data):
                        parsed = _parse_pclntab_header(data[p_idx : min(len(data), p_idx + 64)])
                        if parsed is not None:
                            pclntab_ver, func_count = parsed
                            break
                    pos_scan = p_idx + 1
                if pclntab_ver is not None:
                    break
            if pclntab_ver is not None:
                break

    counts = {
        "dependencies": len(deps),
        "build_settings": len(settings),
        "functions": func_count,
    }

    epistemic = "observed" if has_buildinfo or pclntab_ver else "observed_absence"

    return GoBuildInfoReport(
        has_buildinfo=has_buildinfo,
        go_version=go_version,
        main_path=main_path,
        main_module=main_mod,
        dependencies=deps,
        build_settings=settings,
        pclntab_version=pclntab_ver,
        function_count=func_count,
        counts=counts,
        epistemic_status=epistemic,
    )


# -----------------------------------------------------------------------------
# Main Public Entrypoint
# -----------------------------------------------------------------------------

def audit_rust_go_binary(
    binary_path_or_bytes: str | Path | bytes,
    max_input_bytes: int = DEFAULT_MAX_INPUT_BYTES,
) -> RustGoReport:
    """
    Audits compiled Rust and Go binaries to recover crate dependencies,
    compiler toolchain commits, module paths, and Go build settings.
    """
    if max_input_bytes > MAX_ALLOWED_INPUT_BYTES:
        max_input_bytes = MAX_ALLOWED_INPUT_BYTES

    if isinstance(binary_path_or_bytes, (str, Path)):
        p = Path(binary_path_or_bytes)
        if not p.is_file():
            raise FileNotFoundError(f"Binary file not found: {p}")
        sz = p.stat().st_size
        if sz > max_input_bytes:
            raise ValueError(
                f"Binary size {sz} exceeds admission budget of {max_input_bytes} bytes"
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

    limitations: List[str] = []

    # Format detection
    fmt = "unknown"
    is_64 = True
    if data.startswith(b"\x7fELF"):
        fmt = "ELF"
        is_64 = len(data) > 4 and data[4] == 2
    elif data.startswith(b"MZ"):
        fmt = "PE"
    elif data[:4] in (b"\xfe\xed\xfa\xcf", b"\xcf\xfa\xed\xfe", b"\xfe\xed\xfa\xce", b"\xce\xfa\xed\xfe"):
        fmt = "Mach-O"
        is_64 = data[:4] in (b"\xfe\xed\xfa\xcf", b"\xcf\xfa\xed\xfe")

    sections = _find_sections(data)

    rust_report = _recover_rust_metadata(data, sections, limitations)
    go_report = _recover_go_metadata(data, sections, limitations)

    epistemic = "observed"
    if not rust_report.has_audit_data and not go_report.has_buildinfo and not go_report.pclntab_version:
        epistemic = "observed_absence"

    return RustGoReport(
        binary_format=fmt,
        is_64bit=is_64,
        rust=rust_report,
        go=go_report,
        limitations=limitations,
        epistemic_status=epistemic,
    )


audit_crates_and_go = audit_rust_go_binary


# Backward-compatibility alias
RustGoAuditReport = CrateAuditReport
