"""
superghidra.formats.ida_til_importer
===================================

Extracts and ingests Hex-Rays IDA Pro Type Information Libraries (.til) into
SuperGhidra type records, C header archives, and StructLayoutSpec catalogs.

Closes Gap 6 (Header Parsing & Type Library Engine Robustness) by bridging
IDA's rich, pre-compiled platform types (Windows SDKs, Android NDKs, POSIX,
macOS XNU) into SuperGhidra's type analysis pipelines.
"""

from __future__ import annotations

import os
from pathlib import Path
import re
import subprocess
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple, Union


DEFAULT_IDA_PATHS = [
    r"E:\01_Apps\Installed\IDA_PRO",
    r"C:\Program Files\IDA Pro 8.4",
    r"C:\Program Files\IDA Pro 8.3",
    r"C:\Program Files\IDA Pro 7.7",
]


def find_ida_install(custom_path: Optional[str] = None) -> Optional[Path]:
    """Locate the IDA Pro root directory."""
    candidates = []
    if custom_path:
        candidates.append(Path(custom_path))
    env_dir = os.environ.get("IDA_DIR") or os.environ.get("IDADIR")
    if env_dir:
        candidates.append(Path(env_dir))
    for p in DEFAULT_IDA_PATHS:
        candidates.append(Path(p))

    for p in candidates:
        if p.is_dir() and ((p / "tilib.exe").is_file() or (p / "tools" / "tilib" / "tilib.exe").is_file() or (p / "ida.dll").is_file()):
            return p.resolve()
    return None


def find_tilib(ida_dir: Optional[Path] = None) -> Optional[Path]:
    """Locate the Hex-Rays tilib.exe utility."""
    root = ida_dir or find_ida_install()
    if not root:
        return None
    options = [
        root / "tools" / "tilib" / "tilib.exe",
        root / "tilib.exe",
    ]
    for opt in options:
        if opt.is_file():
            return opt.resolve()
    return None


def list_available_tils(ida_dir: Optional[Path] = None) -> Dict[str, List[Path]]:
    """Enumerate all .til files grouped by architecture / platform directory."""
    root = ida_dir or find_ida_install()
    if not root:
        return {}
    til_dir = root / "til"
    if not til_dir.is_dir():
        return {}

    categorized: Dict[str, List[Path]] = {}
    for p in til_dir.rglob("*.til"):
        rel = p.relative_to(til_dir)
        arch = rel.parts[0] if len(rel.parts) > 1 else "root"
        categorized.setdefault(arch, []).append(p.resolve())
    return categorized


def dump_til_c_code(til_path: Union[str, Path], tilib_path: Optional[Union[str, Path]] = None) -> str:
    """Run `tilib.exe -lc` to dump declarations from a .til file as C source."""
    til = Path(til_path)
    if not til.is_file():
        raise FileNotFoundError(f"TIL file not found: {til}")

    tilib = Path(tilib_path) if tilib_path else find_tilib(til.parents[2] if len(til.parents) >= 3 else None)
    if not tilib or not tilib.is_file():
        tilib = find_tilib()
    if not tilib or not tilib.is_file():
        raise FileNotFoundError("Hex-Rays tilib.exe not found in IDA Pro installation.")

    cmd = [str(tilib), "-lc", str(til)]
    proc = subprocess.run(cmd, capture_output=True, text=True, errors="replace")
    if not proc.stdout and proc.returncode != 0 and proc.stderr:
        raise RuntimeError(f"tilib failed with code {proc.returncode}: {proc.stderr}")
    return proc.stdout


def sanitize_ida_c_declarations(raw_c: str) -> str:
    """
    Normalize Hex-Rays C syntax extensions to clean ANSI / C99 / C11 declarations.
    Converts MSVC/IDA intrinsics, integer literals, and enum modifiers.
    """
    text = raw_c

    # Strip IDA comments and headers
    text = re.sub(r"^//.*$", "", text, flags=re.MULTILINE)

    # Normalize integer types
    text = re.sub(r"\bunsigned\s+__int64\b", "uint64_t", text)
    text = re.sub(r"\b__int64\b", "int64_t", text)
    text = re.sub(r"\bunsigned\s+__int32\b", "uint32_t", text)
    text = re.sub(r"\b__int32\b", "int32_t", text)
    text = re.sub(r"\bunsigned\s+__int16\b", "uint16_t", text)
    text = re.sub(r"\b__int16\b", "int16_t", text)
    text = re.sub(r"\bunsigned\s+__int8\b", "uint8_t", text)
    text = re.sub(r"\b__int8\b", "int8_t", text)

    # Normalize enum modifiers: enum __dec FOO { ... }; or enum __hex FOO { ... };
    text = re.sub(r"\benum\s+__(?:dec|hex)\b", "enum", text)

    # Normalize integer literal suffixes
    text = re.sub(r"([0-9A-Fa-f]+)(?:Ui64|UI64|uI64)\b", r"\1ULL", text)
    text = re.sub(r"([0-9A-Fa-f]+)(?:i64|I64)\b", r"\1LL", text)

    return text


@dataclass
class TilEnumMember:
    name: str
    value: int
    raw_value: str


@dataclass
class TilEnum:
    name: str
    base_type: str
    members: Dict[str, TilEnumMember] = field(default_factory=dict)


@dataclass
class TilField:
    name: str
    c_type: str
    array_dim: Optional[str] = None


@dataclass
class TilStruct:
    kind: str  # struct or union
    name: str
    fields: List[TilField] = field(default_factory=list)


@dataclass
class TilReport:
    til_path: str
    enums: Dict[str, TilEnum] = field(default_factory=dict)
    structs: Dict[str, TilStruct] = field(default_factory=dict)
    typedefs: Dict[str, str] = field(default_factory=dict)

    @property
    def total_types(self) -> int:
        return len(self.enums) + len(self.structs) + len(self.typedefs)


def parse_til_declarations(c_code: str, til_path: str = "") -> TilReport:
    """Parse sanitized C declarations dumped from a .til file."""
    sanitized = sanitize_ida_c_declarations(c_code)
    report = TilReport(til_path=til_path)

    # 1. Parse Enums: enum [name] [: base_type] { member = val, ... };
    enum_pat = re.compile(
        r"\benum\s+([A-Za-z0-9_$]+)?(?:\s*:\s*([A-Za-z0-9_]+))?\s*\{([^}]*)\}\s*;",
        re.MULTILINE | re.DOTALL,
    )
    for m in enum_pat.finditer(sanitized):
        name = m.group(1) or f"anon_enum_{m.start():x}"
        base_type = m.group(2) or "int"
        body = m.group(3)
        enum_obj = TilEnum(name=name, base_type=base_type)

        for item in body.split(","):
            item = item.strip()
            if not item:
                continue
            if "=" in item:
                m_name, m_val = item.split("=", 1)
                m_name = m_name.strip()
                m_val = m_val.strip()
                try:
                    val_clean = m_val.rstrip("uULliI64")
                    val_int = int(val_clean, 0)
                except ValueError:
                    val_int = 0
                enum_obj.members[m_name] = TilEnumMember(name=m_name, value=val_int, raw_value=m_val)
            else:
                enum_obj.members[item] = TilEnumMember(name=item, value=0, raw_value="0")

        report.enums[name] = enum_obj

    # 2. Parse Structs and Unions: (struct|union) [name] { type member; ... };
    struct_pat = re.compile(
        r"\b(struct|union)\s+([A-Za-z0-9_$]+)\s*\{([^}]*)\}\s*;",
        re.MULTILINE | re.DOTALL,
    )
    for m in struct_pat.finditer(sanitized):
        kind = m.group(1)
        name = m.group(2)
        body = m.group(3)
        struct_obj = TilStruct(kind=kind, name=name)

        for stmt in body.split(";"):
            stmt = stmt.strip()
            if not stmt:
                continue
            # Simple declarator: type [*] name [ [dim] ];
            parts = stmt.split()
            if len(parts) >= 2:
                field_name = parts[-1]
                field_type = " ".join(parts[:-1])
                array_dim = None
                if "[" in field_name:
                    fn, dim = field_name.split("[", 1)
                    field_name = fn.strip()
                    array_dim = dim.rstrip("]").strip()
                struct_obj.fields.append(TilField(name=field_name, c_type=field_type, array_dim=array_dim))

        report.structs[name] = struct_obj

    # 3. Parse Typedefs: typedef ... name;
    typedef_pat = re.compile(r"\btypedef\s+([^;]+)\s+([A-Za-z0-9_$]+)\s*;", re.MULTILINE)
    for m in typedef_pat.finditer(sanitized):
        target = m.group(1).strip()
        alias = m.group(2).strip()
        report.typedefs[alias] = target

    return report


def import_til(til_path: Union[str, Path], tilib_path: Optional[Union[str, Path]] = None) -> TilReport:
    """High-level function: dump and parse an IDA .til file into a TilReport."""
    c_code = dump_til_c_code(til_path, tilib_path=tilib_path)
    return parse_til_declarations(c_code, til_path=str(til_path))


def export_clean_header(til_path: Union[str, Path], output_header: Union[str, Path]) -> int:
    """Dump a .til file and write out a fully normalized, compilable C header file."""
    c_code = dump_til_c_code(til_path)
    sanitized = sanitize_ida_c_declarations(c_code)
    header_content = (
        "/* Generated by SuperGhidra IDA TIL Importer */\n"
        "#pragma once\n"
        "#include <stdint.h>\n"
        "#include <stddef.h>\n"
        "#include <stdbool.h>\n\n"
        f"{sanitized}\n"
    )
    out = Path(output_header)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(header_content, encoding="utf-8")
    return len(header_content)


def import_type_library(
    target: Union[str, Path],
    output_header: Optional[Union[str, Path]] = None,
    tilib_path: Optional[Union[str, Path]] = None,
) -> Dict[str, Any]:
    """Import and sanitize an IDA TIL library, or auto-resolve TIL for a binary target."""
    target_str = str(target)
    target_path = Path(target_str)

    if target_path.is_file() and target_str.lower().endswith(".til"):
        report = import_til(target_path, tilib_path=tilib_path)
        til_path_str = str(target_path)
        if output_header:
            export_clean_header(target_path, output_header)
    elif "{" in target_str or ";" in target_str or "\n" in target_str:
        report = parse_til_declarations(target_str, til_path="synthetic")
        til_path_str = "synthetic"
    elif target_path.is_file():
        # Target is a binary file (PE/ELF/Mach-O); discover appropriate TIL
        from superghidra.formats.binary_loader import load_binary
        tils = list_available_tils()
        found_til = None
        try:
            img = load_binary(target_str)
            if img.arch in ("x86_64", "x86"):
                pc_tils = [p for p in tils.get("pc", []) if "mssdk" in p.name.lower() or "ntapi" in p.name.lower()]
                if img.bits == 64:
                    win10_64 = [p for p in pc_tils if "64_win10" in p.name.lower()]
                    found_til = win10_64[0] if win10_64 else (pc_tils[0] if pc_tils else None)
                else:
                    win_32 = [p for p in pc_tils if "64" not in p.name.lower()]
                    found_til = win_32[0] if win_32 else (pc_tils[0] if pc_tils else None)
            elif img.arch in ("arm", "arm64"):
                arm_tils = tils.get("arm", [])
                found_til = arm_tils[0] if arm_tils else None
            elif not found_til:
                arch_candidates = tils.get(img.arch, [])
                if arch_candidates:
                    found_til = arch_candidates[0]
        except Exception:
            pass

        if found_til and found_til.is_file():
            report = import_til(found_til, tilib_path=tilib_path)
            til_path_str = str(found_til)
            if output_header:
                export_clean_header(found_til, output_header)
        else:
            return {
                "target": target_str,
                "til_path": None,
                "total_types": 0,
                "enum_count": 0,
                "struct_count": 0,
                "typedef_count": 0,
                "enums": {},
                "structs": {},
                "typedefs": {},
                "header_path": None,
                "success": False,
                "reason": "No compatible TIL found for binary target",
            }
    else:
        # Fallback empty parse
        report = parse_til_declarations(target_str, til_path=target_str)
        til_path_str = target_str

    return {
        "target": target_str,
        "til_path": til_path_str,
        "total_types": report.total_types,
        "enum_count": len(report.enums),
        "struct_count": len(report.structs),
        "typedef_count": len(report.typedefs),
        "enums": {name: list(e.members.keys()) for name, e in report.enums.items()},
        "structs": {name: [f.name for f in s.fields] for name, s in report.structs.items()},
        "typedefs": dict(report.typedefs),
        "header_path": str(output_header) if output_header else None,
        "success": True,
    }

