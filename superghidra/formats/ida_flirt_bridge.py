"""
superghidra.formats.ida_flirt_bridge
====================================

Extracts, parses, and matches Hex-Rays IDA Pro Fast Library Identification
and Recognition Technology (FLIRT) signatures (.sig) inside SuperGhidra.

Closes Gap 5 (Automated Library Identification / FLIRT vs FID) and implements
Roadmap Tier 3 U11 by allowing SuperGhidra to recognize stripped runtime
functions (C/C++ runtime, STL, Borland, POSIX) using IDA's signature library.
"""

from __future__ import annotations

import os
from pathlib import Path
import re
import subprocess
import tempfile
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence, Tuple, Union

from superghidra.formats.ida_til_importer import find_ida_install


def find_dumpsig(ida_dir: Optional[Union[str, Path]] = None) -> Optional[Path]:
    """Locate the Hex-Rays dumpsig.exe utility."""
    root = Path(ida_dir) if ida_dir else find_ida_install()
    if not root:
        return None
    candidates = [
        root / "tools" / "flair" / "dumpsig.exe",
        root / "dumpsig.exe",
        root / "flair" / "dumpsig.exe",
    ]
    for c in candidates:
        if c.is_file():
            return c.resolve()
    return None


def list_available_sigs(ida_dir: Optional[Union[str, Path]] = None) -> Dict[str, List[Path]]:
    """Enumerate all .sig files grouped by architecture directory."""
    root = Path(ida_dir) if ida_dir else find_ida_install()
    if not root:
        return {}
    sig_dir = root / "sig"
    if not sig_dir.is_dir():
        return {}

    categorized: Dict[str, List[Path]] = {}
    for p in sig_dir.rglob("*.sig"):
        rel = p.relative_to(sig_dir)
        arch = rel.parts[0] if len(rel.parts) > 1 else "root"
        categorized.setdefault(arch, []).append(p.resolve())
    return categorized


@dataclass
class FlirtSymbol:
    offset: int
    name: str


@dataclass
class FlirtPattern:
    pattern_hex: str
    expected_bytes: bytes
    mask_bytes: bytes
    symbols: List[FlirtSymbol] = field(default_factory=list)
    sig_source: str = ""

    @property
    def byte_length(self) -> int:
        return len(self.expected_bytes)

    def matches(self, target_bytes: bytes, target_offset: int = 0) -> bool:
        """Check if target_bytes at target_offset match this pattern with wildcards."""
        plen = len(self.expected_bytes)
        if len(target_bytes) - target_offset < plen:
            return False
        chunk = target_bytes[target_offset : target_offset + plen]
        for i in range(plen):
            m = self.mask_bytes[i]
            if m and (chunk[i] & m) != self.expected_bytes[i]:
                return False
        return True


@dataclass
class FlirtMatch:
    symbol_name: str
    offset_in_module: int
    pattern: FlirtPattern
    matched_address: Optional[int] = None
    confidence: float = 1.0


def parse_flirt_pattern_string(pat_hex: str) -> Tuple[bytes, bytes]:
    """
    Parse a pattern hex string like '558BEC..E8....59' into (expected_bytes, mask_bytes).
    '..' or '.' wildcards become 0x00 with mask 0x00; hex pairs become their value with mask 0xFF.
    """
    clean = pat_hex.strip()
    expected = bytearray()
    mask = bytearray()

    idx = 0
    while idx < len(clean):
        if clean[idx : idx + 2] == "..":
            expected.append(0x00)
            mask.append(0x00)
            idx += 2
        elif clean[idx] == ".":
            expected.append(0x00)
            mask.append(0x00)
            idx += 1
        elif idx + 1 < len(clean):
            try:
                b = int(clean[idx : idx + 2], 16)
                expected.append(b)
                mask.append(0xFF)
            except ValueError:
                expected.append(0x00)
                mask.append(0x00)
            idx += 2
        else:
            break
    return bytes(expected), bytes(mask)


def dump_flirt_file(sig_path: Union[str, Path], dumpsig_path: Optional[Union[str, Path]] = None) -> str:
    """Execute `dumpsig.exe -f <sig>` into a temporary file and return the text."""
    sig = Path(sig_path)
    if not sig.is_file():
        raise FileNotFoundError(f"Signature file not found: {sig}")

    dumpsig = Path(dumpsig_path) if dumpsig_path else find_dumpsig()
    if not dumpsig or not dumpsig.is_file():
        raise FileNotFoundError("dumpsig.exe not found in IDA Pro installation.")

    with tempfile.NamedTemporaryFile(suffix=".txt", delete=False) as tmp:
        tmp_name = tmp.name

    try:
        cmd = [str(dumpsig), "-f", str(sig), tmp_name]
        proc = subprocess.run(cmd, capture_output=True, text=True, errors="replace")
        if os.path.exists(tmp_name) and os.path.getsize(tmp_name) > 0:
            with open(tmp_name, "r", encoding="utf-8", errors="replace") as f:
                return f.read()
        return proc.stdout or ""
    finally:
        if os.path.exists(tmp_name):
            try:
                os.remove(tmp_name)
            except OSError:
                pass


def parse_flirt_dump(dump_text: str, sig_source: str = "") -> List[FlirtPattern]:
    """Parse flat dumpsig output into FlirtPattern objects."""
    patterns: List[FlirtPattern] = []

    blocks = re.findall(r"Pattern:\s*([0-9A-Fa-f.]+)\s*\n((?:\t[^\n]+\n)+)", dump_text)
    for pat_hex, sym_block in blocks:
        expected, mask = parse_flirt_pattern_string(pat_hex)
        if not expected:
            continue

        symbols: List[FlirtSymbol] = []
        for m in re.finditer(r"([0-9A-Fa-f]{4}):([^\s\n]+)", sym_block):
            off_hex, name = m.group(1), m.group(2)
            if name and name != "?":
                try:
                    off_val = int(off_hex, 16)
                except ValueError:
                    off_val = 0
                symbols.append(FlirtSymbol(offset=off_val, name=name))

        if symbols:
            patterns.append(
                FlirtPattern(
                    pattern_hex=pat_hex,
                    expected_bytes=expected,
                    mask_bytes=mask,
                    symbols=symbols,
                    sig_source=sig_source,
                )
            )
    return patterns


class FlirtSignatureIndex:
    """
    Fast, prefix-indexed pattern matcher for FLIRT signatures.
    Supports sub-millisecond matching of unknown binary functions against
    thousands of pre-compiled IDA signatures.
    """

    def __init__(self) -> None:
        self.patterns: List[FlirtPattern] = []
        # Prefix lookup table: 2-byte prefix -> list of FlirtPatterns
        self._prefix_table: Dict[Tuple[int, int], List[FlirtPattern]] = {}
        self._unmasked_patterns: List[FlirtPattern] = []

    def add_pattern(self, pattern: FlirtPattern) -> None:
        self.patterns.append(pattern)
        if len(pattern.mask_bytes) >= 2 and pattern.mask_bytes[0] == 0xFF and pattern.mask_bytes[1] == 0xFF:
            key = (pattern.expected_bytes[0], pattern.expected_bytes[1])
            self._prefix_table.setdefault(key, []).append(pattern)
        else:
            self._unmasked_patterns.append(pattern)

    def load_sig_file(self, sig_path: Union[str, Path], dumpsig_path: Optional[Union[str, Path]] = None) -> int:
        """Load and index all patterns from an IDA .sig file."""
        sig = Path(sig_path)
        text = dump_flirt_file(sig, dumpsig_path=dumpsig_path)
        pats = parse_flirt_dump(text, sig_source=sig.name)
        for p in pats:
            self.add_pattern(p)
        return len(pats)

    def match_bytes(self, code_bytes: bytes, offset: int = 0) -> List[FlirtMatch]:
        """Match code bytes at offset against all indexed signatures."""
        if len(code_bytes) - offset < 2:
            return []

        key = (code_bytes[offset], code_bytes[offset + 1])
        candidates = self._prefix_table.get(key, []) + self._unmasked_patterns

        matches: List[FlirtMatch] = []
        for pat in candidates:
            if pat.matches(code_bytes, target_offset=offset):
                for sym in pat.symbols:
                    matches.append(
                        FlirtMatch(
                            symbol_name=sym.name,
                            offset_in_module=sym.offset,
                            pattern=pat,
                        )
                    )
        return matches

    def match_function_prologue(self, prologue: bytes) -> Optional[str]:
        """Return the best matching symbol name for a function prologue, or None."""
        matches = self.match_bytes(prologue, offset=0)
        if not matches:
            return None
        # Return the symbol at offset 0 (the function entry point)
        for m in matches:
            if m.offset_in_module == 0:
                return m.symbol_name
        return matches[0].symbol_name


def match_flirt_signatures(
    binary_path: Union[str, Path],
    sig_path: Optional[Union[str, Path]] = None,
    max_matches: int = 100,
) -> Dict[str, Any]:
    """Match binary functions against FLIRT signatures without opening a Ghidra .rep."""
    from superghidra.formats.binary_loader import load_binary

    img = load_binary(str(binary_path))
    index = FlirtSignatureIndex()

    if sig_path:
        sp = Path(sig_path)
        if sp.is_file():
            index.load_sig_file(sp)
        elif sp.is_dir():
            for p in sp.glob("*.sig"):
                index.load_sig_file(p)
        elif isinstance(sig_path, str) and ("Pattern:" in sig_path or "\t" in sig_path):
            pats = parse_flirt_dump(sig_path, sig_source="synthetic")
            for p in pats:
                index.add_pattern(p)
    else:
        arch_sigs = list_available_sigs()
        target_archs = []
        if img.arch in ("x86", "x86_64"):
            target_archs = ["pc", "root"]
        elif img.arch in ("arm", "arm64"):
            target_archs = ["arm", "arm64", "root"]
        else:
            target_archs = [img.arch, "root"]
        loaded = 0
        for arch in target_archs:
            for p in arch_sigs.get(arch, []):
                try:
                    index.load_sig_file(p)
                    loaded += 1
                    if loaded >= 5:
                        break
                except Exception:
                    pass
            if loaded:
                break

    candidates: List[int] = []
    if img.function_starts:
        candidates.extend(img.function_starts)
    for exp in img.exports:
        if exp.address and exp.address not in candidates:
            candidates.append(exp.address)
    if img.entry and img.entry not in candidates:
        candidates.append(img.entry)

    matches: List[Dict[str, Any]] = []
    scanned_count = 0

    if candidates:
        for va in candidates:
            scanned_count += 1
            prologue = img.read_va(va, 64)
            if not prologue:
                continue
            m = index.match_function_prologue(prologue)
            if m:
                matches.append({
                    "address": va,
                    "rva": img.va_to_rva(va),
                    "symbol_name": m,
                    "confidence": 1.0,
                })
                if len(matches) >= max_matches:
                    break
    else:
        for sec_va, code in img.code_regions():
            step = 4 if img.arch in ("arm", "arm64", "riscv32", "riscv64", "mips", "mips64") else 1
            limit = max(0, len(code) - 16)
            for off in range(0, limit, step):
                scanned_count += 1
                m = index.match_function_prologue(code[off : off + 64])
                if m:
                    va = sec_va + off
                    matches.append({
                        "address": va,
                        "rva": img.va_to_rva(va),
                        "symbol_name": m,
                        "confidence": 1.0,
                    })
                    if len(matches) >= max_matches:
                        break
            if len(matches) >= max_matches:
                break

    return {
        "binary_path": str(img.path or binary_path),
        "sig_path": str(sig_path) if sig_path else None,
        "patterns_loaded": len(index.patterns),
        "scanned_functions": scanned_count,
        "matched_count": len(matches),
        "matches": matches,
    }

