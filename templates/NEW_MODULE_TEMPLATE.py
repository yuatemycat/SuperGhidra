#!/usr/bin/env python3
"""
<module_name>.py — <Concise One-Line Summary of Module Purpose>.

Canonical Location: `superghidra.<domain>.<module_name>`
Root Shim: `<module_name>.py`

Architectural Context:
  - Domain: `<domain>` (see `superghidra/<domain>/README.md`)
  - Key Invariants:
    1. Zero-JVM or bounded-resource execution with deterministic fallback.
    2. Structured dataclasses with `.to_dict()` serialization for MCP/CLI transport.
    3. Explicit error types and logging without silent exception swallowing.
"""

from __future__ import annotations

import argparse
import json
import logging
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple, Union

logger = logging.getLogger(__name__)

__all__ = [
    "ModuleDomainError",
    "AnalysisConfig",
    "AnalysisItem",
    "AnalysisReport",
    "DomainAnalyzer",
    "run_analysis",
]


# ==============================================================================
# Exceptions
# ==============================================================================


class ModuleDomainError(RuntimeError):
    """Raised when a domain invariant or input validation contract is violated."""


# ==============================================================================
# Data Structures
# ==============================================================================


@dataclass(frozen=True)
class AnalysisConfig:
    """Configuration parameters for `DomainAnalyzer`."""

    image_base: int = 0x100000
    max_items: int = 1000
    strict_verification: bool = True

    def validate(self) -> None:
        """Validates configuration bounds before execution."""
        if self.image_base < 0:
            raise ValueError(f"image_base must be non-negative, got {self.image_base:#x}")
        if self.max_items <= 0:
            raise ValueError(f"max_items must be > 0, got {self.max_items}")


@dataclass
class AnalysisItem:
    """Represents a single verified analysis artifact."""

    address: int
    rva: int
    name: str
    confidence: float = 1.0
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Serializes item into a JSON-compatible dictionary."""
        return {
            "address": f"0x{self.address:08X}",
            "rva": f"0x{self.rva:08X}",
            "address_int": self.address,
            "rva_int": self.rva,
            "name": self.name,
            "confidence": round(self.confidence, 4),
            "metadata": dict(self.metadata),
        }


@dataclass
class AnalysisReport:
    """Aggregated result container returned to CLI and MCP callers."""

    status: str
    total_items: int
    execution_time_ms: float
    items: List[AnalysisItem] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """Serializes report for JSON/MCP transport."""
        return {
            "status": self.status,
            "total_items": self.total_items,
            "execution_time_ms": round(self.execution_time_ms, 3),
            "items": [item.to_dict() for item in self.items],
            "warnings": list(self.warnings),
        }


# ==============================================================================
# Core Implementation
# ==============================================================================


class DomainAnalyzer:
    """Core engine implementing `<module_name>` domain logic."""

    def __init__(self, config: Optional[AnalysisConfig] = None) -> None:
        self.config = config or AnalysisConfig()
        self.config.validate()

    def analyze_bytes(self, data: bytes, base_va: Optional[int] = None) -> AnalysisReport:
        """Analyzes raw binary bytes and returns a structured `AnalysisReport`.

        Args:
            data: Raw binary or section bytes to inspect.
            base_va: Optional virtual address override (defaults to `config.image_base`).

        Returns:
            Populated `AnalysisReport` instance.

        Raises:
            ModuleDomainError: If `data` is empty or violates structural preconditions.
        """
        if not isinstance(data, (bytes, bytearray, memoryview)):
            raise TypeError(f"Expected bytes-like object, got {type(data).__name__}")
        if len(data) == 0:
            raise ModuleDomainError("Cannot analyze empty byte buffer")

        t0 = time.perf_counter()
        effective_base = self.config.image_base if base_va is None else base_va
        items: List[AnalysisItem] = []

        # TODO: Replace with domain-specific analysis logic
        sample_va = effective_base
        items.append(
            AnalysisItem(
                address=sample_va,
                rva=sample_va - self.config.image_base,
                name=f"sub_{sample_va:08x}",
                confidence=1.0,
                metadata={"byte_len": len(data)},
            )
        )

        elapsed_ms = (time.perf_counter() - t0) * 1000.0
        return AnalysisReport(
            status="ok",
            total_items=len(items),
            execution_time_ms=elapsed_ms,
            items=items[: self.config.max_items],
        )


def run_analysis(
    source: Union[str, Path, bytes],
    image_base: int = 0x100000,
    max_items: int = 1000,
) -> AnalysisReport:
    """High-level convenience entrypoint accepting a file path or raw bytes."""
    cfg = AnalysisConfig(image_base=image_base, max_items=max_items)
    analyzer = DomainAnalyzer(config=cfg)
    if isinstance(source, (bytes, bytearray)):
        raw_bytes = bytes(source)
    else:
        path = Path(source).resolve()
        if not path.is_file():
            raise FileNotFoundError(f"Target file not found: {path}")
        raw_bytes = path.read_bytes()
    return analyzer.analyze_bytes(raw_bytes, base_va=image_base)


# ==============================================================================
# CLI Entrypoint
# ==============================================================================


def _build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="SuperGhidra <module_name> CLI")
    parser.add_argument("input", help="Path to input binary file")
    parser.add_argument("--base", default="0x100000", help="Image base address (hex or int)")
    parser.add_argument("--max-items", type=int, default=1000, help="Maximum items to emit")
    parser.add_argument("--json", action="store_true", help="Emit JSON report to stdout")
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = _build_arg_parser()
    args = parser.parse_args(argv)
    base_addr = int(args.base, 16) if str(args.base).lower().startswith("0x") else int(args.base)

    report = run_analysis(args.input, image_base=base_addr, max_items=args.max_items)
    if args.json:
        print(json.dumps(report.to_dict(), indent=2))
    else:
        print(f"[*] Status: {report.status} | Items: {report.total_items} ({report.execution_time_ms:.2f} ms)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
