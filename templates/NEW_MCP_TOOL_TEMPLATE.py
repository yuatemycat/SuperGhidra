r"""
NEW_MCP_TOOL_TEMPLATE.py — Boilerplate for Adding a New Tool to SuperGhidraMCP (`pyghidra-mcp`).

Integration Checklist:
  1. Pydantic Response Model (`E:\02_Projects\pyghidra-mcp\src\pyghidra_mcp\models.py`):
     Define `<ToolName>Item` and `<ToolName>Result(BaseModel)` with explicit types and defaults.
  2. Tool Handler (`E:\02_Projects\pyghidra-mcp\src\pyghidra_mcp\mcp_tools.py`):
     Decorate with `@mcp_error_handler`, validate inputs, call `_ensure_superghidra_imported()`,
     resolve paths via `_resolve_safe_path()`, and return `<ToolName>Result`.
  3. Server Registration (`E:\02_Projects\pyghidra-mcp\src\pyghidra_mcp\server.py`):
     Register with `mcp.tool()(mcp_tools.<tool_name>)`.
  4. Unit Test (`tests/integrations/test_mcp_38_tools.py`):
     Add `<tool_name>` to `EXPECTED_EXTRA_TOOLS` and add a smoke test verifying end-to-end execution.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


# ==============================================================================
# 1. Pydantic Models (place in `pyghidra_mcp/models.py`)
# ==============================================================================


class ExampleToolItem(BaseModel):
    """Single item record returned by `example_superghidra_tool`."""

    address: str = Field(..., description="Virtual address in hex format (e.g. '0x00101000')")
    rva: str = Field(..., description="Relative virtual address in hex format (e.g. '0x00001000')")
    name: str = Field(..., description="Recovered or analyzed symbol name")
    confidence: float = Field(default=1.0, description="Confidence score in [0.0, 1.0]")


class ExampleToolResult(BaseModel):
    """Structured MCP response contract for `example_superghidra_tool`."""

    status: str = Field(default="ok", description="'ok' or 'error'")
    binary_path: str = Field(..., description="Resolved path to analyzed binary")
    total_items: int = Field(default=0, description="Total items discovered before limit truncation")
    execution_time_ms: float = Field(default=0.0, description="Wall-clock execution time in milliseconds")
    items: List[ExampleToolItem] = Field(default_factory=list, description="Bounded list of discovered items")
    message: str = Field(default="", description="Human-readable summary message")


# ==============================================================================
# 2. MCP Tool Handler (place in `pyghidra_mcp/mcp_tools.py`)
# ==============================================================================


# @mcp_error_handler
def example_superghidra_tool(
    binary_path: str,
    image_base: str = "0x100000",
    name_filter: Optional[str] = None,
    limit: int = 200,
    ctx: Any | None = None,
) -> ExampleToolResult:
    """<One-line summary exposed in MCP tool schema>.

    <Detailed description of what the tool computes, whether it runs Zero-JVM,
    and what invariants or safety checks are enforced.>

    Args:
        binary_path: Path to the target binary file (ELF, PE, or Mach-O).
        image_base: Base virtual address in hex or decimal string format (default: '0x100000').
        name_filter: Optional case-insensitive substring to filter results.
        limit: Maximum number of items returned in the response payload (1..5000, default: 200).
    """
    # 1. Input validation contract
    if not binary_path or not binary_path.strip():
        raise ValueError("binary_path must be a non-empty string")
    if limit <= 0:
        raise ValueError(f"limit must be greater than zero, got {limit}")
    bounded_limit = max(1, min(int(limit), 5000))

    base_str = image_base.strip()
    base_int = int(base_str, 16) if base_str.lower().startswith("0x") else int(base_str)

    # 2. Path safety resolution (uses pyghidra_mcp._resolve_safe_path in production)
    safe_path = Path(binary_path).resolve()
    if not safe_path.is_file():
        raise FileNotFoundError(f"Target binary does not exist: {safe_path}")

    # 3. Lazy SuperGhidra import (via root shim or canonical package)
    # _ensure_superghidra_imported()
    # from superghidra.<domain>.<module_name> import run_analysis

    # 4. Execute domain analysis
    # report = run_analysis(safe_path, image_base=base_int, max_items=bounded_limit)
    needle = (name_filter or "").lower()
    raw_items: List[Dict[str, Any]] = []  # Replace with `report.to_dict()["items"]`

    filtered = [
        ExampleToolItem(
            address=item["address"],
            rva=item["rva"],
            name=item["name"],
            confidence=item["confidence"],
        )
        for item in raw_items
        if not needle or needle in item["name"].lower()
    ]

    return ExampleToolResult(
        status="ok",
        binary_path=str(safe_path),
        total_items=len(filtered),
        execution_time_ms=0.0,
        items=filtered[:bounded_limit],
        message=f"Analyzed {safe_path.name}: {len(filtered)} matching items.",
    )
