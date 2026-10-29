"""
views.py
========

Summary-first MCP pagination, retained evidence views, and schema profile negotiation.
Implements:
1. InspectAnalysisViewRequest & InspectAnalysisViewResponse across the 9 analysis facets:
   - compilable_c
   - raw_c
   - assembly
   - pcode_ops
   - def_use_edges
   - incoming_xrefs
   - outgoing_calls
   - struct_fields
   - jump_tables
2. inspect_analysis_view facet paging router querying SQLite L2 retained_evidence.
3. Schema profile negotiation (compact vs. full) via environment variables:
   - SUPERGHIDRA_MCP_INPUT_SCHEMA_PROFILE
   - SUPERGHIDRA_MCP_OUTPUT_SCHEMA_PROFILE
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass
from typing import Any, Dict, List, Literal

FACETS = (
    "compilable_c",
    "raw_c",
    "assembly",
    "pcode_ops",
    "def_use_edges",
    "incoming_xrefs",
    "outgoing_calls",
    "struct_fields",
    "jump_tables",
)

FacetType = Literal[
    "compilable_c",
    "raw_c",
    "assembly",
    "pcode_ops",
    "def_use_edges",
    "incoming_xrefs",
    "outgoing_calls",
    "struct_fields",
    "jump_tables",
]


@dataclass
class InspectAnalysisViewRequest:
    parent_evidence_id: str
    facet: FacetType
    offset: int = 0
    limit: int = 64
    filter_expr: str | None = None

    def __post_init__(self) -> None:
        if self.offset < 0:
            self.offset = 0
        if self.limit < 1:
            self.limit = 1
        elif self.limit > 500:
            self.limit = 500


@dataclass
class InspectAnalysisViewResponse:
    parent_evidence_id: str
    facet: str
    total_count: int
    offset: int
    limit: int
    truncated: bool
    items: List[Any]
    filter_expr: str | None = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "parent_evidence_id": self.parent_evidence_id,
            "facet": self.facet,
            "total_count": self.total_count,
            "offset": self.offset,
            "limit": self.limit,
            "truncated": self.truncated,
            "items": self.items,
            "filter_expr": self.filter_expr,
        }


def get_schema_profile(profile_type: Literal["input", "output"] = "input") -> str:
    """Returns 'compact' or 'full' based on environment configuration."""
    var_name = (
        "SUPERGHIDRA_MCP_INPUT_SCHEMA_PROFILE"
        if profile_type == "input"
        else "SUPERGHIDRA_MCP_OUTPUT_SCHEMA_PROFILE"
    )
    val = os.getenv(var_name, "compact").strip().lower()
    return val if val in ("compact", "full", "off") else "compact"


def compact_tool_schema(schema: Dict[str, Any]) -> Dict[str, Any]:
    """
    Downshifts an MCP tool JSON schema to 'compact' profile to save client token context.
    Retains names, types, and primary descriptions, but strips lengthy parameter documentation.
    """
    if get_schema_profile("input") == "full":
        return schema

    compacted = {
        "name": schema.get("name", ""),
        "description": schema.get("description", "").split("\n\n")[0],
        "parameters": {
            "type": "object",
            "properties": {},
            "required": schema.get("parameters", {}).get("required", []),
        },
    }

    props = schema.get("parameters", {}).get("properties", {})
    for k, v in props.items():
        desc = v.get("description", "")
        # Truncate to first sentence
        first_sentence = desc.split(". ")[0] if desc else ""
        compacted["parameters"]["properties"][k] = {
            "type": v.get("type", "string"),
            "description": first_sentence,
        }
        if "enum" in v:
            compacted["parameters"]["properties"][k]["enum"] = v["enum"]
        if "default" in v:
            compacted["parameters"]["properties"][k]["default"] = v["default"]

    return compacted


def inspect_analysis_view(
    req: InspectAnalysisViewRequest,
    cache_instance: Any | None = None,
) -> InspectAnalysisViewResponse:
    """
    Pages a specific facet from SQLite L2 retained evidence using parent_evidence_id.
    """
    if cache_instance is None:
        from superghidra.core.ghidra_oracle import get_oracle_cache
        cache_instance = get_oracle_cache()

    retained = cache_instance.get_retained_evidence(req.parent_evidence_id)
    if retained is None:
        return InspectAnalysisViewResponse(
            parent_evidence_id=req.parent_evidence_id,
            facet=req.facet,
            total_count=0,
            offset=req.offset,
            limit=req.limit,
            truncated=False,
            items=[],
            filter_expr=req.filter_expr,
        )

    summary, facets = retained
    raw_facet_data = facets.get(req.facet, [])

    # If the facet is a string (e.g. compilable_c, raw_c, assembly), split into lines
    items: List[Any] = []
    if isinstance(raw_facet_data, str):
        items = raw_facet_data.splitlines()
    elif isinstance(raw_facet_data, list):
        items = list(raw_facet_data)
    elif isinstance(raw_facet_data, dict):
        items = [raw_facet_data]
    else:
        items = [str(raw_facet_data)]

    # Apply filter_expr if provided
    if req.filter_expr:
        try:
            pattern = re.compile(req.filter_expr, re.IGNORECASE)
            filtered = []
            for item in items:
                text_repr = item if isinstance(item, str) else json.dumps(item)
                if pattern.search(text_repr):
                    filtered.append(item)
            items = filtered
        except Exception:
            # Fallback to simple substring match
            items = [item for item in items if req.filter_expr.lower() in (item if isinstance(item, str) else json.dumps(item)).lower()]

    total_count = len(items)
    sliced_items = items[req.offset : req.offset + req.limit]
    truncated = (req.offset + req.limit) < total_count

    return InspectAnalysisViewResponse(
        parent_evidence_id=req.parent_evidence_id,
        facet=req.facet,
        total_count=total_count,
        offset=req.offset,
        limit=req.limit,
        truncated=truncated,
        items=sliced_items,
        filter_expr=req.filter_expr,
    )
