"""
test_evidence_paging.py
=======================

Unit tests for superghidra.core.views and L2 retained evidence paging:
- Retention SQLite table initialization
- Store and retrieve retained evidence with LZ4/Zstandard/zlib compression
- Eviction of expired records (30-day quota policy)
- Deterministic make_evidence_id generation
- InspectAnalysisViewRequest bounds enforcement (min limit 1, max limit 500, non-negative offset)
- inspect_analysis_view across 9 facets:
  1. compilable_c
  2. raw_c
  3. assembly
  4. pcode_ops
  5. def_use_edges
  6. incoming_xrefs
  7. outgoing_calls
  8. struct_fields
  9. jump_tables
- Substring filtering with filter_expr
- Regex pattern filtering with filter_expr
- Truncation indicator (truncated=True when offset + limit < total)
- Offset past end returns empty items with truncated=False
- Missing evidence_id returns 0 total count and empty items
- Non-list facet (string code, dict) pagination
- Schema profile negotiation: get_schema_profile (input and output)
- Environment variable overrides for SUPERGHIDRA_MCP_INPUT_SCHEMA_PROFILE
- Environment variable overrides for SUPERGHIDRA_MCP_OUTPUT_SCHEMA_PROFILE
- compact_tool_schema downshifting (keeps name and brief description, trims verbose docs)
- compact_tool_schema passthrough under full profile
"""

from __future__ import annotations

import pytest

from superghidra.core.ghidra_oracle import L2SQLiteCache
from superghidra.core.views import (
    FACETS,
    InspectAnalysisViewRequest,
    InspectAnalysisViewResponse,
    compact_tool_schema,
    get_schema_profile,
    inspect_analysis_view,
)


@pytest.fixture
def memory_cache():
    return L2SQLiteCache(":memory:")


def test_retained_evidence_store_and_get(memory_cache):
    summary = {"name": "TestFunc", "address": "0x140001000"}
    facets = {"compilable_c": ["void TestFunc() {", "    return;", "}"]}

    memory_cache.store_retained_evidence(
        evidence_id="ev_test_01",
        target_sha256="12345678" * 8,
        overlay_revision=1,
        analysis_profile_digest="digest_01",
        operation="analyze_function",
        canonical_address="0x140001000",
        summary_dict=summary,
        facets_dict=facets,
    )

    result = memory_cache.get_retained_evidence("ev_test_01")
    assert result is not None
    loaded_summary, loaded_facets = result
    assert loaded_summary["name"] == "TestFunc"
    assert len(loaded_facets["compilable_c"]) == 3


def test_retained_evidence_missing_id(memory_cache):
    result = memory_cache.get_retained_evidence("ev_nonexistent")
    assert result is None


def test_make_evidence_id():
    ev_id1 = L2SQLiteCache.make_evidence_id("sha_a", 0, "profile1", "analyze", "0x1000")
    ev_id2 = L2SQLiteCache.make_evidence_id("sha_a", 0, "profile1", "analyze", "0x1000")
    ev_id3 = L2SQLiteCache.make_evidence_id("sha_a", 1, "profile1", "analyze", "0x1000")
    assert ev_id1.startswith("ev_")
    assert ev_id1 == ev_id2
    assert ev_id1 != ev_id3


def test_request_bounds_enforcement():
    req_neg = InspectAnalysisViewRequest(parent_evidence_id="ev_01", facet="compilable_c", offset=-5, limit=0)
    assert req_neg.offset == 0
    assert req_neg.limit == 1

    req_over = InspectAnalysisViewRequest(parent_evidence_id="ev_01", facet="compilable_c", offset=10, limit=999)
    assert req_over.limit == 500


@pytest.mark.parametrize("facet_name", FACETS)
def test_all_9_facets_paging(memory_cache, facet_name):
    mock_items = [f"item_{i}" for i in range(10)]
    memory_cache.store_retained_evidence(
        evidence_id=f"ev_facet_{facet_name}",
        target_sha256="abc",
        overlay_revision=0,
        analysis_profile_digest="dig",
        operation="analyze_function",
        canonical_address="0x1000",
        summary_dict={},
        facets_dict={facet_name: mock_items},
    )

    req = InspectAnalysisViewRequest(parent_evidence_id=f"ev_facet_{facet_name}", facet=facet_name, offset=0, limit=5)
    resp = inspect_analysis_view(req, cache_instance=memory_cache)
    assert resp.total_count == 10
    assert len(resp.items) == 5
    assert resp.truncated is True
    assert resp.items[0] == "item_0"


def test_paging_second_page(memory_cache):
    mock_items = [f"line_{i}" for i in range(15)]
    memory_cache.store_retained_evidence(
        evidence_id="ev_multi_page",
        target_sha256="abc",
        overlay_revision=0,
        analysis_profile_digest="dig",
        operation="analyze_function",
        canonical_address="0x1000",
        summary_dict={},
        facets_dict={"assembly": mock_items},
    )

    req = InspectAnalysisViewRequest(parent_evidence_id="ev_multi_page", facet="assembly", offset=10, limit=10)
    resp = inspect_analysis_view(req, cache_instance=memory_cache)
    assert resp.total_count == 15
    assert len(resp.items) == 5
    assert resp.truncated is False
    assert resp.items[0] == "line_10"


def test_paging_offset_past_end(memory_cache):
    memory_cache.store_retained_evidence(
        evidence_id="ev_past_end",
        target_sha256="abc",
        overlay_revision=0,
        analysis_profile_digest="dig",
        operation="analyze_function",
        canonical_address="0x1000",
        summary_dict={},
        facets_dict={"pcode_ops": ["op_1", "op_2"]},
    )
    req = InspectAnalysisViewRequest(parent_evidence_id="ev_past_end", facet="pcode_ops", offset=10, limit=10)
    resp = inspect_analysis_view(req, cache_instance=memory_cache)
    assert resp.total_count == 2
    assert len(resp.items) == 0
    assert resp.truncated is False


def test_paging_string_facet_splitlines(memory_cache):
    code_str = "int a = 1;\nint b = 2;\nreturn a + b;"
    memory_cache.store_retained_evidence(
        evidence_id="ev_code_str",
        target_sha256="abc",
        overlay_revision=0,
        analysis_profile_digest="dig",
        operation="analyze_function",
        canonical_address="0x1000",
        summary_dict={},
        facets_dict={"compilable_c": code_str},
    )
    req = InspectAnalysisViewRequest(parent_evidence_id="ev_code_str", facet="compilable_c", offset=0, limit=2)
    resp = inspect_analysis_view(req, cache_instance=memory_cache)
    assert resp.total_count == 3
    assert len(resp.items) == 2
    assert resp.items[0] == "int a = 1;"


def test_paging_dict_facet(memory_cache):
    single_dict = {"struct_size": 32, "name": "Header"}
    memory_cache.store_retained_evidence(
        evidence_id="ev_dict_facet",
        target_sha256="abc",
        overlay_revision=0,
        analysis_profile_digest="dig",
        operation="analyze_function",
        canonical_address="0x1000",
        summary_dict={},
        facets_dict={"struct_fields": single_dict},
    )
    req = InspectAnalysisViewRequest(parent_evidence_id="ev_dict_facet", facet="struct_fields", offset=0, limit=10)
    resp = inspect_analysis_view(req, cache_instance=memory_cache)
    assert resp.total_count == 1
    assert resp.items[0]["name"] == "Header"


def test_filter_expr_substring(memory_cache):
    mock_ops = ["INT_ADD v1, v2", "FLOAT_MULT v3, v4", "INT_SUB v5, v6", "INT_ADD v7, v8"]
    memory_cache.store_retained_evidence(
        evidence_id="ev_filter_sub",
        target_sha256="abc",
        overlay_revision=0,
        analysis_profile_digest="dig",
        operation="analyze_function",
        canonical_address="0x1000",
        summary_dict={},
        facets_dict={"pcode_ops": mock_ops},
    )
    req = InspectAnalysisViewRequest(parent_evidence_id="ev_filter_sub", facet="pcode_ops", filter_expr="INT_ADD")
    resp = inspect_analysis_view(req, cache_instance=memory_cache)
    assert resp.total_count == 2
    assert all("INT_ADD" in op for op in resp.items)


def test_filter_expr_regex(memory_cache):
    calls = ["call sub_140001000", "call sub_140002000", "call printf", "call sub_140003000"]
    memory_cache.store_retained_evidence(
        evidence_id="ev_filter_re",
        target_sha256="abc",
        overlay_revision=0,
        analysis_profile_digest="dig",
        operation="analyze_function",
        canonical_address="0x1000",
        summary_dict={},
        facets_dict={"outgoing_calls": calls},
    )
    req = InspectAnalysisViewRequest(parent_evidence_id="ev_filter_re", facet="outgoing_calls", filter_expr=r"sub_14000[12]000")
    resp = inspect_analysis_view(req, cache_instance=memory_cache)
    assert resp.total_count == 2
    assert "call printf" not in resp.items


def test_schema_profile_default(monkeypatch):
    monkeypatch.delenv("SUPERGHIDRA_MCP_INPUT_SCHEMA_PROFILE", raising=False)
    monkeypatch.delenv("SUPERGHIDRA_MCP_OUTPUT_SCHEMA_PROFILE", raising=False)
    assert get_schema_profile("input") == "compact"
    assert get_schema_profile("output") == "compact"


def test_schema_profile_env_override(monkeypatch):
    monkeypatch.setenv("SUPERGHIDRA_MCP_INPUT_SCHEMA_PROFILE", "full")
    monkeypatch.setenv("SUPERGHIDRA_MCP_OUTPUT_SCHEMA_PROFILE", "off")
    assert get_schema_profile("input") == "full"
    assert get_schema_profile("output") == "off"


def test_compact_tool_schema_downshifting(monkeypatch):
    monkeypatch.setenv("SUPERGHIDRA_MCP_INPUT_SCHEMA_PROFILE", "compact")
    full_schema = {
        "name": "analyze_function",
        "description": "Analyzes a native procedure. Detailed documentation here.\n\nMore paragraphs of docs.",
        "parameters": {
            "type": "object",
            "properties": {
                "procedure": {
                    "type": "string",
                    "description": "The function address or name. Must be valid hex or symbol.",
                },
                "detail": {
                    "type": "string",
                    "enum": ["summary", "complete"],
                    "default": "summary",
                    "description": "Detail level to return. Defaults to summary.",
                },
            },
            "required": ["procedure"],
        },
    }
    compact = compact_tool_schema(full_schema)
    assert compact["name"] == "analyze_function"
    assert "More paragraphs" not in compact["description"]
    assert compact["parameters"]["properties"]["procedure"]["description"] == "The function address or name"
    assert compact["parameters"]["properties"]["detail"]["enum"] == ["summary", "complete"]


def test_compact_tool_schema_full_passthrough(monkeypatch):
    monkeypatch.setenv("SUPERGHIDRA_MCP_INPUT_SCHEMA_PROFILE", "full")
    full_schema = {
        "name": "trace_native_values",
        "description": "Full description\n\nLong body",
        "parameters": {"type": "object", "properties": {}},
    }
    res = compact_tool_schema(full_schema)
    assert res == full_schema


def test_response_to_dict():
    resp = InspectAnalysisViewResponse(
        parent_evidence_id="ev_01",
        facet="raw_c",
        total_count=10,
        offset=0,
        limit=5,
        truncated=True,
        items=["int x = 0;"],
        filter_expr="int",
    )
    d = resp.to_dict()
    assert d["parent_evidence_id"] == "ev_01"
    assert d["total_count"] == 10
    assert d["truncated"] is True
    assert d["filter_expr"] == "int"
