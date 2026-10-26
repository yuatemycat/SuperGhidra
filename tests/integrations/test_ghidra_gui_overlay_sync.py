"""
Tests for Ghidra GUI Overlay Sync Bridge (Issue #15).
=====================================================

Validates:
1. Ingestion of WriteOverlay JSON and append-only .ghidra-delta.jsonl streams.
2. Address normalization across integer, hex string, and decimal representations.
3. Generation of syntactically valid Ghidra Python scripts.
4. Transaction boundary creation (`startTransaction("SuperGhidra Overlay Sync")` -> `endTransaction(tx_id, True)`).
5. Symbol table and Listing comment API integration.
6. Summary diff report generation grouped by address/RVA.
7. CLI subcommand `overlay-sync` execution and dry-run modes.
8. Execution of the generated script against mock FlatProgramAPI and Program objects.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from superghidra.integrations.ghidra_gui_overlay_sync import (
    OverlaySyncBridge,
    generate_diff_report,
    generate_ghidra_python_script,
    normalize_address_key,
    sync_to_script,
)


@pytest.fixture
def sample_overlay_dict():
    return {
        "renames": {
            "0x10001000": "crypto_aes_encrypt",
            "0x10001080": "g_MasterSecretKey",
        },
        "comments": {
            "0x10001000": {
                "text": "AES-256 single-block encryption routine",
                "type": "PLATE",
            },
            "0x10001020": "Round key addition loop counter",
        },
        "prototypes": {
            "0x10001000": "int crypto_aes_encrypt(uint8_t *buffer, size_t len)",
        },
        "types": {
            "0x10001080": "uint8_t[32]",
        },
        "structs": [
            {
                "struct_name": "AesContext",
                "field_name": "rounds",
                "offset": 0,
                "size": 4,
                "field_type": "uint32_t",
            }
        ],
    }


@pytest.fixture
def sample_delta_jsonl_content():
    events = [
        {
            "event_id": "EVT-001",
            "event_type": "RenameSymbol",
            "target_address": "0x10002000",
            "payload": {"new_name": "auth_token_validate", "old_name": "FUN_10002000"},
        },
        {
            "event_id": "EVT-002",
            "event_type": "SetComment",
            "target_address": "0x10002000",
            "payload": {"comment": "Verifies HMAC-SHA256 signature token", "comment_type": "PLATE"},
        },
        {
            "event_id": "EVT-003",
            "event_type": "SetFunctionSignature",
            "target_address": "0x10002000",
            "payload": {"prototype": "bool auth_token_validate(const char *token)"},
        },
        {
            "event_id": "EVT-004",
            "event_type": "DefineStructField",
            "target_symbol": "SessionToken::expiry",
            "payload": {
                "struct_name": "SessionToken",
                "field_name": "expiry",
                "offset": 8,
                "size": 8,
                "field_type": "uint64_t",
            },
        },
    ]
    return "\n".join(json.dumps(e) for e in events)


class TestOverlaySyncAddressNormalization:
    def test_normalize_address_key(self):
        assert normalize_address_key(0x1000) == "0x1000"
        assert normalize_address_key("0x1000") == "0x1000"
        assert normalize_address_key("0X1000") == "0x1000"
        assert normalize_address_key("4096") == "0x1000"
        assert normalize_address_key("1000") == "0x3E8"


class TestOverlaySyncIngestion:
    def test_ingest_dict(self, sample_overlay_dict):
        bridge = OverlaySyncBridge(sample_overlay_dict)
        assert "0x10001000" in bridge.overlay_data["renames"]
        assert bridge.overlay_data["renames"]["0x10001000"] == "crypto_aes_encrypt"
        assert bridge.overlay_data["prototypes"]["0x10001000"].startswith("int crypto_aes_encrypt")
        assert bridge.overlay_data["comments"]["0x10001000"]["text"].startswith("AES-256")
        assert bridge.overlay_data["comments"]["0x10001020"]["type"] == "PLATE"
        assert len(bridge.overlay_data["structs"]) == 1

    def test_ingest_json_file(self, tmp_path, sample_overlay_dict):
        json_file = tmp_path / "ghidra_overlay.json"
        json_file.write_text(json.dumps(sample_overlay_dict), encoding="utf-8")

        bridge = OverlaySyncBridge(json_file)
        assert bridge.overlay_data["renames"]["0x10001080"] == "g_MasterSecretKey"
        assert bridge.overlay_data["types"]["0x10001080"] == "uint8_t[32]"

    def test_ingest_delta_jsonl_file(self, tmp_path, sample_delta_jsonl_content):
        jsonl_file = tmp_path / ".ghidra-delta.jsonl"
        jsonl_file.write_text(sample_delta_jsonl_content, encoding="utf-8")

        bridge = OverlaySyncBridge(jsonl_file)
        assert "0x10002000" in bridge.overlay_data["renames"]
        assert bridge.overlay_data["renames"]["0x10002000"] == "auth_token_validate"
        assert bridge.overlay_data["comments"]["0x10002000"]["text"].startswith("Verifies HMAC")
        assert bridge.overlay_data["prototypes"]["0x10002000"] == "bool auth_token_validate(const char *token)"
        assert len(bridge.overlay_data["structs"]) == 1
        assert bridge.overlay_data["structs"][0]["struct_name"] == "SessionToken"


class TestGhidraPythonScriptGeneration:
    def test_script_syntax_and_structure(self, sample_overlay_dict):
        script = generate_ghidra_python_script(sample_overlay_dict)

        # 1. Valid Python syntax verification
        compiled = compile(script, "ghidra_sync_script.py", "exec")
        assert compiled is not None

        # 2. Transaction boundary checks
        assert 'prog.startTransaction("SuperGhidra Overlay Sync")' in script
        assert "prog.endTransaction(tx_id, commit)" in script

        # 3. API method calls
        assert "prog.getListing()" in script
        assert "prog.getSymbolTable()" in script
        assert "createLabel" in script
        assert "setComment" in script

        # 4. Progress console logging
        assert "[SuperGhidra] Beginning overlay sync" in script
        assert "[SuperGhidra] Transaction" in script

    def test_script_dry_run_flag(self, sample_overlay_dict):
        dry_script = generate_ghidra_python_script(sample_overlay_dict, dry_run=True)
        assert "DRY_RUN = True" in dry_script
        assert "[DRY RUN] Rename" in dry_script

        live_script = generate_ghidra_python_script(sample_overlay_dict, dry_run=False)
        assert "DRY_RUN = False" in live_script

    def test_mock_script_execution(self, sample_overlay_dict):
        """Execute the generated script inside a mocked Ghidra Python environment."""
        script = generate_ghidra_python_script(sample_overlay_dict, dry_run=False)

        mock_prog = MagicMock()
        mock_listing = MagicMock()
        mock_sym_table = MagicMock()
        mock_addr_factory = MagicMock()
        mock_space = MagicMock()

        mock_prog.getListing.return_value = mock_listing
        mock_prog.getSymbolTable.return_value = mock_sym_table
        mock_prog.getAddressFactory.return_value = mock_addr_factory
        mock_addr_factory.getDefaultAddressSpace.return_value = mock_space

        mock_addr_obj = MagicMock()
        mock_space.getAddress.return_value = mock_addr_obj

        mock_fn = MagicMock()
        mock_fn.getComment.return_value = "Existing header"
        mock_listing.getFunctionAt.return_value = mock_fn

        mock_prog.startTransaction.return_value = 101

        # Global scope simulating Ghidra environment
        env = {
            "currentProgram": mock_prog,
            "toAddr": lambda s: mock_addr_obj,
            "createLabel": MagicMock(),
            "setComment": MagicMock(),
            "print": MagicMock(),
        }

        # Execute script
        exec(script, env)

        # Assertions on mock behavior
        mock_prog.startTransaction.assert_called_once_with("SuperGhidra Overlay Sync")
        mock_prog.endTransaction.assert_called_once_with(101, True)
        assert mock_fn.setName.call_count >= 1
        assert mock_listing.setComment.call_count >= 1 or env["setComment"].call_count >= 1


class TestDiffReportGeneration:
    def test_generate_diff_report(self, sample_overlay_dict):
        report = generate_diff_report(sample_overlay_dict)

        assert "SUPERGHIDRA WRITE-OVERLAY SUMMARY DIFF REPORT" in report
        assert "Total Target Addresses: 3" in report
        assert "Total Symbol Renames:   2" in report
        assert "[0x10001000]" in report
        assert "+ Symbol Rename : crypto_aes_encrypt" in report
        assert "+ Prototype     : int crypto_aes_encrypt(uint8_t *buffer, size_t len)" in report
        assert "+ Comment (PLATE): AES-256 single-block encryption routine" in report
        assert "[0x10001080]" in report
        assert "+ Type Binding  : uint8_t[32]" in report
        assert "AesContext +0x0: uint32_t rounds" in report

    def test_empty_diff_report(self):
        report = generate_diff_report({})
        assert "No pending mutations in write overlay." in report


class TestCLISyncToScript:
    def test_sync_to_script_file_output(self, tmp_path, sample_overlay_dict):
        overlay_path = tmp_path / "overlay.json"
        overlay_path.write_text(json.dumps(sample_overlay_dict), encoding="utf-8")

        out_script = tmp_path / "sync_script.py"
        res = sync_to_script(str(overlay_path), out_path=str(out_script), dry_run=False)

        assert out_script.is_file()
        assert out_script.read_text(encoding="utf-8") == res
        assert 'prog.startTransaction("SuperGhidra Overlay Sync")' in res

    def test_main_cli_overlay_sync(self, tmp_path, sample_overlay_dict):
        overlay_path = tmp_path / "overlay.json"
        overlay_path.write_text(json.dumps(sample_overlay_dict), encoding="utf-8")
        out_script = tmp_path / "cli_sync_out.py"

        cmd = [
            sys.executable,
            "-m",
            "superghidra",
            "overlay-sync",
            "--overlay",
            str(overlay_path),
            "--out",
            str(out_script),
        ]
        proc = subprocess.run(cmd, capture_output=True, text=True)
        assert proc.returncode == 0
        assert f"Ghidra sync script written to {out_script}" in proc.stdout
        assert out_script.is_file()

    def test_main_cli_diff_flag(self, tmp_path, sample_overlay_dict):
        overlay_path = tmp_path / "overlay.json"
        overlay_path.write_text(json.dumps(sample_overlay_dict), encoding="utf-8")

        cmd = [
            sys.executable,
            "-m",
            "superghidra",
            "overlay-sync",
            "--overlay",
            str(overlay_path),
            "--diff",
        ]
        proc = subprocess.run(cmd, capture_output=True, text=True)
        assert proc.returncode == 0
        assert "SUPERGHIDRA WRITE-OVERLAY SUMMARY DIFF REPORT" in proc.stdout
        assert "crypto_aes_encrypt" in proc.stdout


class TestRootCompatibilityShim:
    def test_root_shim_exports(self):
        from superghidra.integrations import ghidra_gui_overlay_sync

        assert hasattr(ghidra_gui_overlay_sync, "OverlaySyncBridge")
        assert hasattr(ghidra_gui_overlay_sync, "generate_ghidra_python_script")
        assert hasattr(ghidra_gui_overlay_sync, "generate_diff_report")
        assert hasattr(ghidra_gui_overlay_sync, "sync_to_script")
