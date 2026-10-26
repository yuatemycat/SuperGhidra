"""
Tests for Live Ghidra GUI Background Overlay Watcher & Conflict-Checked Replay.
===============================================================================

Validates:
1. Ingestion of optional `before` / `expected_before` expectations from overlay dicts,
   `merge_fork` journals, and `.ghidra-delta.jsonl` streams.
2. `compute_incremental_delta` across multiple overlay and JSONL updates.
3. `verify_conflicts` clean application (when live state matches `before` or default
   `FUN_`/`sub_` prefix) and conflict rejection (when the analyst manually renamed
   a symbol or edited metadata in CodeBrowser).
4. `generate_ghidra_watcher_script` AST syntax validity (`ast.parse`), transaction
   wrapping (`SuperGhidra Live Overlay Sync`), `(mtime_ns, size, sha256)` polling,
   conflict check logic, and simulated execution against a mock `currentProgram` /
   `FlatProgramAPI` harness across live file updates.
5. CLI `--watch` and `--poll-ms` flags via `build_arg_parser` and `main`.
"""

from __future__ import annotations

import ast
import copy
import json
import time
from typing import Dict
from unittest.mock import MagicMock

from superghidra.integrations.ghidra_gui_overlay_sync import (
    OverlaySyncBridge,
    build_arg_parser,
    generate_ghidra_watcher_script,
    is_default_ghidra_symbol,
    main,
    sync_to_script,
)


class TestBeforeExpectationIngestion:
    def test_ingest_before_from_dict_and_inline_entries(self):
        data = {
            "renames": {
                "0x140001000": {
                    "before": "FUN_140001000",
                    "after": "pkt_decrypt_header",
                },
                "0x140001050": "pkt_verify_crc",
            },
            "comments": {
                "0x140001000": {
                    "text": "Decrypts packet frame header",
                    "type": "PLATE",
                    "expected_before": "Old header note",
                }
            },
            "prototypes": {
                "0x140001000": {
                    "before": "void FUN_140001000(void)",
                    "after": "int pkt_decrypt_header(uint8_t *buf, uint32_t len)",
                }
            },
            "types": {
                "0x140002000": {
                    "expected_before": "undefined8",
                    "after": "PacketHeader *",
                }
            },
            "before": {
                "renames": {
                    "0x140001050": "sub_140001050",
                }
            },
        }
        bridge = OverlaySyncBridge(data)
        assert bridge.overlay_data["renames"]["0x140001000"] == "pkt_decrypt_header"
        assert bridge.overlay_data["renames"]["0x140001050"] == "pkt_verify_crc"
        assert bridge.before_expectations["renames"]["0x140001000"] == "FUN_140001000"
        assert bridge.before_expectations["renames"]["0x140001050"] == "sub_140001050"
        assert bridge.before_expectations["comments"]["0x140001000"] == "Old header note"
        assert (
            bridge.before_expectations["prototypes"]["0x140001000"]
            == "void FUN_140001000(void)"
        )
        assert bridge.before_expectations["types"]["0x140002000"] == "undefined8"

    def test_ingest_before_from_delta_jsonl_and_merge_fork_journal(self, tmp_path):
        events = [
            {
                "event_id": "EVT-10",
                "event_type": "RenameSymbol",
                "target_address": "0x140003000",
                "payload": {
                    "new_name": "session_handshake",
                    "before": "FUN_140003000",
                },
            },
            {
                "op": "rename",
                "address": "0x140003080",
                "expected_before": "interim_helper",
                "after": "session_derive_key",
            },
            {
                "event_type": "SetComment",
                "target_address": "0x140003000",
                "payload": {
                    "comment": "TLS session handshake entry",
                    "comment_type": "PLATE",
                    "before": "Draft comment",
                },
            },
        ]
        jsonl_file = tmp_path / "fork.ghidra-delta.jsonl"
        jsonl_file.write_text("\n".join(json.dumps(e) for e in events), encoding="utf-8")

        bridge = OverlaySyncBridge(jsonl_file)
        assert bridge.overlay_data["renames"]["0x140003000"] == "session_handshake"
        assert bridge.overlay_data["renames"]["0x140003080"] == "session_derive_key"
        assert bridge.before_expectations["renames"]["0x140003000"] == "FUN_140003000"
        assert bridge.before_expectations["renames"]["0x140003080"] == "interim_helper"
        assert bridge.before_expectations["comments"]["0x140003000"] == "Draft comment"


class TestIncrementalDeltaComputation:
    def test_compute_incremental_delta_across_multiple_updates(self, tmp_path):
        overlay_file = tmp_path / "ghidra_overlay.json"

        # Update 1: initial overlay
        rev1 = {
            "renames": {"0x10001000": "fn_init", "0x10001040": "fn_parse"},
            "comments": {"0x10001000": {"text": "Init subsystem", "type": "PLATE"}},
            "prototypes": {"0x10001000": "int fn_init(void)"},
            "types": {"0x10002000": "uint32_t"},
            "structs": [{"struct_name": "Ctx", "field_name": "flags", "offset": 0, "field_type": "uint32_t"}],
        }
        overlay_file.write_text(json.dumps(rev1), encoding="utf-8")
        bridge = OverlaySyncBridge(overlay_file)

        delta1 = bridge.compute_incremental_delta({})
        assert delta1["renames"] == {"0x10001000": "fn_init", "0x10001040": "fn_parse"}
        assert len(delta1["comments"]) == 1
        assert len(delta1["structs"]) == 1

        snapshot1 = copy.deepcopy(bridge.overlay_data)

        # Update 2: modify one rename, leave 0x10001000 untouched, add one new rename & struct field
        rev2 = {
            "renames": {
                "0x10001000": "fn_init",
                "0x10001040": "fn_parse_v2",
                "0x10001080": "fn_dispatch",
            },
            "comments": {"0x10001000": {"text": "Init subsystem", "type": "PLATE"}},
            "prototypes": {"0x10001000": "int fn_init(void)"},
            "types": {"0x10002000": "uint32_t"},
            "structs": [
                {"struct_name": "Ctx", "field_name": "flags", "offset": 0, "field_type": "uint32_t"},
                {"struct_name": "Ctx", "field_name": "count", "offset": 4, "field_type": "uint32_t"},
            ],
        }
        overlay_file.write_text(json.dumps(rev2), encoding="utf-8")
        bridge.load(overlay_file)

        delta2 = bridge.compute_incremental_delta(snapshot1)
        assert delta2["renames"] == {
            "0x10001040": "fn_parse_v2",
            "0x10001080": "fn_dispatch",
        }
        assert delta2["comments"] == {}
        assert delta2["prototypes"] == {}
        assert delta2["types"] == {}
        assert delta2["structs"] == [
            {"struct_name": "Ctx", "field_name": "count", "offset": 4, "field_type": "uint32_t"}
        ]

        snapshot2 = copy.deepcopy(bridge.overlay_data)

        # Update 3: no changes -> empty incremental delta
        delta3 = bridge.compute_incremental_delta(snapshot2)
        assert delta3 == {
            "renames": {},
            "comments": {},
            "prototypes": {},
            "types": {},
            "structs": [],
        }

    def test_compute_incremental_delta_across_jsonl_appends(self, tmp_path):
        jsonl_file = tmp_path / ".ghidra-delta.jsonl"
        evt1 = {
            "event_type": "RenameSymbol",
            "target_address": "0x140001000",
            "payload": {"new_name": "net_open"},
        }
        jsonl_file.write_text(json.dumps(evt1) + "\n", encoding="utf-8")

        bridge = OverlaySyncBridge(jsonl_file)
        snap1 = copy.deepcopy(bridge.overlay_data)

        evt2 = {
            "event_type": "RenameSymbol",
            "target_address": "0x140001020",
            "payload": {"new_name": "net_close"},
        }
        with open(jsonl_file, "a", encoding="utf-8") as f:
            f.write(json.dumps(evt2) + "\n")

        bridge = OverlaySyncBridge(jsonl_file)
        delta = bridge.compute_incremental_delta(snap1)
        assert delta["renames"] == {"0x140001020": "net_close"}


class TestConflictVerification:
    def test_verify_conflicts_accepts_matching_before_and_default_fun(self):
        overlay = {
            "renames": {
                "0x140001000": {"before": "FUN_140001000", "after": "crypto_hash_init"},
                "0x140001040": {"before": "stage1_update", "after": "crypto_hash_update"},
                "0x140001080": "crypto_hash_final",
                "0x1400010C0": "already_applied_name",
            }
        }
        bridge = OverlaySyncBridge(overlay)

        live_state = {
            "renames": {
                "0x140001000": "FUN_140001000",         # Matches explicit before
                "0x140001040": "stage1_update",         # Matches explicit custom before
                "0x140001080": "sub_140001080",         # Matches default Ghidra/disassembler prefix
                "0x1400010C0": "already_applied_name",  # Already matches target name
            }
        }
        accepted, conflicts = bridge.verify_conflicts(live_state)
        assert conflicts == []
        assert accepted["renames"] == {
            "0x140001000": "crypto_hash_init",
            "0x140001040": "crypto_hash_update",
            "0x140001080": "crypto_hash_final",
            "0x1400010C0": "already_applied_name",
        }

    def test_verify_conflicts_rejects_concurrent_analyst_edits(self):
        overlay = {
            "renames": {
                "0x140001000": {"before": "FUN_140001000", "after": "agent_proposed_a"},
                "0x140001040": {"before": "old_helper_name", "after": "agent_proposed_b"},
                "0x140001080": "agent_proposed_c",  # Implicitly expects FUN_/sub_ default
                "0x1400010C0": "clean_function_d",
            },
            "comments": {
                "0x140001000": {
                    "text": "Agent comment",
                    "type": "PLATE",
                    "before": "Original comment",
                }
            },
        }
        bridge = OverlaySyncBridge(overlay)

        live_state = {
            "renames": {
                "0x140001000": "analyst_manual_decrypt",  # Analyst renamed in CodeBrowser!
                "0x140001040": "analyst_custom_helper",   # Diverges from 'old_helper_name'
                "0x140001080": "analyst_named_handler",   # Diverges from default FUN_140001080
                "0x1400010C0": "FUN_1400010C0",           # Still default FUN_ -> safe
            },
            "comments": {
                "0x140001000": "Analyst hand-written note",
            },
        }
        accepted, conflicts = bridge.verify_conflicts(live_state)

        # Only 0x1400010C0 should be accepted for rename; the 3 analyst-edited symbols are skipped
        assert accepted["renames"] == {"0x1400010C0": "clean_function_d"}
        assert accepted["comments"] == {}
        assert len(conflicts) == 4

        conflict_addrs = [c["address"] for c in conflicts if c["category"] == "renames"]
        assert conflict_addrs == ["0x140001000", "0x140001040", "0x140001080"]
        assert conflicts[0]["before"] == "FUN_140001000"
        assert conflicts[0]["live"] == "analyst_manual_decrypt"
        assert conflicts[0]["proposed"] == "agent_proposed_a"

    def test_is_default_ghidra_symbol_helper(self):
        assert is_default_ghidra_symbol("FUN_140001000") is True
        assert is_default_ghidra_symbol("sub_401000") is True
        assert is_default_ghidra_symbol("LAB_140001010") is True
        assert is_default_ghidra_symbol("DAT_140005000") is True
        assert is_default_ghidra_symbol("analyst_custom_fn") is False


class TestLiveWatcherScriptGenerationAndExecution:
    def test_watcher_script_ast_syntax_and_required_constructs(self, tmp_path):
        overlay_path = tmp_path / "ghidra_overlay.json"
        overlay_path.write_text(
            json.dumps({"renames": {"0x140001000": "watched_func"}}),
            encoding="utf-8",
        )

        bridge = OverlaySyncBridge(overlay_path)
        script = bridge.generate_ghidra_watcher_script(
            poll_interval_ms=350,
            dry_run=False,
            verify_conflicts=True,
        )

        # 1. Verify valid Python AST
        tree = ast.parse(script)
        assert tree is not None

        # 2. Verify polling interval, transaction wrapping, fingerprint check, and conflict check
        assert "POLL_INTERVAL_MS = 350" in script
        assert "VERIFY_CONFLICTS = True" in script
        assert 'prog.startTransaction("SuperGhidra Live Overlay Sync")' in script
        assert "prog.endTransaction(tx_id, commit)" in script
        assert "st_mtime_ns" in script
        assert "hashlib.sha256" in script
        assert "threading.Thread" in script
        assert "daemon=True" in script
        assert "superghidra.watcher.stop" in script
        assert "getFunctionAt" in script
        assert "getName" in script

    def test_simulated_execution_against_mock_current_program_harness(self, tmp_path):
        """
        Simulate running the generated watcher script inside Ghidra CodeBrowser:
        - Tick 1: 0x140001000 has default 'FUN_140001000' -> renamed to 'rpc_dispatch'.
                  0x140002000 was manually renamed by the analyst to 'analyst_keep_me' ->
                  skipped due to conflict check!
        - Tick 2: Overlay file on disk is updated with a new function 0x140003000 ->
                  '_poll_once' detects the new (mtime_ns, size, sha256) and applies ONLY
                  the incremental delta in a new transaction.
        """
        overlay_path = tmp_path / "live_overlay.json"
        initial_payload = {
            "renames": {
                "0x140001000": {"before": "FUN_140001000", "after": "rpc_dispatch"},
                "0x140002000": {"before": "FUN_140002000", "after": "agent_clobber_attempt"},
            },
            "comments": {
                "0x140001000": {"text": "Main RPC entry point", "type": "PLATE"},
            },
        }
        overlay_path.write_text(json.dumps(initial_payload), encoding="utf-8")

        script = generate_ghidra_watcher_script(
            overlay_path,
            poll_interval_ms=200,
            dry_run=False,
            verify_conflicts=True,
        )

        # Build mock currentProgram / FlatProgramAPI harness
        fn_map: Dict[str, MagicMock] = {}

        def _make_fn(initial_name: str) -> MagicMock:
            fn = MagicMock()
            state = {"name": initial_name, "comment": ""}
            fn.getName.side_effect = lambda: state["name"]

            def _set_name(new_name, _src_type=None):
                state["name"] = new_name

            fn.setName.side_effect = _set_name
            fn.getComment.side_effect = lambda: state["comment"]

            def _set_comment(c):
                state["comment"] = c

            fn.setComment.side_effect = _set_comment
            return fn

        fn_map["0x140001000"] = _make_fn("FUN_140001000")
        fn_map["0x140002000"] = _make_fn("analyst_keep_me")
        fn_map["0x140003000"] = _make_fn("FUN_140003000")

        mock_prog = MagicMock()
        mock_listing = MagicMock()
        mock_sym_table = MagicMock()

        mock_prog.getListing.return_value = mock_listing
        mock_prog.getSymbolTable.return_value = mock_sym_table
        mock_listing.getFunctionAt.side_effect = lambda addr: fn_map.get(str(addr))

        tx_counter = {"id": 0}

        def _start_tx(_desc: str) -> int:
            tx_counter["id"] += 1
            return tx_counter["id"]

        mock_prog.startTransaction.side_effect = _start_tx

        env = {
            "currentProgram": mock_prog,
            "toAddr": lambda s: s,
            "createLabel": MagicMock(),
            "setComment": MagicMock(),
            "SUPERGHIDRA_WATCHER_SINGLE_SHOT": True,
        }

        # Execute watcher script (runs Tick 1 synchronously)
        exec(script, env)

        # Verify Tick 1 results:
        # - 0x140001000 renamed to 'rpc_dispatch'
        # - 0x140002000 skipped because analyst renamed it to 'analyst_keep_me'
        assert fn_map["0x140001000"].getName() == "rpc_dispatch"
        assert fn_map["0x140002000"].getName() == "analyst_keep_me"
        assert fn_map["0x140002000"].setName.call_count == 0
        assert len(env["WATCHER_STATE"]["conflicts"]) == 1
        assert env["WATCHER_STATE"]["conflicts"][0]["address"] == "0x140002000"
        assert env["WATCHER_STATE"]["conflicts"][0]["live"] == "analyst_keep_me"
        mock_prog.startTransaction.assert_called_once_with("SuperGhidra Live Overlay Sync")
        mock_prog.endTransaction.assert_called_once_with(1, True)

        # Poll again without changing the file -> no-op (returns False, no new transaction)
        changed = env["_poll_once"](mock_prog, env["WATCHER_STATE"])
        assert changed is False
        assert mock_prog.startTransaction.call_count == 1

        # Tick 2: update the overlay file on disk with a new rename at 0x140003000
        updated_payload = {
            "renames": {
                "0x140001000": {"before": "FUN_140001000", "after": "rpc_dispatch"},
                "0x140002000": {"before": "FUN_140002000", "after": "agent_clobber_attempt"},
                "0x140003000": {"before": "FUN_140003000", "after": "rpc_send_reply"},
            },
            "comments": {
                "0x140001000": {"text": "Main RPC entry point", "type": "PLATE"},
            },
        }
        overlay_path.write_text(json.dumps(updated_payload), encoding="utf-8")

        fn_map["0x140001000"].setName.reset_mock()
        changed2 = env["_poll_once"](mock_prog, env["WATCHER_STATE"])
        assert changed2 is True
        assert mock_prog.startTransaction.call_count == 2
        # Only 0x140003000 should be renamed in Tick 2; 0x140001000 was not re-applied
        assert fn_map["0x140003000"].getName() == "rpc_send_reply"
        assert fn_map["0x140001000"].setName.call_count == 0

    def test_background_thread_lifecycle_and_stop_watcher(self, tmp_path):
        overlay_path = tmp_path / "bg_overlay.json"
        overlay_path.write_text(
            json.dumps({"renames": {"0x140001000": "bg_func_1"}}),
            encoding="utf-8",
        )

        script = sync_to_script(
            str(overlay_path),
            watch=True,
            poll_interval_ms=30,
            verify_conflicts=True,
        )

        mock_prog = MagicMock()
        mock_listing = MagicMock()
        mock_prog.getListing.return_value = mock_listing
        mock_prog.getSymbolTable.return_value = MagicMock()
        mock_fn = MagicMock()
        mock_fn.getName.return_value = "FUN_140001000"
        mock_listing.getFunctionAt.return_value = mock_fn
        mock_prog.startTransaction.return_value = 1

        env = {
            "currentProgram": mock_prog,
            "toAddr": lambda s: s,
        }
        exec(script, env)
        try:
            watcher_thread = env["WATCHER_STATE"]["thread"]
            assert watcher_thread is not None
            assert watcher_thread.daemon is True
            assert watcher_thread.is_alive()

            # Write an update and let the background thread pick it up
            overlay_path.write_text(
                json.dumps({"renames": {"0x140001000": "bg_func_1", "0x140001020": "bg_func_2"}}),
                encoding="utf-8",
            )
            deadline = time.time() + 1.5
            while env["WATCHER_STATE"]["applied_batches"] < 2 and time.time() < deadline:
                time.sleep(0.02)

            assert env["WATCHER_STATE"]["applied_batches"] >= 2
        finally:
            env["stop_watcher"]()
            if env["WATCHER_STATE"]["thread"] is not None:
                env["WATCHER_STATE"]["thread"].join(timeout=1.0)
            assert not env["WATCHER_STATE"]["thread"].is_alive()

    def test_cli_watch_and_poll_ms_arguments(self, tmp_path):
        overlay_path = tmp_path / "cli_watch.json"
        overlay_path.write_text(
            json.dumps({"renames": {"0x140001000": "cli_watched_fn"}}),
            encoding="utf-8",
        )
        out_path = tmp_path / "watcher_out.py"

        parser = build_arg_parser()
        parsed = parser.parse_args(
            ["--overlay", str(overlay_path), "--out", str(out_path), "--watch", "--poll-ms", "450"]
        )
        assert parsed.watch is True
        assert parsed.poll_ms == 450

        rc = main(
            ["--overlay", str(overlay_path), "--out", str(out_path), "--watch", "--poll-ms", "450"]
        )
        assert rc == 0
        assert out_path.is_file()
        content = out_path.read_text(encoding="utf-8")
        assert "POLL_INTERVAL_MS = 450" in content
        assert 'prog.startTransaction("SuperGhidra Live Overlay Sync")' in content
