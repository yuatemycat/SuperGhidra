"""Unit tests for SuperGhidra Versioned JSON Schemas and Schema Validator."""

from __future__ import annotations

import unittest

from superghidra.schemas import (
    SCHEMA_FILES,
    load_schema,
    validate_dict_against_schema,
)


class TestVersionedSchemas(unittest.TestCase):
    """Verifies that versioned schemas correctly validate valid instances and reject invalid data."""

    def test_all_registered_schemas_exist_and_load(self):
        for name in SCHEMA_FILES:
            schema = load_schema(name)
            self.assertIsInstance(schema, dict)
            self.assertIn("$schema", schema)
            self.assertIn("title", schema)

    def test_overlay_schema_valid_instance(self):
        valid_overlay = {
            "version": 1,
            "file": "/path/to/binary.so",
            "renames": {
                "0x00101000": "Player_Init",
                "0x00101050": "Player_Update",
            },
            "comments": {
                "0x00101000": "Initialization function",
            },
            "prototypes": {
                "0x00101000": "void Player_Init(void)",
            },
        }
        is_valid, errors = validate_dict_against_schema(valid_overlay, "overlay")
        self.assertTrue(is_valid, f"Overlay should be valid, got errors: {errors}")
        self.assertEqual(len(errors), 0)

    def test_overlay_schema_missing_required(self):
        invalid_overlay = {
            "version": 1,
            # missing renames and comments
        }
        is_valid, errors = validate_dict_against_schema(invalid_overlay, "overlay")
        self.assertFalse(is_valid)
        self.assertTrue(any("renames" in e for e in errors))
        self.assertTrue(any("comments" in e for e in errors))

    def test_delta_log_schema_valid_event(self):
        valid_event = {
            "schema_version": 1,
            "event_id": "EVT-ABC123DEF456",
            "event_type": "RENAME_FUNCTION",
            "timestamp": "2026-10-26T08:00:00Z",
            "author": "analyst",
            "target_address": 0x1000,
            "payload": {
                "old_name": "FUN_00001000",
                "new_name": "GameMain",
            },
            "proof_hash": "a" * 64,
            "verified": True,
        }
        is_valid, errors = validate_dict_against_schema(valid_event, "delta_log")
        self.assertTrue(is_valid, f"Delta event should be valid, got errors: {errors}")

    def test_delta_log_schema_invalid_type(self):
        invalid_event = {
            "schema_version": 1,
            "event_id": "EVT-123",
            "event_type": "UNKNOWN_EVENT_TYPE_XYZ",
            "timestamp": "2026-10-26T08:00:00Z",
            "payload": {},
            "proof_hash": "a" * 64,
        }
        is_valid, errors = validate_dict_against_schema(invalid_event, "delta_log")
        self.assertFalse(is_valid)
        self.assertTrue(any("event_type" in e for e in errors))

    def test_evidence_ledger_schema_valid_instance(self):
        valid_ledger = {
            "version": "1.0.0",
            "created_at": "2026-10-26T08:00:00Z",
            "obligations": [
                {
                    "obligation_id": "OBL-001",
                    "obligation_type": "VTABLE_SLOT_BOUND",
                    "status": "VERIFIED",
                    "target_address": 0x180005000,
                    "evidence": {"slot_count": 8},
                }
            ],
        }
        is_valid, errors = validate_dict_against_schema(valid_ledger, "evidence_ledger")
        self.assertTrue(is_valid, f"Ledger should be valid, got errors: {errors}")

    def test_struct_shift_schema_valid_report(self):
        valid_shift = {
            "version": 1,
            "v1_binary": "libv1.so",
            "v2_binary": "libv2.so",
            "arch": "arm64",
            "structs": [
                {
                    "name": "PlayerEntity",
                    "v1_size": 32,
                    "v2_size": 40,
                    "fields": [
                        {
                            "name": "health",
                            "v1_offset": 0,
                            "v2_offset": 0,
                            "delta": 0,
                            "classification": "identical",
                        },
                        {
                            "name": "shield",
                            "v1_offset": 16,
                            "v2_offset": 24,
                            "delta": 8,
                            "classification": "insertion_shift",
                        },
                    ],
                }
            ],
        }
        is_valid, errors = validate_dict_against_schema(valid_shift, "struct_shift")
        self.assertTrue(is_valid, f"Struct shift should be valid, got errors: {errors}")


if __name__ == "__main__":
    unittest.main()
