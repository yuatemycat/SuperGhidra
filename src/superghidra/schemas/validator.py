"""Runtime JSON Schema Validation for SuperGhidra Formats.

Provides local validation for SuperGhidra JSON formats against versioned schemas:
- overlay.schema.v1.json (WriteOverlay / ghidra_overlay.json)
- delta_log.schema.v1.json (SemanticDeltaLog / .ghidra-delta.jsonl)
- evidence_ledger.schema.v1.json (ReconstructionObligationLedger)
- struct_shift.schema.v1.json (StructShiftMigrator)
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Tuple

SCHEMAS_DIR = Path(__file__).resolve().parent

SCHEMA_FILES: Dict[str, str] = {
    "overlay": "overlay.schema.v1.json",
    "delta_log": "delta_log.schema.v1.json",
    "evidence_ledger": "evidence_ledger.schema.v1.json",
    "struct_shift": "struct_shift.schema.v1.json",
}

_SCHEMA_CACHE: Dict[str, Dict[str, Any]] = {}


def load_schema(schema_name: str) -> Dict[str, Any]:
    """Loads a schema JSON definition by canonical name."""
    if schema_name not in SCHEMA_FILES:
        raise ValueError(
            f"Unknown schema name '{schema_name}'. Known schemas: {sorted(SCHEMA_FILES.keys())}"
        )

    if schema_name in _SCHEMA_CACHE:
        return _SCHEMA_CACHE[schema_name]

    schema_path = SCHEMAS_DIR / SCHEMA_FILES[schema_name]
    if not schema_path.is_file():
        raise FileNotFoundError(f"Schema file not found: {schema_path}")

    with open(schema_path, encoding="utf-8") as f:
        schema = json.load(f)

    _SCHEMA_CACHE[schema_name] = schema
    return schema


def validate_dict_against_schema(
    instance: Dict[str, Any],
    schema_name: str,
) -> Tuple[bool, List[str]]:
    """Validates an instance dictionary against a registered SuperGhidra schema.

    Returns:
        (is_valid, list_of_error_messages)
    """
    schema = load_schema(schema_name)
    errors: List[str] = []

    # Check top-level required properties
    required_props = schema.get("required", [])
    for prop in required_props:
        if prop not in instance:
            errors.append(f"Missing required property: '{prop}'")

    # Validate type and property rules
    properties = schema.get("properties", {})
    for key, value in instance.items():
        if key not in properties:
            if not schema.get("additionalProperties", True):
                errors.append(f"Disallowed property: '{key}'")
            continue

        prop_spec = properties[key]
        expected_type = prop_spec.get("type")

        if expected_type:
            types = [expected_type] if isinstance(expected_type, str) else expected_type
            type_matched = False
            for t in types:
                if t == "object" and isinstance(value, dict):
                    type_matched = True
                elif t == "array" and isinstance(value, list):
                    type_matched = True
                elif t == "string" and isinstance(value, str):
                    type_matched = True
                elif t == "integer" and isinstance(value, int) and not isinstance(value, bool):
                    type_matched = True
                elif t == "number" and (isinstance(value, (int, float)) and not isinstance(value, bool)):
                    type_matched = True
                elif t == "boolean" and isinstance(value, bool):
                    type_matched = True
                elif t == "null" and value is None:
                    type_matched = True

            if not type_matched:
                errors.append(
                    f"Property '{key}' expected type {expected_type}, got {type(value).__name__}"
                )

        # Check enum if specified
        if "enum" in prop_spec and value not in prop_spec["enum"]:
            errors.append(
                f"Property '{key}' value '{value}' not in allowed enum: {prop_spec['enum']}"
            )

    return len(errors) == 0, errors
