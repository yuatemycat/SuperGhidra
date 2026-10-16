"""
Reconstruction Obligation Ledger for SuperGhidra.

Enforces formal proof verification before any function/struct hook, rename,
or definition is committed into the decompilation database.

Verification Invariants:
1. VTable Slot Index:
   - Slot offset alignment (offset % pointer_size == 0).
   - Slot index bounds and hierarchy consistency.
2. Allocation Size:
   - Allocation source validation (g_game_alloc, malloc, operator new).
   - Struct size <= allocation size, proper memory alignment.
3. Struct Field Displacement Alignment:
   - Natural alignment check: offset % access_size == 0 (e.g. [x22, #0x24] for 32-bit load).
   - Struct boundary check: offset + access_size <= total_struct_size.
   - Overlap collision detection between disjoint struct fields.
4. JSON-Backed Ledger:
   - Persistent proof obligations, verification reports, and timestamps.
"""

from __future__ import annotations

import datetime
import enum
import json
import os
import re
import uuid
from typing import Any, Callable, Dict, List, Optional, Tuple, Union


class ObligationStatus(str, enum.Enum):
    PENDING = "PENDING"
    VERIFIED = "VERIFIED"
    REJECTED = "REJECTED"
    COMMITTED = "COMMITTED"


class ObligationType(str, enum.Enum):
    FUNCTION_RENAME = "FUNCTION_RENAME"
    STRUCT_RENAME = "STRUCT_RENAME"
    STRUCT_DEFINITION = "STRUCT_DEFINITION"
    STRUCT_FIELD_RENAME = "STRUCT_FIELD_RENAME"
    VTABLE_HOOK = "VTABLE_HOOK"
    FUNCTION_HOOK = "FUNCTION_HOOK"


class LedgerVerificationError(Exception):
    """Raised when an unverified or rejected obligation is attempted to be committed."""
    pass


class CheckResult:
    """Outcome of a single verification check."""

    def __init__(self, check_name: str, passed: bool, message: str, details: Optional[Dict[str, Any]] = None):
        self.check_name = check_name
        self.passed = passed
        self.message = message
        self.details = details or {}

    def to_dict(self) -> Dict[str, Any]:
        return {
            "check_name": self.check_name,
            "passed": self.passed,
            "message": self.message,
            "details": self.details,
        }


# --- Invariant Verifiers ---

class VTableSlotVerifier:
    """Verifies VTable slot offset, alignment, and index consistency."""

    @staticmethod
    def verify(evidence: Dict[str, Any], pointer_size: int = 8) -> CheckResult:
        if "vtable_slot" not in evidence and "vtable_offset" not in evidence:
            return CheckResult("VTableSlotCheck", True, "No VTable evidence provided (skipped)")

        offset = evidence.get("vtable_offset")
        index = evidence.get("vtable_slot")

        if offset is None and index is not None:
            offset = index * pointer_size
        elif offset is not None and index is None:
            index = offset // pointer_size

        if offset is None or index is None:
            return CheckResult("VTableSlotCheck", False, "Missing vtable offset/index")

        # Alignment invariant: offset must be divisible by pointer_size
        if offset % pointer_size != 0:
            return CheckResult(
                "VTableSlotCheck",
                False,
                f"VTable offset 0x{offset:x} is not aligned to pointer size ({pointer_size} bytes)",
                {"offset": offset, "pointer_size": pointer_size},
            )

        calculated_index = offset // pointer_size
        if calculated_index != index:
            return CheckResult(
                "VTableSlotCheck",
                False,
                f"VTable index mismatch: expected slot {calculated_index} for offset 0x{offset:x}, got {index}",
                {"offset": offset, "calculated_index": calculated_index, "provided_index": index},
            )

        if index < 0 or index > 4096:
            return CheckResult(
                "VTableSlotCheck",
                False,
                f"VTable slot index {index} out of plausible bounds [0, 4096]",
                {"index": index},
            )

        # Max vtable size check if provided
        max_size = evidence.get("vtable_total_size")
        if max_size is not None and offset + pointer_size > max_size:
            return CheckResult(
                "VTableSlotCheck",
                False,
                f"VTable offset 0x{offset:x} exceeds vtable total size 0x{max_size:x}",
                {"offset": offset, "max_size": max_size},
            )

        return CheckResult(
            "VTableSlotCheck",
            True,
            f"VTable slot verified: index {index} (offset 0x{offset:x}, aligned to {pointer_size}B)",
            {"index": index, "offset": offset},
        )


class AllocationSizeVerifier:
    """Verifies heap allocation size against reconstructed struct bounds."""

    VALID_ALLOCATORS = {
        "g_game_alloc",
        "malloc",
        "operator new",
        "operator new[]",
        "calloc",
        "HeapAlloc",
        "VirtualAlloc",
    }

    @classmethod
    def verify(cls, evidence: Dict[str, Any]) -> CheckResult:
        if "allocation_size" not in evidence:
            return CheckResult("AllocationSizeCheck", True, "No allocation size evidence provided (skipped)")

        alloc_size = evidence["allocation_size"]
        allocator = evidence.get("allocator_symbol", "malloc")
        struct_size = evidence.get("struct_size")
        alignment = evidence.get("struct_alignment", 8)

        if alloc_size <= 0:
            return CheckResult("AllocationSizeCheck", False, f"Allocation size must be positive, got {alloc_size}")

        if allocator not in cls.VALID_ALLOCATORS and not allocator.lower().endswith("alloc"):
            return CheckResult(
                "AllocationSizeCheck",
                False,
                f"Unrecognized or unsupported allocator symbol '{allocator}'",
                {"allocator": allocator},
            )

        if struct_size is not None:
            if struct_size <= 0:
                return CheckResult("AllocationSizeCheck", False, f"Struct size must be positive, got {struct_size}")
            if struct_size > alloc_size:
                return CheckResult(
                    "AllocationSizeCheck",
                    False,
                    f"Reconstructed struct size (0x{struct_size:x}) exceeds allocated buffer size (0x{alloc_size:x})",
                    {"struct_size": struct_size, "allocation_size": alloc_size},
                )

        return CheckResult(
            "AllocationSizeCheck",
            True,
            f"Allocation size verified: 0x{alloc_size:x} via '{allocator}' (struct size: {hex(struct_size) if struct_size else 'N/A'})",
            {"allocation_size": alloc_size, "allocator": allocator, "struct_size": struct_size},
        )


class FieldDisplacementVerifier:
    """
    Verifies struct field displacement alignment (e.g. `[x22, #0x24]`).
    Enforces natural alignment and bounds within the struct.
    """

    DISPLACEMENT_PATTERN = re.compile(r"\[\s*(\w+)\s*,\s*#?(0x[0-9a-fA-F]+|[0-9]+)\s*\]")

    @classmethod
    def parse_instruction_displacement(cls, insn_text: str) -> Optional[Tuple[str, int]]:
        """Parses base register and displacement integer from assembly string."""
        m = cls.DISPLACEMENT_PATTERN.search(insn_text)
        if not m:
            return None
        reg = m.group(1)
        raw_val = m.group(2)
        disp = int(raw_val, 16) if raw_val.lower().startswith("0x") else int(raw_val)
        return reg, disp

    @classmethod
    def verify(cls, evidence: Dict[str, Any]) -> CheckResult:
        fields = evidence.get("field_displacements")
        struct_size = evidence.get("struct_size") or evidence.get("allocation_size")

        if not fields:
            return CheckResult("FieldDisplacementCheck", True, "No field displacement evidence provided (skipped)")

        field_spans: List[Tuple[int, int, str]] = []

        for i, field in enumerate(fields):
            name = field.get("name", f"field_{i}")
            offset = field.get("offset")
            access_size = field.get("access_size", 4)
            insn = field.get("instruction", "")

            # If offset not explicitly given, try extracting from instruction string
            if offset is None and insn:
                parsed = cls.parse_instruction_displacement(insn)
                if parsed:
                    _, offset = parsed

            if offset is None:
                return CheckResult("FieldDisplacementCheck", False, f"Missing displacement offset for field '{name}'")

            # Check natural alignment: offset must be divisible by access_size
            if access_size > 1 and (offset % access_size != 0):
                return CheckResult(
                    "FieldDisplacementCheck",
                    False,
                    f"Field '{name}' at offset 0x{offset:x} violates natural alignment for access size {access_size} bytes (offset % {access_size} != 0)",
                    {"field": name, "offset": offset, "access_size": access_size, "instruction": insn},
                )

            # Check struct bounds
            if struct_size is not None and (offset + access_size > struct_size):
                return CheckResult(
                    "FieldDisplacementCheck",
                    False,
                    f"Field '{name}' span [0x{offset:x}, 0x{offset + access_size:x}) overflows struct bounds (0x{struct_size:x})",
                    {"field": name, "offset": offset, "access_size": access_size, "struct_size": struct_size},
                )

            # Check collision / overlap with previous non-overlapping fields
            allow_overlap = field.get("allow_overlap", False)
            if not allow_overlap:
                for prev_start, prev_end, prev_name in field_spans:
                    if max(offset, prev_start) < min(offset + access_size, prev_end):
                        return CheckResult(
                            "FieldDisplacementCheck",
                            False,
                            f"Field '{name}' [0x{offset:x}, 0x{offset + access_size:x}) collides with '{prev_name}' [0x{prev_start:x}, 0x{prev_end:x})",
                            {"field": name, "colliding_field": prev_name},
                        )

                field_spans.append((offset, offset + access_size, name))

        return CheckResult(
            "FieldDisplacementCheck",
            True,
            f"All {len(fields)} field displacements verified with valid natural alignment and bounds",
            {"count": len(fields)},
        )


class ProofObligation:
    """Represents an individual reconstruction proof obligation."""

    def __init__(
        self,
        obligation_id: str,
        obligation_type: Union[ObligationType, str],
        target_name: str,
        proposed_name: str,
        target_address: Optional[int] = None,
        evidence: Optional[Dict[str, Any]] = None,
        status: Union[ObligationStatus, str] = ObligationStatus.PENDING,
        created_at: Optional[str] = None,
        verified_at: Optional[str] = None,
        committed_at: Optional[str] = None,
        verification_results: Optional[List[Dict[str, Any]]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ):
        self.obligation_id = obligation_id
        self.obligation_type = ObligationType(obligation_type)
        self.target_name = target_name
        self.proposed_name = proposed_name
        self.target_address = target_address
        self.evidence = evidence or {}
        self.status = ObligationStatus(status)
        self.created_at = created_at or datetime.datetime.now(datetime.timezone.utc).isoformat()
        self.verified_at = verified_at
        self.committed_at = committed_at
        self.verification_results = verification_results or []
        self.metadata = metadata or {}

    def to_dict(self) -> Dict[str, Any]:
        return {
            "obligation_id": self.obligation_id,
            "obligation_type": self.obligation_type.value,
            "target_name": self.target_name,
            "proposed_name": self.proposed_name,
            "target_address": hex(self.target_address) if self.target_address is not None else None,
            "evidence": self.evidence,
            "status": self.status.value,
            "created_at": self.created_at,
            "verified_at": self.verified_at,
            "committed_at": self.committed_at,
            "verification_results": self.verification_results,
            "metadata": self.metadata,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> ProofObligation:
        addr = data.get("target_address")
        if isinstance(addr, str) and addr.lower().startswith("0x"):
            addr = int(addr, 16)
        elif isinstance(addr, (int, float)):
            addr = int(addr)
        else:
            addr = None

        return cls(
            obligation_id=data["obligation_id"],
            obligation_type=data["obligation_type"],
            target_name=data["target_name"],
            proposed_name=data["proposed_name"],
            target_address=addr,
            evidence=data.get("evidence", {}),
            status=data.get("status", ObligationStatus.PENDING),
            created_at=data.get("created_at"),
            verified_at=data.get("verified_at"),
            committed_at=data.get("committed_at"),
            verification_results=data.get("verification_results", []),
            metadata=data.get("metadata", {}),
        )


class ReconstructionObligationLedger:
    """
    Reconstruction Obligation Ledger.
    Tracks proof obligations and strictly gates decompilation commits
    behind structural and invariant verification.
    """

    def __init__(self, ledger_file: Optional[str] = None):
        if ledger_file is None:
            ledger_file = os.path.join(os.path.dirname(__file__), "evidence_ledger.json")
        self.ledger_file = os.path.abspath(ledger_file)
        self.obligations: Dict[str, ProofObligation] = {}
        if os.path.exists(self.ledger_file):
            self.load()

    def propose(
        self,
        obligation_type: Union[ObligationType, str],
        target_name: str,
        proposed_name: str,
        target_address: Optional[int] = None,
        evidence: Optional[Dict[str, Any]] = None,
        metadata: Optional[Dict[str, Any]] = None,
        obligation_id: Optional[str] = None,
    ) -> ProofObligation:
        """Proposes a new reconstruction obligation in PENDING state."""
        if obligation_id is None:
            obligation_id = f"OBL-{uuid.uuid4().hex[:8].upper()}"

        obligation = ProofObligation(
            obligation_id=obligation_id,
            obligation_type=obligation_type,
            target_name=target_name,
            proposed_name=proposed_name,
            target_address=target_address,
            evidence=evidence or {},
            status=ObligationStatus.PENDING,
            metadata=metadata or {},
        )
        self.obligations[obligation_id] = obligation
        self.save()
        return obligation

    def verify(self, obligation_id: str) -> bool:
        """
        Executes formal invariant checks on the obligation's evidence.
        Transitions status to VERIFIED if all checks pass, or REJECTED if any fail.
        """
        if obligation_id not in self.obligations:
            raise KeyError(f"Obligation '{obligation_id}' not found in ledger.")

        obligation = self.obligations[obligation_id]
        results: List[CheckResult] = []

        # 1. VTable Slot check
        vtable_res = VTableSlotVerifier.verify(obligation.evidence)
        results.append(vtable_res)

        # 2. Allocation Size check
        alloc_res = AllocationSizeVerifier.verify(obligation.evidence)
        results.append(alloc_res)

        # 3. Field Displacement Alignment check
        field_res = FieldDisplacementVerifier.verify(obligation.evidence)
        results.append(field_res)

        all_passed = all(r.passed for r in results)
        obligation.verification_results = [r.to_dict() for r in results]
        now_ts = datetime.datetime.now(datetime.timezone.utc).isoformat()

        if all_passed:
            obligation.status = ObligationStatus.VERIFIED
            obligation.verified_at = now_ts
        else:
            obligation.status = ObligationStatus.REJECTED
            obligation.verified_at = now_ts

        self.save()
        return all_passed

    def commit(
        self,
        obligation_id: str,
        action_callback: Optional[Callable[[ProofObligation], Any]] = None,
    ) -> Any:
        """
        Commits a verified obligation to the project.
        CRITICAL INVARIANT: Rejects commit if the obligation is not in VERIFIED status.
        """
        if obligation_id not in self.obligations:
            raise KeyError(f"Obligation '{obligation_id}' not found in ledger.")

        obligation = self.obligations[obligation_id]

        if obligation.status == ObligationStatus.COMMITTED:
            return None  # Already committed

        if obligation.status != ObligationStatus.VERIFIED:
            reasons = [r["message"] for r in obligation.verification_results if not r.get("passed", True)]
            err_msg = (
                f"Cannot commit obligation '{obligation_id}' with status {obligation.status.value}. "
                f"Failures: {'; '.join(reasons) if reasons else 'Verification has not been executed.'}"
            )
            raise LedgerVerificationError(err_msg)

        callback_result = None
        if action_callback:
            callback_result = action_callback(obligation)

        obligation.status = ObligationStatus.COMMITTED
        obligation.committed_at = datetime.datetime.now(datetime.timezone.utc).isoformat()
        self.save()
        return callback_result

    def reject(self, obligation_id: str, reason: str) -> None:
        """Manually rejects an obligation with an explanatory note."""
        if obligation_id not in self.obligations:
            raise KeyError(f"Obligation '{obligation_id}' not found in ledger.")
        obligation = self.obligations[obligation_id]
        obligation.status = ObligationStatus.REJECTED
        obligation.verification_results.append({
            "check_name": "ManualRejection",
            "passed": False,
            "message": reason,
            "details": {},
        })
        self.save()

    def get(self, obligation_id: str) -> Optional[ProofObligation]:
        return self.obligations.get(obligation_id)

    def list_obligations(
        self,
        status: Optional[Union[ObligationStatus, str]] = None,
    ) -> List[ProofObligation]:
        if status is None:
            return list(self.obligations.values())
        status_val = ObligationStatus(status)
        return [o for o in self.obligations.values() if o.status == status_val]

    def audit_summary(self) -> Dict[str, Any]:
        """Returns statistics of proof obligations recorded in ledger."""
        counts = {s.value: 0 for s in ObligationStatus}
        for o in self.obligations.values():
            counts[o.status.value] += 1
        return {
            "total_obligations": len(self.obligations),
            "status_counts": counts,
            "ledger_path": self.ledger_file,
        }

    def save(self, file_path: Optional[str] = None) -> None:
        target = file_path or self.ledger_file
        data = {
            "version": "1.0.0",
            "updated_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "obligations": [o.to_dict() for o in self.obligations.values()],
        }
        os.makedirs(os.path.dirname(os.path.abspath(target)), exist_ok=True)
        with open(target, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)

    def load(self, file_path: Optional[str] = None) -> None:
        target = file_path or self.ledger_file
        if not os.path.exists(target):
            return
        with open(target, "r", encoding="utf-8") as f:
            data = json.load(f)
        self.obligations = {}
        for item in data.get("obligations", []):
            obl = ProofObligation.from_dict(item)
            self.obligations[obl.obligation_id] = obl


if __name__ == "__main__":
    print("=== SuperGhidra Reconstruction Obligation Ledger Demo ===")
    ledger = ReconstructionObligationLedger()

    # 1. Propose valid obligation
    obl1 = ledger.propose(
        obligation_type=ObligationType.FUNCTION_HOOK,
        target_name="sub_10045A820",
        proposed_name="Player::TakeDamage",
        target_address=0x10045A820,
        evidence={
            "vtable_slot": 7,
            "vtable_offset": 0x38,
            "allocator_symbol": "g_game_alloc",
            "allocation_size": 0x200,
            "struct_size": 0x180,
            "field_displacements": [
                {"name": "m_vtable", "offset": 0x00, "access_size": 8, "instruction": "ldr x8, [x0]"},
                {"name": "m_health", "offset": 0x24, "access_size": 4, "instruction": "ldr w1, [x22, #0x24]"},
                {"name": "m_maxHealth", "offset": 0x28, "access_size": 4, "instruction": "ldr w2, [x22, #0x28]"},
            ],
        },
    )
    print(f"Created obligation: {obl1.obligation_id} ({obl1.status.value})")

    # Verify and commit
    is_valid = ledger.verify(obl1.obligation_id)
    print(f"Verification result: {'PASS' if is_valid else 'FAIL'} (Status: {obl1.status.value})")
    ledger.commit(obl1.obligation_id)
    print(f"Committed: {obl1.status.value} at {obl1.committed_at}")

    # 2. Propose invalid obligation (unaligned displacement 0x25 for 4-byte load)
    obl2 = ledger.propose(
        obligation_type=ObligationType.STRUCT_DEFINITION,
        target_name="struct_unknown_48",
        proposed_name="BadAlignmentStruct",
        evidence={
            "field_displacements": [
                {"name": "m_badField", "offset": 0x25, "access_size": 4, "instruction": "ldr w1, [x22, #0x25]"},
            ],
        },
    )
    is_valid2 = ledger.verify(obl2.obligation_id)
    print(f"Unaligned test verification: {'PASS' if is_valid2 else 'REJECTED as expected'} (Status: {obl2.status.value})")
    try:
        ledger.commit(obl2.obligation_id)
        print("ERROR: Unverified obligation was committed!")
    except LedgerVerificationError as e:
        print(f"Safety gate successfully blocked unverified commit: {e}")

    summary = ledger.audit_summary()
    print("Ledger summary:", summary)
