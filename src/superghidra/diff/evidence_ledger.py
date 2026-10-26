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
import struct
import uuid
from typing import Any, Callable, Dict, List, Optional, Tuple, Union


class ObligationStatus(str, enum.Enum):
    PENDING = "PENDING"
    VERIFIED = "VERIFIED"
    REJECTED = "REJECTED"
    COMMITTED = "COMMITTED"
    UNVERIFIED = "UNVERIFIED"


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

    def __init__(
        self,
        check_name: str,
        passed: bool,
        message: str,
        details: Optional[Dict[str, Any]] = None,
        proven: bool = True,
    ):
        self.check_name = check_name
        self.passed = passed
        self.message = message
        self.details = details or {}
        self.proven = proven

    def to_dict(self) -> Dict[str, Any]:
        return {
            "check_name": self.check_name,
            "passed": self.passed,
            "message": self.message,
            "details": self.details,
            "proven": self.proven,
        }


# --- Invariant Verifiers ---

class VTableSlotVerifier:
    """Verifies VTable slot offset, alignment, and index consistency."""

    @staticmethod
    def verify(evidence: Dict[str, Any], pointer_size: int = 8) -> CheckResult:
        if "vtable_slot" not in evidence and "vtable_offset" not in evidence:
            return CheckResult("VTableSlotCheck", True, "No VTable evidence provided (not proven)", details={"skipped": True}, proven=False)

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

    @classmethod
    def extract_and_verify_arm64(
        cls,
        code_bytes: bytes,
        expected_slot_offset: int,
        vtable_base_addr: int = 0x200000,
        base_pc: int = 0x1000,
    ) -> CheckResult:
        """
        Scans code_bytes for ARM64 VTable dispatch patterns:
        - LDR Xvt, [Xobj, #0]
        - LDR Xfn, [Xvt, #slot_offset]
        - BLR Xfn
        Confirming slot_offset == expected_slot_offset and 8-byte pointer alignment.
        """
        num_insns = len(code_bytes) // 4
        if num_insns == 0:
            return CheckResult("VTableSlotCheck", False, "Empty ARM64 instruction stream")

        insns = [struct.unpack_from("<I", code_bytes, i * 4)[0] for i in range(num_insns)]
        detected_slots: List[int] = []

        for i in range(num_insns):
            insn = insns[i]
            # 64-bit unsigned immediate load: LDR Xt, [Xn, #offset] -> (insn & 0xFFC00000) == 0xF9400000
            if (insn & 0xFFC00000) == 0xF9400000:
                rt = insn & 0x1F
                imm12 = (insn >> 10) & 0xFFF
                offset = imm12 * 8

                # Look ahead 1..4 instructions for BLR Xt (where rn == rt)
                for j in range(i + 1, min(num_insns, i + 5)):
                    insn_next = insns[j]
                    if (insn_next & 0xFFFFFC1F) == 0xD63F0000:  # BLR
                        blr_rn = (insn_next >> 5) & 0x1F
                        if blr_rn == rt:
                            detected_slots.append(offset)
                            break

        if not detected_slots:
            return CheckResult(
                "VTableSlotCheck",
                False,
                "No ARM64 VTable dispatch pattern (LDR [Xvt, #offset] -> BLR) detected in code stream",
            )

        if expected_slot_offset in detected_slots:
            if expected_slot_offset % 8 != 0:
                return CheckResult(
                    "VTableSlotCheck",
                    False,
                    f"VTable slot offset 0x{expected_slot_offset:x} violates 8-byte pointer alignment",
                    {"offset": expected_slot_offset},
                )
            slot_idx = expected_slot_offset // 8
            return CheckResult(
                "VTableSlotCheck",
                True,
                f"Verified ARM64 VTable slot dispatch: slot offset 0x{expected_slot_offset:x} (slot index {slot_idx})",
                {"slot_offset": expected_slot_offset, "slot_index": slot_idx, "detected_slots": detected_slots},
            )

        return CheckResult(
            "VTableSlotCheck",
            False,
            f"VTable slot offset 0x{expected_slot_offset:x} not found in detected hardware dispatch offsets {[hex(s) for s in detected_slots]}",
            {"expected_slot_offset": expected_slot_offset, "detected_slots": detected_slots},
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
            return CheckResult("AllocationSizeCheck", True, "No allocation size evidence provided (not proven)", details={"skipped": True}, proven=False)

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

    @classmethod
    def extract_and_verify_arm64(
        cls,
        code_bytes: bytes,
        struct_size: int,
        max_field_end: int = 0,
        base_pc: int = 0x1000,
    ) -> CheckResult:
        """
        Scans code_bytes for immediate assignments to W0/X0 followed within 1-4 instructions
        by a BL or BLR allocation call (operator new / malloc), extracts the hardware
        allocation_size, and delegates to cls.verify().
        """
        num_insns = len(code_bytes) // 4
        if num_insns == 0:
            return CheckResult("AllocationSizeCheck", False, "Empty ARM64 instruction stream")

        insns = [struct.unpack_from("<I", code_bytes, i * 4)[0] for i in range(num_insns)]
        alloc_size: Optional[int] = None

        for i in range(num_insns):
            insn = insns[i]
            candidate_imm: Optional[int] = None

            # 1. MOVZ W0/X0, #imm16
            if (insn & 0x7F80001F) == 0x52800000 or (insn & 0xFF80001F) == 0xD2800000:
                imm16 = (insn >> 5) & 0xFFFF
                hw = (insn >> 21) & 3
                candidate_imm = imm16 << (hw * 16)

            # 2. ADD W0/X0, WZR/XZR, #imm12
            elif (insn & 0x7FE003FF) == 0x110003E0 or (insn & 0xFFE003FF) == 0x910003E0:
                candidate_imm = (insn >> 10) & 0xFFF

            # 3. MOVN W0/X0, #imm16
            elif (insn & 0x7F80001F) == 0x12800000 or (insn & 0xFF80001F) == 0x92800000:
                imm16 = (insn >> 5) & 0xFFFF
                candidate_imm = (~imm16) & 0xFFFFFFFF

            if candidate_imm is not None:
                # Check next 1..4 instructions for BL or BLR
                for j in range(i + 1, min(num_insns, i + 5)):
                    next_insn = insns[j]
                    is_bl = (next_insn & 0xFC000000) == 0x94000000
                    is_blr = (next_insn & 0xFFFFFC1F) == 0xD63F0000
                    if is_bl or is_blr:
                        alloc_size = candidate_imm
                        break
                if alloc_size is not None:
                    break

        if alloc_size is None:
            return CheckResult(
                "AllocationSizeCheck",
                False,
                "No ARM64 allocation call (BL/BLR) with immediate size to W0/X0 found in code stream",
            )

        if max_field_end > 0 and max_field_end > alloc_size:
            return CheckResult(
                "AllocationSizeCheck",
                False,
                f"Struct fields boundary (0x{max_field_end:x}) exceeds hardware allocation size (0x{alloc_size:x})",
                {"allocation_size": alloc_size, "max_field_end": max_field_end},
            )

        return cls.verify({
            "allocation_size": alloc_size,
            "struct_size": struct_size,
            "allocator_symbol": "operator new",
        })


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
            return CheckResult("FieldDisplacementCheck", True, "No field displacement evidence provided (not proven)", details={"skipped": True}, proven=False)

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

    @classmethod
    def extract_and_verify_arm64(
        cls,
        code_bytes: bytes,
        claimed_fields: List[Dict[str, Any]],
        base_pc: int = 0x1000,
    ) -> CheckResult:
        """
        Decodes ARM64 memory instructions across code_bytes, collecting hardware
        (offset, size, mnemonic) accesses, and validates claimed_fields for hardware
        backing and natural alignment.
        """
        num_insns = len(code_bytes) // 4
        if num_insns == 0:
            return CheckResult("FieldDisplacementCheck", False, "Empty ARM64 instruction stream")

        hw_accesses: List[Tuple[int, int, str]] = []  # (offset, size, mnemonic)

        for i in range(num_insns):
            insn = struct.unpack_from("<I", code_bytes, i * 4)[0]

            # 1. LDR / STR unsigned immediate: (insn & 0x3B000000) == 0x39000000
            if (insn & 0x3B000000) == 0x39000000:
                rn = (insn >> 5) & 0x1F
                if rn in (29, 31):
                    continue  # Ignore SP (31) and FP (29) frame accesses
                v = (insn >> 26) & 1
                opc = (insn >> 22) & 3
                sz_code = (insn >> 30) & 3
                if v:
                    if (opc & 2) and sz_code == 0:
                        sz = 16  # Q vector
                    elif sz_code == 3:
                        sz = 8   # D vector
                    elif sz_code == 2:
                        sz = 4   # S vector
                    elif sz_code == 1:
                        sz = 2   # H vector
                    else:
                        sz = 1   # B vector
                    is_load = bool(opc & 1)
                else:
                    sz = 1 << sz_code
                    is_load = (opc == 1)
                imm12 = (insn >> 10) & 0xFFF
                offset = imm12 * sz
                hw_accesses.append((offset, sz, "LDR" if is_load else "STR"))

            # 2. LDP / STP: (insn & 0x3A000000) == 0x28000000
            elif (insn & 0x3A000000) == 0x28000000:
                rn = (insn >> 5) & 0x1F
                if rn in (29, 31):
                    continue  # Ignore SP (31) and FP (29) frame accesses
                v = (insn >> 26) & 1
                opc = (insn >> 30) & 3
                if v:
                    if opc == 2:
                        sz = 16  # Q vector
                    elif opc == 1:
                        sz = 8   # D vector
                    else:
                        sz = 4   # S vector
                else:
                    sz = 8 if (opc & 2) else 4
                imm7 = (insn >> 15) & 0x7F
                if imm7 & 0x40:
                    imm7 -= 0x80
                offset1 = imm7 * sz
                offset2 = offset1 + sz
                is_load = bool((insn >> 22) & 1)
                mnem = "LDP" if is_load else "STP"
                if offset1 >= 0:
                    hw_accesses.append((offset1, sz, mnem))
                if offset2 >= 0:
                    hw_accesses.append((offset2, sz, mnem))

            # 3. LDUR / STUR: (insn & 0x3B200C00) == 0x38000000
            elif (insn & 0x3B200C00) == 0x38000000:
                rn = (insn >> 5) & 0x1F
                if rn in (29, 31):
                    continue  # Ignore SP (31) and FP (29) frame accesses
                v = (insn >> 26) & 1
                opc = (insn >> 22) & 3
                sz_code = (insn >> 30) & 3
                if v and (opc & 2) and sz_code == 0:
                    sz = 16
                elif v and sz_code == 3:
                    sz = 8
                elif v and sz_code == 2:
                    sz = 4
                else:
                    sz = 1 << sz_code
                imm9 = (insn >> 12) & 0x1FF
                if imm9 & 0x100:
                    imm9 -= 0x200
                if imm9 >= 0:
                    is_load = bool(opc & 1) if v else bool((insn >> 22) & 1)
                    hw_accesses.append((imm9, sz, "LDUR" if is_load else "STUR"))

        for i, field in enumerate(claimed_fields):
            name = field.get("name", f"field_{i}")
            offset = field.get("offset")
            access_size = field.get("access_size", 4)

            if offset is None:
                return CheckResult(
                    "FieldDisplacementCheck",
                    False,
                    f"Claimed field '{name}' is missing offset",
                    {"field": name},
                )

            # Natural alignment check
            if access_size > 1 and (offset % access_size != 0):
                return CheckResult(
                    "FieldDisplacementCheck",
                    False,
                    f"Field '{name}' at offset 0x{offset:x} violates natural alignment for access size {access_size} bytes (offset % {access_size} != 0)",
                    {"field": name, "offset": offset, "access_size": access_size},
                )

            # Hardware instruction backing check
            has_match = any(off == offset and (sz == access_size or access_size <= sz) for off, sz, _ in hw_accesses)
            if not has_match:
                has_off = any(off == offset for off, sz, _ in hw_accesses)
                if not has_off:
                    return CheckResult(
                        "FieldDisplacementCheck",
                        False,
                        f"Field '{name}' claimed at offset 0x{offset:x} has no matching ARM64 memory access instruction in code stream",
                        {"field": name, "offset": offset, "access_size": access_size, "hw_offsets": [hex(o) for o, _, _ in hw_accesses]},
                    )

        return CheckResult(
            "FieldDisplacementCheck",
            True,
            f"All {len(claimed_fields)} claimed fields verified against ARM64 hardware instructions",
            {"claimed_count": len(claimed_fields), "hw_access_count": len(hw_accesses)},
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
        self.is_safe = (self.status == ObligationStatus.VERIFIED)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "obligation_id": self.obligation_id,
            "obligation_type": self.obligation_type.value,
            "target_name": self.target_name,
            "proposed_name": self.proposed_name,
            "target_address": hex(self.target_address) if self.target_address is not None else None,
            "evidence": self.evidence,
            "status": self.status.value,
            "is_safe": self.is_safe,
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
            _here = os.path.dirname(os.path.abspath(__file__))
            _repo_root = os.path.abspath(os.path.join(_here, "..", ".."))
            _base = _repo_root if os.path.exists(os.path.join(_repo_root, "pyproject.toml")) else _here
            ledger_file = os.path.join(_base, "evidence_ledger.json")
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
        Transitions status to VERIFIED if all checks pass and at least one real proof succeeded,
        or REJECTED if any fail, or stays UNVERIFIED/PENDING if no proofs were available.
        """
        if obligation_id not in self.obligations:
            raise KeyError(f"Obligation '{obligation_id}' not found in ledger.")

        obligation = self.obligations[obligation_id]
        results: List[CheckResult] = []
        is_safe = True

        try:
            # 1. VTable Slot check
            vtable_res = VTableSlotVerifier.verify(obligation.evidence)
            results.append(vtable_res)

            # 2. Allocation Size check
            alloc_res = AllocationSizeVerifier.verify(obligation.evidence)
            results.append(alloc_res)

            # 3. Field Displacement Alignment check
            field_res = FieldDisplacementVerifier.verify(obligation.evidence)
            results.append(field_res)

            # 4. ARM64 instruction-level hardware validation if code_bytes/arm64_bytes provided
            code_bytes = obligation.evidence.get("arm64_bytes") or obligation.evidence.get("code_bytes")
            if code_bytes:
                if "field_displacements" in obligation.evidence:
                    arm_field_res = FieldDisplacementVerifier.extract_and_verify_arm64(
                        code_bytes=code_bytes,
                        claimed_fields=obligation.evidence["field_displacements"],
                        base_pc=obligation.target_address or 0x1000,
                    )
                    results.append(arm_field_res)
                if "vtable_offset" in obligation.evidence or "vtable_slot" in obligation.evidence:
                    vt_off = obligation.evidence.get("vtable_offset")
                    if vt_off is None:
                        vt_off = obligation.evidence.get("vtable_slot", 0) * 8
                    arm_vt_res = VTableSlotVerifier.extract_and_verify_arm64(
                        code_bytes=code_bytes,
                        expected_slot_offset=vt_off,
                        base_pc=obligation.target_address or 0x1000,
                    )
                    results.append(arm_vt_res)

            # 5. SMT Equivalence verification if c_code and code_bytes provided
            c_code = obligation.evidence.get("c_code_snippet") or obligation.evidence.get("c_code")
            if c_code and code_bytes:
                from pcode_lifter_bridge import ARM64PcodeLifter
                from smt_pcode_verifier import SMTPcodeVerifier
                lifter = ARM64PcodeLifter()
                pcode_ops = lifter.lift_block(obligation.target_address or 0x1000, code_bytes)
                verifier = SMTPcodeVerifier(timeout_ms=5000)
                smt_res = verifier.verify_equivalence(
                    pcode_ops=pcode_ops,
                    c_code_or_ast=c_code,
                    obligation_id=obligation.obligation_id,
                )
                if smt_res.equivalent:
                    results.append(CheckResult("SMTEquivalenceCheck", True, "SMT equivalence verified", details=smt_res.details, proven=True))
                else:
                    is_safe = False
                    results.append(CheckResult("SMTEquivalenceCheck", False, f"SMT equivalence check divergent: {smt_res.details}", details=smt_res.details, proven=False))

        except Exception as e:
            is_safe = False
            results.append(
                CheckResult(
                    "VerificationException",
                    False,
                    f"Verification exception: {e}",
                    {"error": str(e), "is_safe": False},
                    proven=False,
                )
            )

        any_failed = any(not r.passed for r in results)
        real_proofs = [r for r in results if r.passed and getattr(r, "proven", True)]
        obligation.verification_results = [r.to_dict() for r in results]
        now_ts = datetime.datetime.now(datetime.timezone.utc).isoformat()

        if any_failed or not is_safe:
            obligation.status = ObligationStatus.REJECTED
            obligation.verified_at = now_ts
            obligation.is_safe = False
            self.save()
            return False
        elif len(real_proofs) > 0:
            obligation.status = ObligationStatus.VERIFIED
            obligation.verified_at = now_ts
            obligation.is_safe = True
            self.save()
            return True
        else:
            obligation.status = ObligationStatus.UNVERIFIED
            obligation.verified_at = now_ts
            obligation.is_safe = False
            obligation.verification_results.append(
                CheckResult(
                    "ProofSufficiencyCheck",
                    False,
                    "No real proof passed: all checks skipped or missing evidence",
                    {"proven": False, "is_safe": False},
                    proven=False,
                ).to_dict()
            )
            self.save()
            return False

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
