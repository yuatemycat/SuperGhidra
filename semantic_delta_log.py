"""
Semantic Delta Log & Cross-Binary Migration Engine for SuperGhidra.

Provides:
1. Git-Mergeable Append-Only Event Log (.ghidra-delta.jsonl):
   - JSON-Lines format: 1 atomic semantic event per line.
   - Clean three-way Git merge compatibility without tree conflicts.
   - Idempotent and deterministic deduplication.
2. Deterministic Semantic Events:
   - RenameSymbol: Function, struct, variable, or label rename.
   - DefineStructField: Layout, offset, size, and field type definition.
   - BindVTableSlot: Dynamic dispatch hook to vtable index/offset.
   - SetFunctionSignature: Return type, parameter list, calling convention.
   - SetComment: Function, plate, pre/post, and inline comments.
3. Cryptographic Proof Obligations (EvidenceLedger Integration):
   - Computes deterministic SHA-256 proof hashes canonicalizing event payload + evidence.
   - Bridges to `evidence_ledger.py` for invariant verification (VTable alignment,
     allocation size, displacement alignment).
4. Auto-Replay & Migration Engine:
   - Takes baseline delta log (`.ghidra-delta.jsonl`).
   - Uses `binary_diff_engine.py` (BatchedBinaryMatcher / FunctionMatch) to pair
     functions across stripped or mutated binaries.
   - Replays and translates events from Binary A -> Binary B.
   - Re-verifies structural invariants on target binary using EvidenceLedger verifiers.
   - Produces target delta log and detailed MigrationReport.
"""

from __future__ import annotations

import collections
import dataclasses
import datetime
import enum
import hashlib
import json
import logging
import os
import time
from typing import Any, Callable, Dict, Iterable, List, Optional, Set, Tuple, Union

logger = logging.getLogger("SuperGhidra.SemanticDelta")

# Import EvidenceLedger verifiers
try:
    from evidence_ledger import (
        AllocationSizeVerifier,
        FieldDisplacementVerifier,
        ObligationStatus,
        ObligationType,
        ProofObligation,
        ReconstructionObligationLedger,
        VTableSlotVerifier,
    )
except ImportError:
    import sys
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    from evidence_ledger import (
        AllocationSizeVerifier,
        FieldDisplacementVerifier,
        ObligationStatus,
        ObligationType,
        ProofObligation,
        ReconstructionObligationLedger,
        VTableSlotVerifier,
    )

# Import BinaryDiffEngine components
try:
    from binary_diff_engine import (
        BatchedBinaryMatcher,
        DiffResult,
        FunctionCFG,
        FunctionMatch,
    )
except ImportError:
    from binary_diff_engine import (  # type: ignore
        BatchedBinaryMatcher,
        DiffResult,
        FunctionCFG,
        FunctionMatch,
    )


class DeltaEventType(str, enum.Enum):
    RENAME_SYMBOL = "RenameSymbol"
    DEFINE_STRUCT_FIELD = "DefineStructField"
    BIND_VTABLE_SLOT = "BindVTableSlot"
    SET_FUNCTION_SIGNATURE = "SetFunctionSignature"
    SET_COMMENT = "SetComment"


class CommentType(str, enum.Enum):
    PLATE = "PLATE"
    PRE = "PRE"
    POST = "POST"
    EOL = "EOL"
    REPEATABLE = "REPEATABLE"


def compute_event_proof_hash(
    event_type: str,
    target_address: Optional[int],
    target_symbol: Optional[str],
    payload: Dict[str, Any],
    evidence: Optional[Dict[str, Any]] = None,
    obligation_id: Optional[str] = None,
) -> str:
    """
    Computes a deterministic, canonical SHA-256 proof hash over an event's data.
    Ensures identical semantic operations generate identical hash digests.
    """
    canonical_data = {
        "event_type": str(event_type),
        "target_address": hex(target_address) if target_address is not None else None,
        "target_symbol": target_symbol,
        "payload": payload,
        "evidence": evidence or {},
        "obligation_id": obligation_id,
    }
    canonical_json = json.dumps(canonical_data, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical_json.encode("utf-8")).hexdigest()


@dataclasses.dataclass
class SemanticEvent:
    """
    Represents an atomic, immutable semantic event in the append-only delta log.
    Carries deterministic payload, EvidenceLedger obligation, and SHA-256 proof hash.
    """
    event_id: str
    event_type: DeltaEventType
    timestamp: str  # ISO-8601 UTC
    author: str = "superghidra"
    target_address: Optional[int] = None
    target_symbol: Optional[str] = None
    payload: Dict[str, Any] = dataclasses.field(default_factory=dict)
    obligation_id: Optional[str] = None
    evidence: Optional[Dict[str, Any]] = None
    proof_hash: str = ""
    verified: bool = False
    metadata: Dict[str, Any] = dataclasses.field(default_factory=dict)

    def __post_init__(self):
        if not self.proof_hash:
            self.proof_hash = self.compute_proof_hash()
        if not self.event_id:
            self.event_id = f"EVT-{self.proof_hash[:12].upper()}"

    def compute_proof_hash(self) -> str:
        return compute_event_proof_hash(
            event_type=self.event_type.value,
            target_address=self.target_address,
            target_symbol=self.target_symbol,
            payload=self.payload,
            evidence=self.evidence,
            obligation_id=self.obligation_id,
        )

    def verify_proof_hash(self) -> bool:
        """Verifies that the stored proof hash matches the canonical hash of the content."""
        expected = self.compute_proof_hash()
        return self.proof_hash.lower() == expected.lower()

    def verify_evidence_invariants(self) -> Tuple[bool, List[str]]:
        """
        Executes formal invariant checks via EvidenceLedger verifiers.
        Checks VTable alignment, allocation bounds, and displacement alignment.
        """
        if not self.evidence:
            return True, ["No evidence payload (skipped)"]

        messages = []
        all_passed = True

        # 1. VTable check
        if "vtable_slot" in self.evidence or "vtable_offset" in self.evidence or self.event_type == DeltaEventType.BIND_VTABLE_SLOT:
            vt_check = VTableSlotVerifier.verify(self.evidence)
            if not vt_check.passed:
                all_passed = False
            messages.append(f"VTableSlotCheck: {vt_check.message}")

        # 2. Allocation size check
        if "allocation_size" in self.evidence:
            alloc_check = AllocationSizeVerifier.verify(self.evidence)
            if not alloc_check.passed:
                all_passed = False
            messages.append(f"AllocationSizeCheck: {alloc_check.message}")

        # 3. Field displacement check
        if "field_displacements" in self.evidence or (self.event_type == DeltaEventType.DEFINE_STRUCT_FIELD and "instruction" in self.payload):
            field_ev = dict(self.evidence)
            if "field_displacements" not in field_ev and "offset" in self.payload:
                field_ev["field_displacements"] = [{
                    "name": self.payload.get("field_name", "field"),
                    "offset": self.payload.get("offset"),
                    "access_size": self.payload.get("size", 4),
                    "instruction": self.payload.get("instruction", ""),
                }]
            field_check = FieldDisplacementVerifier.verify(field_ev)
            if not field_check.passed:
                all_passed = False
            messages.append(f"FieldDisplacementCheck: {field_check.message}")

        return all_passed, messages

    def to_dict(self) -> Dict[str, Any]:
        return {
            "event_id": self.event_id,
            "event_type": self.event_type.value,
            "timestamp": self.timestamp,
            "author": self.author,
            "target_address": hex(self.target_address) if self.target_address is not None else None,
            "target_symbol": self.target_symbol,
            "payload": self.payload,
            "obligation_id": self.obligation_id,
            "evidence": self.evidence,
            "proof_hash": self.proof_hash,
            "verified": self.verified,
            "metadata": self.metadata,
        }

    def to_json_line(self) -> str:
        """Serializes event to a single git-mergeable JSON string without embedded newlines."""
        return json.dumps(self.to_dict(), sort_keys=True) + "\n"

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> SemanticEvent:
        addr = data.get("target_address")
        if isinstance(addr, str) and addr.lower().startswith("0x"):
            addr = int(addr, 16)
        elif isinstance(addr, (int, float)):
            addr = int(addr)
        else:
            addr = None

        return cls(
            event_id=data.get("event_id", ""),
            event_type=DeltaEventType(data["event_type"]),
            timestamp=data.get("timestamp", datetime.datetime.now(datetime.timezone.utc).isoformat()),
            author=data.get("author", "superghidra"),
            target_address=addr,
            target_symbol=data.get("target_symbol"),
            payload=data.get("payload", {}),
            obligation_id=data.get("obligation_id"),
            evidence=data.get("evidence"),
            proof_hash=data.get("proof_hash", ""),
            verified=data.get("verified", False),
            metadata=data.get("metadata", {}),
        )

    @classmethod
    def from_json_line(cls, line: str) -> Optional[SemanticEvent]:
        cleaned = line.strip()
        if not cleaned or cleaned.startswith("#"):
            return None
        data = json.loads(cleaned)
        return cls.from_dict(data)

    # -------------------------------------------------------------------------
    # Event Factory Methods
    # -------------------------------------------------------------------------

    @classmethod
    def create_rename_symbol(
        cls,
        old_name: str,
        new_name: str,
        target_address: Optional[int] = None,
        symbol_type: str = "FUNCTION",
        author: str = "superghidra",
        evidence: Optional[Dict[str, Any]] = None,
        obligation_id: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> SemanticEvent:
        payload = {
            "old_name": old_name,
            "new_name": new_name,
            "symbol_type": symbol_type,
        }
        now_ts = datetime.datetime.now(datetime.timezone.utc).isoformat()
        evt = cls(
            event_id="",
            event_type=DeltaEventType.RENAME_SYMBOL,
            timestamp=now_ts,
            author=author,
            target_address=target_address,
            target_symbol=old_name,
            payload=payload,
            obligation_id=obligation_id,
            evidence=evidence,
            metadata=metadata or {},
        )
        passed, _ = evt.verify_evidence_invariants()
        evt.verified = passed
        return evt

    @classmethod
    def create_define_struct_field(
        cls,
        struct_name: str,
        field_name: str,
        offset: int,
        size: int,
        type_name: str = "uint32_t",
        instruction: Optional[str] = None,
        author: str = "superghidra",
        evidence: Optional[Dict[str, Any]] = None,
        obligation_id: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> SemanticEvent:
        payload = {
            "struct_name": struct_name,
            "field_name": field_name,
            "offset": offset,
            "size": size,
            "type_name": type_name,
            "instruction": instruction,
        }
        # Build evidence if not explicitly passed
        ev = dict(evidence) if evidence else {}
        if "field_displacements" not in ev:
            ev["field_displacements"] = [{
                "name": field_name,
                "offset": offset,
                "access_size": size,
                "instruction": instruction or "",
            }]

        now_ts = datetime.datetime.now(datetime.timezone.utc).isoformat()
        evt = cls(
            event_id="",
            event_type=DeltaEventType.DEFINE_STRUCT_FIELD,
            timestamp=now_ts,
            author=author,
            target_symbol=struct_name,
            payload=payload,
            obligation_id=obligation_id,
            evidence=ev,
            metadata=metadata or {},
        )
        passed, _ = evt.verify_evidence_invariants()
        evt.verified = passed
        return evt

    @classmethod
    def create_bind_vtable_slot(
        cls,
        struct_name: str,
        slot_index: int,
        function_name: str,
        slot_offset: Optional[int] = None,
        function_address: Optional[int] = None,
        pointer_size: int = 8,
        author: str = "superghidra",
        evidence: Optional[Dict[str, Any]] = None,
        obligation_id: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> SemanticEvent:
        if slot_offset is None:
            slot_offset = slot_index * pointer_size

        payload = {
            "struct_name": struct_name,
            "slot_index": slot_index,
            "slot_offset": slot_offset,
            "function_name": function_name,
            "function_address": hex(function_address) if function_address is not None else None,
            "pointer_size": pointer_size,
        }
        ev = dict(evidence) if evidence else {}
        ev.setdefault("vtable_slot", slot_index)
        ev.setdefault("vtable_offset", slot_offset)

        now_ts = datetime.datetime.now(datetime.timezone.utc).isoformat()
        evt = cls(
            event_id="",
            event_type=DeltaEventType.BIND_VTABLE_SLOT,
            timestamp=now_ts,
            author=author,
            target_address=function_address,
            target_symbol=struct_name,
            payload=payload,
            obligation_id=obligation_id,
            evidence=ev,
            metadata=metadata or {},
        )
        passed, _ = evt.verify_evidence_invariants()
        evt.verified = passed
        return evt

    @classmethod
    def create_set_function_signature(
        cls,
        function_name: str,
        return_type: str,
        parameters: List[Tuple[str, str]],  # (type, name)
        function_address: Optional[int] = None,
        calling_convention: str = "__cdecl",
        author: str = "superghidra",
        evidence: Optional[Dict[str, Any]] = None,
        obligation_id: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> SemanticEvent:
        param_dicts = [{"type": p[0], "name": p[1]} for p in parameters]
        param_strs = [f"{p[0]} {p[1]}" if p[1] else p[0] for p in parameters]
        canonical_sig = f"{return_type} {function_name}({', '.join(param_strs)})"

        payload = {
            "function_name": function_name,
            "return_type": return_type,
            "parameters": param_dicts,
            "calling_convention": calling_convention,
            "canonical_signature": canonical_sig,
        }
        now_ts = datetime.datetime.now(datetime.timezone.utc).isoformat()
        evt = cls(
            event_id="",
            event_type=DeltaEventType.SET_FUNCTION_SIGNATURE,
            timestamp=now_ts,
            author=author,
            target_address=function_address,
            target_symbol=function_name,
            payload=payload,
            obligation_id=obligation_id,
            evidence=evidence,
            metadata=metadata or {},
        )
        passed, _ = evt.verify_evidence_invariants()
        evt.verified = passed
        return evt

    @classmethod
    def create_set_comment(
        cls,
        comment_text: str,
        target_address: Optional[int] = None,
        target_symbol: Optional[str] = None,
        comment_type: Union[CommentType, str] = CommentType.EOL,
        author: str = "superghidra",
        evidence: Optional[Dict[str, Any]] = None,
        obligation_id: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> SemanticEvent:
        ctype_val = CommentType(comment_type).value if isinstance(comment_type, (CommentType, str)) else "EOL"
        payload = {
            "comment_text": comment_text,
            "comment_type": ctype_val,
        }
        now_ts = datetime.datetime.now(datetime.timezone.utc).isoformat()
        evt = cls(
            event_id="",
            event_type=DeltaEventType.SET_COMMENT,
            timestamp=now_ts,
            author=author,
            target_address=target_address,
            target_symbol=target_symbol,
            payload=payload,
            obligation_id=obligation_id,
            evidence=evidence,
            metadata=metadata or {},
        )
        passed, _ = evt.verify_evidence_invariants()
        evt.verified = passed
        return evt


# =============================================================================
# Git-Mergeable Append-Only Semantic Delta Log (.ghidra-delta.jsonl)
# =============================================================================

class SemanticDeltaLog:
    """
    Append-only, Git-mergeable JSONL event log for SuperGhidra.
    Supports continuous appending, streaming reads, cryptographic proof verification,
    and Git-branch merge reconciliation.
    """

    DEFAULT_LOG_NAME = ".ghidra-delta.jsonl"

    def __init__(self, file_path: Optional[str] = None):
        if file_path is None:
            file_path = os.path.join(os.getcwd(), self.DEFAULT_LOG_NAME)
        self.file_path = os.path.abspath(file_path)
        self.events: List[SemanticEvent] = []
        self._seen_ids: Set[str] = set()
        self._seen_hashes: Set[str] = set()

        if os.path.exists(self.file_path):
            self.load()

    def append(self, event: SemanticEvent) -> bool:
        """
        Appends a verified semantic event to the log file and in-memory list.
        Idempotent: skips duplicate event IDs or identical proof hashes.
        """
        if event.event_id in self._seen_ids or event.proof_hash in self._seen_hashes:
            return False  # Already recorded

        self.events.append(event)
        self._seen_ids.add(event.event_id)
        self._seen_hashes.add(event.proof_hash)

        os.makedirs(os.path.dirname(self.file_path), exist_ok=True)
        with open(self.file_path, "a", encoding="utf-8") as f:
            f.write(event.to_json_line())
        return True

    def append_many(self, events: Iterable[SemanticEvent]) -> int:
        """Appends multiple events atomically."""
        count = 0
        new_lines = []
        for evt in events:
            if evt.event_id in self._seen_ids or evt.proof_hash in self._seen_hashes:
                continue
            self.events.append(evt)
            self._seen_ids.add(evt.event_id)
            self._seen_hashes.add(evt.proof_hash)
            new_lines.append(evt.to_json_line())
            count += 1

        if new_lines:
            os.makedirs(os.path.dirname(self.file_path), exist_ok=True)
            with open(self.file_path, "a", encoding="utf-8") as f:
                f.writelines(new_lines)
        return count

    def load(self) -> List[SemanticEvent]:
        """Loads and deduplicates all events from the .jsonl file."""
        if not os.path.exists(self.file_path):
            return []

        self.events.clear()
        self._seen_ids.clear()
        self._seen_hashes.clear()

        with open(self.file_path, "r", encoding="utf-8") as f:
            for line in f:
                evt = SemanticEvent.from_json_line(line)
                if evt is None:
                    continue
                if evt.event_id in self._seen_ids or evt.proof_hash in self._seen_hashes:
                    continue
                self.events.append(evt)
                self._seen_ids.add(evt.event_id)
                self._seen_hashes.add(evt.proof_hash)

        return self.events

    def verify_integrity(self) -> Tuple[bool, List[str]]:
        """
        Cryptographically audits all events in the log.
        Verifies SHA-256 proof hashes and evidence invariants.
        """
        violations = []
        for idx, evt in enumerate(self.events):
            if not evt.verify_proof_hash():
                violations.append(
                    f"Line {idx + 1} [{evt.event_id}]: SHA-256 proof hash mismatch! "
                    f"Stored: {evt.proof_hash}, computed: {evt.compute_proof_hash()}"
                )
            passed, errs = evt.verify_evidence_invariants()
            if not passed:
                violations.append(
                    f"Line {idx + 1} [{evt.event_id}]: Invariant check failed: {'; '.join(errs)}"
                )

        return len(violations) == 0, violations

    def filter(
        self,
        event_type: Optional[Union[DeltaEventType, str]] = None,
        target_symbol: Optional[str] = None,
        target_address: Optional[int] = None,
    ) -> List[SemanticEvent]:
        """Filters events by type, symbol, or address."""
        res = self.events
        if event_type is not None:
            tval = DeltaEventType(event_type)
            res = [e for e in res if e.event_type == tval]
        if target_symbol is not None:
            res = [e for e in res if e.target_symbol == target_symbol]
        if target_address is not None:
            res = [e for e in res if e.target_address == target_address]
        return res

    def project_cumulative_state(self) -> Dict[str, Any]:
        """
        Reconstructs the cumulative decompilation state by sequentially
        applying all events in the delta log.
        """
        symbols: Dict[int, str] = {}
        symbol_renames: Dict[str, str] = {}
        structs: Dict[str, Dict[str, Any]] = collections.defaultdict(lambda: {"fields": {}, "vtables": {}})
        signatures: Dict[str, str] = {}
        comments: Dict[int, List[Dict[str, str]]] = collections.defaultdict(list)

        for evt in self.events:
            if evt.event_type == DeltaEventType.RENAME_SYMBOL:
                new_n = evt.payload.get("new_name", "")
                old_n = evt.payload.get("old_name", "")
                if evt.target_address is not None:
                    symbols[evt.target_address] = new_n
                if old_n:
                    symbol_renames[old_n] = new_n

            elif evt.event_type == DeltaEventType.DEFINE_STRUCT_FIELD:
                sname = evt.payload.get("struct_name", "")
                fname = evt.payload.get("field_name", "")
                if sname and fname:
                    structs[sname]["fields"][fname] = {
                        "offset": evt.payload.get("offset"),
                        "size": evt.payload.get("size"),
                        "type": evt.payload.get("type_name"),
                        "instruction": evt.payload.get("instruction"),
                    }

            elif evt.event_type == DeltaEventType.BIND_VTABLE_SLOT:
                sname = evt.payload.get("struct_name", "")
                slot = evt.payload.get("slot_index")
                fn_name = evt.payload.get("function_name", "")
                if sname and slot is not None:
                    structs[sname]["vtables"][slot] = {
                        "function_name": fn_name,
                        "offset": evt.payload.get("slot_offset"),
                        "address": evt.payload.get("function_address"),
                    }

            elif evt.event_type == DeltaEventType.SET_FUNCTION_SIGNATURE:
                fn_name = evt.payload.get("function_name", "")
                sig = evt.payload.get("canonical_signature", "")
                if fn_name and sig:
                    signatures[fn_name] = sig

            elif evt.event_type == DeltaEventType.SET_COMMENT:
                if evt.target_address is not None:
                    comments[evt.target_address].append({
                        "text": evt.payload.get("comment_text", ""),
                        "type": evt.payload.get("comment_type", "EOL"),
                        "author": evt.author,
                        "timestamp": evt.timestamp,
                    })

        return {
            "symbols_by_address": {hex(k): v for k, v in symbols.items()},
            "symbol_renames": symbol_renames,
            "structs": dict(structs),
            "function_signatures": signatures,
            "comments_by_address": {hex(k): v for k, v in comments.items()},
        }


# =============================================================================
# Auto-Replay & Cross-Binary Migration Engine
# =============================================================================

class MigrationStatus(str, enum.Enum):
    MIGRATED_VERIFIED = "MIGRATED_VERIFIED"
    MIGRATED_UNVERIFIED = "MIGRATED_UNVERIFIED"
    SKIPPED_UNMATCHED = "SKIPPED_UNMATCHED"
    EVIDENCE_REJECTED = "EVIDENCE_REJECTED"


@dataclasses.dataclass
class MigratedEventRecord:
    """Individual record of a migrated event from Binary A -> Binary B."""
    original_event: SemanticEvent
    migrated_event: Optional[SemanticEvent]
    status: MigrationStatus
    similarity: float
    confidence: str
    match_detail: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "original_event_id": self.original_event.event_id,
            "event_type": self.original_event.event_type.value,
            "status": self.status.value,
            "similarity": round(float(self.similarity), 4),
            "confidence": self.confidence,
            "match_detail": self.match_detail,
            "migrated_event_id": self.migrated_event.event_id if self.migrated_event else None,
        }


@dataclasses.dataclass
class DeltaMigrationReport:
    """Comprehensive report returned after migrating a delta log to a new binary target."""
    total_baseline_events: int
    migrated_verified_count: int
    migrated_unverified_count: int
    skipped_unmatched_count: int
    evidence_rejected_count: int
    migration_rate_pct: float
    elapsed_time_ms: float
    records: List[MigratedEventRecord] = dataclasses.field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "total_baseline_events": self.total_baseline_events,
            "migrated_verified_count": self.migrated_verified_count,
            "migrated_unverified_count": self.migrated_unverified_count,
            "skipped_unmatched_count": self.skipped_unmatched_count,
            "evidence_rejected_count": self.evidence_rejected_count,
            "migration_rate_pct": round(self.migration_rate_pct, 2),
            "elapsed_time_ms": round(self.elapsed_time_ms, 2),
            "records": [r.to_dict() for r in self.records],
        }

    def summary(self) -> str:
        return (
            f"[Delta Migration Report] Total Baseline: {self.total_baseline_events} | "
            f"Migrated Verified: {self.migrated_verified_count} | "
            f"Migrated Unverified: {self.migrated_unverified_count} | "
            f"Skipped/Unmatched: {self.skipped_unmatched_count} | "
            f"Rejected: {self.evidence_rejected_count} | "
            f"Success Rate: {self.migration_rate_pct:.1f}% | "
            f"Elapsed: {self.elapsed_time_ms:.2f} ms"
        )


class DeltaMigrationEngine:
    """
    Automated Replay and Cross-Version Migration Engine.

    Takes a baseline `.ghidra-delta.jsonl` from Binary Version A, pairs functions
    with stripped Binary Version B using `BatchedBinaryMatcher` (CFG 32-dim features
    and mutual top-1 matching), verifies evidence invariants with `evidence_ledger.py`,
    and emits a migrated, verified delta log for Binary Version B.
    """

    def __init__(
        self,
        diff_result: Optional[DiffResult] = None,
        ledger: Optional[ReconstructionObligationLedger] = None,
        similarity_threshold: float = 0.75,
    ):
        self.diff_result = diff_result
        self.ledger = ledger
        self.similarity_threshold = similarity_threshold

        # Fast lookup tables
        self.addr_a_to_match: Dict[int, FunctionMatch] = {}
        self.name_a_to_match: Dict[str, FunctionMatch] = {}
        self.id_a_to_match: Dict[str, FunctionMatch] = {}

        if diff_result:
            self._index_diff_matches(diff_result.matches)

    def _index_diff_matches(self, matches: List[FunctionMatch]) -> None:
        for m in matches:
            self.addr_a_to_match[m.func_a_addr] = m
            self.name_a_to_match[m.func_a_name] = m
            self.id_a_to_match[m.func_a_id] = m

    def run_diff_pairing(
        self,
        funcs_a: List[FunctionCFG],
        funcs_b: List[FunctionCFG],
        matcher: Optional[BatchedBinaryMatcher] = None,
    ) -> DiffResult:
        """Runs batched binary diffing to pair functions across binaries A and B."""
        if matcher is None:
            matcher = BatchedBinaryMatcher(threshold=self.similarity_threshold)
        self.diff_result = matcher.diff_binaries(funcs_a, funcs_b, strategy="mutual")
        self._index_diff_matches(self.diff_result.matches)
        return self.diff_result

    def migrate_events(
        self,
        baseline_events: List[SemanticEvent],
        target_log_path: Optional[str] = None,
    ) -> Tuple[DeltaMigrationReport, List[SemanticEvent]]:
        """
        Replays baseline events, translating addresses and function names to target binary,
        running invariant verification, and generating a migrated delta log.
        """
        t0 = time.perf_counter()
        migrated_events: List[SemanticEvent] = []
        records: List[MigratedEventRecord] = []

        migrated_verified = 0
        migrated_unverified = 0
        skipped_unmatched = 0
        evidence_rejected = 0

        for evt in baseline_events:
            # 1. Structural / Type events that are binary-address agnostic
            if evt.event_type == DeltaEventType.DEFINE_STRUCT_FIELD:
                # Struct definitions migrate directly across builds
                passed, msgs = evt.verify_evidence_invariants()
                new_evt = SemanticEvent(
                    event_id="",
                    event_type=evt.event_type,
                    timestamp=datetime.datetime.now(datetime.timezone.utc).isoformat(),
                    author=f"{evt.author}-migrated",
                    target_address=None,
                    target_symbol=evt.target_symbol,
                    payload=dict(evt.payload),
                    obligation_id=evt.obligation_id,
                    evidence=dict(evt.evidence) if evt.evidence else None,
                    verified=passed,
                    metadata={"migration_source": evt.event_id},
                )
                if passed:
                    migrated_verified += 1
                    status = MigrationStatus.MIGRATED_VERIFIED
                else:
                    evidence_rejected += 1
                    status = MigrationStatus.EVIDENCE_REJECTED

                migrated_events.append(new_evt)
                records.append(
                    MigratedEventRecord(
                        original_event=evt,
                        migrated_event=new_evt,
                        status=status,
                        similarity=1.0,
                        confidence="HIGH",
                        match_detail="Direct struct layout migration",
                    )
                )
                continue

            # 2. Address / Function specific events (RenameSymbol, SetSignature, SetComment, BindVTableSlot)
            match: Optional[FunctionMatch] = None
            if evt.target_address is not None and evt.target_address in self.addr_a_to_match:
                match = self.addr_a_to_match[evt.target_address]
            elif evt.target_symbol and evt.target_symbol in self.name_a_to_match:
                match = self.name_a_to_match[evt.target_symbol]

            if not match:
                # Could not find paired function in target binary
                skipped_unmatched += 1
                records.append(
                    MigratedEventRecord(
                        original_event=evt,
                        migrated_event=None,
                        status=MigrationStatus.SKIPPED_UNMATCHED,
                        similarity=0.0,
                        confidence="NONE",
                        match_detail=f"Unmatched in target binary (Addr: {hex(evt.target_address) if evt.target_address else 'N/A'}, Symbol: {evt.target_symbol})",
                    )
                )
                continue

            # Target function found! Translate event parameters
            target_addr = match.func_b_addr
            target_symbol = match.func_b_name
            translated_payload = dict(evt.payload)
            translated_evidence = dict(evt.evidence) if evt.evidence else None

            if evt.event_type == DeltaEventType.RENAME_SYMBOL:
                # Apply new_name to target binary function
                translated_payload["old_name"] = match.func_b_name
                # Keep new_name from original event

            elif evt.event_type == DeltaEventType.SET_FUNCTION_SIGNATURE:
                translated_payload["function_name"] = translated_payload.get("function_name", target_symbol)

            elif evt.event_type == DeltaEventType.BIND_VTABLE_SLOT:
                translated_payload["function_address"] = hex(target_addr)

            # Create migrated event with deterministic proof hash
            new_evt = SemanticEvent(
                event_id="",
                event_type=evt.event_type,
                timestamp=datetime.datetime.now(datetime.timezone.utc).isoformat(),
                author=f"{evt.author}-migrated",
                target_address=target_addr,
                target_symbol=target_symbol,
                payload=translated_payload,
                obligation_id=evt.obligation_id,
                evidence=translated_evidence,
                metadata={
                    "migration_source": evt.event_id,
                    "match_similarity": match.similarity,
                    "match_confidence": match.confidence,
                },
            )

            # Re-verify evidence invariants on target
            passed, errs = new_evt.verify_evidence_invariants()
            new_evt.verified = passed

            if passed:
                migrated_verified += 1
                status = MigrationStatus.MIGRATED_VERIFIED
            else:
                evidence_rejected += 1
                status = MigrationStatus.EVIDENCE_REJECTED

            migrated_events.append(new_evt)
            records.append(
                MigratedEventRecord(
                    original_event=evt,
                    migrated_event=new_evt,
                    status=status,
                    similarity=match.similarity,
                    confidence=match.confidence,
                    match_detail=f"Paired with {match.func_b_name} (Addr: {hex(match.func_b_addr)}) [Sim: {match.similarity:.4f}]",
                )
            )

        elapsed_ms = (time.perf_counter() - t0) * 1000.0
        total_baseline = len(baseline_events)
        total_migrated = migrated_verified + migrated_unverified
        success_rate = (total_migrated / total_baseline * 100.0) if total_baseline > 0 else 0.0

        report = DeltaMigrationReport(
            total_baseline_events=total_baseline,
            migrated_verified_count=migrated_verified,
            migrated_unverified_count=migrated_unverified,
            skipped_unmatched_count=skipped_unmatched,
            evidence_rejected_count=evidence_rejected,
            migration_rate_pct=success_rate,
            elapsed_time_ms=elapsed_ms,
            records=records,
        )

        # Write to target delta log file if requested
        if target_log_path:
            target_log = SemanticDeltaLog(target_log_path)
            target_log.append_many(migrated_events)

        return report, migrated_events
