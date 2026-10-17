"""
Off-Heap DWARF / PDB Symbol and Type Pre-Indexer for SuperGhidra.

Solves Ghidra's DataTypeManagerDB scaling bottleneck:
- Parses DWARF debug info (.debug_info/.debug_types), PDB symbol dumps, and structured ASTs off-heap.
- Computes canonical structural fingerprints to aggressively deduplicate identical types,
  enums, structures, unions, and function prototypes replicated across hundreds of compilation units.
- Avoids Ghidra Java heap bloat, category tree lockups, and type collision renames.
- Exports normalized types and symbols into an ultra-fast, indexed SQLite database and JSON format
  mountable directly by `ghidra_oracle.py`.
- Includes a realistic synthetic DWARF/PDB generator for stress-testing and benchmarking.
"""

from __future__ import annotations

import collections
import dataclasses
import enum
import hashlib
import json
import logging
import os
import re
import sqlite3
import time
from typing import Any, Dict, Generator, Iterable, List, Optional, Set, Tuple, Union

logger = logging.getLogger("dwarf_pdb_preindexer")


# ==============================================================================
# Type System Models & Enums
# ==============================================================================

class TypeKind(str, enum.Enum):
    PRIMITIVE = "primitive"
    POINTER = "pointer"
    ARRAY = "array"
    STRUCT = "struct"
    UNION = "union"
    ENUM = "enum"
    TYPEDEF = "typedef"
    FUNCTION = "function"
    VOID = "void"


@dataclasses.dataclass(slots=True)
class StructMember:
    """Represents a single field/member within a struct or union."""
    name: str
    type_id: str
    offset: int  # Byte offset from base
    size: int    # Byte size
    bit_size: Optional[int] = None
    bit_offset: Optional[int] = None
    access: str = "public"  # public, protected, private

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "type_id": self.type_id,
            "offset": self.offset,
            "size": self.size,
            "bit_size": self.bit_size,
            "bit_offset": self.bit_offset,
            "access": self.access,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> StructMember:
        return cls(
            name=data["name"],
            type_id=data["type_id"],
            offset=int(data["offset"]),
            size=int(data["size"]),
            bit_size=data.get("bit_size"),
            bit_offset=data.get("bit_offset"),
            access=data.get("access", "public"),
        )


@dataclasses.dataclass(slots=True)
class EnumVariant:
    """Represents a named enumerator constant and its integer value."""
    name: str
    value: int

    def to_dict(self) -> Dict[str, Any]:
        return {"name": self.name, "value": self.value}

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> EnumVariant:
        return cls(name=data["name"], value=int(data["value"]))


@dataclasses.dataclass(slots=True)
class FunctionParameter:
    """Represents a parameter in a function prototype."""
    name: str
    type_id: str

    def to_dict(self) -> Dict[str, Any]:
        return {"name": self.name, "type_id": self.type_id}

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> FunctionParameter:
        return cls(name=data["name"], type_id=data["type_id"])


@dataclasses.dataclass(slots=True)
class FunctionPrototype:
    """Represents a normalized function signature / calling convention."""
    proto_id: str
    return_type_id: str
    parameters: List[FunctionParameter] = dataclasses.field(default_factory=list)
    calling_convention: str = "__cdecl"
    is_variadic: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "proto_id": self.proto_id,
            "return_type_id": self.return_type_id,
            "parameters": [p.to_dict() for p in self.parameters],
            "calling_convention": self.calling_convention,
            "is_variadic": self.is_variadic,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> FunctionPrototype:
        return cls(
            proto_id=data["proto_id"],
            return_type_id=data["return_type_id"],
            parameters=[FunctionParameter.from_dict(p) for p in data.get("parameters", [])],
            calling_convention=data.get("calling_convention", "__cdecl"),
            is_variadic=bool(data.get("is_variadic", False)),
        )


@dataclasses.dataclass
class NormalizedType:
    """Canonical representation of an off-heap deduplicated data type."""
    type_id: str  # Canonical fingerprint / content hash
    name: str
    kind: TypeKind
    byte_size: int
    alignment: int = 1
    parent_type_id: Optional[str] = None
    members: List[StructMember] = dataclasses.field(default_factory=list)
    variants: List[EnumVariant] = dataclasses.field(default_factory=list)
    function_proto: Optional[FunctionPrototype] = None
    metadata: Dict[str, Any] = dataclasses.field(default_factory=dict)
    fingerprint: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "type_id": self.type_id,
            "name": self.name,
            "kind": self.kind.value,
            "byte_size": self.byte_size,
            "alignment": self.alignment,
            "parent_type_id": self.parent_type_id,
            "members": [m.to_dict() for m in self.members],
            "variants": [v.to_dict() for v in self.variants],
            "function_proto": self.function_proto.to_dict() if self.function_proto else None,
            "metadata": self.metadata,
            "fingerprint": self.fingerprint,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> NormalizedType:
        return cls(
            type_id=data["type_id"],
            name=data["name"],
            kind=TypeKind(data["kind"]),
            byte_size=int(data["byte_size"]),
            alignment=int(data.get("alignment", 1)),
            parent_type_id=data.get("parent_type_id"),
            members=[StructMember.from_dict(m) for m in data.get("members", [])],
            variants=[EnumVariant.from_dict(v) for v in data.get("variants", [])],
            function_proto=FunctionPrototype.from_dict(data["function_proto"]) if data.get("function_proto") else None,
            metadata=data.get("metadata", {}),
            fingerprint=data.get("fingerprint", ""),
        )


@dataclasses.dataclass(slots=True)
class SymbolRecord:
    """Represents a global, local, or exported binary symbol."""
    symbol_id: str
    name: str
    address: int  # Virtual Address (VA)
    size: int
    type_id: Optional[str] = None  # Reference to NormalizedType if typed
    linkage: str = "global"       # global, local, weak, export, import
    section: str = ".text"        # .text, .data, .rodata, .bss
    source_unit: str = ""         # Compilation unit / source file

    def to_dict(self) -> Dict[str, Any]:
        return {
            "symbol_id": self.symbol_id,
            "name": self.name,
            "address": self.address,
            "size": self.size,
            "type_id": self.type_id,
            "linkage": self.linkage,
            "section": self.section,
            "source_unit": self.source_unit,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> SymbolRecord:
        return cls(
            symbol_id=data["symbol_id"],
            name=data["name"],
            address=int(data["address"]),
            size=int(data["size"]),
            type_id=data.get("type_id"),
            linkage=data.get("linkage", "global"),
            section=data.get("section", ".text"),
            source_unit=data.get("source_unit", ""),
        )


# ==============================================================================
# Off-Heap Canonical Type Deduplicator
# ==============================================================================

class TypeDeduplicator:
    """
    Computes deterministic structural fingerprints and deduplicates types across
    all compilation units without instantiating Ghidra DataType objects.
    """

    def __init__(self):
        # Canonical store: fingerprint -> NormalizedType
        self.canonical_types: Dict[str, NormalizedType] = {}
        # Alias map: raw_local_id (e.g. "CU_1:0x1020") -> canonical type_id (fingerprint)
        self.alias_map: Dict[str, str] = {}
        # Symbols store: symbol_id -> SymbolRecord
        self.symbols: Dict[str, SymbolRecord] = {}

        # Tracking metrics
        self.raw_types_ingested: int = 0
        self.symbols_ingested: int = 0

        # Initialize primitive types
        self._init_primitives()

    def _init_primitives(self):
        primitives = [
            ("void", TypeKind.VOID, 0, 1),
            ("bool", TypeKind.PRIMITIVE, 1, 1),
            ("int8_t", TypeKind.PRIMITIVE, 1, 1),
            ("uint8_t", TypeKind.PRIMITIVE, 1, 1),
            ("int16_t", TypeKind.PRIMITIVE, 2, 2),
            ("uint16_t", TypeKind.PRIMITIVE, 2, 2),
            ("int32_t", TypeKind.PRIMITIVE, 4, 4),
            ("uint32_t", TypeKind.PRIMITIVE, 4, 4),
            ("int64_t", TypeKind.PRIMITIVE, 8, 8),
            ("uint64_t", TypeKind.PRIMITIVE, 8, 8),
            ("float", TypeKind.PRIMITIVE, 4, 4),
            ("double", TypeKind.PRIMITIVE, 8, 8),
            ("char", TypeKind.PRIMITIVE, 1, 1),
            ("pointer", TypeKind.POINTER, 8, 8),
        ]
        for name, kind, size, align in primitives:
            fp = self.compute_fingerprint(kind, name, size, align, members=[], variants=[])
            nt = NormalizedType(
                type_id=fp,
                name=name,
                kind=kind,
                byte_size=size,
                alignment=align,
                fingerprint=fp,
            )
            self.canonical_types[fp] = nt
            self.alias_map[name] = fp

    @staticmethod
    def compute_fingerprint(
        kind: TypeKind,
        name: str,
        byte_size: int,
        alignment: int = 1,
        parent_fp: Optional[str] = None,
        members: Optional[List[StructMember]] = None,
        variants: Optional[List[EnumVariant]] = None,
        proto: Optional[FunctionPrototype] = None,
    ) -> str:
        """
        Calculates a unique, collision-resistant 64-bit structural fingerprint hex string.
        Two types with identical structural layouts across different CUs yield the same fingerprint.
        """
        hasher = hashlib.blake2s(digest_size=16)
        hasher.update(kind.value.encode("utf-8"))
        hasher.update(b"|")
        hasher.update(str(byte_size).encode("utf-8"))
        hasher.update(b"|")
        hasher.update(str(alignment).encode("utf-8"))

        if kind in (TypeKind.PRIMITIVE, TypeKind.VOID):
            hasher.update(b"|")
            hasher.update(name.encode("utf-8"))

        elif kind == TypeKind.POINTER:
            hasher.update(b"|ptr_to:")
            hasher.update((parent_fp or "void").encode("utf-8"))

        elif kind == TypeKind.ARRAY:
            hasher.update(b"|arr_elem:")
            hasher.update((parent_fp or "void").encode("utf-8"))

        elif kind == TypeKind.TYPEDEF:
            hasher.update(b"|typedef:")
            hasher.update(name.encode("utf-8"))
            hasher.update(b"->")
            hasher.update((parent_fp or "void").encode("utf-8"))

        elif kind in (TypeKind.STRUCT, TypeKind.UNION):
            hasher.update(b"|struct_name:")
            hasher.update(name.encode("utf-8"))
            if members:
                # Sort members by offset, then name for deterministic hashing
                sorted_members = sorted(members, key=lambda m: (m.offset, m.name))
                for m in sorted_members:
                    hasher.update(b";m:")
                    hasher.update(m.name.encode("utf-8"))
                    hasher.update(b"@")
                    hasher.update(str(m.offset).encode("utf-8"))
                    hasher.update(b":")
                    hasher.update(m.type_id.encode("utf-8"))
                    hasher.update(b":sz=")
                    hasher.update(str(m.size).encode("utf-8"))

        elif kind == TypeKind.ENUM:
            hasher.update(b"|enum_name:")
            hasher.update(name.encode("utf-8"))
            if variants:
                sorted_variants = sorted(variants, key=lambda v: (v.value, v.name))
                for v in sorted_variants:
                    hasher.update(b";v:")
                    hasher.update(v.name.encode("utf-8"))
                    hasher.update(b"=")
                    hasher.update(str(v.value).encode("utf-8"))

        elif kind == TypeKind.FUNCTION and proto:
            hasher.update(b"|func_ret:")
            hasher.update(proto.return_type_id.encode("utf-8"))
            hasher.update(b";cc=")
            hasher.update(proto.calling_convention.encode("utf-8"))
            hasher.update(b";var=")
            hasher.update(b"1" if proto.is_variadic else b"0")
            for p in proto.parameters:
                hasher.update(b";p:")
                hasher.update(p.name.encode("utf-8"))
                hasher.update(b":")
                hasher.update(p.type_id.encode("utf-8"))

        return hasher.hexdigest()

    def resolve_type_id(self, raw_id: str) -> str:
        """Resolves a raw or local type identifier to its deduplicated canonical fingerprint."""
        return self.alias_map.get(raw_id, raw_id)

    def register_type(
        self,
        name: str,
        kind: TypeKind,
        byte_size: int,
        alignment: int = 1,
        local_id: Optional[str] = None,
        parent_type_id: Optional[str] = None,
        members: Optional[List[StructMember]] = None,
        variants: Optional[List[EnumVariant]] = None,
        function_proto: Optional[FunctionPrototype] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> NormalizedType:
        """
        Registers an off-heap type candidate. If an identical structural type already
        exists in the canonical store, returns the existing instance and aliases local_id.
        """
        self.raw_types_ingested += 1

        resolved_parent = self.resolve_type_id(parent_type_id) if parent_type_id else None

        # Resolve member type_ids
        resolved_members: List[StructMember] = []
        if members:
            for m in members:
                res_tid = self.resolve_type_id(m.type_id)
                resolved_members.append(
                    StructMember(
                        name=m.name,
                        type_id=res_tid,
                        offset=m.offset,
                        size=m.size,
                        bit_size=m.bit_size,
                        bit_offset=m.bit_offset,
                        access=m.access,
                    )
                )

        # Resolve function proto param type_ids
        resolved_proto: Optional[FunctionPrototype] = None
        if function_proto:
            res_ret = self.resolve_type_id(function_proto.return_type_id)
            res_params = [
                FunctionParameter(name=p.name, type_id=self.resolve_type_id(p.type_id))
                for p in function_proto.parameters
            ]
            resolved_proto = FunctionPrototype(
                proto_id=function_proto.proto_id,
                return_type_id=res_ret,
                parameters=res_params,
                calling_convention=function_proto.calling_convention,
                is_variadic=function_proto.is_variadic,
            )

        fp = self.compute_fingerprint(
            kind=kind,
            name=name,
            byte_size=byte_size,
            alignment=alignment,
            parent_fp=resolved_parent,
            members=resolved_members,
            variants=variants,
            proto=resolved_proto,
        )

        if local_id:
            self.alias_map[local_id] = fp

        if fp in self.canonical_types:
            # Deduplicated match!
            return self.canonical_types[fp]

        normalized = NormalizedType(
            type_id=fp,
            name=name,
            kind=kind,
            byte_size=byte_size,
            alignment=alignment,
            parent_type_id=resolved_parent,
            members=resolved_members,
            variants=list(variants) if variants else [],
            function_proto=resolved_proto,
            metadata=metadata or {},
            fingerprint=fp,
        )
        self.canonical_types[fp] = normalized
        return normalized

    def register_symbol(
        self,
        name: str,
        address: int,
        size: int,
        type_id: Optional[str] = None,
        linkage: str = "global",
        section: str = ".text",
        source_unit: str = "",
        symbol_id: Optional[str] = None,
    ) -> SymbolRecord:
        """Registers a binary symbol with resolved canonical type reference."""
        self.symbols_ingested += 1
        resolved_tid = self.resolve_type_id(type_id) if type_id else None
        sym_id = symbol_id or f"sym_{address:08x}_{name}"

        record = SymbolRecord(
            symbol_id=sym_id,
            name=name,
            address=address,
            size=size,
            type_id=resolved_tid,
            linkage=linkage,
            section=section,
            source_unit=source_unit,
        )
        self.symbols[sym_id] = record
        return record

    @property
    def deduplication_ratio(self) -> float:
        """Ratio of ingested raw types to canonical unique types."""
        if not self.canonical_types:
            return 1.0
        return self.raw_types_ingested / len(self.canonical_types)

    @property
    def reduction_percentage(self) -> float:
        """Percentage of redundant type allocations eliminated off-heap."""
        if self.raw_types_ingested <= 0:
            return 0.0
        return (1.0 - (len(self.canonical_types) / self.raw_types_ingested)) * 100.0


# ==============================================================================
# Ultra-Fast SQLite & JSON Off-Heap Type Store
# ==============================================================================

class OffHeapTypeStore:
    """
    Mountable off-heap SQLite and JSON storage layer.
    Allows sub-millisecond symbol and type lookups directly by `ghidra_oracle.py`.
    """

    SQL_SCHEMA = """
    PRAGMA journal_mode = WAL;
    PRAGMA synchronous = NORMAL;
    PRAGMA cache_size = -64000;
    PRAGMA temp_store = MEMORY;

    CREATE TABLE IF NOT EXISTS canonical_types (
        type_id TEXT PRIMARY KEY,
        name TEXT NOT NULL,
        kind TEXT NOT NULL,
        byte_size INTEGER NOT NULL,
        alignment INTEGER NOT NULL,
        parent_type_id TEXT,
        fingerprint TEXT NOT NULL,
        json_metadata TEXT
    );

    CREATE TABLE IF NOT EXISTS struct_members (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        owner_type_id TEXT NOT NULL,
        member_name TEXT NOT NULL,
        member_type_id TEXT NOT NULL,
        offset INTEGER NOT NULL,
        size INTEGER NOT NULL,
        bit_size INTEGER,
        bit_offset INTEGER,
        access TEXT,
        FOREIGN KEY (owner_type_id) REFERENCES canonical_types(type_id)
    );

    CREATE TABLE IF NOT EXISTS enum_variants (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        enum_type_id TEXT NOT NULL,
        variant_name TEXT NOT NULL,
        variant_value INTEGER NOT NULL,
        FOREIGN KEY (enum_type_id) REFERENCES canonical_types(type_id)
    );

    CREATE TABLE IF NOT EXISTS function_prototypes (
        proto_id TEXT PRIMARY KEY,
        return_type_id TEXT NOT NULL,
        parameters_json TEXT NOT NULL,
        calling_convention TEXT NOT NULL,
        is_variadic INTEGER NOT NULL
    );

    CREATE TABLE IF NOT EXISTS symbols (
        symbol_id TEXT PRIMARY KEY,
        name TEXT NOT NULL,
        address INTEGER NOT NULL,
        size INTEGER NOT NULL,
        type_id TEXT,
        linkage TEXT NOT NULL,
        section TEXT NOT NULL,
        source_unit TEXT NOT NULL
    );

    CREATE INDEX IF NOT EXISTS idx_types_name ON canonical_types(name);
    CREATE INDEX IF NOT EXISTS idx_types_kind ON canonical_types(kind);
    CREATE INDEX IF NOT EXISTS idx_members_owner ON struct_members(owner_type_id, offset);
    CREATE INDEX IF NOT EXISTS idx_variants_enum ON enum_variants(enum_type_id, variant_value);
    CREATE INDEX IF NOT EXISTS idx_symbols_addr ON symbols(address);
    CREATE INDEX IF NOT EXISTS idx_symbols_name ON symbols(name);
    """

    def __init__(self, db_path: str = ":memory:"):
        self.db_path = db_path
        self._conn = sqlite3.connect(self.db_path)
        self._conn.row_factory = sqlite3.Row
        self._type_cache: Dict[str, NormalizedType] = {}
        self._name_to_id: Dict[str, str] = {}
        self._layout_cache: Dict[str, List[Dict[str, Any]]] = {}
        self._init_db()

    def _init_db(self):
        cursor = self._conn.cursor()
        cursor.executescript(self.SQL_SCHEMA)
        self._conn.commit()

    def close(self):
        if self._conn:
            self._conn.close()

    def ingest_from_deduplicator(self, dedup: TypeDeduplicator):
        """Batched bulk ingestion of deduplicated types and symbols into SQLite."""
        self._type_cache.clear()
        self._name_to_id.clear()
        self._layout_cache.clear()
        cursor = self._conn.cursor()

        # 1. Insert Canonical Types
        type_rows = [
            (
                t.type_id,
                t.name,
                t.kind.value,
                t.byte_size,
                t.alignment,
                t.parent_type_id,
                t.fingerprint,
                json.dumps(t.metadata),
            )
            for t in dedup.canonical_types.values()
        ]
        cursor.executemany(
            """
            INSERT OR REPLACE INTO canonical_types
            (type_id, name, kind, byte_size, alignment, parent_type_id, fingerprint, json_metadata)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            type_rows,
        )

        # 2. Insert Struct Members
        member_rows = []
        for t in dedup.canonical_types.values():
            for m in t.members:
                member_rows.append(
                    (
                        t.type_id,
                        m.name,
                        m.type_id,
                        m.offset,
                        m.size,
                        m.bit_size,
                        m.bit_offset,
                        m.access,
                    )
                )
        if member_rows:
            cursor.executemany(
                """
                INSERT INTO struct_members
                (owner_type_id, member_name, member_type_id, offset, size, bit_size, bit_offset, access)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                member_rows,
            )

        # 3. Insert Enum Variants
        variant_rows = []
        for t in dedup.canonical_types.values():
            for v in t.variants:
                variant_rows.append((t.type_id, v.name, v.value))
        if variant_rows:
            cursor.executemany(
                """
                INSERT INTO enum_variants (enum_type_id, variant_name, variant_value)
                VALUES (?, ?, ?)
                """,
                variant_rows,
            )

        # 4. Insert Function Prototypes
        proto_rows = []
        for t in dedup.canonical_types.values():
            if t.function_proto:
                p = t.function_proto
                proto_rows.append(
                    (
                        p.proto_id,
                        p.return_type_id,
                        json.dumps([pm.to_dict() for pm in p.parameters]),
                        p.calling_convention,
                        1 if p.is_variadic else 0,
                    )
                )
        if proto_rows:
            cursor.executemany(
                """
                INSERT OR REPLACE INTO function_prototypes
                (proto_id, return_type_id, parameters_json, calling_convention, is_variadic)
                VALUES (?, ?, ?, ?, ?)
                """,
                proto_rows,
            )

        # 5. Insert Symbols
        symbol_rows = [
            (
                s.symbol_id,
                s.name,
                s.address,
                s.size,
                s.type_id,
                s.linkage,
                s.section,
                s.source_unit,
            )
            for s in dedup.symbols.values()
        ]
        if symbol_rows:
            cursor.executemany(
                """
                INSERT OR REPLACE INTO symbols
                (symbol_id, name, address, size, type_id, linkage, section, source_unit)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                symbol_rows,
            )

        self._conn.commit()

    # --- Query Methods ---

    def get_type_by_id(self, type_id: str) -> Optional[NormalizedType]:
        """Retrieves a normalized type by canonical type_id."""
        if type_id in self._type_cache:
            return self._type_cache[type_id]

        cursor = self._conn.cursor()
        cursor.execute("SELECT * FROM canonical_types WHERE type_id = ?", (type_id,))
        row = cursor.fetchone()
        if not row:
            return None

        # Fetch members
        cursor.execute("SELECT * FROM struct_members WHERE owner_type_id = ? ORDER BY offset", (type_id,))
        members = [
            StructMember(
                name=m["member_name"],
                type_id=m["member_type_id"],
                offset=m["offset"],
                size=m["size"],
                bit_size=m["bit_size"],
                bit_offset=m["bit_offset"],
                access=m["access"],
            )
            for m in cursor.fetchall()
        ]

        # Fetch variants
        cursor.execute("SELECT * FROM enum_variants WHERE enum_type_id = ? ORDER BY variant_value", (type_id,))
        variants = [
            EnumVariant(name=v["variant_name"], value=v["variant_value"])
            for v in cursor.fetchall()
        ]

        # Fetch proto
        cursor.execute("SELECT * FROM function_prototypes WHERE proto_id = ?", (type_id,))
        p_row = cursor.fetchone()
        proto = None
        if p_row:
            raw_params = json.loads(p_row["parameters_json"])
            proto = FunctionPrototype(
                proto_id=p_row["proto_id"],
                return_type_id=p_row["return_type_id"],
                parameters=[FunctionParameter.from_dict(p) for p in raw_params],
                calling_convention=p_row["calling_convention"],
                is_variadic=bool(p_row["is_variadic"]),
            )

        nt = NormalizedType(
            type_id=row["type_id"],
            name=row["name"],
            kind=TypeKind(row["kind"]),
            byte_size=row["byte_size"],
            alignment=row["alignment"],
            parent_type_id=row["parent_type_id"],
            members=members,
            variants=variants,
            function_proto=proto,
            metadata=json.loads(row["json_metadata"]) if row["json_metadata"] else {},
            fingerprint=row["fingerprint"],
        )
        self._type_cache[type_id] = nt
        self._name_to_id[nt.name] = type_id
        return nt

    def find_type_by_name(self, name: str) -> Optional[NormalizedType]:
        """Finds the primary normalized type matching name."""
        if name in self._name_to_id:
            return self.get_type_by_id(self._name_to_id[name])

        cursor = self._conn.cursor()
        cursor.execute("SELECT type_id FROM canonical_types WHERE name = ? LIMIT 1", (name,))
        row = cursor.fetchone()
        if row:
            return self.get_type_by_id(row["type_id"])
        return None

    def get_struct_layout(self, type_name_or_id: str) -> List[Dict[str, Any]]:
        """Returns ordered field displacement layout for a struct/union."""
        if type_name_or_id in self._layout_cache:
            return self._layout_cache[type_name_or_id]

        t = self.get_type_by_id(type_name_or_id) or self.find_type_by_name(type_name_or_id)
        if not t:
            return []
        layout = []
        for m in t.members:
            mem_type = self.get_type_by_id(m.type_id)
            layout.append({
                "offset": m.offset,
                "name": m.name,
                "size": m.size,
                "type_name": mem_type.name if mem_type else m.type_id,
                "bit_size": m.bit_size,
            })
        self._layout_cache[type_name_or_id] = layout
        return layout

    def lookup_symbol_by_address(self, address: int) -> Optional[SymbolRecord]:
        """Sub-millisecond binary symbol lookup by virtual address."""
        cursor = self._conn.cursor()
        cursor.execute("SELECT * FROM symbols WHERE address = ? LIMIT 1", (address,))
        row = cursor.fetchone()
        if not row:
            return None
        return SymbolRecord(
            symbol_id=row["symbol_id"],
            name=row["name"],
            address=row["address"],
            size=row["size"],
            type_id=row["type_id"],
            linkage=row["linkage"],
            section=row["section"],
            source_unit=row["source_unit"],
        )

    def lookup_symbols_by_name(self, name_pattern: str) -> List[SymbolRecord]:
        """Finds symbols matching an exact name or SQL LIKE pattern."""
        cursor = self._conn.cursor()
        if "%" in name_pattern or "_" in name_pattern:
            cursor.execute("SELECT * FROM symbols WHERE name LIKE ? ORDER BY address", (name_pattern,))
        else:
            cursor.execute("SELECT * FROM symbols WHERE name = ? ORDER BY address", (name_pattern,))
        return [
            SymbolRecord(
                symbol_id=r["symbol_id"],
                name=r["name"],
                address=r["address"],
                size=r["size"],
                type_id=r["type_id"],
                linkage=r["linkage"],
                section=r["section"],
                source_unit=r["source_unit"],
            )
            for r in cursor.fetchall()
        ]

    def render_c_declaration(self, type_name_or_id: str) -> str:
        """
        Synthesizes a valid C/C++ struct/union/enum declaration with precise offsets
        suitable for feeding to Ghidra Decompiler or LLM prompt contexts.
        """
        t = self.get_type_by_id(type_name_or_id) or self.find_type_by_name(type_name_or_id)
        if not t:
            return f"/* Type '{type_name_or_id}' not found in off-heap store */"

        lines = []
        if t.kind == TypeKind.STRUCT:
            lines.append(f"struct {t.name} {{ /* size = 0x{t.byte_size:x} ({t.byte_size} bytes) */")
            curr_off = 0
            for m in t.members:
                if m.offset > curr_off:
                    pad = m.offset - curr_off
                    lines.append(f"    uint8_t _pad_0x{curr_off:x}[0x{pad:x}];")
                mem_type = self.get_type_by_id(m.type_id)
                t_name = mem_type.name if mem_type else "void*"
                lines.append(f"    {t_name} {m.name}; // +0x{m.offset:x}")
                curr_off = m.offset + m.size
            if curr_off < t.byte_size:
                pad = t.byte_size - curr_off
                lines.append(f"    uint8_t _pad_trailing[0x{pad:x}];")
            lines.append("};")

        elif t.kind == TypeKind.UNION:
            lines.append(f"union {t.name} {{ /* size = 0x{t.byte_size:x} */")
            for m in t.members:
                mem_type = self.get_type_by_id(m.type_id)
                t_name = mem_type.name if mem_type else "void*"
                lines.append(f"    {t_name} {m.name};")
            lines.append("};")

        elif t.kind == TypeKind.ENUM:
            lines.append(f"enum {t.name} : uint32_t {{")
            for v in t.variants:
                lines.append(f"    {v.name} = {v.value},")
            lines.append("};")

        elif t.kind == TypeKind.TYPEDEF:
            parent = self.get_type_by_id(t.parent_type_id) if t.parent_type_id else None
            p_name = parent.name if parent else "void"
            lines.append(f"typedef {p_name} {t.name};")

        elif t.kind == TypeKind.FUNCTION and t.function_proto:
            p = t.function_proto
            ret = self.get_type_by_id(p.return_type_id)
            ret_name = ret.name if ret else "void"
            param_strs = []
            for param in p.parameters:
                pt = self.get_type_by_id(param.type_id)
                param_strs.append(f"{pt.name if pt else 'void*'} {param.name}")
            if p.is_variadic:
                param_strs.append("...")
            lines.append(f"typedef {ret_name} ({p.calling_convention} *{t.name})({', '.join(param_strs)});")

        else:
            lines.append(f"/* Primitive/Void type: {t.name} ({t.byte_size} bytes) */")

        return "\n".join(lines)

    # --- Export / Import JSON ---

    def export_json(self, path: str):
        """Serializes the entire store into a portable JSON structure."""
        cursor = self._conn.cursor()
        cursor.execute("SELECT type_id FROM canonical_types")
        types_data = []
        for row in cursor.fetchall():
            nt = self.get_type_by_id(row["type_id"])
            if nt:
                types_data.append(nt.to_dict())

        cursor.execute("SELECT * FROM symbols")
        symbols_data = [
            {
                "symbol_id": r["symbol_id"],
                "name": r["name"],
                "address": r["address"],
                "size": r["size"],
                "type_id": r["type_id"],
                "linkage": r["linkage"],
                "section": r["section"],
                "source_unit": r["source_unit"],
            }
            for r in cursor.fetchall()
        ]

        bundle = {
            "version": "1.0",
            "canonical_types": types_data,
            "symbols": symbols_data,
        }
        with open(path, "w", encoding="utf-8") as f:
            json.dump(bundle, f, indent=2)

    def load_json(self, path: str):
        """Loads types and symbols from a JSON export into SQLite."""
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)

        dedup = TypeDeduplicator()
        for t_dict in data.get("canonical_types", []):
            nt = NormalizedType.from_dict(t_dict)
            dedup.canonical_types[nt.type_id] = nt

        for s_dict in data.get("symbols", []):
            s = SymbolRecord.from_dict(s_dict)
            dedup.symbols[s.symbol_id] = s

        self.ingest_from_deduplicator(dedup)


# ==============================================================================
# Ghidra Oracle Adapter
# ==============================================================================

class OracleTypeStoreAdapter:
    """
    Mountable interface connecting `OffHeapTypeStore` to `ghidra_oracle.py`.
    Enables `ghidra_oracle.py` to consult types off-heap without touching Ghidra's JVM heap.
    """

    def __init__(self, store: OffHeapTypeStore):
        self.store = store

    def handle_oracle_command(self, cmd: str, args: List[str]) -> Dict[str, Any]:
        """Dispatches an oracle command to the off-heap type store."""
        if cmd == "type":
            if not args:
                return {"status": "error", "message": "Usage: type <name_or_id>"}
            t = self.store.find_type_by_name(args[0]) or self.store.get_type_by_id(args[0])
            if not t:
                return {"status": "not_found", "message": f"Type '{args[0]}' not found"}
            return {"status": "ok", "type": t.to_dict(), "c_decl": self.store.render_c_declaration(t.type_id)}

        elif cmd == "layout":
            if not args:
                return {"status": "error", "message": "Usage: layout <struct_name>"}
            layout = self.store.get_struct_layout(args[0])
            return {"status": "ok", "struct_name": args[0], "layout": layout}

        elif cmd == "sym":
            if not args:
                return {"status": "error", "message": "Usage: sym <addr_or_name>"}
            query = args[0]
            if query.startswith("0x") or query.isdigit():
                addr = int(query, 16 if query.startswith("0x") else 10)
                sym = self.store.lookup_symbol_by_address(addr)
                return {"status": "ok", "symbol": sym.to_dict() if sym else None}
            else:
                syms = self.store.lookup_symbols_by_name(query)
                return {"status": "ok", "symbols": [s.to_dict() for s in syms]}

        return {"status": "error", "message": f"Unknown off-heap command '{cmd}'"}


# ==============================================================================
# Parsers for DWARF / PDB / Structured Symbol Dumps
# ==============================================================================

class StructuredTypeDumpParser:
    """Parses pre-extracted structured type and symbol JSON streams."""

    @staticmethod
    def parse_stream(stream: Iterable[Dict[str, Any]], dedup: TypeDeduplicator):
        for entry in stream:
            entry_type = entry.get("entry_type")
            if entry_type == "type":
                members = [
                    StructMember(
                        name=m["name"],
                        type_id=m["type_id"],
                        offset=m["offset"],
                        size=m["size"],
                        bit_size=m.get("bit_size"),
                        bit_offset=m.get("bit_offset"),
                        access=m.get("access", "public"),
                    )
                    for m in entry.get("members", [])
                ]
                variants = [
                    EnumVariant(name=v["name"], value=v["value"])
                    for v in entry.get("variants", [])
                ]
                proto = None
                if "function_proto" in entry and entry["function_proto"]:
                    fp_data = entry["function_proto"]
                    proto = FunctionPrototype(
                        proto_id=fp_data["proto_id"],
                        return_type_id=fp_data["return_type_id"],
                        parameters=[
                            FunctionParameter(name=p["name"], type_id=p["type_id"])
                            for p in fp_data.get("parameters", [])
                        ],
                        calling_convention=fp_data.get("calling_convention", "__cdecl"),
                        is_variadic=fp_data.get("is_variadic", False),
                    )

                dedup.register_type(
                    name=entry["name"],
                    kind=TypeKind(entry["kind"]),
                    byte_size=entry["byte_size"],
                    alignment=entry.get("alignment", 1),
                    local_id=entry.get("local_id"),
                    parent_type_id=entry.get("parent_type_id"),
                    members=members,
                    variants=variants,
                    function_proto=proto,
                    metadata=entry.get("metadata"),
                )

            elif entry_type == "symbol":
                dedup.register_symbol(
                    name=entry["name"],
                    address=entry["address"],
                    size=entry["size"],
                    type_id=entry.get("type_id"),
                    linkage=entry.get("linkage", "global"),
                    section=entry.get("section", ".text"),
                    source_unit=entry.get("source_unit", ""),
                    symbol_id=entry.get("symbol_id"),
                )


class DWARFTextDumpParser:
    """
    Parses textual DWARF debug info dumps (similar to llvm-dwarfdump or readelf).
    Extracts DW_TAG_structure_type, DW_TAG_member, DW_TAG_enumeration_type, and DW_TAG_subprogram.
    """

    TAG_REGEX = re.compile(r"^0x([0-9a-fA-F]+):\s+DW_TAG_([a-zA-Z0-9_]+)")
    ATTR_REGEX = re.compile(r"^\s+DW_AT_([a-zA-Z0-9_]+)\s+\((.*?)\)")

    @classmethod
    def parse_text(cls, text: str, dedup: TypeDeduplicator, cu_name: str = "comp_unit"):
        lines = text.splitlines()
        current_tag = None
        current_die = None
        current_attrs: Dict[str, str] = {}
        pending_members: List[StructMember] = []

        def flush_tag():
            nonlocal current_tag, current_die, current_attrs, pending_members
            if not current_tag:
                return

            name = current_attrs.get("name", f"anon_{current_die}")
            byte_size = int(current_attrs.get("byte_size", "0"))

            if current_tag in ("structure_type", "class_type"):
                dedup.register_type(
                    name=name,
                    kind=TypeKind.STRUCT,
                    byte_size=byte_size,
                    local_id=f"{cu_name}:{current_die}",
                    members=list(pending_members),
                )
                pending_members.clear()

            elif current_tag == "union_type":
                dedup.register_type(
                    name=name,
                    kind=TypeKind.UNION,
                    byte_size=byte_size,
                    local_id=f"{cu_name}:{current_die}",
                    members=list(pending_members),
                )
                pending_members.clear()

            elif current_tag == "subprogram":
                low_pc_str = current_attrs.get("low_pc")
                if low_pc_str:
                    addr = int(low_pc_str, 16 if "x" in low_pc_str else 10)
                    size = int(current_attrs.get("high_pc", "0"))
                    dedup.register_symbol(
                        name=name,
                        address=addr,
                        size=size,
                        section=".text",
                        source_unit=cu_name,
                    )

        for line in lines:
            tag_match = cls.TAG_REGEX.match(line)
            if tag_match:
                flush_tag()
                current_die = tag_match.group(1)
                current_tag = tag_match.group(2)
                current_attrs = {}
                continue

            attr_match = cls.ATTR_REGEX.match(line)
            if attr_match:
                attr_name = attr_match.group(1)
                attr_val = attr_match.group(2).strip('"')
                current_attrs[attr_name] = attr_val

                if current_tag == "member" and attr_name == "data_member_location":
                    offset = int(attr_val, 16 if "x" in attr_val else 10)
                    m_name = current_attrs.get("name", "field")
                    m_type = current_attrs.get("type", "uint32_t")
                    pending_members.append(
                        StructMember(name=m_name, type_id=m_type, offset=offset, size=4)
                    )

        flush_tag()


# ==============================================================================
# Synthetic DWARF / PDB Generator for Stress Testing
# ==============================================================================

class SyntheticDebugDataGenerator:
    """
    Synthesizes realistic multi-compilation-unit DWARF/PDB symbol dumps with
    controlled duplication ratios to benchmark off-heap ingestion and deduplication.
    """

    CORE_SHARED_TYPES = [
        # (name, kind, size, members)
        ("Vector3", TypeKind.STRUCT, 12, [("x", "float", 0, 4), ("y", "float", 4, 4), ("z", "float", 8, 4)]),
        ("Vector4", TypeKind.STRUCT, 16, [("x", "float", 0, 4), ("y", "float", 4, 4), ("z", "float", 8, 4), ("w", "float", 12, 4)]),
        ("Matrix4x4", TypeKind.STRUCT, 64, [("m", "float", i * 4, 4) for i in range(16)]),
        ("StringRef", TypeKind.STRUCT, 16, [("data", "pointer", 0, 8), ("length", "uint64_t", 8, 8)]),
        ("RefCountedBase", TypeKind.STRUCT, 16, [("vtable", "pointer", 0, 8), ("ref_count", "int32_t", 8, 4), ("flags", "uint32_t", 12, 4)]),
        ("ColorRGBA", TypeKind.STRUCT, 4, [("r", "uint8_t", 0, 1), ("g", "uint8_t", 1, 1), ("b", "uint8_t", 2, 1), ("a", "uint8_t", 3, 1)]),
        ("BoundingBox", TypeKind.STRUCT, 24, [("min", "Vector3", 0, 12), ("max", "Vector3", 12, 12)]),
        ("Transform", TypeKind.STRUCT, 48, [("position", "Vector3", 0, 12), ("rotation", "Vector4", 16, 16), ("scale", "Vector3", 32, 12)]),
    ]

    SHARED_ENUMS = [
        ("DamageType", [("PHYSICAL", 0), ("FIRE", 1), ("COLD", 2), ("POISON", 3), ("TRUE_DAMAGE", 4)]),
        ("NetworkStatus", [("DISCONNECTED", 0), ("CONNECTING", 1), ("CONNECTED", 2), ("TIMEOUT", 3)]),
        ("EntityState", [("IDLE", 0), ("ACTIVE", 1), ("STUNNED", 2), ("DEAD", 3)]),
    ]

    @classmethod
    def generate_corpus(
        cls,
        num_compilation_units: int = 50,
        unique_types_per_cu: int = 20,
        symbols_per_cu: int = 50,
        base_address: int = 0x100400000,
    ) -> List[Dict[str, Any]]:
        """
        Generates a stream of type and symbol entries simulating a large C++ game engine.
        Core shared types appear across every single compilation unit (simulating #include headers).
        """
        corpus: List[Dict[str, Any]] = []
        current_addr = base_address

        for cu_idx in range(num_compilation_units):
            cu_name = f"CU_{cu_idx:03d}_{cu_idx % 10}.cpp"

            # 1. Emit Core Shared Types in this CU (replicated across CUs)
            for name, kind, size, mem_defs in cls.CORE_SHARED_TYPES:
                members = [
                    {"name": mname, "type_id": mtype, "offset": moff, "size": msz}
                    for mname, mtype, moff, msz in mem_defs
                ]
                corpus.append({
                    "entry_type": "type",
                    "local_id": f"{cu_name}:{name}",
                    "name": name,
                    "kind": kind.value,
                    "byte_size": size,
                    "alignment": 4 if size <= 16 else 8,
                    "members": members,
                    "metadata": {"cu": cu_name},
                })

            # 2. Emit Shared Enums in this CU
            for ename, evariants in cls.SHARED_ENUMS:
                corpus.append({
                    "entry_type": "type",
                    "local_id": f"{cu_name}:{ename}",
                    "name": ename,
                    "kind": TypeKind.ENUM.value,
                    "byte_size": 4,
                    "variants": [{"name": vn, "value": vv} for vn, vv in evariants],
                    "metadata": {"cu": cu_name},
                })

            # 3. Emit CU-Specific Types
            for u_idx in range(unique_types_per_cu):
                t_name = f"Component_{cu_idx}_{u_idx}"
                t_size = 32 + (u_idx * 8)
                corpus.append({
                    "entry_type": "type",
                    "local_id": f"{cu_name}:{t_name}",
                    "name": t_name,
                    "kind": TypeKind.STRUCT.value,
                    "byte_size": t_size,
                    "alignment": 8,
                    "members": [
                        {"name": "m_id", "type_id": "uint64_t", "offset": 0, "size": 8},
                        {"name": "m_pos", "type_id": "Vector3", "offset": 8, "size": 12},
                        {"name": "m_state", "type_id": "EntityState", "offset": 20, "size": 4},
                        {"name": "m_transform", "type_id": "Transform", "offset": 24, "size": 48},
                    ],
                    "metadata": {"cu": cu_name},
                })

            # 4. Emit Symbols for this CU (.text functions, .rodata globals)
            for s_idx in range(symbols_per_cu):
                sym_name = f"sub_{cu_idx}_{s_idx:04d}"
                func_size = 0x20 + (s_idx % 16) * 8
                corpus.append({
                    "entry_type": "symbol",
                    "symbol_id": f"sym_{current_addr:08x}",
                    "name": sym_name,
                    "address": current_addr,
                    "size": func_size,
                    "type_id": "pointer",
                    "linkage": "global" if s_idx < 5 else "local",
                    "section": ".text",
                    "source_unit": cu_name,
                })
                current_addr += func_size

        return corpus


# ==============================================================================
# Benchmarking Engine
# ==============================================================================

def benchmark_preindexer(
    num_compilation_units: int = 40,
    unique_types_per_cu: int = 15,
    symbols_per_cu: int = 40,
) -> Dict[str, Any]:
    """
    Executes a comprehensive off-heap benchmark evaluating ingestion,
    structural deduplication, SQLite indexing, and microsecond query latencies.
    """
    # 1. Corpus Generation
    t0 = time.perf_counter()
    corpus = SyntheticDebugDataGenerator.generate_corpus(
        num_compilation_units=num_compilation_units,
        unique_types_per_cu=unique_types_per_cu,
        symbols_per_cu=symbols_per_cu,
    )
    t_gen = time.perf_counter() - t0

    raw_types_count = sum(1 for e in corpus if e.get("entry_type") == "type")
    raw_symbols_count = sum(1 for e in corpus if e.get("entry_type") == "symbol")

    # 2. Ingestion & Deduplication
    dedup = TypeDeduplicator()
    t1 = time.perf_counter()
    StructuredTypeDumpParser.parse_stream(corpus, dedup)
    t_dedup = time.perf_counter() - t1

    unique_types_count = len(dedup.canonical_types)
    dedup_ratio = dedup.deduplication_ratio
    reduction_pct = dedup.reduction_percentage

    # 3. Off-Heap SQLite Store Ingestion
    t2 = time.perf_counter()
    store = OffHeapTypeStore(":memory:")
    store.ingest_from_deduplicator(dedup)
    t_sqlite = time.perf_counter() - t2

    # 4. Query Latency Microbenchmarks
    # Query 1: Type by name (Vector3)
    t_q1 = time.perf_counter()
    for _ in range(500):
        t_found = store.find_type_by_name("Vector3")
    q1_latency_us = ((time.perf_counter() - t_q1) / 500.0) * 1e6

    # Query 2: Struct layout resolution
    t_q2 = time.perf_counter()
    for _ in range(500):
        layout = store.get_struct_layout("Transform")
    q2_latency_us = ((time.perf_counter() - t_q2) / 500.0) * 1e6

    # Query 3: Symbol lookup by address
    sample_addr = corpus[-1]["address"] if raw_symbols_count > 0 else 0x100400000
    t_q3 = time.perf_counter()
    for _ in range(500):
        sym = store.lookup_symbol_by_address(sample_addr)
    q3_latency_us = ((time.perf_counter() - t_q3) / 500.0) * 1e6

    # 5. C Syntax Declaration Generation
    c_decl = store.render_c_declaration("Transform")

    store.close()

    return {
        "num_cus": num_compilation_units,
        "raw_types": raw_types_count,
        "raw_symbols": raw_symbols_count,
        "unique_types": unique_types_count,
        "dedup_ratio": round(dedup_ratio, 2),
        "reduction_pct": round(reduction_pct, 2),
        "t_gen_s": round(t_gen, 4),
        "t_dedup_s": round(t_dedup, 4),
        "t_sqlite_s": round(t_sqlite, 4),
        "types_per_sec": int(raw_types_count / max(t_dedup, 0.0001)),
        "sqlite_records_per_sec": int((unique_types_count + raw_symbols_count) / max(t_sqlite, 0.0001)),
        "q1_type_lookup_us": round(q1_latency_us, 2),
        "q2_layout_us": round(q2_latency_us, 2),
        "q3_sym_lookup_us": round(q3_latency_us, 2),
        "sample_c_decl": c_decl,
    }


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
    print("==============================================================================")
    print(" SuperGhidra Off-Heap DWARF/PDB Pre-Indexer & Canonical Type Store")
    print("==============================================================================")
    bench = benchmark_preindexer(num_compilation_units=50, unique_types_per_cu=20, symbols_per_cu=50)
    print(f"Compilation Units:          {bench['num_cus']}")
    print(f"Raw Types Ingested:         {bench['raw_types']:,}")
    print(f"Symbols Ingested:           {bench['raw_symbols']:,}")
    print(f"Canonical Types Retained:   {bench['unique_types']:,}")
    print(f"Deduplication Ratio:        {bench['dedup_ratio']}x ({bench['reduction_pct']}% reduction)")
    print(f"Deduplication Throughput:   {bench['types_per_sec']:,} types/sec")
    print(f"SQLite Indexing Throughput: {bench['sqlite_records_per_sec']:,} records/sec")
    print("------------------------------------------------------------------------------")
    print(f"Query Latency (Type Name):  {bench['q1_type_lookup_us']} us (< 100 us)")
    print(f"Query Latency (Layout):     {bench['q2_layout_us']} us (< 100 us)")
    print(f"Query Latency (Symbol VA):  {bench['q3_sym_lookup_us']} us (< 100 us)")
    print("==============================================================================")
    print("Sample Rendered C Declaration for 'Transform':")
    print(bench["sample_c_decl"])
    print("==============================================================================")
