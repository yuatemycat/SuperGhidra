# `superghidra.formats` — Binary Loader, DWARF/PDB Indexer & Exporters, MSVC RTTI & MFC `CArchive`

> **Progressive Discovery Index:** Read this before inspecting files in `superghidra/formats/`.

## 1. Domain Modules & Primary Exports

| Module | Primary Exports | Purpose |
| :--- | :--- | :--- |
| [`binary_loader.py`](binary_loader.py) | `BinaryImage`, `Section`, `Symbol`, `Import`, `BinaryFormatError`, `load_binary`, `detect_format`, `resolve_import_ordinals` | Zero-dependency parser for ELF 32/64 (including stripped/forged section headers via `PT_LOAD`/`PT_DYNAMIC`), PE32/PE32+ (exports, delay imports, `.pdata`, PDB path), and thin/universal Mach-O. |
| [`dwarf_pdb_preindexer.py`](dwarf_pdb_preindexer.py) | `OffHeapTypeStore`, `OracleTypeStoreAdapter`, `TypeDeduplicator`, `SyntheticDebugDataGenerator`, `StructMember` | Off-heap SQLite type deduplicator (85k types/sec) ingesting ELF64 DWARF 5 `.debug_info`, PDB streams, and JSON type catalogs. |
| [`synthetic_symbol_exporter.py`](synthetic_symbol_exporter.py) | `DWARF5Exporter`, `PDBExporter`, `MapFileExporter`, `SymFileExporter`, `SymbolLedgerIngestor`, `ExportSymbol`, `ExportStruct`, `ExportField`, `export_from_ledger` | Standalone emitter of DWARF 5 ELF containers, MSF 7.0 / PDB containers, Breakpad `.sym`, and linker `.map` files from verified `EvidenceLedger` records. |
| [`msvc_class_recovery.py`](msvc_class_recovery.py) | `ClassRecoveryReport`, `RttiClass`, `MfcRuntimeClass`, `VTable`, `recover_classes`, `demangle_rtti_name` | Recovers MSVC RTTI class hierarchies and MFC `CRuntimeClass` descriptors (`m_lpszClassName`, `m_nObjectSize`, `m_wSchema`), resolving `Serialize(CArchive&)` bodies through `GetRuntimeClass()` vtables. |
| [`serialize_trace.py`](serialize_trace.py) | `SerializeTracer`, `SerializeTrace`, `ArchiveOp`, `trace_serialize_functions` | Interprocedurally walks `Serialize(CArchive&)` functions to recover ordered loading/storing field operations (`u8..u64`, `f32/f64`, `cstring`, `object`, `count`) and version branch gates. |
| [`mfc_archive.py`](mfc_archive.py) | `ArchiveReader`, `ArchiveObject`, `Field`, `LayoutOp`, `NewClassTag`, `decode_stream`, `calibrate`, `layouts_from_traces`, `scan_class_tags` | Decodes binary MFC `CArchive` streams (`0xFFFF` new-class tags, `0x8000` class refs, `0x7FFF` big tags, load map, UTF-16 `CString`s) and auto-calibrates format version gates. |

## 2. Key Data Structures & Invariants
- **DWARF 5 Reference Invariant:** Every emitted `DW_AT_type` (`DW_FORM_ref4`) in `DWARF5Exporter` points to a valid Compile Unit-relative DIE offset (never `0`).
- **MSF 7.0 / PDB Layout Invariant:** `PDBExporter` reserves Free Page Map blocks 1 and 2, writes a valid 64-byte DBI header (`PublicStreamIndex` at offset 16, `Machine` at 58/60), pads CodeView field lists with `LF_PAD` (`0xF0 | rem`), and serializes a valid named-stream hash map.
- **Serialize Mirror Self-Check:** `SerializeTrace.mirrored` verifies whether recovered `loading` and `storing` operation sequences match structurally.

## 3. Quick-Test Command
```powershell
python -m pytest tests/formats -q
```
