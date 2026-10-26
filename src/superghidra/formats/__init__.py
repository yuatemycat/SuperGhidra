"""SuperGhidra Formats Domain: Multi-Arch Binary Loader, Off-Heap DWARF/PDB Pre-Indexer, Symbol Exporters & MSVC/MFC Recovery."""

from __future__ import annotations

import importlib
from typing import Any

_EXPORTS: dict[str, tuple[str, str]] = {
    "BinaryFormatError": ("superghidra.formats.binary_loader", "BinaryFormatError"),
    "Section": ("superghidra.formats.binary_loader", "Section"),
    "Symbol": ("superghidra.formats.binary_loader", "Symbol"),
    "Import": ("superghidra.formats.binary_loader", "Import"),
    "BinaryImage": ("superghidra.formats.binary_loader", "BinaryImage"),
    "load_binary": ("superghidra.formats.binary_loader", "load_binary"),
    "detect_format": ("superghidra.formats.binary_loader", "detect_format"),
    "resolve_import_ordinals": ("superghidra.formats.binary_loader", "resolve_import_ordinals"),
    "OffHeapTypeStore": ("superghidra.formats.dwarf_pdb_preindexer", "OffHeapTypeStore"),
    "OracleTypeStoreAdapter": ("superghidra.formats.dwarf_pdb_preindexer", "OracleTypeStoreAdapter"),
    "TypeDeduplicator": ("superghidra.formats.dwarf_pdb_preindexer", "TypeDeduplicator"),
    "SyntheticDebugDataGenerator": ("superghidra.formats.dwarf_pdb_preindexer", "SyntheticDebugDataGenerator"),
    "StructMember": ("superghidra.formats.dwarf_pdb_preindexer", "StructMember"),
    "ExportSymbol": ("superghidra.formats.synthetic_symbol_exporter", "ExportSymbol"),
    "ExportField": ("superghidra.formats.synthetic_symbol_exporter", "ExportField"),
    "ExportStruct": ("superghidra.formats.synthetic_symbol_exporter", "ExportStruct"),
    "DWARF5Exporter": ("superghidra.formats.synthetic_symbol_exporter", "DWARF5Exporter"),
    "PDBExporter": ("superghidra.formats.synthetic_symbol_exporter", "PDBExporter"),
    "MapFileExporter": ("superghidra.formats.synthetic_symbol_exporter", "MapFileExporter"),
    "SymFileExporter": ("superghidra.formats.synthetic_symbol_exporter", "SymFileExporter"),
    "SymbolLedgerIngestor": ("superghidra.formats.synthetic_symbol_exporter", "SymbolLedgerIngestor"),
    "export_from_ledger": ("superghidra.formats.synthetic_symbol_exporter", "export_from_ledger"),
    "VTable": ("superghidra.formats.msvc_class_recovery", "VTable"),
    "RttiClass": ("superghidra.formats.msvc_class_recovery", "RttiClass"),
    "MfcRuntimeClass": ("superghidra.formats.msvc_class_recovery", "MfcRuntimeClass"),
    "ClassRecoveryReport": ("superghidra.formats.msvc_class_recovery", "ClassRecoveryReport"),
    "demangle_rtti_name": ("superghidra.formats.msvc_class_recovery", "demangle_rtti_name"),
    "recover_classes": ("superghidra.formats.msvc_class_recovery", "recover_classes"),
    "ObjCMethod": ("superghidra.formats.macho_objc_recovery", "ObjCMethod"),
    "ObjCIvar": ("superghidra.formats.macho_objc_recovery", "ObjCIvar"),
    "ObjCClass": ("superghidra.formats.macho_objc_recovery", "ObjCClass"),
    "ObjCRecoveryReport": ("superghidra.formats.macho_objc_recovery", "ObjCRecoveryReport"),
    "recover_objc_classes": ("superghidra.formats.macho_objc_recovery", "recover_objc_classes"),
    "ArchiveOp": ("superghidra.formats.serialize_trace", "ArchiveOp"),
    "SerializeTrace": ("superghidra.formats.serialize_trace", "SerializeTrace"),
    "SerializeTracer": ("superghidra.formats.serialize_trace", "SerializeTracer"),
    "trace_serialize_functions": ("superghidra.formats.serialize_trace", "trace_serialize_functions"),
    "ArchiveError": ("superghidra.formats.mfc_archive", "ArchiveError"),
    "ArchiveReader": ("superghidra.formats.mfc_archive", "ArchiveReader"),
    "ArchiveObject": ("superghidra.formats.mfc_archive", "ArchiveObject"),
    "Field": ("superghidra.formats.mfc_archive", "Field"),
    "LayoutOp": ("superghidra.formats.mfc_archive", "LayoutOp"),
    "NewClassTag": ("superghidra.formats.mfc_archive", "NewClassTag"),
    "scan_class_tags": ("superghidra.formats.mfc_archive", "scan_class_tags"),
    "layouts_from_traces": ("superghidra.formats.mfc_archive", "layouts_from_traces"),
    "decode_stream": ("superghidra.formats.mfc_archive", "decode_stream"),
    "calibrate": ("superghidra.formats.mfc_archive", "calibrate"),
    "evaluate_condition": ("superghidra.formats.mfc_archive", "evaluate_condition"),
    "find_ida_install": ("superghidra.formats.ida_til_importer", "find_ida_install"),
    "find_tilib": ("superghidra.formats.ida_til_importer", "find_tilib"),
    "list_available_tils": ("superghidra.formats.ida_til_importer", "list_available_tils"),
    "import_til": ("superghidra.formats.ida_til_importer", "import_til"),
    "export_clean_header": ("superghidra.formats.ida_til_importer", "export_clean_header"),
    "find_dumpsig": ("superghidra.formats.ida_flirt_bridge", "find_dumpsig"),
    "list_available_sigs": ("superghidra.formats.ida_flirt_bridge", "list_available_sigs"),
    "FlirtSignatureIndex": ("superghidra.formats.ida_flirt_bridge", "FlirtSignatureIndex"),
    "MigratedField": ("superghidra.formats.database_migrator", "MigratedField"),
    "MigratedStruct": ("superghidra.formats.database_migrator", "MigratedStruct"),
    "MigratedSegment": ("superghidra.formats.database_migrator", "MigratedSegment"),
    "MigratedFunction": ("superghidra.formats.database_migrator", "MigratedFunction"),
    "MigratedComment": ("superghidra.formats.database_migrator", "MigratedComment"),
    "MigratedXref": ("superghidra.formats.database_migrator", "MigratedXref"),
    "MigratedSymbol": ("superghidra.formats.database_migrator", "MigratedSymbol"),
    "MigratedProject": ("superghidra.formats.database_migrator", "MigratedProject"),
    "IdaDatabaseMigrator": ("superghidra.formats.database_migrator", "IdaDatabaseMigrator"),
    "BinaryNinjaDatabaseMigrator": ("superghidra.formats.database_migrator", "BinaryNinjaDatabaseMigrator"),
    "DatabaseMigrator": ("superghidra.formats.database_migrator", "DatabaseMigrator"),
    "create_synthetic_ida_database": ("superghidra.formats.database_migrator", "create_synthetic_ida_database"),
    "create_synthetic_bndb_database": ("superghidra.formats.database_migrator", "create_synthetic_bndb_database"),
}

__all__ = list(_EXPORTS.keys())


def __getattr__(name: str) -> Any:
    if name in _EXPORTS:
        mod_path, attr_name = _EXPORTS[name]
        mod = importlib.import_module(mod_path)
        val = getattr(mod, attr_name)
        globals()[name] = val
        return val
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
