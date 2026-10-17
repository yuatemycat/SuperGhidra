"""SuperGhidra Core Package: High-Performance Ghidra Architecture & GPU Acceleration Suite."""

# Phase 1 Core Modules
from .ghidra_oracle import GhidraOracleSession, GhidraDaemonServer, client_send_request
from .storage_compression_prototype import (
    DataBuffer,
    SlotDirectory,
    SlotDirectoryEntry,
    CompressedLocalManagedBufferFile,
    StorageCompressionBenchmark,
)
from .headless_analyzer_tuner import (
    AnalyzerConfiguration,
    AnalyzerProfileName,
    HeadlessCommandBuilder,
    ScriptGenerator,
    get_profile_config,
)
from .gpu_adrp_scanner import (
    GPUAdrpScanner,
    ADRPMatch,
    decode_adrp_target,
    decode_add_imm,
    decode_ldr_imm,
    benchmark_scanner,
)
from .binary_diff_engine import (
    BatchedBinaryMatcher,
    CFGFeatureExtractor,
    DiffResult,
    FunctionCFG,
    FunctionMatch,
    decode_arm64_instruction,
    extract_cfgs_from_arm64_bytes,
    extract_cfgs_from_binary,
)
from .evidence_ledger import (
    ReconstructionObligationLedger,
    ProofObligation,
    VTableSlotVerifier,
    FieldDisplacementVerifier,
    AllocationSizeVerifier,
    CheckResult,
)

# Phase 2 High-Performance Modules
from .shm_decompiler_bridge import (
    ShmBinaryView,
    ShmRingBuffer,
    ShmChannel,
    ShmMessage,
    SectionInfo,
    benchmark_shm_bridge,
)
from .gpu_function_seeder import (
    GPUFunctionSeeder,
    FunctionSeed,
)
from .dependency_cache_dag import (
    DependencyCacheDAG,
    DecompilationLRUCache,
    InvalidationImpactReport,
)
from .semantic_delta_log import (
    SemanticDeltaLog,
    DeltaMigrationEngine,
    DeltaMigrationReport,
    SemanticEvent,
    DeltaEventType,
)
from .dwarf_pdb_preindexer import (
    OffHeapTypeStore,
    OracleTypeStoreAdapter,
    TypeDeduplicator,
    SyntheticDebugDataGenerator,
    StructMember,
)

# Phase 3 Reformation Spec Modules (Sections 5, 6, 7)
from .apk_jni_cross_referencer import (
    APKJNICrossReferencer,
    JavaNativeMethod,
    JNIRegisteredNative,
    JNICrossReferenceMatch,
)
build_synthetic_dex_bytes = APKJNICrossReferencer.build_synthetic_dex_bytes
build_synthetic_jni_elf_bytes = APKJNICrossReferencer.build_synthetic_jni_elf_bytes
from .cross_platform_headless_harness import (
    HeadlessProfile,
    HeadlessEnvironmentConfigurator,
)
from .pcode_lifter_bridge import (
    ARM64PcodeLifter,
    X86_64PcodeLifter,
    PcodeOp,
    PcodeOpcode,
    Varnode,
    AddressSpace,
    PcodeGraphBuilder,
)
from .native_decompiler_pgo_builder import (
    DecompilerBuildConfig,
    NativeDecompilerPGOBuilder,
)
from .neural_decompiler_pipeline import (
    NeuralDecompilerPipeline,
    LLMDecompilerClient,
    SkeletonExtractor,
    DecompiledSkeleton,
    NeuralPrediction,
    VerifiedNeuralCommit,
)

# Section 8 Resource Governor Modules
from .resource_governor import (
    ResourceMode,
    FunctionComplexityTier,
    ModePolicy,
    get_default_mode_policy,
    DecompilerComplexityGovernor,
    JVMResourceConfigurator,
    DecompileProcessPoolReaper,
    PersistentDecompilerDBCache,
    TelemetryResourceGovernor,
)

# Frontiers 5 & 6 Modules
from .emulator_memory_sidecar import (
    FleetSafetyViolationError,
    EmulatorDeviceInfo,
    EmulatorFleetGuard,
    MemoryRegion,
    BaseMemoryReader,
    Win32ProcessMemoryReader,
    FridaMemoryReader,
    MockMemoryReader,
    ModuleBaseResolver,
    VTableSlot,
    VTableVerificationResult,
    StructFieldVerificationResult,
    DynamicKeyResult,
    verify_vtable_pointer,
    verify_struct_field,
    extract_dynamic_encryption_keys,
    EmulatorSidecarShmServer,
    EmulatorSidecarShmClient,
)
from .struct_shift_migrator import (
    MemoryAccess,
    ShiftType,
    FieldMigration,
    StructInsertion,
    MigrationReport,
    StructShiftMigrator,
    migrate_struct_shifts,
    decode_arm64_memory_access,
    parse_disassembly_line,
)

# Frontiers 1 & 2 Modules (Synthetic Symbol Exporters & SMT P-Code Verifier)
from .synthetic_symbol_exporter import (
    ExportSymbol,
    ExportField,
    ExportStruct,
    DWARF5Exporter,
    PDBExporter,
    MapFileExporter,
    SymFileExporter,
    SymbolLedgerIngestor,
    export_from_ledger,
)
from .smt_pcode_verifier import (
    VerificationResult,
    SymbolicState,
    PcodeSymbolicSimulator,
    CASTNode,
    CVar,
    CConst,
    CBinary,
    CUnary,
    CTernary,
    CDeref,
    CFieldAccess,
    CIntrinsic,
    CAssignment,
    CIfElse,
    CWhile,
    CReturn,
    CBlock,
    CCodeParser,
    CSymbolicEvaluator,
    SMTPcodeVerifier,
)

# Frontiers 3 & 4 Modules (In-Engine Java Extension & Cloud Colab TPU/T4 Orchestrator)
from .ghidra_extension_packager import (
    GhidraExtensionPackager,
    ExtensionValidationError,
)
from .colab_cloud_orchestrator import (
    CloudRuntimeTier,
    CloudConfig,
    ColabCloudOrchestrator,
)
