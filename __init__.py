"""SuperGhidra Core Package: High-Performance Ghidra Architecture & GPU Acceleration Suite."""

# Phase 1 Core Modules
from .ghidra_oracle import GhidraOracleClient, GhidraOracleDaemon, run_oracle_cli
from .storage_compression_prototype import (
    DataBuffer,
    SlotDirectory,
    SlotDirectoryEntry,
    CompressedBufferFile,
    benchmark_compression_layer,
)
from .headless_analyzer_tuner import (
    HeadlessAnalyzerTuner,
    AnalyzerProfile,
    AnalyzerOption,
    generate_prescript_java,
    generate_lazy_noreturn_postscript_java,
)
from .gpu_adrp_scanner import (
    GPUADRPScanner,
    ADRPMatch,
    decode_adrp_target,
    decode_add_imm,
    decode_ldr_imm,
    benchmark_adrp_scan,
)
from .binary_diff_engine import (
    BinaryDiffEngine,
    BatchedBinaryMatcher,
    FunctionFeatureVector,
    FunctionMatchResult,
    StructOffsetDelta,
    DisplacementExtractor,
)
from .evidence_ledger import (
    ReconstructionObligationLedger,
    EvidenceObligation,
    VTableSlotVerifier,
    FieldDisplacementVerifier,
    AllocationSizeVerifier,
    VerificationReport,
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
    ARM64InstructionClassifier,
)
from .dependency_cache_dag import (
    DependencyCacheDAG,
    DecompilationLRUCache,
    InvalidationImpactReport,
    benchmark_dag_invalidation,
)
from .semantic_delta_log import (
    SemanticDeltaLog,
    DeltaMigrationEngine,
    DeltaMigrationReport,
    RenameSymbolEvent,
    DefineStructFieldEvent,
    BindVTableSlotEvent,
    SetFunctionSignatureEvent,
    SetCommentEvent,
    benchmark_semantic_delta_log,
)
from .dwarf_pdb_preindexer import (
    DwarfPdbPreindexer,
    TypeDeduplicator,
    OffHeapTypeStore,
    OracleTypeStoreAdapter,
    CanonicalType,
    StructMember,
    EnumMember,
    SyntheticDebugDataGenerator,
    benchmark_dwarf_preindexer,
)

# Phase 3 Reformation Spec Modules (Sections 5, 6, 7)
from .apk_jni_cross_referencer import (
    APKJNICrossReferencer,
    JavaNativeMethod,
    JNIRegisteredNative,
    JNICrossReferenceMatch,
    construct_static_jni_symbol,
    mangle_jni_identifier,
)
from .cross_platform_headless_harness import (
    HeadlessProfile,
    HeadlessEnvironmentConfigurator,
)
from .pcode_lifter_bridge import (
    ARM64PcodeLifter,
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

