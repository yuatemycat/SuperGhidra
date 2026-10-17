package superghidra.codec;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.util.LinkedHashMap;
import java.util.Map;

import db.buffers.BufferFileManager;
import ghidra.app.CorePluginPackage;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.util.Msg;

/**
 * SuperGhidraExtensionPlugin
 *
 * Standalone codec and tooling plugin for the SuperGhidra high-performance codec engine.
 * NOTE: This is a standalone codec and tooling utility; it sets runtime system properties and provides
 * factory methods, but is NOT automatically wired into Ghidra's internal LocalManagedBufferFile
 * storage engine by the Ghidra framework. Codec operations are invoked via explicit adapter
 * factories (createCompressedAdapter, createBufferFileManager) or standalone storage tooling.
 */
@PluginInfo(
    status = PluginStatus.STABLE,
    packageName = CorePluginPackage.NAME,
    category = PluginCategoryNames.COMMON,
    shortDescription = "Standalone Block LZ4/Zstd Compressed Buffer File Codec and Tooling",
    description = "SuperGhidraCodec standalone codec and tooling providing 16KB block LZ4/Zstd compression, CRC32 proofs, and 64-bit slot indexing (invoked via explicit adapter factories, not auto-wired into LocalManagedBufferFile)."
)
public class SuperGhidraExtensionPlugin extends ProgramPlugin {

    public static final String PLUGIN_NAME = "SuperGhidraCodec";
    public static final String CODEC_ACTIVE_PROPERTY = "superghidra.codec.active";

    public SuperGhidraExtensionPlugin(PluginTool tool) {
        super(tool);
    }

    @Override
    public void init() {
        super.init();
        System.setProperty(CODEC_ACTIVE_PROPERTY, "true");
        Msg.info(this, "SuperGhidraCodec extension initialized successfully. Active buffer block size: 16384 bytes.");
    }

    @Override
    public void dispose() {
        System.setProperty(CODEC_ACTIVE_PROPERTY, "false");
        super.dispose();
    }

    /**
     * BufferFileManager implementation backed by a directory and baseName, resolving .sgdb buffer files per version.
     */
    public static class SuperGhidraBufferFileManager implements db.buffers.BufferFileManager {
        private final File baseDir;
        private final String baseName;
        private int currentVersion;
        private String lastComment = "";
        private long lastCheckinId = 0L;

        public SuperGhidraBufferFileManager(File baseDir, String baseName) {
            this(baseDir, baseName, 1);
        }

        public SuperGhidraBufferFileManager(File baseDir, String baseName, int initialVersion) {
            this.baseDir = baseDir != null ? baseDir : new File(".");
            this.baseName = (baseName != null && !baseName.isEmpty()) ? baseName : "db";
            this.currentVersion = Math.max(0, initialVersion);
            if (this.baseDir.isDirectory()) {
                File[] files = this.baseDir.listFiles();
                if (files != null) {
                    String prefix = this.baseName + ".";
                    for (File f : files) {
                        String name = f.getName();
                        if (name.startsWith(prefix) && name.endsWith(".sgdb")) {
                            String mid = name.substring(prefix.length(), name.length() - 5);
                            try {
                                int v = Integer.parseInt(mid);
                                if (v > this.currentVersion) {
                                    this.currentVersion = v;
                                }
                            } catch (NumberFormatException ignored) {
                            }
                        }
                    }
                }
            }
        }

        @Override
        public synchronized int getCurrentVersion() {
            return currentVersion;
        }

        @Override
        public File getBufferFile(int version) {
            return new File(baseDir, baseName + "." + version + ".sgdb");
        }

        @Override
        public File getVersionFile(int version) {
            return new File(baseDir, baseName + "." + version + ".ver.sgdb");
        }

        @Override
        public File getChangeDataFile(int version) {
            return new File(baseDir, baseName + "." + version + ".chg.sgdb");
        }

        @Override
        public File getChangeMapFile() {
            return new File(baseDir, baseName + ".map.sgdb");
        }

        @Override
        public synchronized void versionCreated(int version, String comment, long checkinId) throws FileNotFoundException {
            if (baseDir != null && !baseDir.exists() && !baseDir.mkdirs()) {
                throw new FileNotFoundException("Directory does not exist: " + baseDir.getAbsolutePath());
            }
            if (version > this.currentVersion) {
                this.currentVersion = version;
            }
            this.lastComment = comment != null ? comment : "";
            this.lastCheckinId = checkinId;
        }

        @Override
        public synchronized void updateEnded(long checkinId) {
            this.lastCheckinId = checkinId;
        }

        public File getBaseDir() {
            return baseDir;
        }

        public String getBaseName() {
            return baseName;
        }

        public synchronized String getLastComment() {
            return lastComment;
        }

        public synchronized long getLastCheckinId() {
            return lastCheckinId;
        }
    }

    /**
     * Static factory to instantiate a BufferFileManager backed by a base directory and baseName.
     */
    public static db.buffers.BufferFileManager createBufferFileManager(File baseDir, String baseName) {
        return new SuperGhidraBufferFileManager(baseDir, baseName);
    }

    /**
     * Factory helper to instantiate a SuperGhidraBufferFileAdapter backed by a physical file.
     *
     * @param file the storage container file
     * @param algo the compression algorithm to use (e.g. LZ4, ZSTD)
     * @param readOnly true if opened in read-only mode
     * @return the initialized compressed buffer adapter
     * @throws IOException on file access or corruption error
     */
    public static SuperGhidraBufferFileAdapter createCompressedAdapter(File file, CompressionAlgorithm algo, boolean readOnly) throws IOException {
        return new SuperGhidraBufferFileAdapter(file, algo, SuperGhidraBufferFileAdapter.DEFAULT_BUFFER_SIZE, readOnly);
    }

    /**
     * Factory helper to instantiate a SuperGhidraBufferFileAdapter using the default compression algorithm.
     */
    public static SuperGhidraBufferFileAdapter createCompressedAdapter(File file, boolean readOnly) throws IOException {
        return createCompressedAdapter(file, getDefaultAlgorithm(), readOnly);
    }

    /**
     * Instance convenience helper to instantiate a SuperGhidraBufferFileAdapter.
     */
    public SuperGhidraBufferFileAdapter createAdapter(File file, CompressionAlgorithm algo, boolean readOnly) throws IOException {
        return createCompressedAdapter(file, algo, readOnly);
    }

    /**
     * Resolves the configured or default compression algorithm.
     */
    public static CompressionAlgorithm getDefaultAlgorithm() {
        String algoProp = System.getProperty("superghidra.codec.algorithm", "LZ4");
        try {
            return CompressionAlgorithm.valueOf(algoProp.trim().toUpperCase());
        } catch (IllegalArgumentException e) {
            return CompressionAlgorithm.LZ4;
        }
    }

    /**
     * Returns runtime diagnostics for the codec subsystem, active algorithm, and block parameters.
     */
    public static Map<String, Object> getCodecDiagnostics() {
        Map<String, Object> diag = new LinkedHashMap<>();
        diag.put("pluginName", PLUGIN_NAME);
        diag.put("codecActive", "true".equalsIgnoreCase(System.getProperty(CODEC_ACTIVE_PROPERTY, "false")));
        diag.put("defaultAlgorithm", getDefaultAlgorithm().getName());
        diag.put("defaultBufferSize", SuperGhidraBufferFileAdapter.DEFAULT_BUFFER_SIZE);
        diag.put("defaultCacheCapacity", SuperGhidraBufferFileAdapter.DEFAULT_CACHE_CAPACITY);
        diag.put("zstdSupported", CompressionAlgorithm.isZstdAvailable());
        return diag;
    }

    /**
     * Instance convenience helper for codec diagnostics.
     */
    public Map<String, Object> getDiagnostics() {
        return getCodecDiagnostics();
    }
}
