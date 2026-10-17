package superghidra.codec;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.RandomAccessFile;
import java.lang.reflect.Constructor;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;

import db.buffers.BufferFile;
import db.buffers.DataBuffer;
import db.buffers.ManagedBufferFile;

/**
 * SuperGhidraBufferFileAdapter
 *
 * High-performance, transparent compressed BufferFile and ManagedBufferFile implementation for Ghidra databases.
 * Intercepts 16KB DataBuffer block read/writes, applying LZ4/Zstandard framing with CRC32 integrity checks
 * and maintaining a 64-bit slot directory for O(1) random-access lookups.
 */
public class SuperGhidraBufferFileAdapter implements BufferFile, ManagedBufferFile, java.io.Closeable {

    public static final int DEFAULT_BUFFER_SIZE = 16384; // 16 KB
    public static final int HEADER_SIZE = 32;
    public static final int SLOT_ENTRY_SIZE = 24; // blockId(4) + offset(8) + compLen(4) + origLen(4) + crc32(4)
    public static final byte FLAG_EXTENDED_METADATA = 0x01; // Trailer contains parameters map and freeIndexes array

    private final File backingFile;
    private RandomAccessFile raf;
    private final CompressionAlgorithm algorithm;
    private final int bufferSize;
    private boolean readOnly;
    private boolean closed;

    private final Map<Integer, SlotEntry> slotDirectory = new ConcurrentHashMap<>();
    private final Set<Integer> emptyBuffers = ConcurrentHashMap.newKeySet();
    private final Map<String, Integer> parameters = new ConcurrentHashMap<>();
    private int[] freeIndexes = new int[0];
    private int indexCount = 0;

    // ManagedBufferFile state
    private String versionComment = "";
    private long checkinId = 0L;
    private boolean saveInProgress = false;

    public static final int DEFAULT_CACHE_CAPACITY = 256;
    private final Map<Integer, byte[]> blockCache = new LinkedHashMap<Integer, byte[]>(DEFAULT_CACHE_CAPACITY, 0.75f, true) {
        @Override
        protected boolean removeEldestEntry(Map.Entry<Integer, byte[]> eldest) {
            return size() > DEFAULT_CACHE_CAPACITY;
        }
    };
    private final AtomicLong cacheHits = new AtomicLong(0);
    private final AtomicLong cacheMisses = new AtomicLong(0);
    private final AtomicLong elidedWrites = new AtomicLong(0);

    // Telemetry & metrics
    private final AtomicLong totalCompressedBytesWritten = new AtomicLong(0);
    private final AtomicLong totalUncompressedBytesWritten = new AtomicLong(0);
    private final AtomicLong totalCompressedBytesRead = new AtomicLong(0);
    private final AtomicLong totalUncompressedBytesRead = new AtomicLong(0);

    /**
     * Represents a single indexed block slot in the container.
     */
    public static class SlotEntry {
        public final int blockId;
        public final long offset;
        public final int compLen;
        public final int origLen;
        public final long crc32;

        public SlotEntry(int blockId, long offset, int compLen, int origLen, long crc32) {
            this.blockId = blockId;
            this.offset = offset;
            this.compLen = compLen;
            this.origLen = origLen;
            this.crc32 = crc32;
        }

        public byte[] serialize() {
            ByteBuffer buf = ByteBuffer.allocate(SLOT_ENTRY_SIZE).order(ByteOrder.LITTLE_ENDIAN);
            buf.putInt(blockId);
            buf.putLong(offset);
            buf.putInt(compLen);
            buf.putInt(origLen);
            buf.putInt((int) (crc32 & 0xFFFFFFFFL));
            return buf.array();
        }

        public static SlotEntry deserialize(byte[] data, int offset) {
            ByteBuffer buf = ByteBuffer.wrap(data, offset, SLOT_ENTRY_SIZE).order(ByteOrder.LITTLE_ENDIAN);
            int blockId = buf.getInt();
            long fileOffset = buf.getLong();
            int compLen = buf.getInt();
            int origLen = buf.getInt();
            long crc32 = buf.getInt() & 0xFFFFFFFFL;
            return new SlotEntry(blockId, fileOffset, compLen, origLen, crc32);
        }
    }

    /**
     * Constructs a SuperGhidraBufferFileAdapter backed by a physical file.
     */
    public SuperGhidraBufferFileAdapter(File file, CompressionAlgorithm algorithm, int bufferSize, boolean readOnly) throws IOException {
        this.backingFile = file;
        this.algorithm = algorithm != null ? algorithm : CompressionAlgorithm.LZ4;
        this.bufferSize = bufferSize > 0 ? bufferSize : DEFAULT_BUFFER_SIZE;
        this.readOnly = readOnly;
        this.closed = false;

        if (file != null) {
            String mode = readOnly ? "r" : "rw";
            this.raf = new RandomAccessFile(file, mode);
            if (this.raf.length() >= HEADER_SIZE) {
                readHeaderAndDirectory();
            } else if (!readOnly) {
                writeHeader(0, 0, (byte) 0);
            }
        }
    }

    /**
     * In-memory or temporary buffer file constructor for headless/testing pipelines.
     */
    public SuperGhidraBufferFileAdapter(CompressionAlgorithm algorithm) {
        this.backingFile = null;
        this.raf = null;
        this.algorithm = algorithm != null ? algorithm : CompressionAlgorithm.LZ4;
        this.bufferSize = DEFAULT_BUFFER_SIZE;
        this.readOnly = false;
        this.closed = false;
    }

    // =========================================================================
    // Header & Slot Directory Serialization
    // =========================================================================

    private synchronized void writeHeader(long dirOffset, int dirCount, byte flags) throws IOException {
        if (raf == null || readOnly) return;
        raf.seek(0);
        ByteBuffer buf = ByteBuffer.allocate(HEADER_SIZE).order(ByteOrder.LITTLE_ENDIAN);
        buf.put(CompressionAlgorithm.MAGIC_BYTES);
        buf.putShort((short) CompressionAlgorithm.VERSION);
        buf.put(algorithm.getId());
        buf.put(flags); // flags
        buf.putLong(dirOffset);
        buf.putInt(dirCount);
        buf.putInt(bufferSize);
        buf.putLong(0L); // reserved
        raf.write(buf.array());
    }

    private synchronized void writeHeader(long dirOffset, int dirCount) throws IOException {
        writeHeader(dirOffset, dirCount, FLAG_EXTENDED_METADATA);
    }

    private synchronized void readHeaderAndDirectory() throws IOException {
        if (raf == null) return;
        raf.seek(0);
        byte[] headerBytes = new byte[HEADER_SIZE];
        raf.readFully(headerBytes);
        ByteBuffer buf = ByteBuffer.wrap(headerBytes).order(ByteOrder.LITTLE_ENDIAN);

        byte[] magic = new byte[4];
        buf.get(magic);
        if (!Arrays.equals(magic, CompressionAlgorithm.MAGIC_BYTES)) {
            throw new IOException("Corrupt SuperGhidra storage file: invalid magic header");
        }

        short version = buf.getShort();
        byte algoId = buf.get();
        byte flags = buf.get();
        long dirOffset = buf.getLong();
        int dirCount = buf.getInt();
        int bSize = buf.getInt();

        if (version != CompressionAlgorithm.VERSION) {
            throw new IOException("Unsupported SuperGhidra container version: " + version);
        }
        if (algoId < 0 || algoId > 3) {
            throw new IOException("Unsupported SuperGhidra algorithm ID: " + algoId);
        }
        if (bSize <= 0 || bSize > 16 * 1024 * 1024) {
            throw new IOException("Invalid buffer size in header: " + bSize);
        }
        if (dirOffset < 0 || dirOffset > raf.length() || dirCount < 0) {
            throw new IOException("Invalid directory offset (" + dirOffset + ") or count (" + dirCount + ")");
        }
        long dirBytesLen = (long) dirCount * SLOT_ENTRY_SIZE;
        if (dirOffset + dirBytesLen > raf.length()) {
            throw new IOException("Truncated slot directory: requires " + dirBytesLen + " bytes at offset " + dirOffset + ", file length " + raf.length());
        }

        if (dirOffset > 0 && dirCount >= 0) {
            raf.seek(dirOffset);
            if (dirCount > 0) {
                byte[] dirBytes = new byte[dirCount * SLOT_ENTRY_SIZE];
                raf.readFully(dirBytes);
                for (int i = 0; i < dirCount; i++) {
                    SlotEntry entry = SlotEntry.deserialize(dirBytes, i * SLOT_ENTRY_SIZE);
                    slotDirectory.put(entry.blockId, entry);
                    if (entry.blockId >= indexCount) {
                        indexCount = entry.blockId + 1;
                    }
                }
            }

            // Restore parameters and freeIndexes when FLAG_EXTENDED_METADATA (0x01) is set
            if ((flags & FLAG_EXTENDED_METADATA) != 0 && raf.getFilePointer() < raf.length()) {
                if (raf.getFilePointer() + 4 > raf.length()) {
                    throw new IOException("Truncated trailer parameters header");
                }
                byte[] intBuf = new byte[4];
                raf.readFully(intBuf);
                int paramCount = ByteBuffer.wrap(intBuf).order(ByteOrder.LITTLE_ENDIAN).getInt();
                if (paramCount < 0 || paramCount > 100000) {
                    throw new IOException("Corrupt trailer parameter count: " + paramCount);
                }
                parameters.clear();
                for (int i = 0; i < paramCount; i++) {
                    if (raf.getFilePointer() + 4 > raf.length()) {
                        throw new IOException("Truncated trailer parameter key size");
                    }
                    raf.readFully(intBuf);
                    int kLen = ByteBuffer.wrap(intBuf).order(ByteOrder.LITTLE_ENDIAN).getInt();
                    if (kLen < 0 || kLen > 4096 || raf.getFilePointer() + kLen + 4 > raf.length()) {
                        throw new IOException("Corrupt trailer parameter key length: " + kLen);
                    }
                    byte[] kBytes = new byte[kLen];
                    raf.readFully(kBytes);
                    String key = new String(kBytes, StandardCharsets.UTF_8);
                    raf.readFully(intBuf);
                    int val = ByteBuffer.wrap(intBuf).order(ByteOrder.LITTLE_ENDIAN).getInt();
                    parameters.put(key, val);
                }

                if (raf.getFilePointer() < raf.length()) {
                    if (raf.getFilePointer() + 4 > raf.length()) {
                        throw new IOException("Truncated trailer freeIndexes header");
                    }
                    raf.readFully(intBuf);
                    int freeCount = ByteBuffer.wrap(intBuf).order(ByteOrder.LITTLE_ENDIAN).getInt();
                    if (freeCount < 0 || freeCount > 1000000 || raf.getFilePointer() + ((long) freeCount * 4) > raf.length()) {
                        throw new IOException("Corrupt trailer freeIndexes count: " + freeCount);
                    }
                    int[] loadedFree = new int[freeCount];
                    if (freeCount > 0) {
                        byte[] freeBytes = new byte[freeCount * 4];
                        raf.readFully(freeBytes);
                        ByteBuffer freeBb = ByteBuffer.wrap(freeBytes).order(ByteOrder.LITTLE_ENDIAN);
                        for (int i = 0; i < freeCount; i++) {
                            loadedFree[i] = freeBb.getInt();
                        }
                    }
                    this.freeIndexes = loadedFree;
                }
            }
        }
    }

    // =========================================================================
    // BufferFile Interface Implementation
    // =========================================================================

    @Override
    public synchronized DataBuffer get(DataBuffer buf, int index) throws IOException {
        ensureOpen();
        if (index < 0) {
            throw new IOException("Invalid buffer index: " + index);
        }
        SlotEntry entry = slotDirectory.get(index);
        if (entry == null) {
            throw new java.io.EOFException("Buffer block index " + index + " not found in slot directory");
        }

        byte[] cached = blockCache.get(index);
        byte[] uncompressed;
        byte frameFlags = 0;
        if (cached != null) {
            cacheHits.incrementAndGet();
            uncompressed = cached;
        } else {
            cacheMisses.incrementAndGet();
            byte[] compBytes = new byte[entry.compLen];
            if (raf != null) {
                raf.seek(entry.offset);
                raf.readFully(compBytes);
            }
            if (compBytes.length >= 8) {
                frameFlags = compBytes[7];
            }
            uncompressed = CompressionAlgorithm.decompressFrame(compBytes, 0, compBytes.length);
            blockCache.put(index, Arrays.copyOf(uncompressed, uncompressed.length));
            totalCompressedBytesRead.addAndGet(entry.compLen);
            totalUncompressedBytesRead.addAndGet(uncompressed.length);
        }

        if (buf == null) {
            buf = createDataBufferInstance(uncompressed.length);
        } else {
            ensureBackingArray(buf, uncompressed.length);
        }

        int copyLen = Math.min(uncompressed.length, buf.length());
        buf.put(0, uncompressed, 0, copyLen);

        setBufferId(buf, index);
        boolean isEmpty = emptyBuffers.contains(index) || (frameFlags & CompressionAlgorithm.FLAG_EMPTY_BUFFER) != 0;
        setBufferEmpty(buf, isEmpty);
        return buf;
    }

    @Override
    public synchronized void put(DataBuffer buf, int index) throws IOException {
        ensureOpen();
        if (readOnly) {
            throw new IOException("Cannot write to read-only SuperGhidraBufferFile");
        }
        if (buf == null) {
            throw new IllegalArgumentException("DataBuffer cannot be null");
        }

        int len = buf.length();
        byte[] rawBytes = new byte[len];
        buf.get(0, rawBytes, 0, len);

        boolean isEmpty = isBufferEmpty(buf);
        if (isEmpty) {
            emptyBuffers.add(index);
        } else {
            emptyBuffers.remove(index);
        }

        long crc32 = CompressionAlgorithm.computeCRC32(rawBytes, 0, len);
        SlotEntry existing = slotDirectory.get(index);
        if (existing != null && existing.crc32 == crc32 && existing.origLen == len) {
            elidedWrites.incrementAndGet();
            blockCache.put(index, Arrays.copyOf(rawBytes, len));
            return;
        }

        blockCache.put(index, Arrays.copyOf(rawBytes, len));

        byte extraFlags = isEmpty ? CompressionAlgorithm.FLAG_EMPTY_BUFFER : (byte) 0;
        byte[] frame = CompressionAlgorithm.compressFrame(rawBytes, 0, len, algorithm, extraFlags);

        long fileOffset = 0;
        if (raf != null) {
            // Append-only write for frames to guarantee crash-safety
            fileOffset = raf.length();
            raf.seek(fileOffset);
            raf.write(frame);
        }

        SlotEntry entry = new SlotEntry(index, fileOffset, frame.length, len, crc32);
        slotDirectory.put(index, entry);

        if (index >= indexCount) {
            indexCount = index + 1;
        }

        totalCompressedBytesWritten.addAndGet(frame.length);
        totalUncompressedBytesWritten.addAndGet(len);
    }

    @Override
    public int getBufferSize() throws IOException {
        return bufferSize;
    }

    @Override
    public synchronized int getIndexCount() throws IOException {
        return indexCount;
    }

    @Override
    public synchronized int[] getFreeIndexes() throws IOException {
        return Arrays.copyOf(freeIndexes, freeIndexes.length);
    }

    @Override
    public synchronized void setFreeIndexes(int[] indexes) throws IOException {
        ensureOpen();
        this.freeIndexes = indexes != null ? Arrays.copyOf(indexes, indexes.length) : new int[0];
    }

    @Override
    public boolean isReadOnly() throws IOException {
        return readOnly;
    }

    @Override
    public synchronized boolean setReadOnly() throws IOException {
        this.readOnly = true;
        return true;
    }

    @Override
    public int getParameter(String name) throws NoSuchElementException, IOException {
        Integer val = parameters.get(name);
        if (val == null) {
            throw new NoSuchElementException("Parameter not found: " + name);
        }
        return val;
    }

    @Override
    public void setParameter(String name, int value) throws IOException {
        ensureOpen();
        parameters.put(name, value);
    }

    @Override
    public void clearParameters() throws IOException {
        ensureOpen();
        parameters.clear();
    }

    @Override
    public String[] getParameterNames() throws IOException {
        Set<String> keys = parameters.keySet();
        return keys.toArray(new String[0]);
    }

    /**
     * Flushes the slot directory, parameters map, and freeIndexes array to the trailer of the backing file,
     * updates the file header, and synchronizes to disk for crash safety without closing the file.
     */
    public synchronized void sync() throws IOException {
        ensureOpen();
        if (raf == null || readOnly) return;

        // Write new directory at end of file (append-only)
        long dirOffset = raf.length();
        raf.seek(dirOffset);
        int dirCount = slotDirectory.size();

        ByteBuffer dirBuf = ByteBuffer.allocate(dirCount * SLOT_ENTRY_SIZE).order(ByteOrder.LITTLE_ENDIAN);
        for (SlotEntry entry : slotDirectory.values()) {
            dirBuf.put(entry.serialize());
        }
        raf.write(dirBuf.array());

        // Persist parameters (key-value pairs) and freeIndexes right after the slot directory
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        ByteBuffer pBuf = ByteBuffer.allocate(4).order(ByteOrder.LITTLE_ENDIAN);
        pBuf.putInt(parameters.size());
        baos.write(pBuf.array());

        for (Map.Entry<String, Integer> entry : parameters.entrySet()) {
            byte[] kBytes = entry.getKey().getBytes(StandardCharsets.UTF_8);
            ByteBuffer itemBuf = ByteBuffer.allocate(4 + kBytes.length + 4).order(ByteOrder.LITTLE_ENDIAN);
            itemBuf.putInt(kBytes.length);
            itemBuf.put(kBytes);
            itemBuf.putInt(entry.getValue());
            baos.write(itemBuf.array());
        }

        // Persist freeIndexes
        ByteBuffer fBuf = ByteBuffer.allocate(4 + freeIndexes.length * 4).order(ByteOrder.LITTLE_ENDIAN);
        fBuf.putInt(freeIndexes.length);
        for (int idx : freeIndexes) {
            fBuf.putInt(idx);
        }
        baos.write(fBuf.array());

        raf.write(baos.toByteArray());

        // Crash-safe flush directory & trailer to physical device
        raf.getFD().sync();

        // Re-write header pointing to new directory with FLAG_EXTENDED_METADATA (0x01)
        writeHeader(dirOffset, dirCount, FLAG_EXTENDED_METADATA);

        // Crash-safe flush header update to physical device
        raf.getFD().sync();
    }

    /**
     * Defragments the file by reading the compressed frames for all active entries in slotDirectory,
     * packing them contiguously starting at HEADER_SIZE, updating each SlotEntry offset,
     * truncating the file via raf.setLength(...), and calling sync().
     *
     * @return the number of bytes reclaimed
     * @throws IOException on file access error
     */
    public synchronized long compact() throws IOException {
        ensureOpen();
        if (raf == null || readOnly) return 0L;

        long oldLength = raf.length();
        List<SlotEntry> entries = new ArrayList<>(slotDirectory.values());
        entries.sort(Comparator.comparingLong(e -> e.offset));

        Map<Integer, byte[]> frames = new HashMap<>();
        for (SlotEntry entry : entries) {
            byte[] comp = new byte[entry.compLen];
            raf.seek(entry.offset);
            raf.readFully(comp);
            frames.put(entry.blockId, comp);
        }

        long currentOffset = HEADER_SIZE;
        for (SlotEntry entry : entries) {
            byte[] comp = frames.get(entry.blockId);
            raf.seek(currentOffset);
            raf.write(comp);
            SlotEntry updated = new SlotEntry(entry.blockId, currentOffset, entry.compLen, entry.origLen, entry.crc32);
            slotDirectory.put(entry.blockId, updated);
            currentOffset += comp.length;
        }

        raf.setLength(currentOffset);
        sync();

        return Math.max(0L, oldLength - raf.length());
    }

    public synchronized boolean delete(int index) throws IOException {
        ensureOpen();
        blockCache.remove(index);
        return slotDirectory.remove(index) != null;
    }

    public synchronized void clear() {
        blockCache.clear();
        slotDirectory.clear();
    }

    public synchronized void clearCache() {
        blockCache.clear();
    }

    @Override
    public synchronized void close() throws IOException {
        if (closed) return;
        try {
            if (raf != null && !readOnly) {
                sync();
            }
        } finally {
            blockCache.clear();
            closed = true;
            if (raf != null) {
                raf.close();
                raf = null;
            }
        }
    }

    @Override
    public synchronized boolean delete() throws IOException {
        close();
        if (backingFile != null && backingFile.exists()) {
            return backingFile.delete();
        }
        return true;
    }

    @Override
    public void dispose() {
        try {
            close();
        } catch (IOException ignored) {
        }
    }

    // =========================================================================
    // ManagedBufferFile Interface Implementation
    // =========================================================================

    @Override
    public BufferFile getNextChangeDataFile(boolean forward) throws IOException {
        return null;
    }

    @Override
    public BufferFile getSaveChangeDataFile() throws IOException {
        return null;
    }

    @Override
    public byte[] getForwardModMapData(int version) throws IOException {
        return null;
    }

    @Override
    public synchronized ManagedBufferFile getSaveFile() throws IOException {
        ensureOpen();
        if (readOnly) {
            throw new IOException("Cannot get save file for read-only buffer file");
        }
        if (saveInProgress) {
            throw new IOException("Save already in progress");
        }
        saveInProgress = true;
        return this;
    }

    @Override
    public synchronized void saveCompleted(boolean commit) throws IOException {
        ensureOpen();
        saveInProgress = false;
        if (commit && !readOnly) {
            sync();
        }
    }

    @Override
    public synchronized boolean canSave() throws IOException {
        return !readOnly && !closed;
    }

    @Override
    public synchronized void setVersionComment(String comment) throws IOException {
        this.versionComment = comment != null ? comment : "";
    }

    public synchronized String getVersionComment() {
        return versionComment;
    }

    @Override
    public synchronized long getCheckinID() throws IOException {
        return checkinId;
    }

    public synchronized void setCheckinID(long checkinId) {
        this.checkinId = checkinId;
    }

    public synchronized void checkinCompleted() throws IOException {
        saveCompleted(true);
    }

    public synchronized void checkinCompleted(long checkinId) throws IOException {
        this.checkinId = checkinId;
        saveCompleted(true);
    }

    // =========================================================================
    // Metrics & Diagnostics
    // =========================================================================

    public double getCompressionRatio() {
        long uncomp = totalUncompressedBytesWritten.get();
        long comp = totalCompressedBytesWritten.get();
        if (uncomp == 0) return 0.0;
        return 1.0 - ((double) comp / (double) uncomp);
    }

    public long getTotalCompressedBytesWritten() {
        return totalCompressedBytesWritten.get();
    }

    public long getTotalUncompressedBytesWritten() {
        return totalUncompressedBytesWritten.get();
    }

    public CompressionAlgorithm getAlgorithm() {
        return algorithm;
    }

    public int getSlotCount() {
        return slotDirectory.size();
    }

    public long getCacheHits() {
        return cacheHits.get();
    }

    public long getCacheMisses() {
        return cacheMisses.get();
    }

    public long getElidedWrites() {
        return elidedWrites.get();
    }

    public int getCacheSize() {
        return blockCache.size();
    }

    private void ensureOpen() throws IOException {
        if (closed) {
            throw new IOException("SuperGhidraBufferFileAdapter is closed");
        }
    }

    private void setBufferId(DataBuffer buf, int id) {
        if (buf == null) return;
        try {
            java.lang.reflect.Method m = DataBuffer.class.getDeclaredMethod("setId", int.class);
            m.setAccessible(true);
            m.invoke(buf, id);
        } catch (Throwable t) {
            try {
                java.lang.reflect.Field f = DataBuffer.class.getDeclaredField("id");
                f.setAccessible(true);
                f.setInt(buf, id);
            } catch (Throwable ignored) {
            }
        }
    }

    private void setBufferEmpty(DataBuffer buf, boolean empty) {
        if (buf == null) return;
        try {
            java.lang.reflect.Method m = DataBuffer.class.getDeclaredMethod("setEmpty", boolean.class);
            m.setAccessible(true);
            m.invoke(buf, empty);
        } catch (Throwable t) {
            try {
                java.lang.reflect.Field f = DataBuffer.class.getDeclaredField("empty");
                f.setAccessible(true);
                f.setBoolean(buf, empty);
            } catch (Throwable ignored) {
            }
        }
    }

    private boolean isBufferEmpty(DataBuffer buf) {
        if (buf == null) return false;
        try {
            return buf.isEmpty();
        } catch (Throwable t) {
            return false;
        }
    }

    private void ensureBackingArray(DataBuffer buf, int requiredSize) {
        if (buf == null) return;
        int targetSize = requiredSize > 0 ? requiredSize : bufferSize;
        try {
            java.lang.reflect.Field dataField = DataBuffer.class.getDeclaredField("data");
            dataField.setAccessible(true);
            if (dataField.get(buf) == null) {
                dataField.set(buf, new byte[targetSize]);
            }
        } catch (Throwable ignored) {
        }
    }

    private DataBuffer createDataBufferInstance(int size) {
        int targetSize = size > 0 ? size : bufferSize;
        try {
            Constructor<DataBuffer> c = DataBuffer.class.getDeclaredConstructor(int.class);
            c.setAccessible(true);
            return c.newInstance(targetSize);
        } catch (Throwable t) {
            try {
                DataBuffer buf = new DataBuffer();
                java.lang.reflect.Field dataField = DataBuffer.class.getDeclaredField("data");
                dataField.setAccessible(true);
                dataField.set(buf, new byte[targetSize]);
                return buf;
            } catch (Throwable t2) {
                return new DataBuffer();
            }
        }
    }
}
