package superghidra.codec;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.Arrays;
import java.util.zip.CRC32;
import java.util.zip.Deflater;
import java.util.zip.Inflater;

/**
 * SuperGhidra Compression Algorithms and Framing Utilities.
 * Supports LZ4, Zstandard, Deflate, and Raw pass-through framing with CRC32 integrity verification.
 */
public enum CompressionAlgorithm {
    RAW((byte) 0, "RAW"),
    LZ4((byte) 1, "LZ4"),
    ZSTD((byte) 2, "ZSTD"),
    DEFLATE((byte) 3, "DEFLATE");

    public static final int MAGIC = 0x53474442; // "SGDB"
    public static final byte[] MAGIC_BYTES = new byte[] { 'S', 'G', 'D', 'B' };
    public static final int VERSION = 1;
    public static final int GHIDRA_BUFFER_SIZE = 16384; // 16 KB standard block
    public static final int GHIDRA_HEADER_SIZE = 5;     // 1 byte flags + 4 bytes buffer ID
    public static final int GHIDRA_BLOCK_SIZE = GHIDRA_BUFFER_SIZE + GHIDRA_HEADER_SIZE;
    
    // Framing header: MAGIC(4B) + VERSION(2B) + ALGO(1B) + FLAGS(1B) + ORIG_LEN(4B) + COMP_LEN(4B) + CRC32(4B) = 20B
    public static final int FRAME_HEADER_SIZE = 20;

    private final byte id;
    private final String name;

    CompressionAlgorithm(byte id, String name) {
        this.id = id;
        this.name = name;
    }

    public byte getId() {
        return id;
    }

    public String getName() {
        return name;
    }

    public static CompressionAlgorithm fromId(byte id) {
        for (CompressionAlgorithm algo : values()) {
            if (algo.id == id) {
                return algo;
            }
        }
        return RAW;
    }

    /**
     * Computes CRC32 checksum over the specified byte slice.
     */
    public static long computeCRC32(byte[] data, int offset, int length) {
        CRC32 crc = new CRC32();
        crc.update(data, offset, length);
        return crc.getValue();
    }

    /**
     * Verifies CRC32 checksum over the specified byte slice.
     */
    public static boolean verifyCRC32(byte[] data, int offset, int length, long expectedCrc) {
        long actual = computeCRC32(data, offset, length);
        return actual == expectedCrc;
    }

    /**
     * Compresses a raw payload and packages it with an SGDB frame header and CRC32 proof.
     */
    public static byte[] compressFrame(byte[] rawData, int offset, int length, CompressionAlgorithm algo) throws IOException {
        long crcVal = computeCRC32(rawData, offset, length);
        byte[] payload;

        switch (algo) {
            case LZ4:
                payload = compressLZ4(rawData, offset, length);
                break;
            case ZSTD:
                payload = compressZstdOrFallback(rawData, offset, length);
                break;
            case DEFLATE:
                payload = compressDeflate(rawData, offset, length);
                break;
            case RAW:
            default:
                payload = Arrays.copyOfRange(rawData, offset, offset + length);
                break;
        }

        ByteBuffer header = ByteBuffer.allocate(FRAME_HEADER_SIZE).order(ByteOrder.LITTLE_ENDIAN);
        header.put(MAGIC_BYTES);
        header.putShort((short) VERSION);
        header.put(algo.getId());
        header.put((byte) 0); // flags
        header.putInt(length);
        header.putInt(payload.length);
        header.putInt((int) (crcVal & 0xFFFFFFFFL));

        byte[] result = new byte[FRAME_HEADER_SIZE + payload.length];
        System.arraycopy(header.array(), 0, result, 0, FRAME_HEADER_SIZE);
        System.arraycopy(payload, 0, result, FRAME_HEADER_SIZE, payload.length);
        return result;
    }

    /**
     * Decompresses an SGDB framed payload with CRC32 integrity verification.
     */
    public static byte[] decompressFrame(byte[] frameBytes, int offset, int length) throws IOException {
        if (length < FRAME_HEADER_SIZE) {
            throw new IOException("Invalid frame size: " + length + " is smaller than header size " + FRAME_HEADER_SIZE);
        }

        ByteBuffer header = ByteBuffer.wrap(frameBytes, offset, FRAME_HEADER_SIZE).order(ByteOrder.LITTLE_ENDIAN);
        byte[] magic = new byte[4];
        header.get(magic);
        if (!Arrays.equals(magic, MAGIC_BYTES)) {
            throw new IOException("Invalid frame magic: " + Arrays.toString(magic));
        }

        short version = header.getShort();
        byte algoId = header.get();
        byte flags = header.get();
        int origLen = header.getInt();
        int compLen = header.getInt();
        long expectedCrc = header.getInt() & 0xFFFFFFFFL;

        if (FRAME_HEADER_SIZE + compLen > length) {
            throw new IOException("Corrupt frame: payload declared " + compLen + " bytes, but only " + (length - FRAME_HEADER_SIZE) + " available");
        }

        CompressionAlgorithm algo = fromId(algoId);
        int payloadOffset = offset + FRAME_HEADER_SIZE;
        byte[] decompressed = new byte[origLen];

        switch (algo) {
            case LZ4:
                decompressLZ4(frameBytes, payloadOffset, compLen, decompressed, 0, origLen);
                break;
            case ZSTD:
                decompressed = decompressZstdOrFallback(frameBytes, payloadOffset, compLen, origLen);
                break;
            case DEFLATE:
                decompressDeflate(frameBytes, payloadOffset, compLen, decompressed, 0, origLen);
                break;
            case RAW:
            default:
                System.arraycopy(frameBytes, payloadOffset, decompressed, 0, Math.min(compLen, origLen));
                break;
        }

        long actualCrc = computeCRC32(decompressed, 0, decompressed.length);
        if (actualCrc != expectedCrc) {
            throw new IOException("CRC32 mismatch in frame decompression! Expected: " + Long.toHexString(expectedCrc) + ", Actual: " + Long.toHexString(actualCrc));
        }

        return decompressed;
    }

    // =========================================================================
    // Pure Java High-Performance LZ4 Block Compressor / Decompressor
    // =========================================================================

    public static byte[] compressLZ4(byte[] src, int srcOff, int srcLen) {
        if (srcLen == 0) {
            return new byte[0];
        }

        // Fast hash-table based LZ4 block compression
        int[] hashTable = new int[4096];
        Arrays.fill(hashTable, -1);

        ByteArrayOutputStream out = new ByteArrayOutputStream(srcLen);
        int anchor = srcOff;
        int ip = srcOff;
        int mflimit = srcOff + srcLen - 12;

        while (ip < mflimit) {
            int d = ((src[ip] & 0xFF) |
                    ((src[ip + 1] & 0xFF) << 8) |
                    ((src[ip + 2] & 0xFF) << 16) |
                    ((src[ip + 3] & 0xFF) << 24));
            int h = ((d * -1640531535) >>> 20) & 0xFFF;
            int ref = hashTable[h];
            hashTable[h] = ip;

            if (ref >= srcOff && (ip - ref) < 65535 &&
                src[ref] == src[ip] &&
                src[ref + 1] == src[ip + 1] &&
                src[ref + 2] == src[ip + 2] &&
                src[ref + 3] == src[ip + 3]) {

                // Match found
                int litLen = ip - anchor;
                int matchOff = ip - ref;

                // Find match length
                int len = 4;
                while (ip + len < srcOff + srcLen && src[ref + len] == src[ip + len]) {
                    len++;
                }

                // Write token
                int tokenLit = Math.min(litLen, 15);
                int tokenMatch = (len - 4) < 15 ? (len - 4) : 15;
                out.write((tokenLit << 4) | tokenMatch);

                // Write literal extra length
                if (litLen >= 15) {
                    int extra = litLen - 15;
                    while (extra >= 255) {
                        out.write(255);
                        extra -= 255;
                    }
                    out.write(extra);
                }

                // Write literals
                out.write(src, anchor, litLen);

                // Write offset (little-endian 16-bit)
                out.write(matchOff & 0xFF);
                out.write((matchOff >>> 8) & 0xFF);

                // Write match extra length
                if ((len - 4) >= 15) {
                    int extra = (len - 4) - 15;
                    while (extra >= 255) {
                        out.write(255);
                        extra -= 255;
                    }
                    out.write(extra);
                }

                ip += len;
                anchor = ip;
            } else {
                ip++;
            }
        }

        // Write remaining literals
        int lastLits = (srcOff + srcLen) - anchor;
        int tokenLit = Math.min(lastLits, 15);
        out.write(tokenLit << 4);
        if (lastLits >= 15) {
            int extra = lastLits - 15;
            while (extra >= 255) {
                out.write(255);
                extra -= 255;
            }
            out.write(extra);
        }
        out.write(src, anchor, lastLits);

        return out.toByteArray();
    }

    public static int decompressLZ4(byte[] src, int srcOff, int srcLen, byte[] dst, int dstOff, int dstLen) throws IOException {
        int ip = srcOff;
        int op = dstOff;
        int ipEnd = srcOff + srcLen;
        int opEnd = dstOff + dstLen;

        while (ip < ipEnd && op < opEnd) {
            int token = src[ip++] & 0xFF;
            int litLen = token >>> 4;

            if (litLen == 15) {
                int s;
                do {
                    if (ip >= ipEnd) throw new IOException("Malformed LZ4 stream: unexpected EOF in literal length");
                    s = src[ip++] & 0xFF;
                    litLen += s;
                } while (s == 255);
            }

            if (op + litLen > opEnd || ip + litLen > ipEnd) {
                throw new IOException("Malformed LZ4 stream: literal overrun");
            }
            System.arraycopy(src, ip, dst, op, litLen);
            ip += litLen;
            op += litLen;

            if (ip >= ipEnd || op >= opEnd) {
                break;
            }

            // Match offset
            if (ip + 2 > ipEnd) throw new IOException("Malformed LZ4 stream: unexpected EOF in match offset");
            int offset = (src[ip++] & 0xFF) | ((src[ip++] & 0xFF) << 8);
            if (offset == 0) throw new IOException("Malformed LZ4 stream: 0 offset invalid");

            int matchLen = (token & 0x0F) + 4;
            if ((token & 0x0F) == 15) {
                int s;
                do {
                    if (ip >= ipEnd) throw new IOException("Malformed LZ4 stream: unexpected EOF in match length");
                    s = src[ip++] & 0xFF;
                    matchLen += s;
                } while (s == 255);
            }

            int matchPos = op - offset;
            if (matchPos < dstOff || op + matchLen > opEnd) {
                throw new IOException("Malformed LZ4 stream: match copy overrun");
            }

            for (int i = 0; i < matchLen; i++) {
                dst[op++] = dst[matchPos + i];
            }
        }

        return op - dstOff;
    }

    // =========================================================================
    // Deflate & Zstd Fallback Implementation
    // =========================================================================

    public static byte[] compressDeflate(byte[] src, int srcOff, int srcLen) {
        Deflater deflater = new Deflater(Deflater.BEST_SPEED, true); // raw deflate
        deflater.setInput(src, srcOff, srcLen);
        deflater.finish();
        byte[] buffer = new byte[srcLen + 64];
        ByteArrayOutputStream baos = new ByteArrayOutputStream(srcLen);
        while (!deflater.finished()) {
            int count = deflater.deflate(buffer);
            baos.write(buffer, 0, count);
        }
        deflater.end();
        return baos.toByteArray();
    }

    public static int decompressDeflate(byte[] src, int srcOff, int srcLen, byte[] dst, int dstOff, int dstLen) throws IOException {
        Inflater inflater = new Inflater(true);
        inflater.setInput(src, srcOff, srcLen);
        try {
            int result = inflater.inflate(dst, dstOff, dstLen);
            inflater.end();
            return result;
        } catch (Exception e) {
            inflater.end();
            throw new IOException("Deflate decompression error", e);
        }
    }

    private static byte[] compressZstdOrFallback(byte[] src, int srcOff, int srcLen) throws IOException {
        // Try commons-compress Zstandard if available, else compress with Deflate
        try {
            Class<?> zstdClass = Class.forName("org.apache.commons.compress.compressors.zstandard.ZstdCompressorOutputStream");
            ByteArrayOutputStream baos = new ByteArrayOutputStream(srcLen);
            java.io.OutputStream zstdOut = (java.io.OutputStream) zstdClass.getConstructor(java.io.OutputStream.class).newInstance(baos);
            zstdOut.write(src, srcOff, srcLen);
            zstdOut.close();
            return baos.toByteArray();
        } catch (Throwable t) {
            // High compression fallback
            Deflater deflater = new Deflater(Deflater.BEST_COMPRESSION, true);
            deflater.setInput(src, srcOff, srcLen);
            deflater.finish();
            byte[] buf = new byte[srcLen + 64];
            ByteArrayOutputStream baos = new ByteArrayOutputStream(srcLen);
            while (!deflater.finished()) {
                int count = deflater.deflate(buf);
                baos.write(buf, 0, count);
            }
            deflater.end();
            return baos.toByteArray();
        }
    }

    private static byte[] decompressZstdOrFallback(byte[] src, int srcOff, int srcLen, int expectedOrigLen) throws IOException {
        try {
            Class<?> zstdClass = Class.forName("org.apache.commons.compress.compressors.zstandard.ZstdCompressorInputStream");
            ByteArrayInputStream bais = new ByteArrayInputStream(src, srcOff, srcLen);
            java.io.InputStream zstdIn = (java.io.InputStream) zstdClass.getConstructor(java.io.InputStream.class).newInstance(bais);
            byte[] output = new byte[expectedOrigLen];
            int read = 0;
            while (read < expectedOrigLen) {
                int r = zstdIn.read(output, read, expectedOrigLen - read);
                if (r == -1) break;
                read += r;
            }
            zstdIn.close();
            return output;
        } catch (Throwable t) {
            byte[] output = new byte[expectedOrigLen];
            decompressDeflate(src, srcOff, srcLen, output, 0, expectedOrigLen);
            return output;
        }
    }
}
