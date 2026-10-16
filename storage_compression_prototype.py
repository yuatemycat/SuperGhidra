#!/usr/bin/env python3
"""SuperGhidra Storage Compression Layer Prototype.

Demonstrates transparent compression interception for Ghidra buffer pages
(simulating LocalManagedBufferFile.get() and put()), evaluating:
  1. LZ4 (in-flight fast buffer compression for working sessions)
  2. Zstandard Level 3 (snapshot / repository commit compression)

Implements the 64-bit slot directory index format:
  [block_id: uint32, offset: uint64, comp_len: uint32, orig_len: uint32]
"""

from __future__ import annotations

import argparse
import io
import os
import random
import string
import struct
import sys
import time
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

import lz4.block
import zstandard as zstd

# Ghidra Buffer Constants
GHIDRA_BUFFER_SIZE = 16384  # 16 KB payload
GHIDRA_HEADER_SIZE = 5      # 1 byte flags (EMPTY_BUFFER=0x01) + 4 bytes buffer ID
GHIDRA_BLOCK_SIZE = GHIDRA_BUFFER_SIZE + GHIDRA_HEADER_SIZE  # 16389 bytes
FLAG_EMPTY_BUFFER = 0x01

# Slot Directory Entry: [block_id: uint32, offset: uint64, comp_len: uint32, orig_len: uint32]
# Binary layout: Little-endian <I Q I I (20 bytes per slot entry)
SLOT_ENTRY_STRUCT = struct.Struct("<IQII")
SLOT_ENTRY_SIZE = SLOT_ENTRY_STRUCT.size  # 20 bytes


@dataclass
class SlotDirectoryEntry:
    """Represents an index entry in the 64-bit slot directory."""
    block_id: int   # uint32
    offset: int     # uint64
    comp_len: int   # uint32
    orig_len: int   # uint32

    def pack(self) -> bytes:
        return SLOT_ENTRY_STRUCT.pack(self.block_id, self.offset, self.comp_len, self.orig_len)

    @classmethod
    def unpack(cls, data: bytes) -> SlotDirectoryEntry:
        block_id, offset, comp_len, orig_len = SLOT_ENTRY_STRUCT.unpack(data)
        return cls(block_id=block_id, offset=offset, comp_len=comp_len, orig_len=orig_len)


class DataBuffer:
    """Python representation of Ghidra's db.buffers.DataBuffer."""

    def __init__(self, buffer_id: int = -1, data: Optional[bytearray] = None, empty: bool = False):
        self.buffer_id: int = buffer_id
        self.empty: bool = empty
        self.dirty: bool = False
        if data is None:
            self.data = bytearray(GHIDRA_BUFFER_SIZE)
        else:
            if len(data) != GHIDRA_BUFFER_SIZE:
                raise ValueError(f"Data buffer size must be {GHIDRA_BUFFER_SIZE}, got {len(data)}")
            self.data = bytearray(data)

    def serialize(self) -> bytes:
        """Serializes to Ghidra LocalBufferFile block layout (flags + id + data)."""
        flags = FLAG_EMPTY_BUFFER if self.empty else 0x00
        header = struct.pack(">Bi", flags, self.buffer_id)
        if self.empty:
            return header
        return header + bytes(self.data)

    @classmethod
    def deserialize(cls, raw: bytes) -> DataBuffer:
        """Deserializes from Ghidra LocalBufferFile block layout."""
        if len(raw) < GHIDRA_HEADER_SIZE:
            raise ValueError(f"Corrupt block: expected at least {GHIDRA_HEADER_SIZE} bytes, got {len(raw)}")
        flags, buf_id = struct.unpack(">Bi", raw[:GHIDRA_HEADER_SIZE])
        empty = (flags & FLAG_EMPTY_BUFFER) != 0
        if empty:
            return cls(buffer_id=buf_id, data=None, empty=True)
        payload = raw[GHIDRA_HEADER_SIZE:GHIDRA_HEADER_SIZE + GHIDRA_BUFFER_SIZE]
        if len(payload) < GHIDRA_BUFFER_SIZE:
            payload = payload.ljust(GHIDRA_BUFFER_SIZE, b"\x00")
        return cls(buffer_id=buf_id, data=bytearray(payload), empty=False)


class SlotDirectory:
    """Manages the 64-bit slot directory index for random access to compressed buffer blocks."""

    def __init__(self):
        self._entries: Dict[int, SlotDirectoryEntry] = {}

    def set_entry(self, entry: SlotDirectoryEntry) -> None:
        self._entries[entry.block_id] = entry

    def get_entry(self, block_id: int) -> Optional[SlotDirectoryEntry]:
        return self._entries.get(block_id)

    def __len__(self) -> int:
        return len(self._entries)

    def serialize(self) -> bytes:
        """Serializes all slot directory entries into contiguous 20-byte records."""
        buf = io.BytesIO()
        for block_id in sorted(self._entries.keys()):
            buf.write(self._entries[block_id].pack())
        return buf.getvalue()

    @classmethod
    def deserialize(cls, data: bytes) -> SlotDirectory:
        """Deserializes a contiguous byte sequence into a SlotDirectory."""
        directory = cls()
        num_entries = len(data) // SLOT_ENTRY_SIZE
        for i in range(num_entries):
            chunk = data[i * SLOT_ENTRY_SIZE : (i + 1) * SLOT_ENTRY_SIZE]
            entry = SlotDirectoryEntry.unpack(chunk)
            directory.set_entry(entry)
        return directory


class CompressedLocalManagedBufferFile:
    """Compressed buffer file implementing interception of get() and put()

    Simulates LocalManagedBufferFile with LZ4 or ZSTD storage backend.
    """

    FILE_MAGIC = b"SGDB"  # SuperGhidra DataBase
    VERSION = 1
    CODEC_LZ4 = 1
    CODEC_ZSTD_L3 = 2

    def __init__(self, backing_stream: Optional[io.BytesIO] = None, codec: str = "lz4"):
        self.stream = backing_stream if backing_stream is not None else io.BytesIO()
        self.codec = codec.lower()
        if self.codec not in ("lz4", "zstd"):
            raise ValueError(f"Unsupported codec: {codec}. Must be 'lz4' or 'zstd'")
        self.slot_directory = SlotDirectory()
        self.zstd_cctx = zstd.ZstdCompressor(level=3)
        self.zstd_dctx = zstd.ZstdDecompressor()
        self._init_header()

    def _init_header(self) -> None:
        """Writes initial container header if stream is empty."""
        if self.stream.tell() == 0 and len(self.stream.getvalue()) == 0:
            codec_id = self.CODEC_LZ4 if self.codec == "lz4" else self.CODEC_ZSTD_L3
            # Header: MAGIC(4B) + VERSION(2B) + CODEC(2B) + DIR_OFFSET(8B) + DIR_COUNT(4B) + RESERVED(12B) = 32B
            header = struct.pack("<4sHHQI12s", self.FILE_MAGIC, self.VERSION, codec_id, 0, 0, b"\x00" * 12)
            self.stream.write(header)

    def _compress(self, raw_bytes: bytes) -> bytes:
        if self.codec == "lz4":
            return lz4.block.compress(raw_bytes, store_size=False)
        else:
            return self.zstd_cctx.compress(raw_bytes)

    def _decompress(self, comp_bytes: bytes, orig_len: int) -> bytes:
        if self.codec == "lz4":
            return lz4.block.decompress(comp_bytes, uncompressed_size=orig_len)
        else:
            return self.zstd_dctx.decompress(comp_bytes, max_output_size=orig_len)

    def put(self, buf: DataBuffer, index: int) -> None:
        """Intercepts LocalManagedBufferFile.put(DataBuffer buf, int index).

        Compresses buffer page in-flight, writes to stream, updates 64-bit slot index.
        """
        raw_bytes = buf.serialize()
        comp_bytes = self._compress(raw_bytes)

        # Append compressed block to stream
        self.stream.seek(0, io.SEEK_END)
        offset = self.stream.tell()
        self.stream.write(comp_bytes)

        # Update slot directory
        entry = SlotDirectoryEntry(
            block_id=index,
            offset=offset,
            comp_len=len(comp_bytes),
            orig_len=len(raw_bytes)
        )
        self.slot_directory.set_entry(entry)
        buf.dirty = False

    def get(self, buf: Optional[DataBuffer], index: int) -> DataBuffer:
        """Intercepts LocalManagedBufferFile.get(DataBuffer buf, int index).

        Looks up slot directory entry, seeks to 64-bit offset, decompresses block.
        """
        entry = self.slot_directory.get_entry(index)
        if entry is None:
            raise KeyError(f"Buffer block index {index} not found in slot directory")

        self.stream.seek(entry.offset, io.SEEK_SET)
        comp_bytes = self.stream.read(entry.comp_len)
        if len(comp_bytes) != entry.comp_len:
            raise IOError(f"Short read at offset {entry.offset}: expected {entry.comp_len}, got {len(comp_bytes)}")

        raw_bytes = self._decompress(comp_bytes, entry.orig_len)
        restored = DataBuffer.deserialize(raw_bytes)
        if buf is not None:
            buf.buffer_id = restored.buffer_id
            buf.empty = restored.empty
            buf.data = restored.data
            buf.dirty = False
            return buf
        return restored

    def finalize_file(self) -> int:
        """Writes the slot directory to the end of stream and updates header."""
        self.stream.seek(0, io.SEEK_END)
        dir_offset = self.stream.tell()
        dir_bytes = self.slot_directory.serialize()
        self.stream.write(dir_bytes)
        dir_count = len(self.slot_directory)

        # Update directory offset in header
        codec_id = self.CODEC_LZ4 if self.codec == "lz4" else self.CODEC_ZSTD_L3
        self.stream.seek(0, io.SEEK_SET)
        header = struct.pack("<4sHHQI12s", self.FILE_MAGIC, self.VERSION, codec_id, dir_offset, dir_count, b"\x00" * 12)
        self.stream.write(header)
        self.stream.seek(0, io.SEEK_END)
        return self.stream.tell()


class GhidraPageSimulator:
    """Synthesizes authentic Ghidra database 16 KB B-tree pages."""

    @staticmethod
    def generate_sparse_symbol_table_page(seed: int, fullness: float = 0.55) -> bytearray:
        """Generates a 16 KB B-tree leaf node storing Ghidra symbol records.

        Contains monotonically increasing address keys, namespace IDs, symbol names,
        and trailing slack space (zero-padding).
        """
        rng = random.Random(seed)
        buf = bytearray(GHIDRA_BUFFER_SIZE)

        # B-tree Node Header (32 bytes)
        # [type: uint8 (0x02=leaf), key_count: uint16, free_offset: uint16, next_leaf: int32, prev_leaf: int32]
        struct.pack_into(">BHHii18s", buf, 0, 0x02, 0, 32, -1, -1, b"\x00" * 18)

        symbols = [
            "FUN_", "DAT_", "s_Str_", "PTR_FUN_", "switchTable_",
            "_ZN7System", "_ZN10GhidraCore", "thunk_FUN_", "lab_", "sub_"
        ]

        offset = 32
        key_count = 0
        base_addr = 0x00401000 + (seed * 0x10000)
        target_bytes = int(GHIDRA_BUFFER_SIZE * fullness)

        while offset + 48 < target_bytes:
            addr = base_addr + (key_count * rng.randint(8, 64))
            namespace_id = rng.choice([0, 1, 100, 2048])
            sym_prefix = rng.choice(symbols)
            sym_name = f"{sym_prefix}{addr:08x}_{rng.randint(10, 99)}"
            name_bytes = sym_name.encode("ascii")

            # Entry layout: addr (8B), namespace_id (4B), sym_type (1B), name_len (1B), name, zero_pad
            entry_header = struct.pack(">QIBB", addr, namespace_id, 0x01, len(name_bytes))
            entry_data = entry_header + name_bytes
            buf[offset : offset + len(entry_data)] = entry_data
            offset += len(entry_data)
            key_count += 1

        # Update node header with actual key count and free offset
        struct.pack_into(">H", buf, 1, key_count)
        struct.pack_into(">H", buf, 3, offset)
        return buf

    @staticmethod
    def generate_xref_table_page(seed: int, fullness: float = 0.60) -> bytearray:
        """Generates a 16 KB B-tree node containing cross references (XRefs).

        Highly clustered target addresses, standard reference types, and zero padding.
        """
        rng = random.Random(seed)
        buf = bytearray(GHIDRA_BUFFER_SIZE)

        # Header: type (0x04=xref), count, free_offset
        struct.pack_into(">BHHii18s", buf, 0, 0x04, 0, 32, -1, -1, b"\x00" * 18)

        # Clustered target addresses simulating library calls and global buffers
        hot_targets = [
            0x00405000, 0x00405020, 0x00408100, 0x00410000,
            0x00420000, 0x004351a0, 0x00451000, 0x00490000
        ]

        offset = 32
        ref_count = 0
        base_from = 0x00401000 + (seed * 0x8000)
        target_bytes = int(GHIDRA_BUFFER_SIZE * fullness)

        while offset + 18 <= target_bytes:
            from_addr = base_from + (ref_count * rng.randint(4, 32))
            to_addr = rng.choice(hot_targets) if rng.random() < 0.75 else (base_from + rng.randint(0, 0x20000))
            ref_type = rng.choice([1, 2, 3, 5, 8])  # READ, WRITE, CALL, DATA, UNCOND_JUMP
            op_index = rng.choice([0, 1])

            # Entry: from_addr (8B), to_addr (8B), ref_type (1B), op_index (1B) = 18B
            struct.pack_into(">QQBB", buf, offset, from_addr, to_addr, ref_type, op_index)
            offset += 18
            ref_count += 1

        struct.pack_into(">H", buf, 1, ref_count)
        struct.pack_into(">H", buf, 3, offset)
        return buf

    @staticmethod
    def generate_zero_padded_page(seed: int, zero_ratio: float = 0.94) -> bytearray:
        """Generates a 16 KB page simulating free-list or preallocated buffer blocks."""
        rng = random.Random(seed)
        buf = bytearray(GHIDRA_BUFFER_SIZE)

        # Small 16-byte free-list chain header
        next_free = seed + 1
        free_count = rng.randint(10, 50)
        struct.pack_into(">iiQI", buf, 0, next_free, free_count, 0xDEADBEEF, 0)

        # Sparse metadata entries taking up (1 - zero_ratio)
        active_bytes = int(GHIDRA_BUFFER_SIZE * (1.0 - zero_ratio))
        for i in range(16, active_bytes, 8):
            struct.pack_into(">II", buf, i, rng.randint(0, 0xFFFF), rng.randint(0, 0xFF))

        # Rest remains clean zeroes
        return buf

    @classmethod
    def generate_database_corpus(cls, num_pages: int = 1000, seed: int = 42) -> List[DataBuffer]:
        """Synthesizes a realistic corpus of Ghidra database buffer pages.

        Composition:
          - 35% Sparse Symbol Table pages
          - 35% XRef Table pages
          - 30% Zero-Padded / Free-list pages
        """
        rng = random.Random(seed)
        buffers: List[DataBuffer] = []

        for idx in range(num_pages):
            roll = rng.random()
            page_seed = seed + idx

            if roll < 0.35:
                raw_data = cls.generate_sparse_symbol_table_page(page_seed, fullness=rng.uniform(0.45, 0.65))
            elif roll < 0.70:
                raw_data = cls.generate_xref_table_page(page_seed, fullness=rng.uniform(0.50, 0.70))
            else:
                raw_data = cls.generate_zero_padded_page(page_seed, zero_ratio=rng.uniform(0.90, 0.98))

            buf = DataBuffer(buffer_id=idx, data=raw_data, empty=False)
            buffers.append(buf)

        return buffers


@dataclass
class BenchmarkResult:
    codec: str
    num_pages: int
    orig_total_bytes: int
    comp_total_bytes: int
    reduction_pct: float
    compression_ratio: float
    compress_time_sec: float
    decompress_time_sec: float
    compress_mb_per_sec: float
    decompress_mb_per_sec: float
    avg_comp_latency_us: float
    avg_decomp_latency_us: float
    slot_index_bytes: int
    verified_lossless: bool


class StorageCompressionBenchmark:
    """Benchmarks LZ4 vs Zstandard L3 on Ghidra buffer pages."""

    @staticmethod
    def run_codec_benchmark(corpus: List[DataBuffer], codec: str) -> BenchmarkResult:
        stream = io.BytesIO()
        backend = CompressedLocalManagedBufferFile(backing_stream=stream, codec=codec)

        # 1. Benchmark Compression (put interception)
        num_pages = len(corpus)
        orig_total_bytes = sum(len(b.serialize()) for b in corpus)

        t0 = time.perf_counter()
        for idx, buf in enumerate(corpus):
            backend.put(buf, idx)
        t1 = time.perf_counter()
        comp_time = t1 - t0

        final_file_size = backend.finalize_file()
        slot_index_bytes = len(backend.slot_directory.serialize())
        comp_total_bytes = stream.tell() - 32 - slot_index_bytes  # Pure payload bytes

        # 2. Benchmark Decompression (get interception)
        t2 = time.perf_counter()
        restored_buffers: List[DataBuffer] = []
        for idx in range(num_pages):
            restored = backend.get(None, idx)
            restored_buffers.append(restored)
        t3 = time.perf_counter()
        decomp_time = t3 - t2

        # 3. Verify Lossless Fidelity
        verified = True
        for idx, (orig, rest) in enumerate(zip(corpus, restored_buffers)):
            if orig.buffer_id != rest.buffer_id or orig.data != rest.data:
                verified = False
                break

        reduction_pct = (1.0 - (comp_total_bytes / orig_total_bytes)) * 100.0
        ratio = orig_total_bytes / comp_total_bytes if comp_total_bytes > 0 else 0.0
        orig_mb = orig_total_bytes / (1024 * 1024)

        comp_mb_s = orig_mb / comp_time if comp_time > 0 else 0.0
        decomp_mb_s = orig_mb / decomp_time if decomp_time > 0 else 0.0
        avg_comp_lat_us = (comp_time / num_pages) * 1_000_000
        avg_decomp_lat_us = (decomp_time / num_pages) * 1_000_000

        return BenchmarkResult(
            codec=codec.upper(),
            num_pages=num_pages,
            orig_total_bytes=orig_total_bytes,
            comp_total_bytes=comp_total_bytes,
            reduction_pct=reduction_pct,
            compression_ratio=ratio,
            compress_time_sec=comp_time,
            decompress_time_sec=decomp_time,
            compress_mb_per_sec=comp_mb_s,
            decompress_mb_per_sec=decomp_mb_s,
            avg_comp_latency_us=avg_comp_lat_us,
            avg_decomp_latency_us=avg_decomp_lat_us,
            slot_index_bytes=slot_index_bytes,
            verified_lossless=verified
        )

    @classmethod
    def run_comparison(cls, num_pages: int = 1000, seed: int = 42) -> Tuple[BenchmarkResult, BenchmarkResult]:
        print(f"[*] Generating Ghidra DB synthetic corpus: {num_pages} pages ({num_pages * 16 / 1024:.2f} MB)...")
        corpus = GhidraPageSimulator.generate_database_corpus(num_pages=num_pages, seed=seed)

        print(f"[*] Running LZ4 (In-Flight Buffer Compression) benchmark...")
        res_lz4 = cls.run_codec_benchmark(corpus, codec="lz4")

        print(f"[*] Running Zstandard Level 3 (Snapshot Compression) benchmark...")
        res_zstd = cls.run_codec_benchmark(corpus, codec="zstd")

        return res_lz4, res_zstd

    @staticmethod
    def print_report(res_lz4: BenchmarkResult, res_zstd: BenchmarkResult) -> str:
        orig_mb = res_lz4.orig_total_bytes / (1024 * 1024)
        lz4_mb = res_lz4.comp_total_bytes / (1024 * 1024)
        zstd_mb = res_zstd.comp_total_bytes / (1024 * 1024)

        report = []
        report.append("=" * 78)
        report.append(" SUPERGHIDRA STORAGE COMPRESSION LAYER BENCHMARK REPORT")
        report.append(" 16 KB Buffer Interception & 64-bit Slot Directory Format")
        report.append("=" * 78)
        report.append(f" Corpus Pages:        {res_lz4.num_pages:,} Ghidra B-Tree pages (16 KB each)")
        report.append(f" Raw Database Size:   {orig_mb:.2f} MB ({res_lz4.orig_total_bytes:,} bytes)")
        report.append(f" Slot Entry Format:   [block_id: uint32, offset: uint64, comp_len: uint32, orig_len: uint32]")
        report.append(f" Slot Entry Size:     {SLOT_ENTRY_SIZE} bytes / page ({res_lz4.slot_index_bytes:,} bytes total)")
        report.append("-" * 78)
        report.append(f"{'Metric':<32} | {'LZ4 (In-Flight)':<20} | {'ZSTD Level 3 (Snapshot)':<20}")
        report.append("-" * 78)
        report.append(f"{'Compressed Size':<32} | {lz4_mb:>16.2f} MB | {zstd_mb:>16.2f} MB")
        report.append(f"{'Reduction Percentage (Target > 75%)':<32} | {res_lz4.reduction_pct:>19.2f}% | {res_zstd.reduction_pct:>19.2f}%")
        report.append(f"{'Compression Ratio':<32} | {res_lz4.compression_ratio:>18.2f}x | {res_zstd.compression_ratio:>18.2f}x")
        report.append(f"{'Compression Throughput':<32} | {res_lz4.compress_mb_per_sec:>14.2f} MB/s | {res_zstd.compress_mb_per_sec:>14.2f} MB/s")
        report.append(f"{'Decompression Throughput':<32} | {res_lz4.decompress_mb_per_sec:>14.2f} MB/s | {res_zstd.decompress_mb_per_sec:>14.2f} MB/s")
        report.append(f"{'Avg Page Comp Latency':<32} | {res_lz4.avg_comp_latency_us:>17.2f} us | {res_zstd.avg_comp_latency_us:>17.2f} us")
        report.append(f"{'Avg Page Decomp Latency':<32} | {res_lz4.avg_decomp_latency_us:>17.2f} us | {res_zstd.avg_decomp_latency_us:>17.2f} us")
        report.append(f"{'Round-Trip Lossless Fidelity':<32} | {str(res_lz4.verified_lossless):>20} | {str(res_zstd.verified_lossless):>20}")
        report.append("=" * 78)

        target_met_lz4 = "PASS (Met > 75%)" if res_lz4.reduction_pct >= 75.0 else "FAIL (< 75%)"
        target_met_zstd = "PASS (Met > 75%)" if res_zstd.reduction_pct >= 75.0 else "FAIL (< 75%)"
        report.append(f" Target Verification:")
        report.append(f"   - LZ4 Reduction > 75%:    {res_lz4.reduction_pct:.2f}% -> {target_met_lz4}")
        report.append(f"   - ZSTD Reduction > 75%:   {res_zstd.reduction_pct:.2f}% -> {target_met_zstd}")
        report.append("=" * 78)

        out_text = "\n".join(report)
        print(out_text)
        return out_text


def main():
    parser = argparse.ArgumentParser(description="SuperGhidra Storage Compression Layer Prototype")
    parser.add_argument("--pages", type=int, default=1000, help="Number of 16 KB Ghidra pages to simulate (default: 1000)")
    parser.add_argument("--seed", type=int, default=42, help="Random seed for deterministic reproducibility")
    parser.add_argument("--export-report", type=str, default="", help="File path to save the text benchmark report")
    args = parser.parse_args()

    res_lz4, res_zstd = StorageCompressionBenchmark.run_comparison(num_pages=args.pages, seed=args.seed)
    report_text = StorageCompressionBenchmark.print_report(res_lz4, res_zstd)

    if args.export_report:
        os.makedirs(os.path.dirname(os.path.abspath(args.export_report)), exist_ok=True)
        with open(args.export_report, "w", encoding="utf-8") as f:
            f.write(report_text)
        print(f"[*] Report exported to {args.export_report}")


if __name__ == "__main__":
    main()
