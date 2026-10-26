#!/usr/bin/env python3
"""
SuperGhidra Reproducible Benchmark Runner
=========================================
Runs verifiable performance micro-benchmarks on the local machine using
redistributable sample binaries and synthetic database pages.

Usage:
    python scripts/reproduce_benchmarks.py
    python scripts/reproduce_benchmarks.py --json
"""

from __future__ import annotations

import argparse
import json
import os
import platform
import sys
import time

# Ensure project root is in sys.path
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, os.path.join(PROJECT_ROOT, "src"))
    sys.path.insert(0, PROJECT_ROOT)

from superghidra.core.compilable_filter import CompilableDecompilerFilter
from superghidra.formats.binary_loader import load_binary
from superghidra.acceleration.gpu_adrp_scanner import GPUAdrpScanner
from superghidra.storage.storage_compression_prototype import StorageCompressionBenchmark


def get_sample_binary_paths() -> tuple[str, str]:
    fixtures_dir = os.path.join(PROJECT_ROOT, "tests", "fixtures", "binaries")
    arm64_so = os.path.join(fixtures_dir, "sample_arm64.so")
    x64_dll = os.path.join(fixtures_dir, "sample_x64.dll")
    return arm64_so, x64_dll


def benchmark_binary_loader(filepath: str, iterations: int = 50) -> dict:
    with open(filepath, "rb") as f:
        file_size = len(f.read())

    t0 = time.perf_counter()
    for _ in range(iterations):
        load_binary(filepath)
    elapsed = time.perf_counter() - t0

    avg_ms = (elapsed / iterations) * 1000.0
    throughput_mb_s = ((file_size * iterations) / (1024 * 1024)) / elapsed if elapsed > 0 else 0.0

    return {
        "file": os.path.basename(filepath),
        "file_size_bytes": file_size,
        "iterations": iterations,
        "avg_latency_ms": round(avg_ms, 3),
        "throughput_mb_s": round(throughput_mb_s, 2),
    }


def benchmark_compilable_filter(iterations: int = 200) -> dict:
    sample_code = """
    // Unresolved decompilation fragment with Ghidra quirks
    undefined4 entry(int param_1, undefined8 param_2) {
        int iVar1;
        code *pcVar2;
        in_FS_OFFSET;
        DAT_00401000 = param_1;
        if (param_1 == 0) {
            halt_baddata();
        }
        pcVar2 = (code *)swi(3);
        (*pcVar2)();
        return 0;
    }
    """
    code_bytes = len(sample_code.encode("utf-8"))
    c_filter = CompilableDecompilerFilter()

    t0 = time.perf_counter()
    for _ in range(iterations):
        c_filter.filter(sample_code)
    elapsed = time.perf_counter() - t0

    avg_ms = (elapsed / iterations) * 1000.0
    throughput_kb_s = ((code_bytes * iterations) / 1024.0) / elapsed if elapsed > 0 else 0.0

    return {
        "benchmark": "CompilableDecompilerFilter",
        "code_size_bytes": code_bytes,
        "iterations": iterations,
        "avg_latency_ms": round(avg_ms, 3),
        "throughput_kb_s": round(throughput_kb_s, 2),
    }


def benchmark_adrp_scanner(arm64_path: str, iterations: int = 100) -> dict:
    with open(arm64_path, "rb") as f:
        payload = f.read()

    scanner = GPUAdrpScanner(backend="numpy")
    t0 = time.perf_counter()
    for _ in range(iterations):
        scanner.scan_matches(payload, base_pc=0x100000)
    elapsed = time.perf_counter() - t0

    avg_ms = (elapsed / iterations) * 1000.0
    throughput_mb_s = ((len(payload) * iterations) / (1024 * 1024)) / elapsed if elapsed > 0 else 0.0

    return {
        "benchmark": "ARM64_ADRP_Scanner",
        "buffer_size_bytes": len(payload),
        "iterations": iterations,
        "avg_latency_ms": round(avg_ms, 3),
        "throughput_mb_s": round(throughput_mb_s, 2),
    }


def benchmark_storage_compression(num_pages: int = 50) -> dict:
    res = StorageCompressionBenchmark.run_comparison(num_pages=num_pages)
    lz4_res, zstd_res = res
    return {
        "benchmark": "StorageCompression",
        "pages": num_pages,
        "raw_size_bytes": lz4_res.orig_total_bytes,
        "lz4_ratio": round(lz4_res.compression_ratio, 3),
        "lz4_throughput_mb_s": round(lz4_res.compress_mb_per_sec, 2),
        "zstd_ratio": round(zstd_res.compression_ratio, 3),
        "zstd_throughput_mb_s": round(zstd_res.compress_mb_per_sec, 2),
    }


def main():
    parser = argparse.ArgumentParser(description="Reproduce SuperGhidra Micro-Benchmarks")
    parser.add_argument("--json", action="store_true", help="Output results as JSON")
    parser.add_argument("--pages", type=int, default=50, help="Number of pages for storage benchmark")
    args = parser.parse_args()

    arm64_so, x64_dll = get_sample_binary_paths()

    results = {
        "environment": {
            "os": platform.platform(),
            "cpu": platform.processor() or platform.machine(),
            "python": platform.python_version(),
        },
        "benchmarks": {
            "loader_arm64": benchmark_binary_loader(arm64_so),
            "loader_x64": benchmark_binary_loader(x64_dll),
            "compilable_filter": benchmark_compilable_filter(),
            "adrp_scanner": benchmark_adrp_scanner(arm64_so),
            "storage_compression": benchmark_storage_compression(num_pages=args.pages),
        },
    }

    if args.json:
        print(json.dumps(results, indent=2))
        return

    print("=" * 70)
    print("SuperGhidra Reproducible Benchmark Summary")
    print("=" * 70)
    print(f"OS:      {results['environment']['os']}")
    print(f"CPU:     {results['environment']['cpu']}")
    print(f"Python:  {results['environment']['python']}")
    print("-" * 70)
    print(f"{'Benchmark':<30} {'Latency (ms)':<15} {'Throughput':<20}")
    print("-" * 70)

    b_loader_arm = results["benchmarks"]["loader_arm64"]
    print(f"{'Loader (sample_arm64.so)':<30} {b_loader_arm['avg_latency_ms']:<15.3f} {b_loader_arm['throughput_mb_s']} MB/s")

    b_loader_x64 = results["benchmarks"]["loader_x64"]
    print(f"{'Loader (sample_x64.dll)':<30} {b_loader_x64['avg_latency_ms']:<15.3f} {b_loader_x64['throughput_mb_s']} MB/s")

    b_filter = results["benchmarks"]["compilable_filter"]
    print(f"{'Compilable C Filter':<30} {b_filter['avg_latency_ms']:<15.3f} {b_filter['throughput_kb_s']} KB/s")

    b_adrp = results["benchmarks"]["adrp_scanner"]
    print(f"{'ADRP Scanner':<30} {b_adrp['avg_latency_ms']:<15.3f} {b_adrp['throughput_mb_s']} MB/s")

    b_storage = results["benchmarks"]["storage_compression"]
    print(f"{'Storage LZ4 (50 pages)':<30} {'ratio: ' + str(b_storage['lz4_ratio']):<15} {b_storage['lz4_throughput_mb_s']} MB/s")
    print(f"{'Storage Zstd (50 pages)':<30} {'ratio: ' + str(b_storage['zstd_ratio']):<15} {b_storage['zstd_throughput_mb_s']} MB/s")
    print("=" * 70)


if __name__ == "__main__":
    main()
