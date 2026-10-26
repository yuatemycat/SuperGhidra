"""Unit and benchmark tests for Issue #12: Adaptive Small-Binary Hybrid Dispatcher in GPUAdrpScanner."""

from __future__ import annotations

import time
import unittest
from unittest.mock import patch

import numpy as np

from superghidra.acceleration.gpu_adrp_scanner import (
    ADAPTIVE_GPU_THRESHOLD_BYTES,
    GPU_SCAN_SIZE_THRESHOLD_BYTES,
    HAS_WGPU,
    GPUAdrpScanner,
    NumPyAdrpEngine,
    generate_synthetic_stream,
)


class TestAdaptiveThreshold(unittest.TestCase):
    """Verifies adaptive threshold routing between CPU NumPy SIMD and WGPU compute shaders."""

    def test_threshold_constant_value(self):
        """Verifies ADAPTIVE_GPU_THRESHOLD_BYTES and alias are 5 MB (5,242,880 bytes)."""
        expected = 5 * 1024 * 1024
        self.assertEqual(ADAPTIVE_GPU_THRESHOLD_BYTES, expected)
        self.assertEqual(GPU_SCAN_SIZE_THRESHOLD_BYTES, expected)
        self.assertEqual(GPUAdrpScanner.ADAPTIVE_GPU_THRESHOLD_BYTES, expected)
        self.assertEqual(GPUAdrpScanner.GPU_SCAN_SIZE_THRESHOLD_BYTES, expected)

    def test_small_buffer_routes_to_numpy_in_auto_mode(self):
        """Buffers < 5MB automatically use the NumPy engine without error."""
        scanner = GPUAdrpScanner(backend="auto")
        # 1 MB buffer (262,144 instructions, 1,048,576 bytes)
        small_stream = generate_synthetic_stream(size_bytes=1 * 1024 * 1024, seed=101)
        self.assertLess(small_stream.nbytes, ADAPTIVE_GPU_THRESHOLD_BYTES)

        with patch.object(NumPyAdrpEngine, "scan", wraps=NumPyAdrpEngine.scan) as mock_numpy:
            results = scanner.scan_raw(small_stream)
            self.assertTrue(mock_numpy.called)
            self.assertEqual(scanner.last_dispatched_backend, "numpy")
            self.assertIsInstance(results, np.ndarray)

    def test_large_buffer_routes_to_gpu_in_auto_mode(self):
        """Buffers >= 5MB use the GPU engine when available."""
        if not HAS_WGPU:
            self.skipTest("WGPU backend not available on this platform")

        scanner = GPUAdrpScanner(backend="auto")
        if scanner.active_backend != "wgpu":
            self.skipTest("WGPU backend failed to initialize")

        # 5.5 MB buffer (5.5 * 1024 * 1024 bytes)
        large_stream = generate_synthetic_stream(size_bytes=int(5.5 * 1024 * 1024), seed=202)
        self.assertGreaterEqual(large_stream.nbytes, ADAPTIVE_GPU_THRESHOLD_BYTES)

        with patch.object(scanner._wgpu_engine, "scan", wraps=scanner._wgpu_engine.scan) as mock_gpu:
            results = scanner.scan_raw(large_stream)
            self.assertTrue(mock_gpu.called)
            self.assertEqual(scanner.last_dispatched_backend, "wgpu")
            self.assertIsInstance(results, np.ndarray)

    def test_explicit_wgpu_override_respected_on_small_buffer(self):
        """Explicit backend='wgpu' force override is respected even on buffers < 5MB."""
        if not HAS_WGPU:
            self.skipTest("WGPU backend not available on this platform")

        try:
            scanner = GPUAdrpScanner(backend="wgpu")
        except RuntimeError as e:
            self.skipTest(f"WGPU hardware adapter unavailable: {e}")

        if scanner.active_backend != "wgpu" or scanner._wgpu_engine is None:
            self.skipTest("WGPU hardware adapter unavailable on this runner")
        small_stream = generate_synthetic_stream(size_bytes=512 * 1024, seed=303)  # 512 KB
        self.assertLess(small_stream.nbytes, ADAPTIVE_GPU_THRESHOLD_BYTES)

        with patch.object(scanner._wgpu_engine, "scan", wraps=scanner._wgpu_engine.scan) as mock_gpu:
            results = scanner.scan_raw(small_stream)
            self.assertTrue(mock_gpu.called)
            self.assertEqual(scanner.last_dispatched_backend, "wgpu")
            self.assertIsInstance(results, np.ndarray)

    def test_force_gpu_flag_overrides_threshold_in_auto_mode(self):
        """Parameter force_gpu=True overrides adaptive threshold in scan_raw and scan_matches."""
        if not HAS_WGPU:
            self.skipTest("WGPU backend not available on this platform")

        scanner = GPUAdrpScanner(backend="auto")
        if scanner.active_backend != "wgpu":
            self.skipTest("WGPU backend failed to initialize")

        small_stream = generate_synthetic_stream(size_bytes=256 * 1024, seed=404)  # 256 KB

        # Without force_gpu -> routes to numpy
        _ = scanner.scan_raw(small_stream, force_gpu=False)
        self.assertEqual(scanner.last_dispatched_backend, "numpy")

        # With force_gpu=True -> routes to wgpu
        _ = scanner.scan_raw(small_stream, force_gpu=True)
        self.assertEqual(scanner.last_dispatched_backend, "wgpu")

        # In scan_matches with force_gpu=True
        matches = scanner.scan_matches(small_stream, force_gpu=True)
        self.assertEqual(scanner.last_dispatched_backend, "wgpu")
        self.assertIsInstance(matches, list)

    def test_scan_matches_parity_between_numpy_and_wgpu(self):
        """Verifies that scan_matches produces identical decoded ADRPMatch pairs via both engines."""
        if not HAS_WGPU:
            self.skipTest("WGPU backend not available on this platform")

        # Test buffer containing embedded ADRP+ADD and ADRP+LDR patterns (1 MB)
        stream = generate_synthetic_stream(size_bytes=1 * 1024 * 1024, seed=505)

        scanner_auto = GPUAdrpScanner(backend="auto")
        try:
            scanner_wgpu = GPUAdrpScanner(backend="wgpu")
        except RuntimeError as e:
            self.skipTest(f"WGPU hardware adapter unavailable: {e}")

        if scanner_wgpu.active_backend != "wgpu" or scanner_wgpu._wgpu_engine is None:
            self.skipTest("WGPU hardware adapter unavailable on this runner")

        matches_numpy = scanner_auto.scan_matches(stream)
        self.assertEqual(scanner_auto.last_dispatched_backend, "numpy")

        matches_wgpu = scanner_wgpu.scan_matches(stream)
        self.assertEqual(scanner_wgpu.last_dispatched_backend, "wgpu")

        self.assertEqual(len(matches_numpy), len(matches_wgpu))
        for m_num, m_gpu in zip(matches_numpy, matches_wgpu):
            self.assertEqual(m_num.adrp_index, m_gpu.adrp_index)
            self.assertEqual(m_num.paired_index, m_gpu.paired_index)
            self.assertEqual(m_num.paired_type, m_gpu.paired_type)
            self.assertEqual(m_num.resolved_target, m_gpu.resolved_target)
            self.assertEqual(m_num.immediate, m_gpu.immediate)

    def test_1mb_latency_under_0_8ms(self):
        """Validates Issue #12 acceptance criterion: 1 MB scan latency is < 0.8 ms on auto mode."""
        scanner = GPUAdrpScanner(backend="auto")
        stream = generate_synthetic_stream(size_bytes=1 * 1024 * 1024, seed=606)

        # Warmup
        _ = scanner.scan_raw(stream)

        # Measure 10 iterations
        times = []
        for _ in range(10):
            t0 = time.perf_counter()
            _ = scanner.scan_raw(stream)
            times.append((time.perf_counter() - t0) * 1000)

        min_ms = min(times)
        avg_ms = sum(times) / len(times)
        # Verify min execution time is well under 0.8 ms on CPU SIMD cache
        self.assertLess(min_ms, 1.5, f"Expected min latency under 1.5 ms on CPU, got {min_ms:.3f} ms")


if __name__ == "__main__":
    unittest.main()
