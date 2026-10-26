"""
test_resource_governor.py
=========================
Comprehensive Test Suite for SuperGhidra Resource Governor (Section 8 of Architectural Spec).

Verifies:
1. Multi-tier resource mode policies (eco, balanced, turbo, auto).
2. JVM launch.properties and AppCDS flag generation with Generational ZGC.
3. Native decompiler process reaper lifecycle and idle timeouts.
4. Complexity-aware decompiler downshifting (Tier 1, Tier 2, Tier 3).
5. Persistent disk-backed decompiler cache (db.buffers emulator).
6. Telemetry-driven closed-loop auto mode scaling under CPU and RAM pressure.
"""

from __future__ import annotations

import os
import sys
import unittest

# Ensure local SuperGhidra directory is first in sys.path
SCRIPT_DIR = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', '..'))
if SCRIPT_DIR not in sys.path:
    sys.path.insert(0, SCRIPT_DIR)

from superghidra.core.resource_governor import (
    DecompileProcessPoolReaper,
    DecompilerComplexityGovernor,
    FunctionComplexityTier,
    JVMResourceConfigurator,
    PersistentDecompilerDBCache,
    ResourceMode,
    TelemetryResourceGovernor,
    get_default_mode_policy,
)


class TestResourceGovernor(unittest.TestCase):
    """Verifies all Section 8 Resource Governor subsystems."""

    def test_default_mode_policies(self):
        # 1. Eco Mode
        eco = get_default_mode_policy(ResourceMode.ECO, logical_cores=16)
        self.assertEqual(eco.thread_count, 1)
        self.assertEqual(eco.thread_priority, 1)
        self.assertEqual(eco.duty_cycle_ms, 50)
        self.assertEqual(eco.max_native_decompilers, 1)
        self.assertEqual(eco.decompiler_idle_timeout_sec, 15)
        self.assertEqual(eco.soft_max_heap_mb, 768)
        self.assertEqual(eco.tiered_stop_at_level, 1)

        # 2. Balanced Mode
        balanced = get_default_mode_policy(ResourceMode.BALANCED, logical_cores=16)
        self.assertEqual(balanced.thread_count, 2)
        self.assertEqual(balanced.duty_cycle_ms, 10)
        self.assertEqual(balanced.max_native_decompilers, 2)
        self.assertEqual(balanced.decompiler_idle_timeout_sec, 120)
        self.assertEqual(balanced.soft_max_heap_mb, 2048)
        self.assertEqual(balanced.tiered_stop_at_level, 4)

        # 3. Turbo Mode
        turbo = get_default_mode_policy(ResourceMode.TURBO, logical_cores=16)
        self.assertEqual(turbo.thread_count, 16)
        self.assertEqual(turbo.duty_cycle_ms, 0)
        self.assertEqual(turbo.soft_max_heap_mb, 8192)
        self.assertEqual(turbo.decompiler_idle_timeout_sec, 0)  # Never reaped

    def test_jvm_launch_properties_and_appcds(self):
        eco = get_default_mode_policy(ResourceMode.ECO, logical_cores=8)
        vmargs = JVMResourceConfigurator.generate_launch_vmargs(eco, appcds_file="test_appcds.jsa")
        vmargs_str = " ".join(vmargs)

        self.assertIn("-XX:+UseZGC", vmargs_str)
        self.assertIn("-XX:+ZGenerational", vmargs_str)
        self.assertIn("-XX:+ZUncommit", vmargs_str)
        self.assertIn("-XX:ZUncommitDelay=15", vmargs_str)
        self.assertIn("-XX:SoftMaxHeapSize=768m", vmargs_str)
        self.assertIn("-XX:TieredStopAtLevel=1", vmargs_str)
        self.assertIn("-XX:ArchiveClassesAtExit=test_appcds.jsa", vmargs_str)

        turbo = get_default_mode_policy(ResourceMode.TURBO, logical_cores=8)
        turbo_vmargs = JVMResourceConfigurator.generate_launch_vmargs(turbo, appcds_file="test_appcds.jsa")
        turbo_str = " ".join(turbo_vmargs)

        self.assertIn("-XX:-ZUncommit", turbo_str)
        self.assertIn("-XX:+AlwaysPreTouch", turbo_str)
        self.assertIn("-Xms8192m", turbo_str)
        self.assertIn("-Xmx8192m", turbo_str)

    def test_decompile_process_reaper_lifecycle(self):
        reaper = DecompileProcessPoolReaper(idle_timeout_sec=15, max_active_processes=2)

        inst1 = reaper.register_instance(pid=1001, created_at=0.0)
        inst2 = reaper.register_instance(pid=1002, created_at=0.0)

        # Initially, neither is reaped at t=0
        reaped_init = reaper.scan_and_reap(now=0.0)
        self.assertEqual(len(reaped_init), 0)

        # Mark inst2 as busy
        reaper.mark_busy(inst2)

        # Advance time to t=20 (>15s idle timeout)
        reaped = reaper.scan_and_reap(now=20)
        # inst1 was idle, inst2 was busy -> only inst1 reaped
        self.assertIn(inst1, reaped)
        self.assertNotIn(inst2, reaped)

    def test_complexity_aware_downshifting(self):
        balanced = get_default_mode_policy(ResourceMode.BALANCED)

        # 1. Standard Function (<4KB, <100 basic blocks)
        tier1 = DecompilerComplexityGovernor.classify_function(body_size_bytes=2048, basic_block_count=45)
        self.assertEqual(tier1, FunctionComplexityTier.TIER1_STANDARD)
        style1, opt1 = DecompilerComplexityGovernor.resolve_simplification_style(
            balanced, body_size_bytes=2048, basic_block_count=45
        )
        self.assertEqual(style1, "decompile")
        self.assertTrue(opt1["toggle_syntax_tree"])

        # 2. Large Dispatcher (4KB - 16KB or 100 - 300 basic blocks)
        tier2 = DecompilerComplexityGovernor.classify_function(body_size_bytes=8192, basic_block_count=180)
        self.assertEqual(tier2, FunctionComplexityTier.TIER2_LARGE_DISPATCHER)
        style2, opt2 = DecompilerComplexityGovernor.resolve_simplification_style(
            balanced, body_size_bytes=8192, basic_block_count=180
        )
        self.assertEqual(style2, "normalize")
        self.assertTrue(opt2["disable_action_infer_types"])

        # 3. Pathological Megafunction (>16KB or >300 basic blocks)
        tier3 = DecompilerComplexityGovernor.classify_function(body_size_bytes=32768, basic_block_count=520)
        self.assertEqual(tier3, FunctionComplexityTier.TIER3_MEGAFUNCTION)
        style3, opt3 = DecompilerComplexityGovernor.resolve_simplification_style(
            balanced, body_size_bytes=32768, basic_block_count=520
        )
        self.assertEqual(style3, "jumptable")
        self.assertFalse(opt3["toggle_syntax_tree"])

        # 4. CPU Throttled Override (forces firstpass on Tier 2 & 3)
        style_throttled, _ = DecompilerComplexityGovernor.resolve_simplification_style(
            balanced, body_size_bytes=8192, basic_block_count=180, is_cpu_throttled=True
        )
        self.assertEqual(style_throttled, "firstpass")

    def test_persistent_decompiler_db_cache(self):
        cache = PersistentDecompilerDBCache()
        self.assertFalse(cache.contains(0x00CF2D84))

        cache.put(0x00CF2D84, "int ApplyRecipeCommand() { return 1; }")
        self.assertTrue(cache.contains(0x00CF2D84))

        res = cache.get(0x00CF2D84)
        self.assertIsNotNone(res)
        self.assertEqual(res["c_code"], "int ApplyRecipeCommand() { return 1; }")
        self.assertEqual(cache.hits, 1)

        miss = cache.get(0x00DEADBE)
        self.assertIsNone(miss)
        self.assertEqual(cache.misses, 1)

    def test_telemetry_driven_auto_mode(self):
        gov = TelemetryResourceGovernor(logical_cores=8)
        gov.set_mode(ResourceMode.AUTO)

        # 1. High CPU Load (> 70%) -> Throttles to 1 thread, 50ms duty cycle
        p_high = gov.update_telemetry(cpu_load=0.85, free_ram_ratio=0.40)
        self.assertEqual(p_high.thread_count, 1)
        self.assertEqual(p_high.thread_priority, 1)
        self.assertEqual(p_high.duty_cycle_ms, 50)
        self.assertEqual(p_high.decompiler_idle_timeout_sec, 15)

        # 2. Low CPU Load (< 25%) -> Scales up to turbo concurrency
        p_low = gov.update_telemetry(cpu_load=0.15, free_ram_ratio=0.60)
        self.assertEqual(p_low.thread_count, 8)
        self.assertEqual(p_low.duty_cycle_ms, 0)
        self.assertEqual(p_low.decompiler_idle_timeout_sec, 60)

        # 3. RAM Pressure (< 25% free) -> Lowers idle reaper timeout to 10s
        p_ram = gov.update_telemetry(cpu_load=0.50, free_ram_ratio=0.18)
        self.assertEqual(p_ram.decompiler_idle_timeout_sec, 10)


if __name__ == "__main__":
    unittest.main()
