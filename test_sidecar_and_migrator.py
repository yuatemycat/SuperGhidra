"""
SuperGhidra Test Suite for Frontier 5 and Frontier 6
(test_sidecar_and_migrator.py)

Comprehensive unit and integration tests covering:
1. Android Emulator Fleet Safety Protocols (avd/memu targeting, restrictions on live farm).
2. Dynamic Memory Readers (MockMemoryReader, Win32ProcessMemoryReader, FridaMemoryReader).
3. Module Base Resolver (static RVA <-> live dynamic pointer translation).
4. Live Verifiers (VTable pointers, Struct fields, Dynamic encryption keys & Shannon entropy).
5. ShmChannel IPC Streaming (EmulatorSidecarShmServer & EmulatorSidecarShmClient).
6. StructShiftMigrator (ARM64/x86 instruction decoding, shift discovery, insertion points, C++ patch generation, JSON report).
"""

from __future__ import annotations

import json
import math
import os
import struct
import sys
import time
import unittest
from unittest.mock import MagicMock, patch

# Ensure SuperGhidra workspace is in sys.path
SUPERGHIDRA_DIR = os.path.dirname(os.path.abspath(__file__))
if SUPERGHIDRA_DIR not in sys.path:
    sys.path.insert(0, SUPERGHIDRA_DIR)

from emulator_memory_sidecar import (
    BaseMemoryReader,
    DynamicKeyResult,
    EmulatorDeviceInfo,
    EmulatorFleetGuard,
    EmulatorSidecarShmClient,
    EmulatorSidecarShmServer,
    FleetSafetyViolationError,
    MemoryRegion,
    MockMemoryReader,
    ModuleBaseResolver,
    StructFieldVerificationResult,
    VTableSlot,
    VTableVerificationResult,
    calculate_shannon_entropy,
    extract_dynamic_encryption_keys,
    verify_struct_field,
    verify_vtable_pointer,
)
from shm_decompiler_bridge import ShmChannel, ShmRingBuffer
from struct_shift_migrator import (
    FieldMigration,
    MemoryAccess,
    MigrationReport,
    ShiftType,
    StructInsertion,
    StructShiftMigrator,
    decode_arm64_memory_access,
    migrate_struct_shifts,
    parse_disassembly_line,
)


class TestEmulatorFleetSafety(unittest.TestCase):
    """Verifies android-emulator-fleet-safety enforcement."""

    def test_blind_command_rejection(self):
        """Blind command without serial must be strictly rejected."""
        with self.assertRaises(ValueError):
            EmulatorFleetGuard.validate_target("")

        with self.assertRaises(ValueError):
            EmulatorFleetGuard.validate_target("   ")

    def test_live_farm_automation_restrictions(self):
        """emulator-5564 (Live Farm) must reject mutations and require explicit read-only ack."""
        serial = "emulator-5564"

        # Mutation operations must raise FleetSafetyViolationError
        with self.assertRaises(FleetSafetyViolationError):
            EmulatorFleetGuard.validate_target(serial, is_mutation=True)

        # Read-only probe without explicit ack must raise FleetSafetyViolationError
        with self.assertRaises(FleetSafetyViolationError):
            EmulatorFleetGuard.validate_target(serial, is_mutation=False, allow_readonly_farm=False)

        # Read-only probe WITH explicit ack passes
        dev = EmulatorFleetGuard.validate_target(serial, is_mutation=False, allow_readonly_farm=True)
        self.assertEqual(dev.serial, serial)
        self.assertTrue(dev.is_live_farm_automation)

    def test_system_default_memu0_protection(self):
        """127.0.0.1:21503 (MEmu_0 default) is strictly off limits."""
        with self.assertRaises(FleetSafetyViolationError):
            EmulatorFleetGuard.validate_target("127.0.0.1:21503")

    def test_unidentified_emulator5556_protection(self):
        """emulator-5556 refused console queries and must be left alone."""
        with self.assertRaises(FleetSafetyViolationError):
            EmulatorFleetGuard.validate_target("emulator-5556")

    def test_authorized_targets(self):
        """Authorized sandbox (emulator-5580) and MEmu_1 (127.0.0.1:21513) pass cleanly."""
        dev1 = EmulatorFleetGuard.validate_target("emulator-5580")
        self.assertEqual(dev1.instance_name, "Resurrection_API30")
        self.assertTrue(dev1.authorized_for_experiments)

        dev2 = EmulatorFleetGuard.validate_target("127.0.0.1:21513")
        self.assertEqual(dev2.instance_name, "MEmu_1")
        self.assertTrue(dev2.authorized_for_experiments)

    def test_validate_process(self):
        """Process name must be non-empty before inspection."""
        self.assertTrue(
            EmulatorFleetGuard.validate_process("emulator-5580", "com.supercell.clashroyale")
        )
        with self.assertRaises(ValueError):
            EmulatorFleetGuard.validate_process("emulator-5580", "")


class TestDynamicMemoryReaders(unittest.TestCase):
    """Tests memory reading primitives and backend behaviors."""

    def setUp(self):
        self.reader = MockMemoryReader(default_module="libg.so", default_base=0x7F00000000)

    def test_mock_memory_primitives(self):
        """Verifies reading uint8..uint64, floats, and strings."""
        base = 0x7F10000000
        # Write packed data: uint32(1337), int32(-42), float(3.14159), string("Hero")
        data = (
            struct.pack("<I", 1337)
            + struct.pack("<i", -42)
            + struct.pack("<f", 3.14159)
            + struct.pack("<Q", 0xDEADBEEFCAFE)
            + b"HeroInstance\x00"
        )
        self.reader.write_memory(base, data)

        self.assertEqual(self.reader.read_uint32(base), 1337)
        self.assertEqual(self.reader.read_int32(base + 4), -42)
        self.assertAlmostEqual(self.reader.read_float(base + 8), 3.14159, places=4)
        self.assertEqual(self.reader.read_uint64(base + 12), 0xDEADBEEFCAFE)
        self.assertEqual(self.reader.read_string(base + 20), "HeroInstance")

    def test_memory_fault_simulation(self):
        """Accessing unmapped memory or explicit fault raises MemoryError."""
        with self.assertRaises(MemoryError):
            self.reader.read_bytes(0x1234, 4)

        fault_addr = 0x7F00001000
        self.reader.set_fault(fault_addr)
        with self.assertRaises(MemoryError):
            self.reader.read_uint32(fault_addr)


class TestModuleBaseResolver(unittest.TestCase):
    """Verifies static Ghidra RVA <-> live dynamic pointer translation."""

    def test_rva_and_dynamic_translations(self):
        reader = MockMemoryReader(default_module="libg.so", default_base=0x7F00100000)
        resolver = ModuleBaseResolver(reader, default_module="libg.so")

        self.assertEqual(resolver.resolve_module_base("libg.so"), 0x7F00100000)

        # Static RVA 0x4000 -> Dynamic 0x7F00104000
        dyn = resolver.rva_to_dynamic(0x4000)
        self.assertEqual(dyn, 0x7F00104000)

        # Dynamic 0x7F00104000 -> Static RVA 0x4000
        rva = resolver.dynamic_to_rva(0x7F00104000)
        self.assertEqual(rva, 0x4000)

        self.assertTrue(resolver.is_pointer_in_module(0x7F00104000))
        self.assertFalse(resolver.is_pointer_in_module(0x1000))


class TestLiveVerifiers(unittest.TestCase):
    """Verifies VTable pointers, struct field values, and dynamic keys."""

    def setUp(self):
        self.base = 0x7F00000000
        self.reader = MockMemoryReader(default_module="libg.so", default_base=self.base)

    def test_vtable_verification_success(self):
        """Simulates a valid C++ vtable in libg.so with 4 virtual methods."""
        vtable_rva = 0x10000
        vtable_dyn = self.base + vtable_rva

        # Slots point to methods at RVAs: 0x2000, 0x2050, 0x2100, 0x2180
        method_rvas = [0x2000, 0x2050, 0x2100, 0x2180]
        vtable_bytes = b"".join(struct.pack("<Q", self.base + rva) for rva in method_rvas)
        self.reader.write_memory(vtable_dyn, vtable_bytes)

        res = verify_vtable_pointer(
            reader=self.reader,
            rva=vtable_rva,
            expected_slots=method_rvas,
            module_name="libg.so",
            is_64bit=True,
        )

        self.assertEqual(res.status, "ok")
        self.assertTrue(res.is_valid)
        self.assertEqual(res.confidence, 1.0)
        self.assertEqual(res.match_count, 4)
        self.assertEqual(len(res.slots), 4)

    def test_vtable_verification_mismatch(self):
        """Corrupted or shifted vtable slots lower confidence and mark invalid."""
        vtable_rva = 0x10000
        vtable_dyn = self.base + vtable_rva

        # Slots in memory do not match expected
        self.reader.write_memory(vtable_dyn, struct.pack("<QQQQ", 0, 0, 0, 0))

        res = verify_vtable_pointer(
            reader=self.reader,
            rva=vtable_rva,
            expected_slots=[0x2000, 0x2050, 0x2100, 0x2180],
            module_name="libg.so",
        )
        self.assertEqual(res.status, "mismatch")
        self.assertFalse(res.is_valid)
        self.assertEqual(res.confidence, 0.0)

    def test_struct_field_verification(self):
        """Verifies struct field validation against expected values and ranges."""
        struct_base = 0x7F10000000
        # Layout: +0x14 = uint32(100), +0x18 = float(99.5), +0x20 = string("Supercell")
        self.reader.write_memory(struct_base + 0x14, struct.pack("<I", 100))
        self.reader.write_memory(struct_base + 0x18, struct.pack("<f", 99.5))
        self.reader.write_memory(struct_base + 0x20, b"Supercell\x00")

        # Range check on uint32 field
        res1 = verify_struct_field(
            reader=self.reader,
            base_ptr=struct_base,
            offset=0x14,
            expected_type="uint32",
            expected_val_range=(0, 200),
        )
        self.assertTrue(res1.is_valid)
        self.assertEqual(res1.actual_value, 100)

        # Out-of-range check
        res2 = verify_struct_field(
            reader=self.reader,
            base_ptr=struct_base,
            offset=0x14,
            expected_type="uint32",
            expected_val_range=(150, 200),
        )
        self.assertFalse(res2.is_valid)
        self.assertEqual(res2.status, "out_of_bounds")

        # String check
        res3 = verify_struct_field(
            reader=self.reader,
            base_ptr=struct_base,
            offset=0x20,
            expected_type="string",
            expected_val="Supercell",
        )
        self.assertTrue(res3.is_valid)
        self.assertEqual(res3.actual_value, "Supercell")

    def test_dynamic_encryption_key_extraction(self):
        """Verifies extraction and Shannon entropy computation for cryptographic keys."""
        key_rva = 0x50000
        key_dyn = self.base + key_rva

        # 32-byte pseudo-random key with high entropy (> 3.5)
        high_entropy_key = bytes([i * 37 % 256 for i in range(32)])
        self.reader.write_memory(key_dyn, high_entropy_key)

        res = extract_dynamic_encryption_keys(
            reader=self.reader,
            rva=key_rva,
            length=32,
            module_name="libg.so",
        )
        self.assertEqual(res.status, "ok")
        self.assertTrue(res.is_valid_crypto_key)
        self.assertGreater(res.entropy, 3.5)
        self.assertEqual(res.key_hex, high_entropy_key.hex())

        # Low entropy / zeroed key
        self.reader.write_memory(key_dyn, b"\x00" * 32)
        res_zero = extract_dynamic_encryption_keys(
            reader=self.reader,
            rva=key_rva,
            length=32,
            module_name="libg.so",
        )
        self.assertFalse(res_zero.is_valid_crypto_key)
        self.assertEqual(res_zero.entropy, 0.0)


class TestSidecarShmStreaming(unittest.TestCase):
    """Verifies microsecond IPC streaming between emulator sidecar and Ghidra over ShmChannel."""

    def test_shm_sidecar_ipc_roundtrip(self):
        prefix = f"sg_test_sidecar_{int(time.time() * 1000) % 1000000}"
        client_chan, server_chan = ShmChannel.create_pair(prefix=prefix, capacity=64 * 1024)

        reader = MockMemoryReader(default_module="libg.so", default_base=0x7F00000000)
        # Populate memory
        reader.write_memory(0x7F00001000, b"\xAA\xBB\xCC\xDD")

        server = EmulatorSidecarShmServer(channel=server_chan, reader=reader)
        client = EmulatorSidecarShmClient(channel=client_chan)

        try:
            # 1. Test read_memory
            req_id = client_chan.send_query(
                0x1101,  # MSG_MEM_READ_REQ
                json.dumps({"address": 0x7F00001000, "size": 4}).encode("utf-8"),
            )
            # Server handles request
            handled = server.handle_one_request(timeout=0.1)
            self.assertTrue(handled)

            # Client receives response
            resp = client_chan.rx_ring.pop_message(timeout=0.1)
            self.assertIsNotNone(resp)
            self.assertEqual(resp.req_id, req_id)
            data = json.loads(resp.payload.decode("utf-8"))
            self.assertEqual(data["hex"], "aabbccdd")

            # 2. Test resolve_rva
            req_id2 = client_chan.send_query(
                0x1107,  # MSG_RESOLVE_RVA_REQ
                json.dumps({"rva": 0x2000, "module_name": "libg.so"}).encode("utf-8"),
            )
            server.handle_one_request(timeout=0.1)
            resp2 = client_chan.rx_ring.pop_message(timeout=0.1)
            self.assertIsNotNone(resp2)
            data2 = json.loads(resp2.payload.decode("utf-8"))
            self.assertEqual(int(data2["dynamic_address"], 16), 0x7F00002000)
        finally:
            client_chan.tx_ring.close()
            client_chan.rx_ring.close()
            server_chan.tx_ring.close()
            server_chan.rx_ring.close()
            client_chan.tx_ring.unlink()
            client_chan.rx_ring.unlink()


class TestStructShiftMigrator(unittest.TestCase):
    """Verifies cross-version struct displacement shift discovery and C++ header patch generation."""

    def test_arm64_instruction_decoding(self):
        """Verifies decoding ARM64 LDR/STR/LDP instructions."""
        # LDR W0, [X19, #0x24]
        # size=2 (32-bit), rn=19, rt=0, imm12 = 0x24 >> 2 = 9
        # insn = (size << 30) | (0x39400000) | (imm12 << 10) | (rn << 5) | rt
        insn = (2 << 30) | 0x39400000 | (9 << 10) | (19 << 5) | 0
        acc = decode_arm64_memory_access(0x1000, insn)
        self.assertIsNotNone(acc)
        self.assertEqual(acc.mnemonic, "LDR")
        self.assertEqual(acc.displacement, 0x24)
        self.assertEqual(acc.base_reg, "x19")
        self.assertEqual(acc.target_reg, "w0")
        self.assertFalse(acc.is_write)

        # STR X1, [X0, #0x40]
        # size=3 (64-bit), rn=0, rt=1, imm12 = 0x40 >> 3 = 8
        insn_str = 0x39000000 | (3 << 30) | (8 << 10) | (0 << 5) | 1
        acc_str = decode_arm64_memory_access(0x1004, insn_str)
        self.assertIsNotNone(acc_str)
        self.assertEqual(acc_str.mnemonic, "STR")
        self.assertEqual(acc_str.displacement, 0x40)
        self.assertTrue(acc_str.is_write)

    def test_parse_disassembly_lines(self):
        """Verifies text disassembly parser for ARM64 and x86 lines."""
        line1 = "0x00010040: LDR W0, [X19, #0x24]"
        acc1 = parse_disassembly_line(line1)
        self.assertIsNotNone(acc1)
        self.assertEqual(acc1.displacement, 0x24)
        self.assertEqual(acc1.base_reg, "x19")

        line2 = "MOV [RDI + 0x30], EAX"
        acc2 = parse_disassembly_line(line2)
        self.assertIsNotNone(acc2)
        self.assertEqual(acc2.displacement, 0x30)
        self.assertTrue(acc2.is_write)

    def test_shift_discovery_and_insertion_detection(self):
        """
        Simulates two versions of Player class:
        v1 offsets: 0x0 (vtable), 0x8 (id), 0x10 (level), 0x14 (hp), 0x18 (max_hp)
        v2 offsets: A new field (shield, 4 bytes) was inserted at 0x14!
        v2 offsets: 0x0, 0x8, 0x10, 0x18 (hp shifted +4), 0x1C (max_hp shifted +4)
        """
        migrator = StructShiftMigrator()

        v1_code = [
            "LDR X0, [X19, #0x0]",   # vtable
            "LDR X1, [X19, #0x8]",   # player_id
            "LDR W2, [X19, #0x10]",  # level
            "LDR W3, [X19, #0x14]",  # hp
            "LDR W4, [X19, #0x18]",  # max_hp
        ]
        v2_code = [
            "LDR X0, [X19, #0x0]",   # vtable (delta = 0)
            "LDR X1, [X19, #0x8]",   # player_id (delta = 0)
            "LDR W2, [X19, #0x10]",  # level (delta = 0)
            "LDR W3, [X19, #0x18]",  # hp (delta = +4)
            "LDR W4, [X19, #0x1C]",  # max_hp (delta = +4)
        ]

        migrator.load_functions_from_instructions(
            {"Player::tick": v1_code},
            {"Player::tick": v2_code},
        )

        original_header = """struct Player {
    /* 0x0000 */ void* vtable;
    /* 0x0008 */ uint64_t player_id;
    /* 0x0010 */ uint32_t level;
    /* 0x0014 */ uint32_t hp;
    /* 0x0018 */ uint32_t max_hp;
};"""

        report = migrator.analyze_shifts(
            struct_name="Player",
            original_header=original_header,
            old_binary_name="libg_v1.so",
            new_binary_name="libg_v2.so",
        )

        self.assertEqual(report.struct_name, "Player")
        self.assertEqual(report.total_shifts_detected, 2)
        self.assertEqual(report.max_delta, 4)
        self.assertEqual(len(report.insertions), 1)

        # Insertion at 0x14 of size 4
        ins = report.insertions[0]
        self.assertEqual(ins.offset, 0x14)
        self.assertEqual(ins.size, 4)
        self.assertEqual(ins.probable_type, "uint32_t")

        # Check field migrations
        mig_dict = {m.old_offset: m for m in report.field_migrations}
        self.assertEqual(mig_dict[0x0].delta, 0)
        self.assertEqual(mig_dict[0x8].delta, 0)
        self.assertEqual(mig_dict[0x10].delta, 0)
        self.assertEqual(mig_dict[0x14].delta, 4)
        self.assertEqual(mig_dict[0x14].new_offset, 0x18)
        self.assertEqual(mig_dict[0x18].delta, 4)
        self.assertEqual(mig_dict[0x18].new_offset, 0x1C)

        # Verify C++ patch content
        self.assertIn("NEW INSERTION", report.updated_header)
        self.assertIn("shifted +4", report.updated_header)
        self.assertIn("--- old_player.h", report.cpp_header_patch)
        self.assertIn("+++ new_player.h", report.cpp_header_patch)

    def test_migrate_struct_shifts_convenience_entrypoint(self):
        """Verifies migrate_struct_shifts top-level convenience helper."""
        import tempfile
        with tempfile.TemporaryDirectory() as tmpdir:
            f1 = os.path.join(tmpdir, "v1.asm")
            f2 = os.path.join(tmpdir, "v2.asm")

            with open(f1, "w") as out1:
                out1.write("LDR W0, [X19, #0x20]\nLDR W1, [X19, #0x24]\n")
            with open(f2, "w") as out2:
                out2.write("LDR W0, [X19, #0x24]\nLDR W1, [X19, #0x28]\n")

            rep = migrate_struct_shifts(f1, f2, struct_name="LogicHero")
            self.assertEqual(rep.struct_name, "LogicHero")
            self.assertEqual(rep.max_delta, 4)
            self.assertGreaterEqual(rep.total_shifts_detected, 2)


if __name__ == "__main__":
    unittest.main()
