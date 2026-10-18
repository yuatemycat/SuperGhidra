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
SUPERGHIDRA_DIR = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', '..'))
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
from binary_diff_engine import (
    BasicBlock,
    BatchedBinaryMatcher,
    FunctionCFG,
    InsnCategory,
    InstructionInfo,
    decode_arm64_instruction,
    extract_cfgs_from_arm64_bytes,
    extract_cfgs_from_binary,
    get_arm64_branch_info,
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
    decode_x86_64_memory_accesses,
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



    def test_arm64_general_purpose_instruction_decoding(self):
        """Verifies decoding ARM64 V==0 integer LDR/STR/LDP instructions."""
        # LDR W0, [X19, #0x24]
        insn = (2 << 30) | 0x39400000 | (9 << 10) | (19 << 5) | 0
        acc = decode_arm64_memory_access(0x1000, insn)
        self.assertIsNotNone(acc)
        self.assertEqual(acc.mnemonic, "LDR")
        self.assertEqual(acc.displacement, 0x24)
        self.assertEqual(acc.access_size, 4)
        self.assertEqual(acc.base_reg, "x19")
        self.assertEqual(acc.target_reg, "w0")
        self.assertFalse(acc.is_write)

        # STR X1, [X0, #0x40]
        insn_str = 0x39000000 | (3 << 30) | (8 << 10) | (0 << 5) | 1
        acc_str = decode_arm64_memory_access(0x1004, insn_str)
        self.assertIsNotNone(acc_str)
        self.assertEqual(acc_str.mnemonic, "STR")
        self.assertEqual(acc_str.displacement, 0x40)
        self.assertEqual(acc_str.access_size, 8)
        self.assertTrue(acc_str.is_write)

    def test_arm64_neon_128bit_and_simd_fp_decoding(self):
        """
        Verifies 128-bit NEON LDR Q0, [X0, #0x20] (0x3DC00800) decodes with
        displacement=0x20, access_size=16, target_reg='q0', plus STR Qn, LDR Dn/Sn, and SIMD LDP/STP.
        """
        # 1. 128-bit NEON Load: LDR Q0, [X0, #0x20] -> 0x3DC00800
        # size_code=0, V=1 (0x3D000000), opc=3 (0b11 -> 128-bit load), imm12=2 (2 << 4 = 0x20), rn=0, rt=0
        acc_q0 = decode_arm64_memory_access(0x2000, 0x3DC00800)
        self.assertIsNotNone(acc_q0)
        self.assertEqual(acc_q0.mnemonic, "LDR")
        self.assertEqual(acc_q0.displacement, 0x20)
        self.assertEqual(acc_q0.access_size, 16)
        self.assertEqual(acc_q0.target_reg, "q0")
        self.assertEqual(acc_q0.base_reg, "x0")
        self.assertFalse(acc_q0.is_write)

        # 2. 128-bit NEON Store: STR Q2, [X19, #0x30]
        # size_code=0, V=1, opc=2 (0b10 -> 128-bit store), imm12=3 (3 << 4 = 0x30), rn=19, rt=2
        insn_str_q2 = 0x3D800000 | (3 << 10) | (19 << 5) | 2
        acc_str_q2 = decode_arm64_memory_access(0x2004, insn_str_q2)
        self.assertIsNotNone(acc_str_q2)
        self.assertEqual(acc_str_q2.mnemonic, "STR")
        self.assertEqual(acc_str_q2.displacement, 0x30)
        self.assertEqual(acc_str_q2.access_size, 16)
        self.assertEqual(acc_str_q2.target_reg, "q2")
        self.assertEqual(acc_str_q2.base_reg, "x19")
        self.assertTrue(acc_str_q2.is_write)

        # 3. 64-bit FP Load: LDR D4, [X1, #0x18] (size_code=3, opc=1, imm12=3 -> 3<<3 = 0x18)
        insn_ldr_d4 = (3 << 30) | 0x3D400000 | (3 << 10) | (1 << 5) | 4
        acc_d4 = decode_arm64_memory_access(0x2008, insn_ldr_d4)
        self.assertIsNotNone(acc_d4)
        self.assertEqual(acc_d4.displacement, 0x18)
        self.assertEqual(acc_d4.access_size, 8)
        self.assertEqual(acc_d4.target_reg, "d4")

        # 4. 32-bit FP Load: LDR S3, [X2, #0x14] (size_code=2, opc=1, imm12=5 -> 5<<2 = 0x14)
        insn_ldr_s3 = (2 << 30) | 0x3D400000 | (5 << 10) | (2 << 5) | 3
        acc_s3 = decode_arm64_memory_access(0x200C, insn_ldr_s3)
        self.assertIsNotNone(acc_s3)
        self.assertEqual(acc_s3.displacement, 0x14)
        self.assertEqual(acc_s3.access_size, 4)
        self.assertEqual(acc_s3.target_reg, "s3")

        # 5. SIMD 128-bit LDP Q0, Q1, [X0, #0x40] (opc=2 -> scale=4, imm7=4 -> 4<<4 = 0x40)
        insn_ldp_q = (2 << 30) | 0x2D400000 | (4 << 15) | (1 << 10) | (0 << 5) | 0
        acc_ldp_q = decode_arm64_memory_access(0x2010, insn_ldp_q)
        self.assertIsNotNone(acc_ldp_q)
        self.assertEqual(acc_ldp_q.mnemonic, "LDP")
        self.assertEqual(acc_ldp_q.displacement, 0x40)
        self.assertEqual(acc_ldp_q.access_size, 16)
        self.assertEqual(acc_ldp_q.target_reg, "q0")

    def test_decode_x86_64_memory_accesses(self):
        """
        Verifies decode_x86_64_memory_accesses decodes MOV load (8B), MOV store (89),
        LEA (8D), ADD (03/01), CMP (3B/39) with disp8 (mod=01) and disp32 (mod=10) and REX prefixes.
        """
        # Assemble a realistic x86_64 function with prologue and displacement accesses:
        # 0x00: F3 0F 1E FA                 -> ENDBR64
        # 0x04: 55                          -> PUSH rbp
        # 0x05: 48 89 E5                    -> MOV rbp, rsp (mod=11, skipped)
        # 0x08: 48 8B 47 20                 -> MOV rax, [rdi + 0x20] (8B, REX.W, disp8=0x20, size=8)
        # 0x0C: 89 77 28                    -> MOV [rdi + 0x28], esi (89, no REX, disp8=0x28, size=4)
        # 0x0F: 4C 8D 87 80 00 00 00        -> LEA r8, [rdi + 0x80] (8D, REX.WR, disp32=0x80, size=8)
        # 0x16: 03 4F 14                    -> ADD ecx, [rdi + 0x14] (03, disp8=0x14, size=4)
        # 0x19: 48 3B 57 30                 -> CMP rdx, [rdi + 0x30] (3B, REX.W, disp8=0x30, size=8)
        # 0x1D: 5D                          -> POP rbp
        # 0x1E: C3                          -> RET
        code = (
            b"\xf3\x0f\x1e\xfa"
            b"\x55"
            b"\x48\x89\xe5"
            b"\x48\x8b\x47\x20"
            b"\x89\x77\x28"
            b"\x4c\x8d\x87\x80\x00\x00\x00"
            b"\x03\x4f\x14"
            b"\x48\x3b\x57\x30"
            b"\x5d"
            b"\xc3"
        )

        accs = decode_x86_64_memory_accesses(code, base_pc=0x401000)
        self.assertEqual(len(accs), 5)

        # 1. MOV rax, [rdi + 0x20]
        self.assertEqual(accs[0].pc, 0x401008)
        self.assertEqual(accs[0].mnemonic, "MOV")
        self.assertEqual(accs[0].base_reg, "rdi")
        self.assertEqual(accs[0].target_reg, "rax")
        self.assertEqual(accs[0].displacement, 0x20)
        self.assertEqual(accs[0].access_size, 8)
        self.assertFalse(accs[0].is_write)

        # 2. MOV [rdi + 0x28], esi
        self.assertEqual(accs[1].pc, 0x40100C)
        self.assertEqual(accs[1].mnemonic, "MOV")
        self.assertEqual(accs[1].base_reg, "rdi")
        self.assertEqual(accs[1].target_reg, "esi")
        self.assertEqual(accs[1].displacement, 0x28)
        self.assertEqual(accs[1].access_size, 4)
        self.assertTrue(accs[1].is_write)

        # 3. LEA r8, [rdi + 0x80]
        self.assertEqual(accs[2].pc, 0x40100F)
        self.assertEqual(accs[2].mnemonic, "LEA")
        self.assertEqual(accs[2].base_reg, "rdi")
        self.assertEqual(accs[2].target_reg, "r8")
        self.assertEqual(accs[2].displacement, 0x80)
        self.assertEqual(accs[2].access_size, 8)
        self.assertFalse(accs[2].is_write)

        # 4. ADD ecx, [rdi + 0x14]
        self.assertEqual(accs[3].pc, 0x401016)
        self.assertEqual(accs[3].mnemonic, "ADD")
        self.assertEqual(accs[3].base_reg, "rdi")
        self.assertEqual(accs[3].target_reg, "ecx")
        self.assertEqual(accs[3].displacement, 0x14)
        self.assertEqual(accs[3].access_size, 4)
        self.assertFalse(accs[3].is_write)

        # 5. CMP rdx, [rdi + 0x30]
        self.assertEqual(accs[4].pc, 0x401019)
        self.assertEqual(accs[4].mnemonic, "CMP")
        self.assertEqual(accs[4].base_reg, "rdi")
        self.assertEqual(accs[4].target_reg, "rdx")
        self.assertEqual(accs[4].displacement, 0x30)
        self.assertEqual(accs[4].access_size, 8)
        self.assertFalse(accs[4].is_write)

    def test_struct_shift_migrator_with_x86_64_bytes(self):
        """Verifies StructShiftMigrator discovers struct shifts directly from x86_64 machine bytes."""
        # v1: MOV rax, [rdi + 0x10]; MOV ecx, [rdi + 0x18]; MOV edx, [rdi + 0x1C]; RET
        v1_bytes = (
            b"\x48\x8b\x47\x10"
            b"\x8b\x4f\x18"
            b"\x8b\x57\x1c"
            b"\xc3"
        )
        # v2: 8-byte insertion at 0x18 -> 0x18 shifted to 0x20, 0x1C shifted to 0x24
        v2_bytes = (
            b"\x48\x8b\x47\x10"
            b"\x8b\x4f\x20"
            b"\x8b\x57\x24"
            b"\xc3"
        )

        migrator = StructShiftMigrator()
        migrator.load_from_x86_64_bytes(v1_bytes, v2_bytes, base_pc=0x401000)
        report = migrator.analyze_shifts(struct_name="X86Player")

        self.assertEqual(report.total_shifts_detected, 2)
        self.assertEqual(report.max_delta, 8)
        mig_map = {m.old_offset: m for m in report.field_migrations}
        self.assertEqual(mig_map[0x10].delta, 0)
        self.assertEqual(mig_map[0x18].new_offset, 0x20)
        self.assertEqual(mig_map[0x1C].new_offset, 0x24)

    def test_struct_shift_migrator_with_x86_64_bytes(self):
        """Verifies StructShiftMigrator discovers struct shifts directly from x86_64 machine bytes."""
        # v1: MOV rax, [rdi + 0x10]; MOV ecx, [rdi + 0x18]; MOV edx, [rdi + 0x1C]; RET
        v1_bytes = (
            b"\x48\x8b\x47\x10"
            b"\x8b\x4f\x18"
            b"\x8b\x57\x1c"
            b"\xc3"
        )
        # v2: 8-byte insertion at 0x18 -> 0x18 shifted to 0x20, 0x1C shifted to 0x24
        v2_bytes = (
            b"\x48\x8b\x47\x10"
            b"\x8b\x4f\x20"
            b"\x8b\x57\x24"
            b"\xc3"
        )

        migrator = StructShiftMigrator()
        migrator.load_from_x86_64_bytes(v1_bytes, v2_bytes, base_pc=0x401000)
        report = migrator.analyze_shifts(struct_name="X86Player")

        self.assertEqual(report.total_shifts_detected, 2)
        self.assertEqual(report.max_delta, 8)
        mig_map = {m.old_offset: m for m in report.field_migrations}
        self.assertEqual(mig_map[0x10].delta, 0)
        self.assertEqual(mig_map[0x18].new_offset, 0x20)
        self.assertEqual(mig_map[0x1C].new_offset, 0x24)

    def test_shift_discovery_and_insertion_detection(self):
        migrator = StructShiftMigrator()
        v1_code = [
            "LDR X0, [X19, #0x0]",
            "LDR X1, [X19, #0x8]",
            "LDR W2, [X19, #0x10]",
            "LDR W3, [X19, #0x14]",
            "LDR W4, [X19, #0x18]",
        ]
        v2_code = [
            "LDR X0, [X19, #0x0]",
            "LDR X1, [X19, #0x8]",
            "LDR W2, [X19, #0x10]",
            "LDR W3, [X19, #0x18]",
            "LDR W4, [X19, #0x1C]",
        ]
        migrator.load_functions_from_instructions(
            {"Player::tick": v1_code},
            {"Player::tick": v2_code},
        )
        report = migrator.analyze_shifts(struct_name="Player")
        self.assertEqual(report.total_shifts_detected, 2)
        self.assertEqual(report.max_delta, 4)
        self.assertEqual(len(report.insertions), 1)
        self.assertEqual(report.insertions[0].offset, 0x14)





# Helper ARM64 Instruction Encoders for Unit Testing
# ==============================================================================

def encode_ret() -> int:
    return 0xD65F03C0

def encode_nop() -> int:
    return 0xD503201F

def encode_b(pc: int, target: int) -> int:
    imm26 = ((target - pc) >> 2) & 0x03FFFFFF
    return 0x14000000 | imm26

def encode_bl(pc: int, target: int) -> int:
    imm26 = ((target - pc) >> 2) & 0x03FFFFFF
    return 0x94000000 | imm26

def encode_b_eq(pc: int, target: int) -> int:
    imm19 = ((target - pc) >> 2) & 0x7FFFF
    return 0x54000000 | (imm19 << 5) | 0

def encode_cbz(pc: int, target: int, reg: int = 0) -> int:
    imm19 = ((target - pc) >> 2) & 0x7FFFF
    return 0x34000000 | (imm19 << 5) | (reg & 0x1F)

def encode_ldr_w(base_reg: int, rt: int, disp: int) -> int:
    imm12 = (disp >> 2) & 0xFFF
    return 0x39400000 | (2 << 30) | (imm12 << 10) | ((base_reg & 0x1F) << 5) | (rt & 0x1F)

def encode_ldr_x(base_reg: int, rt: int, disp: int) -> int:
    imm12 = (disp >> 3) & 0xFFF
    return 0x39400000 | (3 << 30) | (imm12 << 10) | ((base_reg & 0x1F) << 5) | (rt & 0x1F)

def encode_str_w(base_reg: int, rt: int, disp: int) -> int:
    imm12 = (disp >> 2) & 0xFFF
    return 0x39000000 | (2 << 30) | (imm12 << 10) | ((base_reg & 0x1F) << 5) | (rt & 0x1F)

def encode_str_x(base_reg: int, rt: int, disp: int) -> int:
    imm12 = (disp >> 3) & 0xFFF
    return 0x39000000 | (3 << 30) | (imm12 << 10) | ((base_reg & 0x1F) << 5) | (rt & 0x1F)

def encode_movz(rd: int, imm16: int) -> int:
    return 0x52800000 | ((imm16 & 0xFFFF) << 5) | (rd & 0x1F)

def encode_add_imm(rd: int, rn: int, imm12: int) -> int:
    return 0x11000000 | ((imm12 & 0xFFF) << 10) | ((rn & 0x1F) << 5) | (rd & 0x1F)


# ==============================================================================
# 1. Binary Diffing Engine CFG Extraction Tests (Frontier 5)
# ==============================================================================


class TestBinaryDiffEngineCFGExtraction(unittest.TestCase):
    """Verifies ARM64 instruction decoding, CFG extraction, and batched diffing."""

    def test_decode_arm64_instructions(self):
        """Verifies individual ARM64 instruction decoding into InstructionInfo."""
        pc = 0x1000

        # 1. RET
        info_ret = decode_arm64_instruction(pc, encode_ret())
        self.assertEqual(info_ret.mnemonic, "ret")
        self.assertEqual(info_ret.category, InsnCategory.RETURN)

        # 2. B (target pc + 16 = 0x1010)
        insn_b = encode_b(pc, pc + 16)
        info_b = decode_arm64_instruction(pc, insn_b)
        self.assertEqual(info_b.mnemonic, "b")
        self.assertEqual(info_b.category, InsnCategory.BRANCH_UNCOND)
        self.assertIn("0x1010", info_b.op_str)

        # 3. BL (target pc + 8 = 0x1008)
        insn_bl = encode_bl(pc, pc + 8)
        info_bl = decode_arm64_instruction(pc, insn_bl)
        self.assertEqual(info_bl.mnemonic, "bl")
        self.assertEqual(info_bl.category, InsnCategory.CALL)

        # 4. B.EQ (target pc + 24 = 0x1018)
        insn_beq = encode_b_eq(pc, pc + 24)
        info_beq = decode_arm64_instruction(pc, insn_beq)
        self.assertEqual(info_beq.mnemonic, "b.eq")
        self.assertEqual(info_beq.category, InsnCategory.BRANCH_COND)

        # 5. LDR W0, [X19, #0x24]
        insn_ldr = encode_ldr_w(19, 0, 0x24)
        info_ldr = decode_arm64_instruction(pc, insn_ldr)
        self.assertEqual(info_ldr.mnemonic, "ldr")
        self.assertEqual(info_ldr.category, InsnCategory.MEMORY_LOAD)

        # 6. STR X1, [X19, #0x40]
        insn_str = encode_str_x(19, 1, 0x40)
        info_str = decode_arm64_instruction(pc, insn_str)
        self.assertEqual(info_str.mnemonic, "str")
        self.assertEqual(info_str.category, InsnCategory.MEMORY_STORE)

        # 7. MOVZ W0, #0x1234
        insn_movz = encode_movz(0, 0x1234)
        info_movz = decode_arm64_instruction(pc, insn_movz)
        self.assertEqual(info_movz.mnemonic, "movz")
        self.assertEqual(info_movz.category, InsnCategory.ARITHMETIC)
        self.assertIn("0x1234", info_movz.op_str)

        # 8. NOP
        info_nop = decode_arm64_instruction(pc, encode_nop())
        self.assertEqual(info_nop.mnemonic, "nop")

    def test_extract_cfgs_from_arm64_bytes_multi_function(self):
        """
        Verifies partitioning multiple functions from raw machine bytes
        using RET boundaries, discovering BasicBlocks and wiring control flow edges.
        """
        base_vaddr = 0x100000

        # Function 1: Diamond branch (pc: 0x100000 - 0x10000C)
        # 0x100000: ADD W0, W0, #1
        # 0x100004: B.EQ 0x10000C
        # 0x100008: MOVZ W0, #0x42
        # 0x10000C: RET
        f1_words = [
            encode_add_imm(0, 0, 1),
            encode_b_eq(0x100004, 0x10000C),
            encode_movz(0, 0x42),
            encode_ret(),
        ]

        # Function 2: Call and return (pc: 0x100010 - 0x100018)
        # 0x100010: BL 0x100000
        # 0x100014: MOVZ W1, #0x100
        # 0x100018: RET
        f2_words = [
            encode_bl(0x100010, 0x100000),
            encode_movz(1, 0x100),
            encode_ret(),
        ]

        # Function 3: Memory operations (pc: 0x10001C - 0x100024)
        # 0x10001C: LDR W0, [X19, #0x10]
        # 0x100020: STR W0, [X19, #0x14]
        # 0x100024: RET
        f3_words = [
            encode_ldr_w(19, 0, 0x10),
            encode_str_w(19, 0, 0x14),
            encode_ret(),
        ]

        raw_buffer = struct.pack(f"<{len(f1_words + f2_words + f3_words)}I", *(f1_words + f2_words + f3_words))

        cfgs = extract_cfgs_from_arm64_bytes(raw_buffer, base_vaddr=base_vaddr)
        self.assertEqual(len(cfgs), 3)

        # Inspect Function 1
        cfg1 = cfgs[0]
        self.assertEqual(cfg1.address, 0x100000)
        self.assertGreaterEqual(len(cfg1.blocks), 2)
        # Check conditional branch edges (branch target + fallthrough)
        src_blocks = [src for src, dst in cfg1.edges]
        self.assertIn(0x100000, src_blocks)

        # Inspect Function 2
        cfg2 = cfgs[1]
        self.assertEqual(cfg2.address, 0x100010)
        self.assertIn("0x100000", cfg2.callees)

        # Inspect Function 3
        cfg3 = cfgs[2]
        self.assertEqual(cfg3.address, 0x10001C)
        all_cats = [insn.category for b in cfg3.blocks.values() for insn in b.instructions]
        self.assertIn(InsnCategory.MEMORY_LOAD, all_cats)
        self.assertIn(InsnCategory.MEMORY_STORE, all_cats)

    def test_batched_diff_on_extracted_cfgs(self):
        """
        Verifies BatchedBinaryMatcher accurately pairs functions extracted
        directly from ARM64 byte buffers across versions.
        """
        # Version A
        f1_a = [encode_add_imm(0, 0, 1), encode_b_eq(0x100004, 0x10000C), encode_movz(0, 0x42), encode_ret()]
        f2_a = [encode_bl(0x100010, 0x100000), encode_movz(1, 0x100), encode_ret()]
        raw_a = struct.pack(f"<{len(f1_a + f2_a)}I", *(f1_a + f2_a))
        cfgs_a = extract_cfgs_from_arm64_bytes(raw_a, base_vaddr=0x100000)

        # Version B (Offset by 0x50000, slightly mutated instruction)
        f1_b = [encode_add_imm(0, 0, 2), encode_b_eq(0x150004, 0x15000C), encode_movz(0, 0x43), encode_ret()]
        f2_b = [encode_bl(0x150010, 0x150000), encode_movz(1, 0x200), encode_ret()]
        raw_b = struct.pack(f"<{len(f1_b + f2_b)}I", *(f1_b + f2_b))
        cfgs_b = extract_cfgs_from_arm64_bytes(raw_b, base_vaddr=0x150000)

        matcher = BatchedBinaryMatcher(threshold=0.6, use_gpu=False)
        diff_res = matcher.diff_binaries(cfgs_a, cfgs_b)

        self.assertEqual(len(diff_res.matches), 2)
        self.assertGreaterEqual(diff_res.avg_similarity, 0.7)

    def test_extract_cfgs_from_binary_elf_and_raw(self):
        """Verifies extract_cfgs_from_binary parses ELF and raw payloads."""
        # 1. Raw buffer
        raw = struct.pack("<2I", encode_movz(0, 0x10), encode_ret())
        cfgs_raw = extract_cfgs_from_binary(raw, base_vaddr=0x2000)
        self.assertEqual(len(cfgs_raw), 1)

        # 2. Synthetic ELF header + instructions
        elf_header = b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 8
        elf_payload = elf_header + raw
        cfgs_elf = extract_cfgs_from_binary(elf_payload, base_vaddr=0x4000)
        self.assertEqual(len(cfgs_elf), 1)


# ==============================================================================
# 2. Struct Shift Migrator Alignment & Profile Matching (Frontier 6)
# ==============================================================================

class TestStructShiftMigratorSequenceAlignment(unittest.TestCase):
    """Verifies sequence-aligned access pairing and profile similarity matching."""

    def test_sequence_aligned_access_pairing_with_inserted_middle_insn(self):
        """
        Tests sequence-aligned pairing using SequenceMatcher when len(v1) != len(v2)
        due to an inserted instruction in v2.
        v1 (5 accesses):
          0x0 (vtable), 0x8 (id), 0x10 (level), 0x14 (hp), 0x18 (max_hp)
        v2 (6 accesses):
          0x0, 0x8, 0x10,
          [INSERTED WRITE at 0x14],
          0x18 (hp shifted +4), 0x1C (max_hp shifted +4)
        """
        migrator = StructShiftMigrator()

        v1_code = [
            "LDR X0, [X19, #0x0]",
            "LDR X1, [X19, #0x8]",
            "LDR W2, [X19, #0x10]",
            "LDR W3, [X19, #0x14]",
            "LDR W4, [X19, #0x18]",
        ]
        # v2 has an extra STR inserted in the middle
        v2_code = [
            "LDR X0, [X19, #0x0]",
            "LDR X1, [X19, #0x8]",
            "LDR W2, [X19, #0x10]",
            "STR W9, [X19, #0x14]",  # Newly inserted write
            "LDR W3, [X19, #0x18]",  # Shifted +4
            "LDR W4, [X19, #0x1C]",  # Shifted +4
        ]

        migrator.load_functions_from_instructions(
            {"Entity::update": v1_code},
            {"Entity::update": v2_code},
        )

        report = migrator.analyze_shifts(
            struct_name="Entity",
            old_binary_name="libv1.so",
            new_binary_name="libv2.so",
        )

        mig_dict = {m.old_offset: m for m in report.field_migrations}
        self.assertEqual(mig_dict[0x0].delta, 0)
        self.assertEqual(mig_dict[0x8].delta, 0)
        self.assertEqual(mig_dict[0x10].delta, 0)
        # Shifted fields matched accurately despite the extra instruction!
        self.assertEqual(mig_dict[0x14].delta, 4)
        self.assertEqual(mig_dict[0x14].new_offset, 0x18)
        self.assertEqual(mig_dict[0x18].delta, 4)
        self.assertEqual(mig_dict[0x18].new_offset, 0x1C)

    def test_extract_binary_accesses_single_vs_multi_function(self):
        """Verifies _extract_binary_accesses partitions functions by RET."""
        migrator = StructShiftMigrator()

        # Multi-function binary: 2 functions ending with RET
        f1_insns = [encode_ldr_w(19, 0, 0x20), encode_ret()]
        f2_insns = [encode_str_w(19, 1, 0x24), encode_ret()]
        multi_raw = struct.pack("<4I", *(f1_insns + f2_insns))

        multi_funcs = migrator._sweep_arm64_functions(multi_raw, 0x1000)
        self.assertEqual(len(multi_funcs), 2)
        self.assertIn("func_0", multi_funcs)
        self.assertIn("func_1", multi_funcs)

        # Single function binary: only 1 RET
        single_insns = [encode_ldr_w(19, 0, 0x20), encode_ret()]
        single_raw = struct.pack("<2I", *single_insns)
        single_funcs = migrator._sweep_arm64_functions(single_raw, 0x1000, default_name="text_section")
        self.assertEqual(len(single_funcs), 1)
        self.assertIn("text_section", single_funcs)

    def test_profile_similarity_matching_for_unmatched_symbols(self):
        """Verifies matching stripped functions across versions by memory access profile similarity."""
        migrator = StructShiftMigrator()

        # Version 1 with stripped name sub_1040
        v1_accs = [
            "LDR X0, [X19, #0x20]",
            "LDR W1, [X19, #0x28]",
            "STR W2, [X19, #0x2C]",
        ]
        # Version 2 with different stripped name sub_5080
        v2_accs = [
            "LDR X0, [X19, #0x24]",
            "LDR W1, [X19, #0x2C]",
            "STR W2, [X19, #0x30]",
        ]

        migrator.load_functions_from_instructions(
            {"sub_1040": v1_accs},
            {"sub_5080": v2_accs},
        )

        report = migrator.analyze_shifts(struct_name="StrippedHero")
        self.assertEqual(report.matched_functions, 1)
        self.assertEqual(report.total_shifts_detected, 3)
        self.assertEqual(report.max_delta, 4)


# ==============================================================================
# 3. Struct Shift Migrator ShiftType Classification Tests (Frontier 6)
# ==============================================================================

class TestStructShiftMigratorShiftTypes(unittest.TestCase):
    """Verifies precise classification of EXPANSION_SHIFT, ALIGNMENT_ADJUSTMENT, and INSERTION_SHIFT."""

    def test_expansion_shift_classification(self):
        """
        Verifies ShiftType.EXPANSION_SHIFT when a field expands from 32-bit to 64-bit,
        and on fields following that expansion.
        """
        migrator = StructShiftMigrator()

        # v1: field at 0x10 is 32-bit (LDR W0)
        # v2: field at 0x10 is expanded to 64-bit (LDR X0)
        # and subsequent field at 0x14 shifted to 0x18
        v1 = [
            "LDR W0, [X19, #0x10]",  # 32-bit (size: 4)
            "LDR W1, [X19, #0x14]",  # 32-bit (size: 4)
        ]
        v2 = [
            "LDR X0, [X19, #0x10]",  # 64-bit (size: 8, expanded!)
            "LDR W1, [X19, #0x18]",  # shifted by +4 due to expansion
        ]

        migrator.load_functions_from_instructions({"func": v1}, {"func": v2})
        report = migrator.analyze_shifts(struct_name="ExpandedStruct")

        mig_dict = {m.old_offset: m for m in report.field_migrations}
        self.assertEqual(mig_dict[0x10].shift_type, ShiftType.EXPANSION_SHIFT)
        self.assertEqual(mig_dict[0x14].shift_type, ShiftType.EXPANSION_SHIFT)
        self.assertEqual(mig_dict[0x14].delta, 4)

    def test_alignment_adjustment_classification(self):
        """
        Verifies ShiftType.ALIGNMENT_ADJUSTMENT when an unaligned 8-byte field
        (e.g. at 0x14 where 0x14 % 8 != 0) is shifted to an 8-byte aligned offset (0x18).
        """
        migrator = StructShiftMigrator()

        # 8-byte pointer was misaligned at offset 0x14 in v1, shifted to 0x18 in v2
        v1 = [
            "LDR X0, [X19, #0x14]",  # 8-byte pointer at unaligned offset 0x14
        ]
        v2 = [
            "LDR X0, [X19, #0x18]",  # 8-byte pointer aligned at 0x18
        ]

        migrator.load_functions_from_instructions({"func": v1}, {"func": v2})
        report = migrator.analyze_shifts(struct_name="AlignedStruct")

        mig = report.field_migrations[0]
        self.assertEqual(mig.old_offset, 0x14)
        self.assertEqual(mig.new_offset, 0x18)
        self.assertEqual(mig.shift_type, ShiftType.ALIGNMENT_ADJUSTMENT)

    def test_standard_insertion_shift_classification(self):
        """
        Verifies naturally aligned fields shifted by a new member insertion
        remain classified as ShiftType.INSERTION_SHIFT.
        """
        migrator = StructShiftMigrator()

        v1 = [
            "LDR W0, [X19, #0x14]",  # 4-byte uint32 (0x14 % 4 == 0)
        ]
        v2 = [
            "LDR W0, [X19, #0x18]",  # Shifted +4 due to insertion
        ]

        migrator.load_functions_from_instructions({"func": v1}, {"func": v2})
        report = migrator.analyze_shifts(struct_name="InsertionStruct")

        mig = report.field_migrations[0]
        self.assertEqual(mig.old_offset, 0x14)
        self.assertEqual(mig.shift_type, ShiftType.INSERTION_SHIFT)

    def test_identical_and_deletion_shift_classification(self):
        """Verifies ShiftType.IDENTICAL and ShiftType.DELETION_SHIFT."""
        migrator = StructShiftMigrator()

        v1 = [
            "LDR X0, [X19, #0x0]",   # Identical
            "LDR W1, [X19, #0x20]",  # Deleted/reduced offset
        ]
        v2 = [
            "LDR X0, [X19, #0x0]",   # Identical
            "LDR W1, [X19, #0x1C]",  # Delta: -4
        ]

        migrator.load_functions_from_instructions({"func": v1}, {"func": v2})
        report = migrator.analyze_shifts(struct_name="DeletionStruct")

        mig_dict = {m.old_offset: m for m in report.field_migrations}
        self.assertEqual(mig_dict[0x0].shift_type, ShiftType.IDENTICAL)
        self.assertEqual(mig_dict[0x20].shift_type, ShiftType.DELETION_SHIFT)
        self.assertEqual(mig_dict[0x20].delta, -4)



if __name__ == "__main__":
    unittest.main()
