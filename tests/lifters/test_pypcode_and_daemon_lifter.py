"""
tests/lifters/test_pypcode_and_daemon_lifter.py
===============================================

Unit and integration tests for Roadmap Item 1:
  - `PypcodeSleighBackend` (both mock/stubbed `pypcode` translation objects and live if installed)
  - `DaemonPcodeBackend` (against a real local TCP loopback server in a background thread)
  - `X86_64PcodeLifter` backed by `superghidra.lifters.x86_decode` (SIB scale/index/base, ALU, extensions)
  - `UnifiedPcodeLifter` multi-tier resolution (`pypcode` -> `daemon` -> `builtin`)
  - `SMTPcodeVerifier.verify_byte_sequences` proving/refuting semantic equivalence on x86_64 and ARM64
"""

from __future__ import annotations

import json
import socket
import struct
import threading
import types
import unittest
from typing import Any, Dict, List
from unittest import mock

import superghidra.lifters.pcode_lifter_bridge as pcode_bridge
from superghidra.lifters.pcode_lifter_bridge import (
    CANONICAL_REG_OFFSETS,
    AddressSpace,
    AddrSpace,
    DaemonPcodeBackend,
    PcodeOpcode,
    PypcodeSleighBackend,
    UnifiedPcodeLifter,
    X86_64PcodeLifter,
)
from superghidra.lifters.smt_pcode_verifier import (
    EquivalenceResult,
    SMTPcodeVerifier,
)

# ---------------------------------------------------------------------------
# Stub pypcode classes for deterministic testing without C++ wheel dependency
# ---------------------------------------------------------------------------

class _StubSpace:
    def __init__(self, name: str):
        self.name = name


class _StubVarnode:
    def __init__(self, space_name: str, offset: int, size: int, reg_name: str | None = None):
        self.space = _StubSpace(space_name)
        self.offset = offset
        self.size = size
        self._reg_name = reg_name

    def getRegisterName(self) -> str:
        return self._reg_name or ""


class _StubOpCode:
    def __init__(self, name: str):
        self.name = name


class _StubSeqNum:
    def __init__(self, pc: int):
        self.target = pc
        self.pc = pc


class _StubPcodeOp:
    def __init__(
        self,
        opcode_name: str,
        inputs: List[_StubVarnode],
        output: _StubVarnode | None = None,
        pc: int = 0x1000,
    ):
        self.opcode = _StubOpCode(opcode_name)
        self.inputs = inputs
        self.output = output
        self.seq = _StubSeqNum(pc)


class _StubTranslation:
    def __init__(self, ops: List[_StubPcodeOp]):
        self.ops = ops


class _StubPypcodeContext:
    """Simulates a `pypcode.Context` with SLEIGH register tables and `translate()`."""

    def __init__(self, language_id: str):
        self.language_id = language_id
        self.registers: Dict[str, _StubVarnode] = {
            "RAX": _StubVarnode("register", 0x00, 8, "RAX"),
            "EAX": _StubVarnode("register", 0x00, 4, "EAX"),
            "RCX": _StubVarnode("register", 0x08, 8, "RCX"),
            "RDX": _StubVarnode("register", 0x10, 8, "RDX"),
            "RBX": _StubVarnode("register", 0x18, 8, "RBX"),
            "RSP": _StubVarnode("register", 0x20, 8, "RSP"),
            "R8": _StubVarnode("register", 0x80, 8, "R8"),
            "ZF": _StubVarnode("register", 0x206, 1, "ZF"),
            "CF": _StubVarnode("register", 0x200, 1, "CF"),
            "x0": _StubVarnode("register", 0x4000, 8, "x0"),
            "x1": _StubVarnode("register", 0x4008, 8, "x1"),
        }

    def translate(self, code: bytes, base_address: int = 0x1000, max_instructions: int = 0) -> _StubTranslation:
        # Simulate SLEIGH translation for `add rax, rbx; mov [rsp+8], rax`
        ops: List[_StubPcodeOp] = [
            _StubPcodeOp("IMARK", [_StubVarnode("ram", base_address, 3)], None, pc=base_address),
            _StubPcodeOp(
                "INT_CARRY",
                [_StubVarnode("register", 0x00, 8), _StubVarnode("register", 0x18, 8)],
                _StubVarnode("register", 0x200, 1),
                pc=base_address,
            ),
            _StubPcodeOp(
                "INT_ADD",
                [_StubVarnode("register", 0x00, 8), _StubVarnode("register", 0x18, 8)],
                _StubVarnode("register", 0x00, 8),
                pc=base_address,
            ),
            _StubPcodeOp(
                "POPCOUNT",
                [_StubVarnode("register", 0x00, 1)],
                _StubVarnode("unique", 0x100, 1),
                pc=base_address,
            ),
        ]
        if max_instructions != 1 and len(code) > 3:
            ops.extend([
                _StubPcodeOp("IMARK", [_StubVarnode("ram", base_address + 3, 5)], None, pc=base_address + 3),
                _StubPcodeOp(
                    "INT_ADD",
                    [_StubVarnode("register", 0x20, 8), _StubVarnode("const", 8, 8)],
                    _StubVarnode("unique", 0x200, 8),
                    pc=base_address + 3,
                ),
                _StubPcodeOp(
                    "STORE",
                    [
                        _StubVarnode("const", 0, 8),
                        _StubVarnode("unique", 0x200, 8),
                        _StubVarnode("register", 0x00, 8),
                    ],
                    None,
                    pc=base_address + 3,
                ),
            ])
        return _StubTranslation(ops)


# ---------------------------------------------------------------------------
# Test Cases
# ---------------------------------------------------------------------------

class TestPypcodeAndDaemonLifter(unittest.TestCase):
    """Tests for PypcodeSleighBackend, DaemonPcodeBackend, UnifiedPcodeLifter, and SMTPcodeVerifier."""

    def test_addr_space_aliases(self):
        self.assertIs(AddrSpace, AddressSpace)
        self.assertIs(AddrSpace.CONSTANT, AddressSpace.CONST)
        self.assertEqual(AddrSpace.CONSTANT.value, "const")
        self.assertEqual(AddrSpace.REGISTER.value, "register")
        self.assertEqual(AddrSpace.UNIQUE.value, "unique")
        self.assertEqual(AddrSpace.RAM.value, "ram")

    def test_pypcode_sleigh_backend_with_stub_context(self):
        """Verifies PypcodeSleighBackend language resolution and Varnode/PcodeOp mapping."""
        self.assertEqual(PypcodeSleighBackend.resolve_language_id("x86_64"), "x86:LE:64:default")
        self.assertEqual(PypcodeSleighBackend.resolve_language_id("x86"), "x86:LE:32:default")
        self.assertEqual(PypcodeSleighBackend.resolve_language_id("arm64"), "AArch64:LE:64:v8A")
        self.assertEqual(PypcodeSleighBackend.resolve_language_id("arm"), "ARM:LE:32:v8")
        self.assertEqual(PypcodeSleighBackend.resolve_language_id("x86:LE:64:default"), "x86:LE:64:default")

        stub_ctx = _StubPypcodeContext("x86:LE:64:default")
        backend = PypcodeSleighBackend("x86_64", context=stub_ctx)
        ops = backend.lift_bytes(b"\x48\x01\xd8\x48\x89\x44\x24\x08", base_addr=0x401000)

        # IMARK pseudo-ops must be filtered out; 5 real PcodeOps remain
        self.assertEqual(len(ops), 5)
        self.assertEqual(ops[0].opcode, PcodeOpcode.INT_CARRY)
        self.assertEqual(ops[0].pc, 0x401000)
        self.assertEqual(ops[0].output.space, AddrSpace.REGISTER)
        self.assertEqual(ops[0].output.reg_name, "cf")

        # INT_ADD(rax, rbx) -> rax
        add_op = ops[1]
        self.assertEqual(add_op.opcode, PcodeOpcode.INT_ADD)
        self.assertEqual(add_op.inputs[0].space, AddrSpace.REGISTER)
        self.assertEqual(add_op.inputs[0].offset, CANONICAL_REG_OFFSETS["rax"])
        self.assertEqual(add_op.inputs[0].reg_name, "rax")
        self.assertEqual(add_op.inputs[1].offset, CANONICAL_REG_OFFSETS["rbx"])
        self.assertEqual(add_op.inputs[1].reg_name, "rbx")
        self.assertEqual(add_op.output.offset, CANONICAL_REG_OFFSETS["rax"])

        # Second instruction at 0x401003 uses CONST, UNIQUE, and STORE
        self.assertEqual(ops[3].pc, 0x401003)
        self.assertEqual(ops[3].inputs[1].space, AddrSpace.CONSTANT)
        self.assertEqual(ops[3].inputs[1].offset, 8)
        self.assertEqual(ops[3].output.space, AddrSpace.UNIQUE)
        self.assertEqual(ops[4].opcode, PcodeOpcode.STORE)

    def test_pypcode_sleigh_backend_via_mock_module(self):
        """Verifies PypcodeSleighBackend when `pypcode` module is dynamically provided."""
        fake_mod = types.SimpleNamespace(Context=_StubPypcodeContext)
        with mock.patch.object(pcode_bridge, "pypcode", fake_mod):
            self.assertTrue(PypcodeSleighBackend.is_available())
            lifter = UnifiedPcodeLifter(arch="x86_64", backend="auto")
            ops, backend_used = lifter.lift_with_provenance(b"\x48\x01\xd8", base_addr=0x2000, max_insns=1)
            self.assertEqual(backend_used, "pypcode")
            self.assertEqual(len(ops), 3)

    @unittest.skipUnless(PypcodeSleighBackend.is_available(), "pypcode native wheel not installed")
    def test_pypcode_sleigh_backend_live(self):
        """Runs live SLEIGH translation when pypcode is installed in the test environment."""
        backend = PypcodeSleighBackend("x86_64")
        ops = backend.lift_bytes(b"\x48\x01\xd8", base_addr=0x1000)
        self.assertGreater(len(ops), 0)
        self.assertTrue(any(op.opcode == PcodeOpcode.INT_ADD for op in ops))

    def test_daemon_pcode_backend_tcp_loopback_server(self):
        """Tests DaemonPcodeBackend against a real local TCP loopback server in a background thread."""
        received_requests: List[Dict[str, Any]] = []

        server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_sock.bind(("127.0.0.1", 0))
        _, port = server_sock.getsockname()
        server_sock.listen(5)

        stop_event = threading.Event()

        def _server_loop():
            server_sock.settimeout(0.2)
            while not stop_event.is_set():
                try:
                    conn, _ = server_sock.accept()
                except TimeoutError:
                    continue
                except OSError:
                    break
                with conn:
                    try:
                        data = conn.recv(65536)
                        if not data:
                            continue
                        req = json.loads(data.decode("utf-8").strip())
                        received_requests.append(req)
                        resp = {
                            "status": "ok",
                            "ops": [
                                {
                                    "opcode": "INT_ADD",
                                    "seq_addr": req.get("address", "0x1000"),
                                    "output": {"space": "register", "offset": "rax", "size": 8},
                                    "inputs": [
                                        {"space": "register", "offset": "rax", "size": 8},
                                        {"space": "register", "offset": "rbx", "size": 8},
                                    ],
                                },
                                {
                                    "opcode": "RETURN",
                                    "seq_addr": "0x1003",
                                    "output": None,
                                    "inputs": [{"space": "register", "offset": "rax", "size": 8}],
                                },
                            ],
                        }
                        conn.sendall((json.dumps(resp) + "\n").encode("utf-8"))
                    except Exception:
                        pass

        thread = threading.Thread(target=_server_loop, daemon=True)
        thread.start()
        try:
            backend = DaemonPcodeBackend(host="127.0.0.1", port=port, timeout=2.0, arch="x86_64")
            self.assertTrue(backend.is_available())
            self.assertTrue(DaemonPcodeBackend.is_available("127.0.0.1", port, timeout=1.0))

            lifter = UnifiedPcodeLifter(
                arch="x86_64",
                backend="daemon",
                daemon_host="127.0.0.1",
                daemon_port=port,
                daemon_timeout=2.0,
            )
            ops, used = lifter.lift_with_provenance(b"\x48\x01\xd8\xc3", base_addr=0x1000, max_insns=2)
            self.assertEqual(used, "daemon")
            self.assertEqual(len(ops), 2)
            self.assertEqual(ops[0].opcode, PcodeOpcode.INT_ADD)
            self.assertEqual(ops[0].output.offset, CANONICAL_REG_OFFSETS["rax"])
            self.assertEqual(ops[0].inputs[1].offset, CANONICAL_REG_OFFSETS["rbx"])
            self.assertEqual(ops[1].opcode, PcodeOpcode.RETURN)
            self.assertEqual(ops[1].pc, 0x1003)

            self.assertGreaterEqual(len(received_requests), 1)
            self.assertEqual(received_requests[-1]["cmd"], "pcode")
            self.assertEqual(received_requests[-1]["address"], "0x1000")
            self.assertEqual(received_requests[-1]["max_insns"], 2)
        finally:
            stop_event.set()
            server_sock.close()
            thread.join(timeout=2.0)

    def test_x86_64_pcode_lifter_with_x86_decode_sib_and_alu(self):
        """Verifies X86_64PcodeLifter SIB addressing, LEA, MOVZX/MOVSX, and ALU operations."""
        lifter = X86_64PcodeLifter()
        # lea rax, [rdi + rsi*4 + 0x10] -> 48 8d 44 b7 10
        ops = lifter.lift_bytes(bytes.fromhex("488d44b710"), base_addr=0x1000)
        opcodes = [op.opcode for op in ops]
        self.assertIn(PcodeOpcode.INT_MULT, opcodes)
        self.assertIn(PcodeOpcode.INT_ADD, opcodes)

        verifier = SMTPcodeVerifier()
        res = verifier.verify_equivalence(
            ops,
            "rax = rdi + rsi * 4 + 16;",
            check_memory=False,
            tracked_registers=[0],
        )
        self.assertTrue(res.equivalent, res.details)
        self.assertEqual(res.status, "UNSAT")

    def test_smt_verify_byte_sequences_x86_64_and_arm64(self):
        """Verifies SMTPcodeVerifier.verify_byte_sequences across x86_64 and ARM64 sequences."""
        verifier = SMTPcodeVerifier()

        # 1. x86_64: `add rax, rbx` (48 01 d8) vs `lea rax, [rax + rbx]` (48 8d 04 18)
        res_add_lea = verifier.verify_byte_sequences(
            bytes.fromhex("4801d8"),
            bytes.fromhex("488d0418"),
            arch="x86_64",
            output_regs=["rax"],
            backend="builtin",
        )
        self.assertIsInstance(res_add_lea, EquivalenceResult)
        self.assertTrue(res_add_lea.equivalent, res_add_lea.details)
        self.assertEqual(res_add_lea.status, "UNSAT")
        self.assertEqual(res_add_lea.backend_used, "builtin")

        # 2. x86_64: `xor eax, eax` (31 c0) vs `sub eax, eax` (29 c0)
        res_zero = verifier.verify_byte_sequences(
            bytes.fromhex("31c0"),
            bytes.fromhex("29c0"),
            arch="x86_64",
            output_regs=["rax"],
            backend="builtin",
        )
        self.assertTrue(res_zero.equivalent, res_zero.details)
        self.assertEqual(res_zero.status, "UNSAT")

        # 3. x86_64 non-equivalent sequences: `add rax, rbx` (48 01 d8) vs `sub rax, rbx` (48 29 d8)
        res_diff = verifier.verify_byte_sequences(
            bytes.fromhex("4801d8"),
            bytes.fromhex("4829d8"),
            arch="x86_64",
            output_regs=["rax"],
            backend="builtin",
        )
        self.assertFalse(res_diff.equivalent)
        self.assertEqual(res_diff.status, "SAT")
        self.assertIsNotNone(res_diff.counterexample)

        # 4. ARM64: `add x0, x0, x0` (0x8B000000) vs `lsl x0, x0, #1` (0xD37FF800)
        arm_add = struct.pack("<I", 0x8B000000)
        arm_lsl = struct.pack("<I", 0xD37FF800)
        res_arm = verifier.verify_byte_sequences(
            arm_add,
            arm_lsl,
            arch="arm64",
            output_regs=["x0"],
            backend="auto",
        )
        self.assertTrue(res_arm.equivalent, res_arm.details)
        self.assertEqual(res_arm.status, "UNSAT")


if __name__ == "__main__":
    unittest.main()
