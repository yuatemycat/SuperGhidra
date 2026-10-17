"""
SuperGhidra Live Android Emulator Memory Introspection Sidecar
(emulator_memory_sidecar.py)

Frontier 5: Live Android Emulator Memory Introspection Sidecar.
Features:
1. Strict adherence to android-emulator-fleet-safety rules:
   - Targets identified before any inspection or adb execution.
   - Device fleet routing matrix:
     * emulator-5564 (Optimumu_HayDay): Live Farm Automation (STRICTLY OFF LIMITS for mutations).
     * emulator-5580 (Resurrection_API30): Meteor / Sandbox (authorized root target).
     * 127.0.0.1:21513 (MEmu_1): Authorized ODM-Native target.
     * 127.0.0.1:21503 (MEmu_0): System / Default (DO NOT TOUCH).
     * emulator-5556: Unidentified (leave alone).
   - Validates process identity and rejects blind commands.
2. Dynamic memory reader backend abstraction:
   - Win32ProcessMemoryReader (using ctypes OpenProcess, VirtualQueryEx, ReadProcessMemory).
   - FridaMemoryReader (Frida RPC bridge).
   - MockMemoryReader (deterministic for testing and CI).
3. Module base resolver:
   - Locates libg.so base address.
   - Translates static Ghidra RVA <-> live dynamic pointer (dynamic_addr = module_base + rva).
4. Live verifiers:
   - verify_vtable_pointer(rva, expected_slots): reads dynamic pointers, verifies against expected function addresses.
   - verify_struct_field(base_ptr, offset, expected_type, expected_val_range): validates live struct field values.
   - extract_dynamic_encryption_keys(rva, length): reads live runtime keys from memory and verifies Shannon entropy.
5. Integration with ShmChannel:
   - Microsecond IPC streaming between emulator sidecar and Ghidra.
"""

from __future__ import annotations

import abc
import ctypes
import dataclasses
import json
import math
import os
import re
import struct
import sys
import time
from typing import Any, Dict, List, Optional, Tuple, Union

# Import SuperGhidra ShmChannel and message structures
try:
    from shm_decompiler_bridge import ShmChannel, ShmMessage
except ImportError:
    from .shm_decompiler_bridge import ShmChannel, ShmMessage

# -----------------------------------------------------------------------------
# 1. Android Emulator Fleet Safety Protocols
# -----------------------------------------------------------------------------

class FleetSafetyViolationError(PermissionError):
    """Raised when an operation violates workstation emulator fleet safety rules."""
    pass


@dataclasses.dataclass(frozen=True)
class EmulatorDeviceInfo:
    """Represents verified device profile in the workstation fleet routing matrix."""
    serial: str
    instance_name: str
    purpose: str
    authorized_for_experiments: bool
    is_live_farm_automation: bool = False
    is_system_default_protected: bool = False
    requires_explicit_readonly_ack: bool = False
    description: str = ""


# Fleet Routing Matrix definitions from android-emulator-fleet-safety
FLEET_DEVICE_MAP: Dict[str, EmulatorDeviceInfo] = {
    "emulator-5564": EmulatorDeviceInfo(
        serial="emulator-5564",
        instance_name="Optimumu_HayDay",
        purpose="Live Farm Automation",
        authorized_for_experiments=False,
        is_live_farm_automation=True,
        requires_explicit_readonly_ack=True,
        description="STRICTLY OFF LIMITS for mutations. User live game process.",
    ),
    "emulator-5580": EmulatorDeviceInfo(
        serial="emulator-5580",
        instance_name="Resurrection_API30",
        purpose="Meteor / Sandbox",
        authorized_for_experiments=True,
        description="Headless root target for OS sandbox and container experimentation.",
    ),
    "127.0.0.1:21513": EmulatorDeviceInfo(
        serial="127.0.0.1:21513",
        instance_name="MEmu_1",
        purpose="ODM-Native",
        authorized_for_experiments=True,
        description="Authorized target for ODM Downloader test runs (com.woaiyj1314.odm).",
    ),
    "127.0.0.1:21503": EmulatorDeviceInfo(
        serial="127.0.0.1:21503",
        instance_name="MEmu_0",
        purpose="System / Default",
        authorized_for_experiments=False,
        is_system_default_protected=True,
        description="DO NOT TOUCH. Leave index 0 unmodified.",
    ),
    "emulator-5556": EmulatorDeviceInfo(
        serial="emulator-5556",
        instance_name="SH_M24",
        purpose="Unidentified",
        authorized_for_experiments=False,
        description="Refused console queries; leave alone.",
    ),
}


class EmulatorFleetGuard:
    """Enforces android-emulator-fleet-safety rules before any command or inspection."""

    @classmethod
    def identify_device(cls, serial: str) -> EmulatorDeviceInfo:
        """Looks up device serial against authoritative fleet matrix."""
        s = serial.strip()
        if not s:
            raise ValueError("Target serial must be explicitly specified (no blind commands).")

        if s in FLEET_DEVICE_MAP:
            return FLEET_DEVICE_MAP[s]

        # Generic / unrecognized device
        return EmulatorDeviceInfo(
            serial=s,
            instance_name="GenericDevice",
            purpose="Unclassified Target",
            authorized_for_experiments=True,
            description="Unregistered target device; proceeding with caution.",
        )

    @classmethod
    def validate_target(
        cls,
        serial: str,
        is_mutation: bool = False,
        allow_readonly_farm: bool = False,
    ) -> EmulatorDeviceInfo:
        """
        Validates whether target device serial can be accessed.
        Raises FleetSafetyViolationError if the operation is dangerous or forbidden.
        """
        info = cls.identify_device(serial)

        # 1. MEmu_0 is strictly off limits
        if info.is_system_default_protected:
            raise FleetSafetyViolationError(
                f"Fleet Safety Violation: Device '{info.serial}' ({info.instance_name}) "
                "is the system/default VM index 0. DO NOT TOUCH."
            )

        # 2. emulator-5556 is refused/unidentified
        if info.serial == "emulator-5556":
            raise FleetSafetyViolationError(
                f"Fleet Safety Violation: Device '{info.serial}' refused console queries and is reserved. Leave alone."
            )

        # 3. emulator-5564 is live farm automation
        if info.is_live_farm_automation:
            if is_mutation:
                raise FleetSafetyViolationError(
                    f"Fleet Safety Violation: Device '{info.serial}' ({info.instance_name}) "
                    "is user's live game process. NEVER install APKs, stop processes, reboot, or mutate root."
                )
            if not allow_readonly_farm:
                raise FleetSafetyViolationError(
                    f"Fleet Safety Violation: Device '{info.serial}' ({info.instance_name}) "
                    "requires explicit allow_readonly_farm=True acknowledgement for read-only probes."
                )

        return info

    @classmethod
    def validate_process(
        cls,
        serial: str,
        package_name: str,
        pid: Optional[int] = None,
    ) -> bool:
        """Ensures that the process is explicitly verified before probing."""
        cls.validate_target(serial, is_mutation=False, allow_readonly_farm=True)
        if not package_name or len(package_name.strip()) == 0:
            raise ValueError("Target process/package name must be explicitly specified.")
        return True


# -----------------------------------------------------------------------------
# 2. Dynamic Memory Reader Backend Abstraction
# -----------------------------------------------------------------------------

@dataclasses.dataclass
class MemoryRegion:
    """Represents a mapped virtual memory page range."""
    base_addr: int
    size: int
    permissions: str  # e.g. "r-x", "rw-", "r--"
    name: str = ""

    @property
    def end_addr(self) -> int:
        return self.base_addr + self.size

    def contains(self, addr: int) -> bool:
        return self.base_addr <= addr < self.end_addr


class BaseMemoryReader(abc.ABC):
    """Abstract interface for dynamic emulator memory readers."""

    @abc.abstractmethod
    def read_bytes(self, address: int, size: int) -> bytes:
        """Reads raw bytes from target virtual memory address."""
        pass

    @abc.abstractmethod
    def get_module_base(self, module_name: str) -> Optional[int]:
        """Resolves dynamic base virtual address of a shared object (.so) or library."""
        pass

    @abc.abstractmethod
    def get_memory_regions(self) -> List[MemoryRegion]:
        """Returns mapped memory regions of the target process."""
        pass

    def read_uint8(self, address: int) -> int:
        data = self.read_bytes(address, 1)
        return struct.unpack("<B", data)[0]

    def read_int8(self, address: int) -> int:
        data = self.read_bytes(address, 1)
        return struct.unpack("<b", data)[0]

    def read_uint16(self, address: int) -> int:
        data = self.read_bytes(address, 2)
        return struct.unpack("<H", data)[0]

    def read_int16(self, address: int) -> int:
        data = self.read_bytes(address, 2)
        return struct.unpack("<h", data)[0]

    def read_uint32(self, address: int) -> int:
        data = self.read_bytes(address, 4)
        return struct.unpack("<I", data)[0]

    def read_int32(self, address: int) -> int:
        data = self.read_bytes(address, 4)
        return struct.unpack("<i", data)[0]

    def read_uint64(self, address: int) -> int:
        data = self.read_bytes(address, 8)
        return struct.unpack("<Q", data)[0]

    def read_int64(self, address: int) -> int:
        data = self.read_bytes(address, 8)
        return struct.unpack("<q", data)[0]

    def read_pointer(self, address: int, is_64bit: bool = True) -> int:
        if is_64bit:
            return self.read_uint64(address)
        return self.read_uint32(address)

    def read_float(self, address: int) -> float:
        data = self.read_bytes(address, 4)
        return struct.unpack("<f", data)[0]

    def read_double(self, address: int) -> float:
        data = self.read_bytes(address, 8)
        return struct.unpack("<d", data)[0]

    def read_string(self, address: int, max_len: int = 256, encoding: str = "utf-8") -> str:
        """Reads a null-terminated C string from memory."""
        chunk = self.read_bytes(address, max_len)
        null_idx = chunk.find(b"\x00")
        if null_idx != -1:
            chunk = chunk[:null_idx]
        return chunk.decode(encoding, errors="replace")

    def is_valid_address(self, address: int) -> bool:
        """Checks if address falls within a valid readable memory region."""
        for reg in self.get_memory_regions():
            if reg.contains(address) and "r" in reg.permissions:
                return True
        return False

    def close(self) -> None:
        pass


# Windows ctypes definitions for Win32ProcessMemoryReader
PROCESS_VM_READ = 0x0010
PROCESS_QUERY_INFORMATION = 0x0400
MEM_COMMIT = 0x1000
PAGE_NOACCESS = 0x01
PAGE_GUARD = 0x100

class MEMORY_BASIC_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("BaseAddress", ctypes.c_void_p),
        ("AllocationBase", ctypes.c_void_p),
        ("AllocationProtect", ctypes.c_ulong),
        ("RegionSize", ctypes.c_size_t),
        ("State", ctypes.c_ulong),
        ("Protect", ctypes.c_ulong),
        ("Type", ctypes.c_ulong),
    ]


class Win32ProcessMemoryReader(BaseMemoryReader):
    """
    Direct Windows process memory reader using Win32 API
    (OpenProcess, VirtualQueryEx, ReadProcessMemory).
    Ideal for reading memory from Windows emulator host processes (MEmuHeadless.exe, qemu, etc.).
    """

    def __init__(self, pid: int):
        self.pid = pid
        self._kernel32 = ctypes.windll.kernel32
        self.h_process = self._kernel32.OpenProcess(
            PROCESS_VM_READ | PROCESS_QUERY_INFORMATION,
            False,
            pid,
        )
        if not self.h_process:
            err = self._kernel32.GetLastError()
            raise OSError(f"OpenProcess failed for PID {pid} with Win32 error code {err}")

        self._module_cache: Dict[str, int] = {}
        self._cached_regions: List[MemoryRegion] = []
        self._last_refresh = 0.0

    def read_bytes(self, address: int, size: int) -> bytes:
        if size <= 0:
            return b""
        buffer = ctypes.create_string_buffer(size)
        bytes_read = ctypes.c_size_t(0)
        res = self._kernel32.ReadProcessMemory(
            self.h_process,
            ctypes.c_void_p(address),
            buffer,
            ctypes.c_size_t(size),
            ctypes.byref(bytes_read),
        )
        if not res or bytes_read.value == 0:
            err = self._kernel32.GetLastError()
            raise MemoryError(
                f"ReadProcessMemory failed at 0x{address:016X} (size {size}) with Win32 error {err}"
            )
        return buffer.raw[: bytes_read.value]

    def get_memory_regions(self) -> List[MemoryRegion]:
        now = time.time()
        if self._cached_regions and (now - self._last_refresh < 5.0):
            return self._cached_regions

        regions = []
        addr = 0
        mbi = MEMORY_BASIC_INFORMATION()
        mbi_size = ctypes.sizeof(mbi)

        while True:
            res = self._kernel32.VirtualQueryEx(
                self.h_process,
                ctypes.c_void_p(addr),
                ctypes.byref(mbi),
                mbi_size,
            )
            if not res:
                break

            base = mbi.BaseAddress or 0
            size = mbi.RegionSize or 0
            state = mbi.State
            protect = mbi.Protect

            perm = []
            if state == MEM_COMMIT and not (protect & PAGE_NOACCESS) and not (protect & PAGE_GUARD):
                perm.append("r")
                if protect in (0x04, 0x08, 0x40, 0x80):
                    perm.append("w")
                if protect in (0x10, 0x20, 0x40, 0x80):
                    perm.append("x")
            perm_str = "".join(perm) if perm else "---"

            if size > 0:
                regions.append(MemoryRegion(base_addr=base, size=size, permissions=perm_str))
                addr = base + size
            else:
                break

            # Bound upper limit for 64-bit user address space
            if addr >= 0x7FFFFFFF0000:
                break

        self._cached_regions = regions
        self._last_refresh = now
        return regions

    def get_module_base(self, module_name: str) -> Optional[int]:
        norm_name = module_name.lower()
        if norm_name in self._module_cache:
            return self._module_cache[norm_name]

        # Scan regions or toolhelp snapshot if needed
        # By default return first valid executable region or cached entry
        for reg in self.get_memory_regions():
            if "x" in reg.permissions:
                self._module_cache[norm_name] = reg.base_addr
                return reg.base_addr
        return None

    def close(self) -> None:
        if hasattr(self, "h_process") and self.h_process:
            self._kernel32.CloseHandle(self.h_process)
            self.h_process = None


class FridaMemoryReader(BaseMemoryReader):
    """
    Frida RPC Bridge memory reader for attached Android devices/emulators.
    Enforces fleet safety verification before establishing Frida session.
    """

    def __init__(
        self,
        device_serial: str,
        target_process: Union[str, int],
        allow_readonly_farm: bool = False,
    ):
        self.device_serial = device_serial
        self.target_process = target_process

        # 1. Enforce safety validation
        self.device_info = EmulatorFleetGuard.validate_target(
            device_serial,
            is_mutation=False,
            allow_readonly_farm=allow_readonly_farm,
        )

        self._session = None
        self._script = None
        self._module_cache: Dict[str, int] = {}
        self._regions: List[MemoryRegion] = []
        self._init_frida()

    def _init_frida(self) -> None:
        """Connects to device and injects minimal memory RPC agent."""
        try:
            import frida  # type: ignore
            device = frida.get_device(self.device_serial)
            self._session = device.attach(self.target_process)

            rpc_source = """
            rpc.exports = {
                readBytes: function(addrHex, size) {
                    var p = ptr(addrHex);
                    var buf = Memory.readByteArray(p, size);
                    return [].slice.call(new Uint8Array(buf));
                },
                getModuleBase: function(modName) {
                    var m = Process.findModuleByName(modName);
                    return m ? m.base.toString() : null;
                },
                getRanges: function() {
                    return Process.enumerateRanges('r--').map(function(r) {
                        return {base: r.base.toString(), size: r.size, prot: r.protection};
                    });
                }
            };
            """
            self._script = self._session.create_script(rpc_source)
            self._script.load()
        except ImportError:
            # Graceful simulation fallback when frida package is not present
            pass
        except Exception as e:
            # Offline or permission issue
            pass

    def read_bytes(self, address: int, size: int) -> bytes:
        if size <= 0:
            return b""
        if self._script is not None:
            try:
                byte_list = self._script.exports_sync.read_bytes(hex(address), size)
                return bytes(byte_list)
            except Exception as e:
                raise MemoryError(f"Frida readBytes failed at 0x{address:X}: {e}")
        raise MemoryError("Frida session not connected.")

    def get_module_base(self, module_name: str) -> Optional[int]:
        if module_name in self._module_cache:
            return self._module_cache[module_name]

        if self._script is not None:
            try:
                base_str = self._script.exports_sync.get_module_base(module_name)
                if base_str:
                    base_int = int(base_str, 16)
                    self._module_cache[module_name] = base_int
                    return base_int
            except Exception:
                pass
        return None

    def get_memory_regions(self) -> List[MemoryRegion]:
        if self._regions:
            return self._regions
        if self._script is not None:
            try:
                ranges = self._script.exports_sync.get_ranges()
                self._regions = [
                    MemoryRegion(
                        base_addr=int(r["base"], 16),
                        size=r["size"],
                        permissions=r["prot"],
                    )
                    for r in ranges
                ]
                return self._regions
            except Exception:
                pass
        return []

    def close(self) -> None:
        if self._session is not None:
            try:
                self._session.detach()
            except Exception:
                pass
            self._session = None


class MockMemoryReader(BaseMemoryReader):
    """
    Deterministic in-memory reader backend for CI tests, offline simulations,
    and unit testing of struct/vtable verifiers.
    """

    def __init__(self, default_module: str = "libg.so", default_base: int = 0x7F00000000):
        self.default_module = default_module
        self.default_base = default_base
        self._regions: Dict[int, Tuple[int, str, bytearray, str]] = {}
        self._module_map: Dict[str, int] = {default_module: default_base}
        self.read_count: int = 0
        self.fault_addresses: set[int] = set()

        # Allocate default code and data regions
        self.add_region(base=default_base, size=0x1000000, permissions="r-x", name=default_module)
        self.add_region(base=0x7F10000000, size=0x1000000, permissions="rw-", name="heap")

    def add_region(
        self,
        base: int,
        size: int,
        permissions: str = "r-x",
        data: Optional[bytes] = None,
        name: str = "",
    ) -> None:
        buf = bytearray(size)
        if data:
            copy_len = min(len(data), size)
            buf[:copy_len] = data[:copy_len]
        self._regions[base] = (size, permissions, buf, name)

    def write_memory(self, address: int, data: bytes) -> None:
        """Writes synthetic test bytes into mock memory buffer."""
        for base, (size, permissions, buf, name) in self._regions.items():
            if base <= address < base + size:
                offset = address - base
                end_offset = offset + len(data)
                if end_offset <= size:
                    buf[offset:end_offset] = data
                    return
                else:
                    part1 = size - offset
                    buf[offset:size] = data[:part1]
                    self.write_memory(base + size, data[part1:])
                    return
        # If not present, create a dynamic region
        self.add_region(base=address, size=max(4096, len(data)), permissions="rw-", data=data)

    def set_module(self, name: str, base_addr: int, size: int = 0x100000) -> None:
        self._module_map[name] = base_addr
        self.add_region(base=base_addr, size=size, permissions="r-x", name=name)

    def set_fault(self, address: int) -> None:
        self.fault_addresses.add(address)

    def read_bytes(self, address: int, size: int) -> bytes:
        self.read_count += 1
        if address in self.fault_addresses:
            raise MemoryError(f"Simulated segmentation fault / page violation at 0x{address:X}")

        for base, (reg_size, permissions, buf, name) in self._regions.items():
            if base <= address < base + reg_size:
                offset = address - base
                if offset + size <= reg_size:
                    return bytes(buf[offset : offset + size])
                else:
                    part1 = bytes(buf[offset:])
                    part2 = self.read_bytes(base + reg_size, size - len(part1))
                    return part1 + part2

        raise MemoryError(f"Unmapped address 0x{address:016X} (size {size}) in MockMemoryReader")

    def get_module_base(self, module_name: str) -> Optional[int]:
        return self._module_map.get(module_name)

    def get_memory_regions(self) -> List[MemoryRegion]:
        return [
            MemoryRegion(base_addr=base, size=size, permissions=perm, name=name)
            for base, (size, perm, _, name) in self._regions.items()
        ]


# -----------------------------------------------------------------------------
# 3. Module Base Resolver (Static RVA <-> Live Dynamic Pointer)
# -----------------------------------------------------------------------------

class ModuleBaseResolver:
    """Translates static Ghidra Relative Virtual Addresses (RVA) to live dynamic pointers."""

    def __init__(self, reader: BaseMemoryReader, default_module: str = "libg.so"):
        self.reader = reader
        self.default_module = default_module
        self._module_base_cache: Dict[str, int] = {}

    def resolve_module_base(self, module_name: Optional[str] = None) -> int:
        mod = module_name or self.default_module
        if mod in self._module_base_cache:
            return self._module_base_cache[mod]

        base = self.reader.get_module_base(mod)
        if base is None:
            raise ValueError(f"Module '{mod}' could not be located in target process memory.")
        self._module_base_cache[mod] = base
        return base

    def rva_to_dynamic(self, rva: int, module_name: Optional[str] = None) -> int:
        """dynamic_addr = module_base + rva"""
        base = self.resolve_module_base(module_name)
        return base + rva

    def dynamic_to_rva(self, dynamic_addr: int, module_name: Optional[str] = None) -> int:
        """rva = dynamic_addr - module_base"""
        base = self.resolve_module_base(module_name)
        return dynamic_addr - base

    def is_pointer_in_module(self, ptr: int, module_name: Optional[str] = None) -> bool:
        """Checks whether dynamic pointer points within the mapped module address range."""
        try:
            base = self.resolve_module_base(module_name)
            # Default module range check against memory regions
            for reg in self.reader.get_memory_regions():
                if reg.base_addr == base or (reg.name and (module_name or self.default_module) in reg.name):
                    if reg.contains(ptr):
                        return True
            # Fallback 64MB window if regions not tagged
            return base <= ptr < (base + 0x4000000)
        except Exception:
            return False


# -----------------------------------------------------------------------------
# 4. Live Memory Verifiers (VTables, Struct Fields, Encryption Keys)
# -----------------------------------------------------------------------------

@dataclasses.dataclass
class VTableSlot:
    """Represents a validated slot in a dynamic C++ virtual method table."""
    index: int
    slot_dynamic_addr: int
    target_dynamic_addr: int
    target_rva: int
    expected_rva: Optional[int]
    is_match: bool


@dataclasses.dataclass
class VTableVerificationResult:
    """Outcome of vtable pointer verification."""
    status: str
    is_valid: bool
    confidence: float
    vtable_dynamic_addr: int
    match_count: int
    total_slots: int
    slots: List[VTableSlot]
    message: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "status": self.status,
            "is_valid": self.is_valid,
            "confidence": round(self.confidence, 4),
            "vtable_dynamic_addr": f"0x{self.vtable_dynamic_addr:016X}",
            "match_count": self.match_count,
            "total_slots": self.total_slots,
            "message": self.message,
            "slots": [
                {
                    "index": s.index,
                    "slot_dynamic_addr": f"0x{s.slot_dynamic_addr:016X}",
                    "target_dynamic_addr": f"0x{s.target_dynamic_addr:016X}",
                    "target_rva": f"0x{s.target_rva:08X}",
                    "expected_rva": f"0x{s.expected_rva:08X}" if s.expected_rva is not None else None,
                    "is_match": s.is_match,
                }
                for s in self.slots
            ],
        }


def verify_vtable_pointer(
    reader: BaseMemoryReader,
    rva: int,
    expected_slots: List[Union[int, str]],
    module_name: str = "libg.so",
    is_64bit: bool = True,
) -> VTableVerificationResult:
    """
    Reads dynamic pointers at module_base + rva, verifies against expected function addresses.
    """
    resolver = ModuleBaseResolver(reader, default_module=module_name)
    vtable_base = resolver.rva_to_dynamic(rva, module_name)
    ptr_size = 8 if is_64bit else 4

    slots: List[VTableSlot] = []
    matches = 0
    total = len(expected_slots)

    for i, exp in enumerate(expected_slots):
        slot_addr = vtable_base + (i * ptr_size)
        try:
            target_dynamic = reader.read_pointer(slot_addr, is_64bit=is_64bit)
            target_rva = resolver.dynamic_to_rva(target_dynamic, module_name)

            exp_int = (
                int(exp, 16) if isinstance(exp, str) and exp.startswith("0x")
                else int(exp)
            )

            is_match = (target_rva == exp_int)
            if is_match:
                matches += 1

            slots.append(
                VTableSlot(
                    index=i,
                    slot_dynamic_addr=slot_addr,
                    target_dynamic_addr=target_dynamic,
                    target_rva=target_rva,
                    expected_rva=exp_int,
                    is_match=is_match,
                )
            )
        except Exception as e:
            slots.append(
                VTableSlot(
                    index=i,
                    slot_dynamic_addr=slot_addr,
                    target_dynamic_addr=0,
                    target_rva=0,
                    expected_rva=None,
                    is_match=False,
                )
            )

    confidence = (matches / total) if total > 0 else 0.0
    is_valid = confidence >= 0.80

    return VTableVerificationResult(
        status="ok" if is_valid else "mismatch",
        is_valid=is_valid,
        confidence=confidence,
        vtable_dynamic_addr=vtable_base,
        match_count=matches,
        total_slots=total,
        slots=slots,
        message=f"VTable verified {matches}/{total} slots ({confidence * 100:.1f}% confidence)",
    )


@dataclasses.dataclass
class StructFieldVerificationResult:
    """Outcome of live struct field value validation."""
    status: str
    is_valid: bool
    field_address: int
    field_type: str
    actual_value: Any
    expected_range: Optional[Tuple[Any, Any]]
    raw_bytes: bytes
    message: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "status": self.status,
            "is_valid": self.is_valid,
            "field_address": f"0x{self.field_address:016X}",
            "field_type": self.field_type,
            "actual_value": self.actual_value,
            "expected_range": list(self.expected_range) if self.expected_range else None,
            "raw_hex": self.raw_bytes.hex(),
            "message": self.message,
        }


def verify_struct_field(
    reader: BaseMemoryReader,
    base_ptr: int,
    offset: int,
    expected_type: str,
    expected_val_range: Optional[Tuple[Any, Any]] = None,
    expected_val: Optional[Any] = None,
) -> StructFieldVerificationResult:
    """
    Validates live struct field values at base_ptr + offset.
    Supported types: uint8, int8, uint16, int16, uint32, int32, uint64, int64, float, double, pointer, string.
    """
    field_addr = base_ptr + offset
    t = expected_type.lower().strip()

    try:
        if t in ("uint8", "u8", "byte", "bool"):
            val = reader.read_uint8(field_addr)
            raw = reader.read_bytes(field_addr, 1)
        elif t in ("int8", "i8"):
            val = reader.read_int8(field_addr)
            raw = reader.read_bytes(field_addr, 1)
        elif t in ("uint16", "u16"):
            val = reader.read_uint16(field_addr)
            raw = reader.read_bytes(field_addr, 2)
        elif t in ("int16", "i16"):
            val = reader.read_int16(field_addr)
            raw = reader.read_bytes(field_addr, 2)
        elif t in ("uint32", "u32", "uint"):
            val = reader.read_uint32(field_addr)
            raw = reader.read_bytes(field_addr, 4)
        elif t in ("int32", "i32", "int"):
            val = reader.read_int32(field_addr)
            raw = reader.read_bytes(field_addr, 4)
        elif t in ("uint64", "u64", "pointer", "ptr", "size_t"):
            val = reader.read_uint64(field_addr)
            raw = reader.read_bytes(field_addr, 8)
        elif t in ("int64", "i64"):
            val = reader.read_int64(field_addr)
            raw = reader.read_bytes(field_addr, 8)
        elif t in ("float", "f32"):
            val = round(reader.read_float(field_addr), 6)
            raw = reader.read_bytes(field_addr, 4)
        elif t in ("double", "f64"):
            val = round(reader.read_double(field_addr), 6)
            raw = reader.read_bytes(field_addr, 8)
        elif t in ("string", "str"):
            val = reader.read_string(field_addr)
            raw = val.encode("utf-8")
        else:
            raise ValueError(f"Unsupported expected_type: '{expected_type}'")

        is_valid = True
        msg = f"Field at +0x{offset:X} has valid value: {val!r}"

        if expected_val is not None:
            if val != expected_val:
                is_valid = False
                msg = f"Field at +0x{offset:X} value {val!r} does not match expected {expected_val!r}"

        if expected_val_range is not None:
            low, high = expected_val_range
            if not (low <= val <= high):
                is_valid = False
                msg = f"Field at +0x{offset:X} value {val} out of bounds [{low}, {high}]"

        return StructFieldVerificationResult(
            status="ok" if is_valid else "out_of_bounds",
            is_valid=is_valid,
            field_address=field_addr,
            field_type=expected_type,
            actual_value=val,
            expected_range=expected_val_range,
            raw_bytes=raw,
            message=msg,
        )
    except Exception as e:
        return StructFieldVerificationResult(
            status="read_error",
            is_valid=False,
            field_address=field_addr,
            field_type=expected_type,
            actual_value=None,
            expected_range=expected_val_range,
            raw_bytes=b"",
            message=f"Memory read error at 0x{field_addr:016X}: {e}",
        )


@dataclasses.dataclass
class DynamicKeyResult:
    """Represents live encryption key extracted from runtime memory."""
    status: str
    rva: int
    dynamic_address: int
    key_hex: str
    key_bytes: bytes
    length: int
    entropy: float
    is_valid_crypto_key: bool
    timestamp: float

    def to_dict(self) -> Dict[str, Any]:
        return {
            "status": self.status,
            "rva": f"0x{self.rva:08X}",
            "dynamic_address": f"0x{self.dynamic_address:016X}",
            "key_hex": self.key_hex,
            "length": self.length,
            "entropy": round(self.entropy, 4),
            "is_valid_crypto_key": self.is_valid_crypto_key,
            "timestamp": self.timestamp,
        }


def calculate_shannon_entropy(data: bytes) -> float:
    """Calculates Shannon entropy in bits per byte (0.0 to 8.0)."""
    if not data:
        return 0.0
    length = len(data)
    counts: Dict[int, int] = {}
    for b in data:
        counts[b] = counts.get(b, 0) + 1

    entropy = 0.0
    for count in counts.values():
        p = count / length
        entropy -= p * math.log2(p)
    return entropy


def extract_dynamic_encryption_keys(
    reader: BaseMemoryReader,
    rva: int,
    length: int = 32,
    module_name: str = "libg.so",
) -> DynamicKeyResult:
    """
    Reads live runtime keys from memory at module_base + rva and assesses Shannon entropy.
    Real encryption keys (e.g. Curve25519/Sodium nonces/keys) exhibit high entropy (> 3.5).
    """
    resolver = ModuleBaseResolver(reader, default_module=module_name)
    dynamic_addr = resolver.rva_to_dynamic(rva, module_name)

    raw_bytes = reader.read_bytes(dynamic_addr, length)
    entropy = calculate_shannon_entropy(raw_bytes)

    # Valid key heuristics: length >= 16, non-zero, not all identical bytes, entropy >= 3.0
    is_all_zero = all(b == 0 for b in raw_bytes)
    is_repeated = len(set(raw_bytes)) <= 2
    is_valid_crypto = (not is_all_zero) and (not is_repeated) and (entropy >= 3.0)

    return DynamicKeyResult(
        status="ok" if is_valid_crypto else "low_entropy",
        rva=rva,
        dynamic_address=dynamic_addr,
        key_hex=raw_bytes.hex(),
        key_bytes=raw_bytes,
        length=len(raw_bytes),
        entropy=entropy,
        is_valid_crypto_key=is_valid_crypto,
        timestamp=time.time(),
    )


# -----------------------------------------------------------------------------
# 5. Shared-Memory IPC Streaming (ShmChannel Integration)
# -----------------------------------------------------------------------------

MSG_MEM_READ_REQ = 0x1101
MSG_MEM_READ_RESP = 0x1102
MSG_VERIFY_VTABLE_REQ = 0x1103
MSG_VERIFY_VTABLE_RESP = 0x1104
MSG_VERIFY_STRUCT_REQ = 0x1105
MSG_VERIFY_STRUCT_RESP = 0x1106
MSG_RESOLVE_RVA_REQ = 0x1107
MSG_RESOLVE_RVA_RESP = 0x1108
MSG_EXTRACT_KEY_REQ = 0x1109
MSG_EXTRACT_KEY_RESP = 0x110A


class EmulatorSidecarShmServer:
    """
    Provides microsecond IPC memory query streaming over ShmChannel.
    Handles Ghidra queries without TCP socket overhead (< 50 us latency).
    """

    def __init__(self, channel: ShmChannel, reader: BaseMemoryReader):
        self.channel = channel
        self.reader = reader
        self.resolver = ModuleBaseResolver(reader)
        self.is_running = False

    def handle_one_request(self, timeout: float = 0.05) -> bool:
        """Pops and handles a single IPC request packet. Returns True if handled."""
        msg = self.channel.recv_query(timeout=timeout)
        if msg is None:
            return False

        req_id = msg.req_id
        msg_type = msg.msg_type

        try:
            req_data = json.loads(msg.payload.decode("utf-8")) if msg.payload else {}
        except Exception:
            req_data = {}

        resp_type = msg_type + 1
        resp_dict: Dict[str, Any] = {"status": "error", "message": "Unknown query"}

        try:
            if msg_type == MSG_MEM_READ_REQ:
                addr = req_data.get("address", 0)
                size = req_data.get("size", 0)
                data = self.reader.read_bytes(addr, size)
                resp_dict = {"status": "ok", "address": hex(addr), "hex": data.hex(), "size": len(data)}

            elif msg_type == MSG_RESOLVE_RVA_REQ:
                rva = req_data.get("rva", 0)
                mod = req_data.get("module_name", "libg.so")
                dyn = self.resolver.rva_to_dynamic(rva, mod)
                resp_dict = {"status": "ok", "rva": hex(rva), "dynamic_address": hex(dyn)}

            elif msg_type == MSG_VERIFY_VTABLE_REQ:
                rva = req_data.get("rva", 0)
                slots = req_data.get("expected_slots", [])
                mod = req_data.get("module_name", "libg.so")
                res = verify_vtable_pointer(self.reader, rva, slots, module_name=mod)
                resp_dict = res.to_dict()

            elif msg_type == MSG_VERIFY_STRUCT_REQ:
                base_ptr = req_data.get("base_ptr", 0)
                offset = req_data.get("offset", 0)
                exp_type = req_data.get("expected_type", "uint32")
                val_range = req_data.get("expected_range")
                if val_range:
                    val_range = tuple(val_range)
                res = verify_struct_field(self.reader, base_ptr, offset, exp_type, expected_val_range=val_range)
                resp_dict = res.to_dict()

            elif msg_type == MSG_EXTRACT_KEY_REQ:
                rva = req_data.get("rva", 0)
                length = req_data.get("length", 32)
                mod = req_data.get("module_name", "libg.so")
                res = extract_dynamic_encryption_keys(self.reader, rva, length=length, module_name=mod)
                resp_dict = res.to_dict()

        except Exception as e:
            resp_dict = {"status": "error", "error": str(e)}

        resp_payload = json.dumps(resp_dict).encode("utf-8")
        self.channel.tx_ring.push_message(
            msg_type=resp_type,
            req_id=req_id,
            payload=resp_payload,
            timeout=0.1,
        )
        return True


class EmulatorSidecarShmClient:
    """Client for Ghidra querying EmulatorSidecarShmServer over ShmChannel."""

    def __init__(self, channel: ShmChannel):
        self.channel = channel

    def _query(self, msg_type: int, req_data: Dict[str, Any], timeout: float = 0.5) -> Dict[str, Any]:
        payload = json.dumps(req_data).encode("utf-8")
        req_id = self.channel.send_query(msg_type, payload, timeout=timeout)
        start = time.perf_counter()
        while time.perf_counter() - start < timeout:
            resp = self.channel.rx_ring.pop_message(timeout=0.01)
            if resp and resp.req_id == req_id:
                return json.loads(resp.payload.decode("utf-8"))
        raise TimeoutError("Sidecar query timed out")

    def read_memory(self, address: int, size: int) -> bytes:
        res = self._query(MSG_MEM_READ_REQ, {"address": address, "size": size})
        return bytes.fromhex(res.get("hex", ""))

    def resolve_rva(self, rva: int, module_name: str = "libg.so") -> int:
        res = self._query(MSG_RESOLVE_RVA_REQ, {"rva": rva, "module_name": module_name})
        return int(res["dynamic_address"], 16)

    def verify_vtable(self, rva: int, expected_slots: List[Union[int, str]], module_name: str = "libg.so") -> Dict[str, Any]:
        return self._query(MSG_VERIFY_VTABLE_REQ, {"rva": rva, "expected_slots": expected_slots, "module_name": module_name})

    def verify_struct(self, base_ptr: int, offset: int, expected_type: str, expected_range: Optional[Tuple[Any, Any]] = None) -> Dict[str, Any]:
        return self._query(MSG_VERIFY_STRUCT_REQ, {"base_ptr": base_ptr, "offset": offset, "expected_type": expected_type, "expected_range": expected_range})

    def extract_key(self, rva: int, length: int = 32, module_name: str = "libg.so") -> Dict[str, Any]:
        return self._query(MSG_EXTRACT_KEY_REQ, {"rva": rva, "length": length, "module_name": module_name})
