"""
cross_platform_headless_harness.py
==================================
SuperGhidra Cross-Platform Headless Execution Harness.

Implements Section 5 of GHIDRA_REFORMATION_ARCHITECTURAL_SPEC.md:
- Cross-platform configuration for Windows, Linux, and Google Colab runtimes.
- Optimal PE Loader & ELF Loader flag generation:
    * PE:  -loader PeLoader -loader-parseCliHeaders true -loader-ordinalLookup true -loader-showDebugLineNumbers true
    * ELF: -loader ElfLoader -loader-applyDataImageBase true -loader-loadLibraries true -loader-libraryLoadDepth 0
- Resource & concurrency tuning: -max-cpu, -analysisTimeoutPerPage 120, RAM disk (/dev/shm) isolation.
- Ephemeral project policies: -readOnly, -deleteProject.
- JADX deobfuscation integration: jadx --deobf -j <threads> with tuned G1GC heap bounds.
"""

from __future__ import annotations

import dataclasses
import os
import platform
from typing import Dict, List, Tuple


@dataclasses.dataclass
class HeadlessProfile:
    """Represents a tuned headless execution profile for a target OS and binary type."""
    os_target: str              # "windows", "linux", or "colab"
    binary_format: str          # "elf" or "pe"
    ghidra_install_dir: str
    project_location: str
    project_name: str
    target_binary_path: str
    max_cpu_cores: int = 4
    analysis_timeout_seconds: int = 120
    use_ram_disk: bool = False
    ephemeral_project: bool = True
    pre_script_path: str | None = None
    post_script_path: str | None = None
    script_paths: List[str] = dataclasses.field(default_factory=list)

    def to_command_args(self) -> List[str]:
        """Constructs canonical analyzeHeadless argument list."""
        executable = "analyzeHeadless.bat" if self.os_target == "windows" else "analyzeHeadless"
        head_path = os.path.join(self.ghidra_install_dir, "support", executable)

        # Base project parameters
        cmd = [head_path, self.project_location, self.project_name]

        # Ephemeral project configuration
        if self.ephemeral_project:
            cmd.extend(["-readOnly", "-deleteProject"])

        # Target file import
        cmd.extend(["-import", self.target_binary_path])

        # Binary loader flags (Section 5.1)
        if self.binary_format.lower() == "elf":
            cmd.extend([
                "-loader", "ElfLoader",
                "-loader-applyDataImageBase", "true",
                "-loader-loadLibraries", "true",
                "-loader-libraryLoadDepth", "0"
            ])
        elif self.binary_format.lower() == "pe":
            cmd.extend([
                "-loader", "PeLoader",
                "-loader-parseCliHeaders", "true",
                "-loader-ordinalLookup", "true",
                "-loader-showDebugLineNumbers", "true"
            ])

        # Resource bounds & timeouts
        cmd.extend([
            "-max-cpu", str(self.max_cpu_cores),
            "-analysisTimeoutPerPage", str(self.analysis_timeout_seconds)
        ])

        # Script directory search paths
        for p in self.script_paths:
            cmd.extend(["-scriptPath", p])

        # Pre-Script (Prunes heavy analyzers before analysis starts)
        if self.pre_script_path:
            cmd.extend(["-preScript", self.pre_script_path])

        # Post-Script (Runs extraction/reporting after analysis)
        if self.post_script_path:
            cmd.extend(["-postScript", self.post_script_path])

        return cmd


class HeadlessEnvironmentConfigurator:
    """Manages environment setup, RAM disks, and CLI flags across Windows, Linux, and Colab."""

    @staticmethod
    def detect_environment() -> str:
        """Detects whether running on Windows, native Linux, or Google Colab."""
        if platform.system().lower() == "windows":
            return "windows"
        if os.path.exists("/content") or "COLAB_GPU" in os.environ:
            return "colab"
        return "linux"

    @classmethod
    def get_optimal_ram_disk_path(cls, env: str | None = None) -> str:
        """Returns optimal RAM disk mount path for zero-I/O ephemeral analysis."""
        target_env = env or cls.detect_environment()
        if target_env in ("linux", "colab"):
            if os.path.exists("/dev/shm") and os.access("/dev/shm", os.W_OK):
                return "/dev/shm"
            return "/tmp"
        # Windows fallback (temporary directory or dedicated RAM disk if available)
        return os.environ.get("TEMP", "C:\\Temp")

    @classmethod
    def generate_jadx_deobf_command(
        cls,
        apk_path: str,
        output_dir: str,
        threads: int = 4,
        max_heap_gb: int = 8
    ) -> Tuple[List[str], Dict[str, str]]:
        """
        Builds JADX command line for multi-DEX deobfuscation with G1GC bounds (Section 5.1).
        """
        jadx_bin = "jadx.bat" if platform.system().lower() == "windows" else "jadx"
        cmd = [
            jadx_bin,
            "--deobf",
            "-j", str(threads),
            "-d", output_dir,
            apk_path
        ]
        env = os.environ.copy()
        env["JAVA_OPTS"] = f"-Xmx{max_heap_gb}g -XX:+UseG1GC"
        return cmd, env

    @classmethod
    def build_colab_t4_gpu_environment(cls) -> Dict[str, str]:
        """
        Configures environment variables for Colab NVIDIA T4 GPU neural decompilation (Section 5.2).
        """
        return {
            "PYTORCH_CUDA_ALLOC_CONF": "expandable_segments:True",
            "OMP_NUM_THREADS": "4",
            "KMP_AFFINITY": "granularity=fine,compact,1,0",
            "CUDA_DEVICE_ORDER": "PCI_BUS_ID",
        }

    @classmethod
    def build_colab_tpu_v5e_environment(cls) -> Dict[str, str]:
        """
        Configures environment variables for Colab Cloud TPU v5e JAX/XLA execution (Section 5.2).
        """
        return {
            "XLA_PYTHON_CLIENT_PREALLOCATE": "false",
            "JAX_XLA_FLAGS": "--xla_dump_to=/tmp/xla_dump --xla_cpu_multi_thread_eigen=false",
            "TF_CPP_MIN_LOG_LEVEL": "2",
        }
