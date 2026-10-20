"""Compile and run small C/C++ drivers with gcc or the portable MSVC cl.exe.

The skin-path differential oracle and the HumanEval harness both call
`compile_and_run`. gcc/g++ win when they are on PATH. Otherwise the portable
MSVC at E:\\03_Devops\\msvc is used, with its INCLUDE and LIB set on the
child process only.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Optional, Sequence, Tuple


_MSVC_ROOT = Path(r"E:\03_Devops\msvc")
_VC_VER = "14.44.35207"
_SDK_VER = "10.0.26100.0"
_CL = _MSVC_ROOT / "VC" / "Tools" / "MSVC" / _VC_VER / "bin" / "Hostx64" / "x64" / "cl.exe"


def msvc_env() -> dict:
    """Environment in which the portable cl.exe can compile a console program."""
    env = os.environ.copy()
    vc = _MSVC_ROOT / "VC" / "Tools" / "MSVC" / _VC_VER
    sdk = _MSVC_ROOT / "Windows Kits" / "10"
    include = [
        vc / "include",
        sdk / "Include" / _SDK_VER / "ucrt",
        sdk / "Include" / _SDK_VER / "shared",
        sdk / "Include" / _SDK_VER / "um",
        sdk / "Include" / _SDK_VER / "winrt",
        sdk / "Include" / _SDK_VER / "cppwinrt",
    ]
    lib = [
        vc / "lib" / "x64",
        sdk / "Lib" / _SDK_VER / "ucrt" / "x64",
        sdk / "Lib" / _SDK_VER / "um" / "x64",
    ]
    bindir = vc / "bin" / "Hostx64" / "x64"
    sdkbin = sdk / "bin" / _SDK_VER / "x64"
    env["INCLUDE"] = ";".join(str(p) for p in include)
    env["LIB"] = ";".join(str(p) for p in lib)
    env["PATH"] = str(bindir) + os.pathsep + str(sdkbin) + os.pathsep + env.get("PATH", "")
    return env


def c_compiler() -> Optional[str]:
    return shutil.which("gcc") or shutil.which("clang") or (str(_CL) if _CL.is_file() else None)


def cxx_compiler() -> Optional[str]:
    return shutil.which("g++") or shutil.which("clang++") or (str(_CL) if _CL.is_file() else None)


def _is_cl(compiler: str) -> bool:
    return Path(compiler).name.lower() in ("cl.exe", "cl")


def compile_and_run(
    source: str,
    *,
    language: str = "C",
    timeout_compile: float = 20.0,
    timeout_run: float = 5.0,
    extra_flags: Sequence[str] = (),
) -> Tuple[bool, str, str]:
    """Compile `source` to a console program and run it.

    Returns (ran_ok, combined_output, compiler_or_runtime_error).
    ran_ok is True only when the compiler succeeded and the process exited 0.
    """
    compiler = cxx_compiler() if language == "C++" else c_compiler()
    if compiler is None:
        return False, "", "no C compiler (gcc/clang/cl) found"

    suffix = ".cpp" if language == "C++" else ".c"
    with tempfile.TemporaryDirectory(prefix="sgc_") as tmp:
        src_path = Path(tmp) / f"unit{suffix}"
        exe_path = Path(tmp) / "unit.exe"
        src_path.write_text(source, encoding="utf-8")
        env = msvc_env() if _is_cl(compiler) else None
        if _is_cl(compiler):
            cmd = [
                compiler,
                "/nologo",
                "/Od",
                "/TC" if language != "C++" else "/TP",
                "/std:c++17" if language == "C++" else "/std:c11",
                str(src_path),
                f"/Fe:{exe_path}",
                "/link",
                "/DEBUG:NONE",
            ]
        else:
            cmd = [compiler, "-O0", str(src_path), "-o", str(exe_path), "-lm", *extra_flags]
            if language == "C++":
                cmd.append("-std=c++17")
        try:
            compiled = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout_compile,
                env=env,
                cwd=tmp,
            )
        except subprocess.TimeoutExpired:
            return False, "", "compile timeout"
        except OSError as exc:
            return False, "", f"compile spawn failed: {exc}"
        if compiled.returncode != 0 or not exe_path.is_file():
            err = (compiled.stdout or "") + (compiled.stderr or "")
            return False, err, err.strip() or "compile failed"
        try:
            ran = subprocess.run(
                [str(exe_path)],
                capture_output=True,
                text=True,
                timeout=timeout_run,
                cwd=tmp,
            )
        except subprocess.TimeoutExpired:
            return False, "", "run timeout"
        out = (ran.stdout or "") + (ran.stderr or "")
        if ran.returncode != 0:
            return False, out, f"exit {ran.returncode}: {out.strip()}"
        return True, out, ""
