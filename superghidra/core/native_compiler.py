"""Compile and run small C/C++ drivers with gcc or the portable MSVC cl.exe.

The skin-path differential oracle and the HumanEval harness both call
`compile_and_run`. gcc/g++ or clang win when they are on PATH. Otherwise a
portable MSVC install is used. Set SUPERGHIDRA_MSVC_ROOT to a folder holding
`VC/Tools/MSVC/<ver>` and `Windows Kits/10`. When that variable is unset, the
portable tree at `E:\\03_Devops\\msvc` is used if it is present. INCLUDE and
LIB are set on the child process only.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Optional, Sequence, Tuple


def _newest_subdir(parent: Path) -> str:
    """Name of the highest-versioned subfolder, or "" if there is none."""
    try:
        names = [p.name for p in parent.iterdir() if p.is_dir() and p.name[:1].isdigit()]
    except OSError:
        return ""
    return max(names, key=lambda n: tuple(int(x) for x in n.split(".") if x.isdigit()), default="")


def _resolve_msvc_root() -> Path:
    """Portable MSVC tree. The environment variable overrides the known install."""
    env = os.environ.get("SUPERGHIDRA_MSVC_ROOT", "").strip()
    if env:
        return Path(env)
    default = Path(r"E:\03_Devops\msvc")
    if (default / "VC" / "Tools" / "MSVC").is_dir():
        return default
    return Path()


_MSVC_ROOT = _resolve_msvc_root()
_VC_VER = _newest_subdir(_MSVC_ROOT / "VC" / "Tools" / "MSVC") if _MSVC_ROOT.parts else ""
_SDK_VER = _newest_subdir(_MSVC_ROOT / "Windows Kits" / "10" / "Include") if _MSVC_ROOT.parts else ""
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


def _portable_cl() -> Optional[str]:
    return str(_CL) if _VC_VER and _CL.is_file() else None


def c_compiler() -> Optional[str]:
    return shutil.which("gcc") or shutil.which("clang") or _portable_cl()


def cxx_compiler() -> Optional[str]:
    return shutil.which("g++") or shutil.which("clang++") or _portable_cl()


def _is_cl(compiler: str) -> bool:
    return Path(compiler).name.lower() in ("cl.exe", "cl")


_NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0)


def _compiler_for(language: str) -> Optional[str]:
    return cxx_compiler() if language == "C++" else c_compiler()


def _compile_command(
    compiler: str,
    src_path: Path,
    exe_path: Path,
    language: str,
    extra_flags: Sequence[str],
) -> Tuple[list, Optional[dict]]:
    if _is_cl(compiler):
        cmd = [
            compiler,
            "/nologo",
            "/Od",
            "/utf-8",
            "/TC" if language != "C++" else "/TP",
            "/std:c++17" if language == "C++" else "/std:c11",
        ]
        if language == "C++":
            cmd.append("/EHsc")
        cmd.extend(extra_flags)
        cmd.extend([str(src_path), f"/Fe:{exe_path}", "/link", "/DEBUG:NONE"])
        return cmd, msvc_env()
    cmd = [compiler, "-O0", str(src_path), "-o", str(exe_path), "-lm", *extra_flags]
    if language == "C++":
        cmd.append("-std=c++17")
    return cmd, None


def _spawn(cmd: list, *, timeout: float, env: Optional[dict], cwd: str):
    return subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        timeout=timeout,
        env=env,
        cwd=cwd,
        creationflags=_NO_WINDOW,
    )


def compile_to_exe(
    source: str,
    exe_path: str | Path,
    *,
    language: str = "C",
    timeout_compile: float = 20.0,
    extra_flags: Sequence[str] = (),
) -> Tuple[bool, str]:
    """Compile `source` to `exe_path` and leave the executable on disk.

    Returns (ok, compiler_error). The caller owns `exe_path`.
    """
    compiler = _compiler_for(language)
    if compiler is None:
        return False, "no C compiler (gcc/clang/cl) found"
    exe = Path(exe_path)
    exe.parent.mkdir(parents=True, exist_ok=True)
    suffix = ".cpp" if language == "C++" else ".c"
    src_path = exe.with_suffix(suffix)
    src_path.write_text(source, encoding="utf-8")
    cmd, env = _compile_command(compiler, src_path, exe, language, extra_flags)
    try:
        compiled = _spawn(cmd, timeout=timeout_compile, env=env, cwd=str(exe.parent))
    except subprocess.TimeoutExpired:
        return False, "compile timeout"
    except OSError as exc:
        return False, f"compile spawn failed: {exc}"
    if compiled.returncode != 0 or not exe.is_file():
        err = ((compiled.stdout or "") + (compiled.stderr or "")).strip()
        return False, err or "compile failed"
    return True, ""


def _remove_tree(path: str) -> None:
    """Delete a compile directory. Windows may still be scanning unit.exe."""
    for _ in range(12):
        try:
            shutil.rmtree(path)
            return
        except OSError:
            time.sleep(0.05)
    shutil.rmtree(path, ignore_errors=True)


def compile_and_run(
    source: str,
    *,
    language: str = "C",
    timeout_compile: float = 20.0,
    timeout_run: float = 5.0,
    extra_flags: Sequence[str] = (),
    repeat: int = 1,
) -> Tuple[bool, str, str]:
    """Compile `source` to a console program and run it.

    Returns (ran_ok, combined_output, compiler_or_runtime_error).
    ran_ok is True only when the compiler succeeded and every run exited 0.
    `repeat` above 1 requires the same executable to agree, which drops a
    pass that depends on uninitialized bytes past a decompiled allocation.
    """
    compiler = _compiler_for(language)
    if compiler is None:
        return False, "", "no C compiler (gcc/clang/cl) found"

    suffix = ".cpp" if language == "C++" else ".c"
    tmp = tempfile.mkdtemp(prefix="sgc_")
    try:
        src_path = Path(tmp) / f"unit{suffix}"
        exe_path = Path(tmp) / "unit.exe"
        src_path.write_text(source, encoding="utf-8")
        cmd, env = _compile_command(compiler, src_path, exe_path, language, extra_flags)
        try:
            compiled = _spawn(cmd, timeout=timeout_compile, env=env, cwd=tmp)
        except subprocess.TimeoutExpired:
            return False, "", "compile timeout"
        except OSError as exc:
            return False, "", f"compile spawn failed: {exc}"
        if compiled.returncode != 0 or not exe_path.is_file():
            err = (compiled.stdout or "") + (compiled.stderr or "")
            return False, err, err.strip() or "compile failed"
        last_out = ""
        for _ in range(max(1, int(repeat))):
            try:
                ran = _spawn([str(exe_path)], timeout=timeout_run, env=None, cwd=tmp)
            except subprocess.TimeoutExpired:
                return False, "", "run timeout"
            except OSError as exc:
                return False, "", f"run spawn failed: {exc}"
            last_out = (ran.stdout or "") + (ran.stderr or "")
            if ran.returncode != 0:
                return False, last_out, f"exit {ran.returncode}: {last_out.strip()}"
        return True, last_out, ""
    finally:
        _remove_tree(tmp)
