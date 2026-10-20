"""Live checks that call the shipped byte-backed tools on real binaries.

These tests do not build edge lists, constraint lists, or block JSON.
"""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest

from superghidra.core.ghidra_oracle import WriteOverlay
from superghidra.core.live_binary_tools import (
    compile_usercall_prototype,
    deflatten_control_flow,
    query_binary_dataflow,
    roundtrip_real_chunk,
    solve_global_type_lattice,
)
from superghidra.formats.binary_loader import BinaryImage, load_binary

# Large stripped ARM64 ELF to test against; set SUPERGHIDRA_TEST_ARM64_ELF to enable.
REAL_LIBG = os.environ.get("SUPERGHIDRA_TEST_ARM64_ELF", "")
REAL_KERNEL32 = r"C:\Windows\System32\kernel32.dll"
_REAL_BINARIES = [REAL_LIBG, REAL_KERNEL32]

_FLAT_SOURCE = """\
int flattened_score(int a, int b) {
  volatile int state = 0; volatile int acc = 0;
  for (;;) { switch (state) {
    case 0: acc = a; state = 1; break;
    case 1: acc = acc + b; state = 2; break;
    case 2: return acc;
    default: return -1;
  } }
}
int main(void) { return flattened_score(2, 3) == 5 ? 0 : 1; }
"""

_USERCALL = "int calculate_vector@<x0>(void *this@<x0>, int64_t vec@<d0>)"
_REPO = Path(__file__).resolve().parents[2]


def _require(path: str) -> str:
    if not os.path.isfile(path):
        pytest.skip(f"{path} is missing")
    return path


def _inside_image(img: BinaryImage, addr: int) -> bool:
    """`section_for_va` returns None when `addr` is outside the image."""
    return img.section_for_va(addr) is not None


def _node_addrs(node: str):
    marker = "@0x"
    if marker not in node:
        return
    tail = node.split(marker, 1)[1]
    digits = []
    for ch in tail:
        if ch not in "0123456789abcdefABCDEF":
            break
        digits.append(ch)
    if digits:
        yield int("".join(digits), 16)


def _rep_snapshot(roots) -> dict:
    """Size and mtime of every `.rep` file or directory under `roots`."""
    found = {}
    skip = {".git", "__pycache__", "node_modules", ".venv"}
    for root in roots:
        root = Path(root)
        if root.is_file():
            root = root.parent
        if not root.exists():
            continue
        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = [d for d in dirnames if d not in skip]
            inside_rep = any(part.lower().endswith(".rep") for part in Path(dirpath).parts)
            for name in dirnames:
                if name.lower().endswith(".rep"):
                    fp = os.path.join(dirpath, name)
                    try:
                        st = os.stat(fp)
                    except OSError:
                        continue
                    found[fp] = (st.st_size, st.st_mtime_ns)
            for name in filenames:
                if not inside_rep and not name.lower().endswith(".rep"):
                    continue
                fp = os.path.join(dirpath, name)
                try:
                    st = os.stat(fp)
                except OSError:
                    continue
                found[fp] = (st.st_size, st.st_mtime_ns)
    return found


def _compile_flattened(exe: Path) -> None:
    """Compile the flattened switch with whatever C compiler native_compiler finds."""
    from superghidra.core import native_compiler

    if native_compiler.c_compiler() is None:
        pytest.skip("no C compiler (gcc/clang, or MSVC via SUPERGHIDRA_MSVC_ROOT)")
    ok, err = native_compiler.compile_to_exe(_FLAT_SOURCE, exe)
    if not ok or not exe.is_file():
        raise AssertionError(err or "compile_to_exe did not leave an executable")


@pytest.mark.integration
@pytest.mark.parametrize("path", _REAL_BINARIES, ids=["libg.so", "kernel32.dll"])
def test_query_binary_dataflow_reads_real_image(path: str) -> None:
    path = _require(path)
    res = query_binary_dataflow(path)
    assert res["is_reachable"] is True
    assert res["edge_count"] > 0
    assert res["binary_path"]
    assert os.path.normcase(os.path.abspath(res["binary_path"])) == os.path.normcase(os.path.abspath(path))
    img = load_binary(path)
    parsed = [addr for node in res["traversed_nodes"] for addr in _node_addrs(node)]
    assert parsed
    for addr in parsed:
        assert _inside_image(img, addr)


@pytest.mark.integration
@pytest.mark.parametrize("path", _REAL_BINARIES, ids=["libg.so", "kernel32.dll"])
def test_solve_global_type_lattice_reads_real_image(path: str) -> None:
    path = _require(path)
    res = solve_global_type_lattice(path)
    assert res["constraint_count"] > 0
    field_count = sum(len(fields) for fields in res["recovered_struct_layouts"].values())
    assert field_count > 0
    img = load_binary(path)
    assert res["source_addresses"]
    for addr in res["source_addresses"]:
        assert isinstance(addr, int)
        assert _inside_image(img, addr)


@pytest.mark.integration
def test_deflatten_control_flow_on_compiled_switch(tmp_path: Path) -> None:
    exe = tmp_path / "flattened_score.exe"
    _compile_flattened(exe)
    assert exe.is_file()
    res = deflatten_control_flow(str(exe))
    assert res["deflattened"] is True
    assert res["gotos_eliminated"] > 0
    assert res["back_edges_removed"] > 0


@pytest.mark.integration
def test_compile_usercall_prototype_overlay_only(tmp_path: Path) -> None:
    path = _require(REAL_LIBG)
    overlay = tmp_path / "usercall_overlay.json"
    roots = [tmp_path, Path.cwd(), _REPO, Path(path).parent]
    before = _rep_snapshot(roots)
    res = compile_usercall_prototype(_USERCALL, path, str(overlay), arch="arm64")
    after = _rep_snapshot(roots)
    assert after == before
    assert not list(tmp_path.rglob("*.rep"))
    assert "d0" in res["vector_spills"]
    assert res["readback"] == res["xml_cspec"]
    assert "d0" in res["readback"]
    img = load_binary(path)
    addr = res["function_address"]
    assert isinstance(addr, int)
    assert _inside_image(img, addr)
    assert WriteOverlay(str(overlay)).get_prototype(addr) == res["xml_cspec"]


@pytest.mark.integration
@pytest.mark.parametrize("codec", ["lz4", "zstd"])
def test_roundtrip_real_chunk_kernel32(codec: str) -> None:
    path = _require(REAL_KERNEL32)
    res = roundtrip_real_chunk(path, codec)
    assert res["chunk_len"] == 16384
    assert res["lossless"] is True
    assert res["slot_matches_stored"] is True
    assert res["comp_len"] > 0
    assert res["orig_len"] > 16384
