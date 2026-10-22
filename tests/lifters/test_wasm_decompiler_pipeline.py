"""
Unit test suite for WebAssembly Decompiler Pipeline & Browser UI Generator.
"""

import os
import tempfile
import pytest

from superghidra.lifters.wasm_decompiler_pipeline import (
    WasmModuleBuilder,
    WasmValType,
    WasmSection,
    create_token_accelerator_wasm,
    CSourceTokenizer,
    WasmDecompilerAppGenerator,
    export_wasm_decompiler_package,
    WasmViewerServer,
)
import wasm_decompiler_pipeline as root_wasm


def test_wasm_module_builder_valid_binary():
    builder = WasmModuleBuilder()
    t0 = builder.add_type(params=[WasmValType.I32, WasmValType.I32], results=[WasmValType.I32])
    builder.add_function(
        type_index=t0,
        code_bytes=bytes([0x20, 0x00, 0x20, 0x01, 0x6A, 0x0B]), # local.get 0, local.get 1, i32.add, end
        export_name="add"
    )
    builder.add_memory(min_pages=1, max_pages=2, export_name="memory")
    wasm_bytes = builder.build()

    assert len(wasm_bytes) > 8
    assert WasmModuleBuilder.validate_wasm_header(wasm_bytes)
    assert wasm_bytes[:4] == b"\x00asm"
    assert wasm_bytes[4:8] == b"\x01\x00\x00\x00"


def test_create_token_accelerator_wasm():
    wasm_bytes = create_token_accelerator_wasm()
    assert WasmModuleBuilder.validate_wasm_header(wasm_bytes)
    assert b"add_offsets" in wasm_bytes
    assert b"is_underscore" in wasm_bytes
    assert b"memory" in wasm_bytes


def test_csource_tokenizer():
    c_code = """
    // Process incoming packet
    int handle_event(uint32_t event_id, void* ctx) {
        if (event_id == 0x10A4) {
            return 1;
        }
        return 0;
    }
    """
    tokens = CSourceTokenizer.tokenize(c_code, base_rva=0x401000)
    assert len(tokens) > 10

    keywords = [t.text for t in tokens if t.token_type == "keyword"]
    assert "if" in keywords
    assert "return" in keywords

    types = [t.text for t in tokens if t.token_type == "type"]
    assert "int" in types
    assert "uint32_t" in types
    assert "void" in types

    literals = [t for t in tokens if t.token_type == "literal"]
    hex_lit = [l for l in literals if l.text == "0x10A4"]
    assert len(hex_lit) == 1
    assert hex_lit[0].xref_target == 0x10A4


def test_wasm_app_generator_bundle():
    gen = WasmDecompilerAppGenerator()
    code = "int run() { return 42; }"
    bundle = gen.generate_bundle(
        function_name="run",
        decompiled_c=code,
        rva=0x500000,
        cfg_nodes=[{"id": "entry", "label": "loc_500000", "lines": ["int run() { return 42; }"]}],
        cfg_edges=[]
    )

    assert "html" in bundle
    assert "js" in bundle
    assert "wasm_bytes" in bundle
    assert "SuperGhidra Wasm Decompiler" in bundle["html"]
    assert "0x500000" in bundle["html"]
    assert bundle["wasm_bytes"][:4] == b"\x00asm"


def test_export_wasm_decompiler_package():
    with tempfile.TemporaryDirectory() as tmpdir:
        res = export_wasm_decompiler_package(
            function_name="sub_1000",
            decompiled_c="void sub_1000() { return; }",
            rva=0x1000,
            output_dir=tmpdir
        )

        assert os.path.exists(res["html_path"])
        assert os.path.exists(res["js_path"])
        assert os.path.exists(res["wasm_path"])
        assert os.path.getsize(res["wasm_path"]) > 10


def test_wasm_viewer_server_lifecycle():
    with tempfile.TemporaryDirectory() as tmpdir:
        export_wasm_decompiler_package(
            function_name="sub_2000",
            decompiled_c="void sub_2000() { return; }",
            rva=0x2000,
            output_dir=tmpdir
        )

        server = WasmViewerServer(directory=tmpdir, port=9876)
        url = server.start()
        assert "http://127.0.0.1:9876/index.html" in url
        server.stop()


def test_root_shim_export():
    assert root_wasm.WasmModuleBuilder is WasmModuleBuilder
    assert root_wasm.WasmDecompilerAppGenerator is WasmDecompilerAppGenerator
