#!/usr/bin/env python3
"""
test_g3a_regressions.py
=======================
Regression test suite for Agent G3a: Emulator Safety & Honest Outputs.

Verifies:
1. Fleet Guard:
   - 127.0.0.1:5565 (ADB TCP alias of protected emulator-5564) is strictly blocked
   - MEmu_0 <-> 127.0.0.1:21503 alias is blocked
   - Unknown serials are denied by default (authorized_for_experiments=False)
   - FridaMemoryReader classifies attach as mutation (blocked on protected/unknown serials)
   - Frida connection errors are raised, not silently swallowed
   - EmulatorFleetGuard.validate_process requires explicit allow_readonly_farm=True opt-in
   - Win32ProcessMemoryReader requires explicit device_serial; refuses protected/unknown serials
   - extract_dynamic_encryption_keys restricted strictly to authorized sandbox serials
2. Neural Decompiler Pipeline:
   - Generic neutral names (sub_<addr>, field_0x<offset>)
   - Confidence <= 0.3, model_identifier="heuristic-fallback", source="heuristic"
   - Real LLM errors surfaced on prediction.error and logged
3. Colab Cloud Orchestrator:
   - Missing source binary raises FileNotFoundError in stage_binary_to_ram_disk
   - Reconstruction pipeline returns no canned symbols or fixed ledger obligations
   - Honors dry_run=True
   - Upload defaults to False; restricted strictly to <workspace>/results with allow_patterns
"""

from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import colab_cloud_orchestrator
from colab_cloud_orchestrator import CloudConfig, ColabCloudOrchestrator
import emulator_memory_sidecar
from emulator_memory_sidecar import (
    EmulatorFleetGuard,
    FleetSafetyViolationError,
    FridaMemoryReader,
    MockMemoryReader,
    Win32ProcessMemoryReader,
    extract_dynamic_encryption_keys,
)
import neural_decompiler_pipeline
from neural_decompiler_pipeline import (
    DecompiledSkeleton,
    LLMDecompilerClient,
    NeuralDecompilerPipeline,
    NeuralPrediction,
)


class TestG3aFleetGuardRegressions(unittest.TestCase):
    """Verifies workstation emulator fleet safety and alias protection."""

    def test_tcp_alias_5565_blocked(self):
        """127.0.0.1:5565 is the ADB TCP alias of protected live farm emulator-5564."""
        info = EmulatorFleetGuard.identify_device("127.0.0.1:5565")
        self.assertTrue(info.is_live_farm_automation)
        self.assertFalse(info.authorized_for_experiments)

        # Blocked without explicit allow_readonly_farm acknowledgement
        with self.assertRaises(FleetSafetyViolationError):
            EmulatorFleetGuard.validate_target("127.0.0.1:5565", is_mutation=False, allow_readonly_farm=False)

        # Strictly blocked for mutations regardless of ack
        with self.assertRaises(FleetSafetyViolationError):
            EmulatorFleetGuard.validate_target("127.0.0.1:5565", is_mutation=True, allow_readonly_farm=True)

    def test_memu_0_alias_protected(self):
        """MEmu_0 is system default VM index 0 and strictly off limits."""
        info = EmulatorFleetGuard.identify_device("MEmu_0")
        self.assertTrue(info.is_system_default_protected)

        with self.assertRaises(FleetSafetyViolationError):
            EmulatorFleetGuard.validate_target("MEmu_0", is_mutation=False)

    def test_unknown_serial_denied_by_default(self):
        """Unknown serials default to authorized_for_experiments=False and deny mutations."""
        info = EmulatorFleetGuard.identify_device("emulator-9999")
        self.assertFalse(info.authorized_for_experiments)
        self.assertEqual(info.instance_name, "GenericDevice")

        with self.assertRaises(FleetSafetyViolationError):
            EmulatorFleetGuard.validate_target("emulator-9999", is_mutation=True)

    def test_frida_attach_counted_as_mutation(self):
        """FridaMemoryReader injects agent and must be treated as a mutation."""
        # Live farm device emulator-5564 blocked
        with self.assertRaises(FleetSafetyViolationError):
            FridaMemoryReader(device_serial="emulator-5564", target_process=1001, allow_readonly_farm=True)

        # 127.0.0.1:5565 alias blocked
        with self.assertRaises(FleetSafetyViolationError):
            FridaMemoryReader(device_serial="127.0.0.1:5565", target_process=1001)

        # MEmu_0 protected index 0 blocked
        with self.assertRaises(FleetSafetyViolationError):
            FridaMemoryReader(device_serial="127.0.0.1:21503", target_process=1001)

        # Unknown device blocked from mutation
        with self.assertRaises(FleetSafetyViolationError):
            FridaMemoryReader(device_serial="emulator-9999", target_process=1001)

    def test_frida_connection_error_raised(self):
        """Frida connection errors must raise an exception rather than being silently ignored."""
        # Authorized sandbox device emulator-5580 passes fleet gate, but fails connection if offline
        mock_frida = mock.MagicMock()
        mock_device = mock.MagicMock()
        mock_device.attach.side_effect = RuntimeError("Device disconnected")
        mock_frida.get_device.return_value = mock_device
        with mock.patch.dict("sys.modules", {"frida": mock_frida}):
            with self.assertRaises(ConnectionError) as ctx:
                FridaMemoryReader(device_serial="emulator-5580", target_process=1001)
            self.assertIn("Frida connection failed", str(ctx.exception))

    def test_validate_process_requires_explicit_opt_in(self):
        """validate_process defaults allow_readonly_farm=False and requires explicit opt-in."""
        # Blocked by default on live farm device
        with self.assertRaises(FleetSafetyViolationError):
            EmulatorFleetGuard.validate_process("emulator-5564", "com.supercell.hayday")

        # Allowed only with explicit opt-in
        ok = EmulatorFleetGuard.validate_process(
            "emulator-5564", "com.supercell.hayday", allow_readonly_farm=True
        )
        self.assertTrue(ok)

        # Authorized sandbox works with default False
        ok_sandbox = EmulatorFleetGuard.validate_process("emulator-5580", "com.target.app")
        self.assertTrue(ok_sandbox)

    def test_win32_reader_requires_device_serial(self):
        """Win32ProcessMemoryReader requires caller to pass verified sandbox device_serial."""
        # Refuses unknown serial
        with self.assertRaises(FleetSafetyViolationError):
            Win32ProcessMemoryReader(pid=1234, device_serial="emulator-unknown")

        # Refuses protected live game serial
        with self.assertRaises(FleetSafetyViolationError):
            Win32ProcessMemoryReader(pid=1234, device_serial="emulator-5564")

        # Check docstring contains the warning
        self.assertIn("pid->serial binding cannot be auto-verified", Win32ProcessMemoryReader.__doc__)

    def test_extract_dynamic_encryption_keys_authorized_sandbox_only(self):
        """extract_dynamic_encryption_keys is restricted to authorized sandbox devices."""
        mock_reader = MockMemoryReader(device_serial="emulator-5580")
        mock_reader.write_memory(0x7F00001000, bytes([i * 17 % 256 for i in range(32)]))

        # Authorized sandbox succeeds
        res = extract_dynamic_encryption_keys(
            reader=mock_reader,
            rva=0x1000,
            length=32,
            device_serial="emulator-5580",
        )
        self.assertEqual(res.status, "ok")
        self.assertGreater(res.entropy, 3.0)

        # Protected device emulator-5564 is refused
        with self.assertRaises(FleetSafetyViolationError):
            extract_dynamic_encryption_keys(
                reader=mock_reader,
                rva=0x1000,
                length=32,
                device_serial="emulator-5564",
            )

        # TCP alias 127.0.0.1:5565 is refused
        with self.assertRaises(FleetSafetyViolationError):
            extract_dynamic_encryption_keys(
                reader=mock_reader,
                rva=0x1000,
                length=32,
                device_serial="127.0.0.1:5565",
            )

        # Unknown device is refused
        with self.assertRaises(FleetSafetyViolationError):
            extract_dynamic_encryption_keys(
                reader=mock_reader,
                rva=0x1000,
                length=32,
                device_serial="emulator-unregistered",
            )


class TestG3aNeuralDecompilerRegressions(unittest.TestCase):
    """Verifies honest generic heuristics and surfaced errors in neural pipeline."""

    def test_neural_fallback_neutral_names_and_metadata(self):
        """Fallback produces neutral names from evidence, low confidence, and source=heuristic."""
        pipeline = NeuralDecompilerPipeline()
        skeleton = DecompiledSkeleton(
            function_address=0x104050,
            function_rva=0x4050,
            raw_source="void test() { *(int *)(ptr + 0x24) = 1; }",
            skeleton_source="void test() { *(int *)(v0 + 0x24) = 1; }",
            variable_mapping={},
            parameter_count=1,
            call_targets=[],
            memory_displacements=[0x20, 0x24],
            vtable_call_offsets=[0x30],
        )

        pred = pipeline.mock_neural_inference(skeleton)
        self.assertEqual(pred.predicted_function_name, "sub_104050")
        self.assertEqual(pred.model_identifier, "heuristic-fallback")
        self.assertEqual(pred.source, "heuristic")
        self.assertLessEqual(pred.confidence, 0.30)
        self.assertIn(0x24, pred.predicted_struct_fields)
        self.assertEqual(pred.predicted_struct_fields[0x24], ("int32_t", "field_0x24"))
        self.assertIn(0x20, pred.predicted_struct_fields)
        self.assertEqual(pred.predicted_struct_fields[0x20], ("int32_t", "field_0x20"))
        self.assertIn(0x30, pred.predicted_struct_fields)
        self.assertEqual(pred.predicted_struct_fields[0x30], ("void*", "vfunc_0x30"))

    def test_llm_failure_surfaced_on_prediction(self):
        """When LLM inference fails, error is surfaced and not silently hidden."""
        pipeline = NeuralDecompilerPipeline()
        skeleton = DecompiledSkeleton(
            function_address=0x1000,
            function_rva=0x1000,
            raw_source="void foo() {}",
            skeleton_source="void foo() {}",
            variable_mapping={},
            parameter_count=1,
            call_targets=[],
            memory_displacements=[0x10],
            vtable_call_offsets=[],
        )

        mock_client = LLMDecompilerClient(endpoint_url="http://offline.local")
        with mock.patch.object(mock_client, "predict", side_effect=RuntimeError("Endpoint offline 503")):
            pred = pipeline.predict_skin(skeleton, llm_client=mock_client)
            self.assertEqual(pred.source, "heuristic")
            self.assertEqual(pred.model_identifier, "heuristic-fallback")
            self.assertIsNotNone(pred.error)
            self.assertIn("Endpoint offline 503", pred.error)
            self.assertEqual(pred.predicted_function_name, "sub_1000")


class TestG3aColabCloudRegressions(unittest.TestCase):
    """Verifies honest cloud execution, file safety, and Hugging Face upload restrictions."""

    def test_missing_binary_raises_file_not_found(self):
        """stage_binary_to_ram_disk raises FileNotFoundError when source file is missing."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            with self.assertRaises(FileNotFoundError):
                ColabCloudOrchestrator.stage_binary_to_ram_disk(
                    src_path=os.path.join(tmp_dir, "non_existent_binary.so"),
                    ram_disk_dir=tmp_dir,
                )

    def test_no_canned_symbols_and_honors_dry_run(self):
        """run_reconstruction_pipeline contains no canned symbols and honors dry_run."""
        with tempfile.TemporaryDirectory() as tmp_ws:
            dummy_bin = os.path.join(tmp_ws, "libg.so")
            with open(dummy_bin, "wb") as f:
                f.write(b"\x7fELF" + b"\x00" * 256)

            cfg = CloudConfig(workspace_dir=tmp_ws, tensor_matrix_size=32)

            # Dry run honored
            dry_res = ColabCloudOrchestrator.run_reconstruction_pipeline(cfg, dummy_bin, dry_run=True)
            self.assertEqual(dry_res["status"], "dry_run")
            self.assertEqual(dry_res["symbols_reconstructed"], 0)
            self.assertEqual(dry_res["evidence_ledger_entries"], 0)
            self.assertIsNone(dry_res["bundle_zip"])

            # Full run: no canned outputs
            res = ColabCloudOrchestrator.run_reconstruction_pipeline(cfg, dummy_bin, dry_run=False)
            self.assertEqual(res["status"], "success")
            self.assertEqual(res["symbols_reconstructed"], 0)
            self.assertEqual(res["evidence_ledger_entries"], 0)
            self.assertEqual(res["stages"]["symbol_reconstruction"], "not_implemented")
            self.assertEqual(res["stages"]["evidence_ledger"], "not_implemented")

            # Check symbols file is empty dict, not canned GameWorld::tick
            with open(res["symbols_path"], "r", encoding="utf-8") as f:
                symbols = json.load(f)
            self.assertEqual(symbols, {})

    def test_upload_restricted_to_results_and_default_false(self):
        """Hugging Face upload defaults to False and only uploads <workspace>/results."""
        with tempfile.TemporaryDirectory() as tmp_ws:
            dummy_bin = os.path.join(tmp_ws, "libg.so")
            with open(dummy_bin, "wb") as f:
                f.write(b"\x7fELF" + b"\x00" * 256)

            cfg = CloudConfig(
                workspace_dir=tmp_ws,
                hf_repo_id="test/repo",
                tensor_matrix_size=32,
            )

            # Case 1: Default upload=False -> never uploads even if token is present
            with mock.patch.dict(os.environ, {"HF_TOKEN": "hf_test_token"}):
                with mock.patch("colab_cloud_orchestrator.HAS_HF", True):
                    with mock.patch("colab_cloud_orchestrator.HfApi") as MockHfApi:
                        mock_api_instance = MockHfApi.return_value
                        res = ColabCloudOrchestrator.run_reconstruction_pipeline(
                            cfg, dummy_bin, dry_run=False
                        )
                        self.assertFalse(res["hf_uploaded"])
                        mock_api_instance.upload_folder.assert_not_called()

            # Case 2: Explicit upload=True -> uploads ONLY results directory with allow_patterns
            with mock.patch.dict(os.environ, {"HF_TOKEN": "hf_test_token"}):
                with mock.patch("colab_cloud_orchestrator.HAS_HF", True):
                    with mock.patch("colab_cloud_orchestrator.HfApi") as MockHfApi:
                        mock_api_instance = MockHfApi.return_value
                        res = ColabCloudOrchestrator.run_reconstruction_pipeline(
                            cfg, dummy_bin, dry_run=False, upload=True
                        )
                        self.assertTrue(res["hf_uploaded"])
                        mock_api_instance.upload_folder.assert_called_once()
                        call_kwargs = mock_api_instance.upload_folder.call_args[1]
                        self.assertTrue(
                            call_kwargs["folder_path"].endswith("results"),
                            f"Uploaded path '{call_kwargs['folder_path']}' does not end with 'results'",
                        )
                        self.assertIn("allow_patterns", call_kwargs)
                        self.assertIn("*.json", call_kwargs["allow_patterns"])
                        self.assertIn("*.sym", call_kwargs["allow_patterns"])


if __name__ == "__main__":
    unittest.main()
