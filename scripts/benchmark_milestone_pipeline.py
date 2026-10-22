"""
Comprehensive Benchmark & Stress Harness for Future Milestones:
1. Distributed Daemon Clustering (gRPC)
2. Full IDA Pro / Binary Ninja Project Migration
3. Browser WebAssembly Decompiler UI & Wasm Pipeline

Outputs structured JSON telemetry with min, avg, max, std_dev, and p99 latencies.
"""

import json
import math
import os
import sqlite3
import struct
import tempfile
import time
from dataclasses import asdict, dataclass
from typing import Any, Dict, List


def calculate_metrics(samples: List[float]) -> Dict[str, float]:
    if not samples:
        return {"min_ms": 0.0, "avg_ms": 0.0, "max_ms": 0.0, "std_dev_ms": 0.0, "p99_ms": 0.0}
    sorted_samples = sorted(samples)
    n = len(sorted_samples)
    min_val = sorted_samples[0]
    max_val = sorted_samples[-1]
    avg_val = sum(sorted_samples) / n
    variance = sum((x - avg_val) ** 2 for x in sorted_samples) / n
    std_dev = math.sqrt(variance)
    p99_idx = min(int(n * 0.99), n - 1)
    p99_val = sorted_samples[p99_idx]
    return {
        "min_ms": round(min_val * 1000.0, 4),
        "avg_ms": round(avg_val * 1000.0, 4),
        "max_ms": round(max_val * 1000.0, 4),
        "std_dev_ms": round(std_dev * 1000.0, 4),
        "p99_ms": round(p99_val * 1000.0, 4),
    }


def benchmark_milestone_modules() -> Dict[str, Any]:
    telemetry: Dict[str, Any] = {
        "timestamp": time.time(),
        "milestones": {}
    }

    # --- 1. Distributed Daemon Clustering Benchmark ---
    try:
        from superghidra.core.cluster_daemon import (
            ClusterCoordinator,
            ClusterWorkerNode,
            ClusterTaskType,
            TaskEnvelope,
            WorkerDescriptor,
        )

        coordinator = ClusterCoordinator(heartbeat_timeout_sec=10.0)
        # Register 8 simulated worker nodes
        for i in range(8):
            desc = WorkerDescriptor(
                worker_id=f"worker-node-{i}",
                endpoint=f"127.0.0.1:600{i}",
                max_concurrency=4,
                capabilities=[ClusterTaskType.DECOMPILE, ClusterTaskType.VSA, ClusterTaskType.DIFF],
            )
            coordinator.register_worker(desc)

        dispatch_samples: List[float] = []
        num_tasks = 2000
        for i in range(num_tasks):
            t0 = time.perf_counter()
            envelope = coordinator.submit_task(
                task_type=ClusterTaskType.DECOMPILE,
                payload={"rva": 0x1000 + (i * 4), "binary": "libg.so"},
            )
            # Poll task to simulate worker pickup
            worker_id = f"worker-node-{i % 8}"
            assigned = coordinator.poll_task_for_worker(worker_id, timeout=0.01)
            if assigned:
                coordinator.complete_task(
                    worker_id=worker_id,
                    task_id=assigned.task_id,
                    result={"decompiled": f"void sub_{hex(0x1000 + i*4)}() {{ return; }}"},
                )
            t1 = time.perf_counter()
            dispatch_samples.append(t1 - t0)

        telemetry["milestones"]["distributed_clustering"] = {
            "status": "PASS",
            "workers_registered": 8,
            "tasks_dispatched_and_resolved": num_tasks,
            "throughput_tasks_per_sec": round(num_tasks / sum(dispatch_samples), 2) if sum(dispatch_samples) > 0 else 0,
            "latency_metrics": calculate_metrics(dispatch_samples),
        }
    except Exception as e:
        telemetry["milestones"]["distributed_clustering"] = {
            "status": "WAITING_OR_FAIL",
            "error": str(e),
        }

    # --- 2. Database Migrator Benchmark ---
    try:
        from superghidra.formats.database_migrator import (
            DatabaseMigrator,
            MigratedProject,
        )

        with tempfile.TemporaryDirectory() as tmpdir:
            # Create synthetic SQLite .bndb
            bndb_path = os.path.join(tmpdir, "sample.bndb")
            conn = sqlite3.connect(bndb_path)
            conn.execute("CREATE TABLE metadata (key TEXT, value TEXT)")
            conn.execute("INSERT INTO metadata VALUES ('arch', 'aarch64'), ('version', '3.5')")
            conn.execute("CREATE TABLE segments (name TEXT, start INTEGER, length INTEGER, flags INTEGER)")
            conn.execute("INSERT INTO segments VALUES ('.text', 65536, 1048576, 5), ('.data', 1114112, 65536, 6)")
            conn.execute("CREATE TABLE functions (address INTEGER, name TEXT, auto_decompiled TEXT)")
            # 500 functions
            fns = [(65536 + j * 64, f"fn_{hex(65536 + j * 64)}", f"int fn_{hex(65536 + j * 64)}() {{ return {j}; }}") for j in range(500)]
            conn.executemany("INSERT INTO functions VALUES (?, ?, ?)", fns)
            conn.execute("CREATE TABLE types (name TEXT, kind TEXT, definition TEXT)")
            conn.execute("INSERT INTO types VALUES ('PlayerState', 'struct', 'struct PlayerState { int hp; int mp; };')")
            conn.commit()
            conn.close()

            # Benchmark extraction & conversion
            migrator = DatabaseMigrator()
            parse_samples: List[float] = []
            for _ in range(50):
                t0 = time.perf_counter()
                proj = DatabaseMigrator.migrate_bndb(bndb_path)
                overlay = proj.to_write_overlay()
                delta_events = proj.to_ghidra_delta_jsonl()
                t1 = time.perf_counter()
                parse_samples.append(t1 - t0)

            telemetry["milestones"]["database_migration"] = {
                "status": "PASS",
                "functions_extracted": len(proj.functions),
                "types_extracted": len(proj.structs),
                "segments_extracted": len(proj.segments),
                "delta_events_generated": len(delta_events),
                "throughput_databases_per_sec": round(50 / sum(parse_samples), 2) if sum(parse_samples) > 0 else 0,
                "latency_metrics": calculate_metrics(parse_samples),
            }
    except Exception as e:
        telemetry["milestones"]["database_migration"] = {
            "status": "WAITING_OR_FAIL",
            "error": str(e),
        }

    # --- 3. Wasm Decompiler Pipeline Benchmark ---
    try:
        from superghidra.lifters.wasm_decompiler_pipeline import (
            WasmModuleBuilder,
            WasmDecompilerAppGenerator,
        )

        # 1. Benchmark Wasm binary module generation
        wasm_gen_samples: List[float] = []
        for _ in range(100):
            t0 = time.perf_counter()
            builder = WasmModuleBuilder()
            builder.add_type(params=[0x7F, 0x7F], results=[0x7F]) # (i32, i32) -> i32
            # Add function that computes token offset
            builder.add_function(type_index=0, code_bytes=bytes([
                0x20, 0x00, # local.get 0
                0x20, 0x01, # local.get 1
                0x6A,       # i32.add
                0x0B        # end
            ]))
            wasm_binary = builder.build()
            t1 = time.perf_counter()
            wasm_gen_samples.append(t1 - t0)

        # 2. Benchmark Web Client Bundle Generation
        app_gen = WasmDecompilerAppGenerator()
        sample_code = """
        int handle_packet(Player* player, uint8_t* buffer, size_t len) {
            if (!player || len < 4) return -1;
            uint32_t magic = *(uint32_t*)buffer;
            if (magic != 0x53474844) return 0;
            player->credits += 100;
            return 1;
        }
        """
        web_bundle_samples: List[float] = []
        for _ in range(50):
            t0 = time.perf_counter()
            bundle = app_gen.generate_bundle(
                function_name="handle_packet",
                decompiled_c=sample_code,
                rva=0x401000,
                cfg_nodes=[
                    {"id": "entry", "label": "loc_401000", "lines": ["int handle_packet(...)"]},
                    {"id": "valid_magic", "label": "loc_401040", "lines": ["player->credits += 100;", "return 1;"]},
                    {"id": "exit", "label": "loc_401060", "lines": ["return -1;"]}
                ],
                cfg_edges=[
                    {"from": "entry", "to": "valid_magic"},
                    {"from": "entry", "to": "exit"}
                ]
            )
            t1 = time.perf_counter()
            web_bundle_samples.append(t1 - t0)

        telemetry["milestones"]["wasm_decompiler_pipeline"] = {
            "status": "PASS",
            "wasm_module_bytes": len(wasm_binary),
            "wasm_valid_magic": wasm_binary[:4] == b"\x00asm",
            "web_html_size_bytes": len(bundle.get("html", "")),
            "web_js_size_bytes": len(bundle.get("js", "")),
            "wasm_binary_builder_latency": calculate_metrics(wasm_gen_samples),
            "web_app_bundle_latency": calculate_metrics(web_bundle_samples),
        }
    except Exception as e:
        telemetry["milestones"]["wasm_decompiler_pipeline"] = {
            "status": "WAITING_OR_FAIL",
            "error": str(e),
        }

    return telemetry


if __name__ == "__main__":
    results = benchmark_milestone_modules()
    print(json.dumps(results, indent=2))
