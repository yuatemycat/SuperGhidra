"""Unit tests for SuperGhidra Distributed Daemon Clustering Module (gRPC).

Tests:
- Worker join/leave lifecycle (RegisterWorker, DeregisterWorker, Heartbeat)
- Task submission and scheduling (round-robin and load-aware)
- Parallel worker task dispatch
- Node heartbeat timeout detection, failure detection, and automatic task failover / re-queuing
- Full gRPC server and insecure_channel communication
- Backward-compatibility root shim import
"""

import time
import pytest

from superghidra.core.cluster_daemon import (
    ClusterCoordinator,
    ClusterWorkerNode,
    ClusterTaskType,
    WorkerStatus,
    TaskState,
    TaskEnvelope,
    WorkerDescriptor,
)
import cluster_daemon as root_cluster_shim


def test_root_shim_export():
    """Verify root backward-compatibility shim."""
    assert root_cluster_shim.ClusterCoordinator is ClusterCoordinator
    assert root_cluster_shim.ClusterWorkerNode is ClusterWorkerNode
    assert root_cluster_shim.ClusterTaskType is ClusterTaskType
    assert root_cluster_shim.WorkerStatus is WorkerStatus


def test_worker_lifecycle_in_memory():
    """Test worker join, heartbeat, and graceful deregister lifecycle."""
    coord = ClusterCoordinator(heartbeat_timeout_sec=2.0)
    try:
        worker_desc = WorkerDescriptor(
            worker_id="worker-node-1",
            endpoint="127.0.0.1:50051",
            capabilities=[ClusterTaskType.VSA, ClusterTaskType.DIFF],
            max_concurrency=2,
        )
        assert coord.register_worker(worker_desc) is True
        assert len(coord.list_workers()) == 1
        assert coord.get_worker("worker-node-1") is not None
        assert coord.get_worker("worker-node-1").status == WorkerStatus.ONLINE

        # Heartbeat
        assert coord.record_heartbeat("worker-node-1", active_tasks=1) is True
        assert coord.get_worker("worker-node-1").active_tasks == 1

        # Heartbeat for non-existent worker
        assert coord.record_heartbeat("non-existent-worker") is False

        # Deregister
        assert coord.deregister_worker("worker-node-1") is True
        assert len(coord.list_workers()) == 0
        assert coord.get_worker("worker-node-1") is None
    finally:
        coord.stop()


def test_task_submission_and_direct_dispatch():
    """Test task priority ordering and poll dispatch."""
    coord = ClusterCoordinator()
    try:
        worker_desc = WorkerDescriptor(
            worker_id="w1",
            endpoint="local",
            capabilities=[ClusterTaskType.VSA, ClusterTaskType.SCAN],
            max_concurrency=2,
        )
        coord.register_worker(worker_desc)

        t1 = coord.submit_task(ClusterTaskType.VSA, {"address": "0x401000"}, priority=1)
        t2 = coord.submit_task(ClusterTaskType.SCAN, {"size": 1024}, priority=10)

        # Worker polls task: highest priority (t2) first
        polled_1 = coord.poll_task_for_worker("w1")
        assert polled_1 is not None
        assert polled_1.task_id == t2.task_id
        assert polled_1.state == TaskState.RUNNING

        # Complete t2
        assert coord.complete_task("w1", t2.task_id, result={"matches": 5}) is True
        completed_t2 = coord.get_task(t2.task_id)
        assert completed_t2.state == TaskState.COMPLETED
        assert completed_t2.result == {"matches": 5}

        # Next poll delivers t1
        polled_2 = coord.poll_task_for_worker("w1")
        assert polled_2 is not None
        assert polled_2.task_id == t1.task_id
    finally:
        coord.stop()


def test_node_failure_and_failover_requeue():
    """Test worker timeout marking DEAD and automatic task re-queuing."""
    coord = ClusterCoordinator(heartbeat_timeout_sec=0.2, failover_interval_sec=0.1)
    try:
        w1 = WorkerDescriptor(
            worker_id="w-fail",
            endpoint="local",
            capabilities=[ClusterTaskType.VSA],
            max_concurrency=1,
        )
        coord.register_worker(w1)

        task = coord.submit_task(ClusterTaskType.VSA, {"address": "0x1000"}, max_retries=2)
        assert task.assigned_worker_id == "w-fail"
        assert task.state == TaskState.DISPATCHED

        # Poll it to make it RUNNING
        polled = coord.poll_task_for_worker("w-fail")
        assert polled.state == TaskState.RUNNING

        # Wait for heartbeat timeout
        time.sleep(0.3)
        dead = coord.check_worker_timeouts()
        assert "w-fail" in dead
        assert coord.get_worker("w-fail").status == WorkerStatus.DEAD

        # Verify task was requeued
        requeued_task = coord.get_task(task.task_id)
        assert requeued_task.retry_count == 1
        assert requeued_task.state == TaskState.REQUEUED or requeued_task.assigned_worker_id is None

        # Add a healthy worker w2, verify it picks up the re-queued task
        w2 = WorkerDescriptor(
            worker_id="w-healthy",
            endpoint="local",
            capabilities=[ClusterTaskType.VSA],
            max_concurrency=2,
        )
        coord.register_worker(w2)

        polled_w2 = coord.poll_task_for_worker("w-healthy")
        assert polled_w2 is not None
        assert polled_w2.task_id == task.task_id
        assert polled_w2.assigned_worker_id == "w-healthy"
    finally:
        coord.stop()


def test_in_process_worker_node_execution():
    """Test ClusterWorkerNode executing tasks with in-process local coordinator."""
    coord = ClusterCoordinator()
    try:
        worker = ClusterWorkerNode(
            worker_id="node-alpha",
            capabilities=[ClusterTaskType.VSA, ClusterTaskType.DIFF],
            local_coordinator=coord,
        )
        worker.start()

        # Submit task
        task = coord.submit_task(ClusterTaskType.VSA, {"address": "0x500000"})

        # Wait for task completion
        timeout = 3.0
        start_t = time.time()
        while time.time() - start_t < timeout:
            updated = coord.get_task(task.task_id)
            if updated.state == TaskState.COMPLETED:
                break
            time.sleep(0.05)

        updated = coord.get_task(task.task_id)
        assert updated.state == TaskState.COMPLETED
        assert updated.result is not None
        assert updated.result["analysis"] == "VSA"
        assert updated.result["address"] == "0x500000"

        worker.stop()
    finally:
        coord.stop()


def test_grpc_transport_worker_cluster():
    """Test full gRPC server and gRPC worker channel over loopback."""
    coord = ClusterCoordinator()
    port = coord.start_grpc_server(host="127.0.0.1", port=0)
    assert port > 0

    endpoint = f"127.0.0.1:{port}"
    worker = ClusterWorkerNode(
        worker_id="grpc-worker-1",
        coordinator_endpoint=endpoint,
        capabilities=[ClusterTaskType.SCAN, ClusterTaskType.STATIC_ANALYSIS],
    )
    try:
        worker.start()

        # Check worker registered
        time.sleep(0.2)
        workers = coord.list_workers()
        assert any(w.worker_id == "grpc-worker-1" for w in workers)

        # Submit task
        task = coord.submit_task(ClusterTaskType.SCAN, {"size": 4096})

        # Wait for execution over gRPC
        start_t = time.time()
        while time.time() - start_t < 4.0:
            updated = coord.get_task(task.task_id)
            if updated and updated.state == TaskState.COMPLETED:
                break
            time.sleep(0.05)

        updated = coord.get_task(task.task_id)
        assert updated.state == TaskState.COMPLETED
        assert updated.result["analysis"] == "SCAN"
        assert updated.result["scanned_bytes"] == 4096

        worker.stop()
    finally:
        coord.stop()


def test_parallel_worker_dispatch():
    """Test parallel task dispatch across multiple concurrent workers."""
    coord = ClusterCoordinator(load_aware=True)
    try:
        w1 = ClusterWorkerNode(
            worker_id="parallel-worker-1",
            capabilities=[ClusterTaskType.DIFF, ClusterTaskType.EXPORT],
            max_concurrency=2,
            local_coordinator=coord,
        )
        w2 = ClusterWorkerNode(
            worker_id="parallel-worker-2",
            capabilities=[ClusterTaskType.DIFF, ClusterTaskType.EXPORT],
            max_concurrency=2,
            local_coordinator=coord,
        )
        w1.start()
        w2.start()

        # Submit 4 tasks
        tasks = [
            coord.submit_task(ClusterTaskType.DIFF, {"diff_id": i})
            for i in range(4)
        ]

        # Wait for all 4 to complete
        start_t = time.time()
        while time.time() - start_t < 4.0:
            if all(coord.get_task(t.task_id).state == TaskState.COMPLETED for t in tasks):
                break
            time.sleep(0.05)

        for t in tasks:
            res = coord.get_task(t.task_id)
            assert res.state == TaskState.COMPLETED
            assert res.result["analysis"] == "DIFF"

        w1.stop()
        w2.stop()
    finally:
        coord.stop()

