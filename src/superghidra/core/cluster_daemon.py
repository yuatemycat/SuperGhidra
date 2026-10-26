"""SuperGhidra Distributed Daemon Clustering Module (gRPC).

Provides resilient gRPC-based worker distribution cluster for SuperGhidra daemon tasks:
- Worker lifecycle registration (RegisterWorker, Heartbeat, DeregisterWorker)
- Task routing, scheduling (round-robin / load-aware), and dispatch
- Failover, heartbeat monitoring, and automatic task re-queuing on node crash/timeout
- Typed TaskEnvelope, ClusterTaskType, WorkerStatus
- Pure-Python fallback mock transport alongside full grpc.server / grpc.insecure_channel transport.
"""

from __future__ import annotations

import concurrent.futures
import dataclasses
import enum
import json
import logging
import queue
import socket
import threading
import time
import uuid
from typing import Any, Callable, Dict, List, Tuple

logger = logging.getLogger("superghidra.core.cluster_daemon")

try:
    import grpc
    _GRPC_AVAILABLE = True
except ImportError:
    grpc = None  # type: ignore[assignment]
    _GRPC_AVAILABLE = False


class ClusterTaskType(str, enum.Enum):
    """Supported distributed daemon task types."""
    STRUCTURE_INTROSPECTION = "STRUCTURE_INTROSPECTION"
    STATIC_ANALYSIS = "STATIC_ANALYSIS"
    VSA = "VSA"
    DIFF = "DIFF"
    SCAN = "SCAN"
    EXPORT = "EXPORT"
    DECOMPILE = "DECOMPILE"


class WorkerStatus(str, enum.Enum):
    """Health and scheduling state of cluster worker nodes."""
    UNKNOWN = "UNKNOWN"
    ONLINE = "ONLINE"
    BUSY = "BUSY"
    DRAINING = "DRAINING"
    DEAD = "DEAD"


class TaskState(str, enum.Enum):
    """Lifecycle state of a queued/assigned task."""
    PENDING = "PENDING"
    DISPATCHED = "DISPATCHED"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    REQUEUED = "REQUEUED"


@dataclasses.dataclass
class TaskEnvelope:
    """Envelope describing a distributed execution unit across the daemon cluster."""
    task_id: str
    task_type: ClusterTaskType
    payload: Dict[str, Any] = dataclasses.field(default_factory=dict)
    state: TaskState = TaskState.PENDING
    assigned_worker_id: str | None = None
    created_at: float = dataclasses.field(default_factory=time.time)
    dispatched_at: float | None = None
    completed_at: float | None = None
    result: Dict[str, Any] | None = None
    error: str | None = None
    retry_count: int = 0
    max_retries: int = 3
    priority: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "task_id": self.task_id,
            "task_type": self.task_type.value if isinstance(self.task_type, enum.Enum) else str(self.task_type),
            "payload": self.payload,
            "state": self.state.value if isinstance(self.state, enum.Enum) else str(self.state),
            "assigned_worker_id": self.assigned_worker_id,
            "created_at": self.created_at,
            "dispatched_at": self.dispatched_at,
            "completed_at": self.completed_at,
            "result": self.result,
            "error": self.error,
            "retry_count": self.retry_count,
            "max_retries": self.max_retries,
            "priority": self.priority,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> TaskEnvelope:
        return cls(
            task_id=data["task_id"],
            task_type=ClusterTaskType(data["task_type"]),
            payload=data.get("payload", {}),
            state=TaskState(data.get("state", TaskState.PENDING.value)),
            assigned_worker_id=data.get("assigned_worker_id"),
            created_at=data.get("created_at", time.time()),
            dispatched_at=data.get("dispatched_at"),
            completed_at=data.get("completed_at"),
            result=data.get("result"),
            error=data.get("error"),
            retry_count=data.get("retry_count", 0),
            max_retries=data.get("max_retries", 3),
            priority=data.get("priority", 0),
        )


@dataclasses.dataclass
class WorkerDescriptor:
    """Metadata and operational state of a registered worker node."""
    worker_id: str
    endpoint: str
    capabilities: List[ClusterTaskType] = dataclasses.field(default_factory=list)
    status: WorkerStatus = WorkerStatus.ONLINE
    active_tasks: int = 0
    max_concurrency: int = 4
    last_heartbeat: float = dataclasses.field(default_factory=time.time)
    metadata: Dict[str, Any] = dataclasses.field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "worker_id": self.worker_id,
            "endpoint": self.endpoint,
            "capabilities": [c.value if isinstance(c, enum.Enum) else str(c) for c in self.capabilities],
            "status": self.status.value if isinstance(self.status, enum.Enum) else str(self.status),
            "active_tasks": self.active_tasks,
            "max_concurrency": self.max_concurrency,
            "last_heartbeat": self.last_heartbeat,
            "metadata": self.metadata,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> WorkerDescriptor:
        return cls(
            worker_id=data["worker_id"],
            endpoint=data["endpoint"],
            capabilities=[ClusterTaskType(c) for c in data.get("capabilities", [])],
            status=WorkerStatus(data.get("status", WorkerStatus.ONLINE.value)),
            active_tasks=data.get("active_tasks", 0),
            max_concurrency=data.get("max_concurrency", 4),
            last_heartbeat=data.get("last_heartbeat", time.time()),
            metadata=data.get("metadata", {}),
        )


class RPCDispatcher:
    """Generic RPC message dispatcher for JSON-encoded payloads over gRPC or fallback."""

    def __init__(self, coordinator: ClusterCoordinator) -> None:
        self.coordinator = coordinator

    def dispatch(self, method: str, params: Dict[str, Any]) -> Dict[str, Any]:
        """Route method calls to coordinator handler."""
        if method == "RegisterWorker":
            descriptor = WorkerDescriptor(
                worker_id=params["worker_id"],
                endpoint=params["endpoint"],
                capabilities=[ClusterTaskType(c) for c in params.get("capabilities", [])],
                max_concurrency=params.get("max_concurrency", 4),
                metadata=params.get("metadata", {}),
            )
            success = self.coordinator.register_worker(descriptor)
            return {"status": "ok" if success else "error", "worker_id": descriptor.worker_id}

        elif method == "Heartbeat":
            success = self.coordinator.record_heartbeat(
                worker_id=params["worker_id"],
                active_tasks=params.get("active_tasks", 0),
                status=WorkerStatus(params.get("status", WorkerStatus.ONLINE.value)),
            )
            return {"status": "ok" if success else "worker_not_found"}

        elif method == "DeregisterWorker":
            success = self.coordinator.deregister_worker(params["worker_id"])
            return {"status": "ok" if success else "worker_not_found"}

        elif method == "SubmitTask":
            task_type = ClusterTaskType(params["task_type"])
            task = self.coordinator.submit_task(
                task_type=task_type,
                payload=params.get("payload", {}),
                task_id=params.get("task_id"),
                priority=params.get("priority", 0),
                max_retries=params.get("max_retries", 3),
            )
            return {"status": "ok", "task": task.to_dict()}

        elif method == "PollTask":
            worker_id = params["worker_id"]
            polled_task = self.coordinator.poll_task_for_worker(worker_id)
            return {"status": "ok", "task": polled_task.to_dict() if polled_task else None}

        elif method == "CompleteTask":
            worker_id = params["worker_id"]
            task_id = params["task_id"]
            result = params.get("result")
            error = params.get("error")
            success = self.coordinator.complete_task(
                worker_id=worker_id,
                task_id=task_id,
                result=result,
                error=error,
            )
            return {"status": "ok" if success else "error"}

        elif method == "GetTaskStatus":
            status_task = self.coordinator.get_task(params["task_id"])
            return {"status": "ok", "task": status_task.to_dict() if status_task else None}

        elif method == "ListWorkers":
            workers = [w.to_dict() for w in self.coordinator.list_workers()]
            return {"status": "ok", "workers": workers}

        else:
            return {"status": "error", "message": f"Unknown method: {method}"}


class GenericClusterServiceServicer:
    """gRPC generic streaming/unary RPC servicer for JSON-RPC over gRPC."""

    def __init__(self, dispatcher: RPCDispatcher) -> None:
        self.dispatcher = dispatcher

    def Invoke(self, request_bytes: bytes, context: Any = None) -> bytes:
        try:
            req = json.loads(request_bytes.decode("utf-8"))
            method = req.get("method", "")
            params = req.get("params", {})
            res = self.dispatcher.dispatch(method, params)
            return json.dumps(res).encode("utf-8")
        except Exception as ex:
            logger.exception("Error in generic cluster RPC invocation")
            return json.dumps({"status": "error", "message": str(ex)}).encode("utf-8")


class ClusterCoordinator:
    """Coordinates worker node registry, heartbeat monitoring, task scheduling and failover."""

    def __init__(
        self,
        heartbeat_timeout_sec: float = 5.0,
        failover_interval_sec: float = 1.0,
        load_aware: bool = True,
    ) -> None:
        self.heartbeat_timeout_sec = heartbeat_timeout_sec
        self.failover_interval_sec = failover_interval_sec
        self.load_aware = load_aware

        self._workers: Dict[str, WorkerDescriptor] = {}
        self._tasks: Dict[str, TaskEnvelope] = {}
        self._pending_tasks: List[TaskEnvelope] = []
        self._worker_queues: Dict[str, queue.PriorityQueue[Tuple[int, float, str, TaskEnvelope]]] = {}

        self._lock = threading.RLock()
        self._round_robin_idx = 0

        self._dispatcher = RPCDispatcher(self)
        self._grpc_server: Any | None = None
        self._grpc_port: int | None = None
        self._stop_event = threading.Event()
        self._reaper_thread: threading.Thread | None = None

    def start_grpc_server(self, host: str = "127.0.0.1", port: int = 0) -> int:
        """Starts real gRPC server with generic binary RPC handler."""
        if not _GRPC_AVAILABLE:
            raise RuntimeError("grpcio is not installed in the environment")

        servicer = GenericClusterServiceServicer(self._dispatcher)

        def rpc_handler(request_bytes: bytes, context: Any) -> bytes:
            return servicer.Invoke(request_bytes, context)

        generic_handler = grpc.unary_unary_rpc_method_handler(
            rpc_handler,
            request_deserializer=lambda x: x,
            response_serializer=lambda x: x,
        )

        class ClusterGenericHandler(grpc.GenericRpcHandler):
            def service(self, handler_call_details: Any) -> Any:
                if handler_call_details.method == "/superghidra.cluster.ClusterService/Invoke":
                    return generic_handler
                return None

        server = grpc.server(concurrent.futures.ThreadPoolExecutor(max_workers=10))
        server.add_generic_rpc_handlers((ClusterGenericHandler(),))
        bound_port = server.add_insecure_port(f"{host}:{port}")
        server.start()

        self._grpc_server = server
        self._grpc_port = bound_port

        self.start_health_monitor()
        logger.info(f"ClusterCoordinator gRPC server started on {host}:{bound_port}")
        return bound_port

    def start_health_monitor(self) -> None:
        """Starts background monitor thread for node heartbeats and failovers."""
        with self._lock:
            if self._reaper_thread is not None and self._reaper_thread.is_alive():
                return
            self._stop_event.clear()
            self._reaper_thread = threading.Thread(target=self._monitor_loop, daemon=True)
            self._reaper_thread.start()

    def stop(self) -> None:
        """Stops background health monitor and stops gRPC server if running."""
        self._stop_event.set()
        if self._grpc_server:
            self._grpc_server.stop(grace=1.0)
            self._grpc_server = None
        if self._reaper_thread and self._reaper_thread.is_alive():
            self._reaper_thread.join(timeout=2.0)
            self._reaper_thread = None

    def _monitor_loop(self) -> None:
        while not self._stop_event.is_set():
            try:
                self.check_worker_timeouts()
            except Exception as e:
                logger.error(f"Error during worker health check: {e}")
            self._stop_event.wait(timeout=self.failover_interval_sec)

    # --- Worker Management ---

    def register_worker(self, descriptor: WorkerDescriptor) -> bool:
        """Registers a worker node in the cluster."""
        with self._lock:
            descriptor.last_heartbeat = time.time()
            self._workers[descriptor.worker_id] = descriptor
            if descriptor.worker_id not in self._worker_queues:
                self._worker_queues[descriptor.worker_id] = queue.PriorityQueue()
            logger.info(f"Worker {descriptor.worker_id} registered at {descriptor.endpoint}")
            self._schedule_pending_tasks()
            return True

    def record_heartbeat(
        self,
        worker_id: str,
        active_tasks: int = 0,
        status: WorkerStatus = WorkerStatus.ONLINE,
    ) -> bool:
        """Updates worker heartbeat timestamp and status."""
        with self._lock:
            worker = self._workers.get(worker_id)
            if not worker:
                return False
            worker.last_heartbeat = time.time()
            worker.active_tasks = active_tasks
            if worker.status != WorkerStatus.DRAINING:
                worker.status = status
            return True

    def deregister_worker(self, worker_id: str) -> bool:
        """Removes a worker node and re-queues its assigned running tasks."""
        with self._lock:
            worker = self._workers.pop(worker_id, None)
            if not worker:
                return False
            self._worker_queues.pop(worker_id, None)
            self._handle_worker_failure(worker_id)
            logger.info(f"Worker {worker_id} deregistered")
            return True

    def list_workers(self) -> List[WorkerDescriptor]:
        with self._lock:
            return list(self._workers.values())

    def get_worker(self, worker_id: str) -> WorkerDescriptor | None:
        with self._lock:
            return self._workers.get(worker_id)

    # --- Task Scheduling & Routing ---

    def submit_task(
        self,
        task_type: ClusterTaskType,
        payload: Dict[str, Any] | None = None,
        task_id: str | None = None,
        priority: int = 0,
        max_retries: int = 3,
    ) -> TaskEnvelope:
        """Submits a new task to the cluster coordinator."""
        with self._lock:
            envelope = TaskEnvelope(
                task_id=task_id or str(uuid.uuid4()),
                task_type=task_type,
                payload=payload or {},
                state=TaskState.PENDING,
                priority=priority,
                max_retries=max_retries,
            )
            self._tasks[envelope.task_id] = envelope
            self._pending_tasks.append(envelope)
            self._pending_tasks.sort(key=lambda t: t.priority, reverse=True)
            self._schedule_pending_tasks()
            return envelope

    def get_task(self, task_id: str) -> TaskEnvelope | None:
        with self._lock:
            return self._tasks.get(task_id)

    def _select_worker_for_task(self, task: TaskEnvelope) -> str | None:
        """Selects suitable worker using round-robin or load-aware scheduling."""
        eligible: List[WorkerDescriptor] = []
        for w in self._workers.values():
            if w.status == WorkerStatus.ONLINE:
                if not w.capabilities or task.task_type in w.capabilities:
                    if w.active_tasks < w.max_concurrency:
                        eligible.append(w)

        if not eligible:
            return None

        if self.load_aware:
            eligible.sort(key=lambda w: (w.active_tasks, -(w.max_concurrency - w.active_tasks)))
            return eligible[0].worker_id
        else:
            idx = self._round_robin_idx % len(eligible)
            self._round_robin_idx += 1
            return eligible[idx].worker_id

    def _schedule_pending_tasks(self) -> None:
        """Attempts to match pending tasks to available workers."""
        remaining_tasks: List[TaskEnvelope] = []
        for task in self._pending_tasks:
            worker_id = self._select_worker_for_task(task)
            if worker_id:
                task.assigned_worker_id = worker_id
                task.state = TaskState.DISPATCHED
                task.dispatched_at = time.time()
                worker = self._workers[worker_id]
                worker.active_tasks += 1
                self._worker_queues[worker_id].put((-task.priority, task.created_at, task.task_id, task))
            else:
                remaining_tasks.append(task)
        self._pending_tasks = remaining_tasks

    def poll_task_for_worker(self, worker_id: str, timeout: float = 0.05) -> TaskEnvelope | None:
        """Called by a worker node to poll for an assigned task."""
        wqueue = None
        with self._lock:
            wqueue = self._worker_queues.get(worker_id)
        if not wqueue:
            return None
        try:
            item = wqueue.get(timeout=timeout)
            task = item[3]
            with self._lock:
                task.state = TaskState.RUNNING
            return task
        except queue.Empty:
            return None

    def complete_task(
        self,
        worker_id: str,
        task_id: str,
        result: Dict[str, Any] | None = None,
        error: str | None = None,
    ) -> bool:
        """Called when a worker completes task execution."""
        with self._lock:
            task = self._tasks.get(task_id)
            if not task:
                return False
            task.completed_at = time.time()
            if error:
                task.state = TaskState.FAILED
                task.error = error
            else:
                task.state = TaskState.COMPLETED
                task.result = result

            worker = self._workers.get(worker_id)
            if worker and worker.active_tasks > 0:
                worker.active_tasks -= 1

            self._schedule_pending_tasks()
            return True

    # --- Health Monitoring & Failover ---

    def check_worker_timeouts(self) -> List[str]:
        """Detects timed-out workers, marks them DEAD and requeues their in-flight tasks."""
        dead_workers: List[str] = []
        now = time.time()
        with self._lock:
            for wid, worker in list(self._workers.items()):
                if worker.status in (WorkerStatus.ONLINE, WorkerStatus.BUSY):
                    if now - worker.last_heartbeat > self.heartbeat_timeout_sec:
                        logger.warning(
                            f"Worker {wid} exceeded heartbeat timeout ({self.heartbeat_timeout_sec}s). Marking DEAD."
                        )
                        worker.status = WorkerStatus.DEAD
                        dead_workers.append(wid)

            for wid in dead_workers:
                self._handle_worker_failure(wid)

        return dead_workers

    def _handle_worker_failure(self, failed_worker_id: str) -> None:
        """Fails over any pending or running tasks that were assigned to failed_worker_id."""
        for task in self._tasks.values():
            if task.assigned_worker_id == failed_worker_id and task.state in (
                TaskState.DISPATCHED,
                TaskState.RUNNING,
            ):
                if task.retry_count < task.max_retries:
                    task.retry_count += 1
                    task.state = TaskState.REQUEUED
                    task.assigned_worker_id = None
                    self._pending_tasks.append(task)
                    logger.info(
                        f"Re-queued task {task.task_id} (retry {task.retry_count}/{task.max_retries}) after worker {failed_worker_id} failure"
                    )
                else:
                    task.state = TaskState.FAILED
                    task.error = f"Exceeded max retries after worker {failed_worker_id} failure"
                    logger.warning(f"Task {task.task_id} failed permanently: max retries reached")

        self._pending_tasks.sort(key=lambda t: t.priority, reverse=True)
        self._schedule_pending_tasks()


class ClusterWorkerNode:
    """Worker node running either via direct local RPC / fallback or gRPC transport."""

    def __init__(
        self,
        worker_id: str | None = None,
        coordinator_endpoint: str | None = None,
        capabilities: List[ClusterTaskType] | None = None,
        max_concurrency: int = 4,
        local_coordinator: ClusterCoordinator | None = None,
    ) -> None:
        self.worker_id = worker_id or f"worker-{uuid.uuid4().hex[:8]}"
        self.coordinator_endpoint = coordinator_endpoint
        self.capabilities = capabilities or list(ClusterTaskType)
        self.max_concurrency = max_concurrency
        self.local_coordinator = local_coordinator

        self._grpc_channel: Any | None = None
        self._running = False
        self._active_tasks = 0
        self._lock = threading.Lock()
        self._poll_thread: threading.Thread | None = None
        self._heartbeat_thread: threading.Thread | None = None

        self._handlers: Dict[ClusterTaskType, Callable[[Dict[str, Any]], Dict[str, Any]]] = {}
        self._setup_default_handlers()

    def _setup_default_handlers(self) -> None:
        """Register built-in execution handlers for SuperGhidra task types."""
        def handle_vsa(payload: Dict[str, Any]) -> Dict[str, Any]:
            address = payload.get("address", "0x0")
            return {"status": "success", "analysis": "VSA", "address": address, "invariants": ["esp >= 0"]}

        def handle_scan(payload: Dict[str, Any]) -> Dict[str, Any]:
            size = payload.get("size", 0)
            return {"status": "success", "analysis": "SCAN", "scanned_bytes": size, "matches": 0}

        def handle_diff(payload: Dict[str, Any]) -> Dict[str, Any]:
            return {"status": "success", "analysis": "DIFF", "similarity": 1.0}

        def handle_structure(payload: Dict[str, Any]) -> Dict[str, Any]:
            return {"status": "success", "analysis": "STRUCTURE", "fields": payload.get("fields", [])}

        def handle_static(payload: Dict[str, Any]) -> Dict[str, Any]:
            return {"status": "success", "analysis": "STATIC_ANALYSIS", "functions": payload.get("count", 1)}

        def handle_export(payload: Dict[str, Any]) -> Dict[str, Any]:
            return {"status": "success", "analysis": "EXPORT", "exported_symbols": 0}

        self.register_handler(ClusterTaskType.VSA, handle_vsa)
        self.register_handler(ClusterTaskType.SCAN, handle_scan)
        self.register_handler(ClusterTaskType.DIFF, handle_diff)
        self.register_handler(ClusterTaskType.STRUCTURE_INTROSPECTION, handle_structure)
        self.register_handler(ClusterTaskType.STATIC_ANALYSIS, handle_static)
        self.register_handler(ClusterTaskType.EXPORT, handle_export)

    def register_handler(
        self,
        task_type: ClusterTaskType,
        handler: Callable[[Dict[str, Any]], Dict[str, Any]],
    ) -> None:
        self._handlers[task_type] = handler

    def _call_rpc(self, method: str, params: Dict[str, Any]) -> Dict[str, Any]:
        """Invokes RPC over local coordinator dispatcher or gRPC channel."""
        if self.local_coordinator:
            return self.local_coordinator._dispatcher.dispatch(method, params)

        if not self._grpc_channel:
            if not _GRPC_AVAILABLE or not self.coordinator_endpoint:
                raise RuntimeError("No coordinator connection available")
            self._grpc_channel = grpc.insecure_channel(self.coordinator_endpoint)

        req_bytes = json.dumps({"method": method, "params": params}).encode("utf-8")
        invoker = self._grpc_channel.unary_unary(
            "/superghidra.cluster.ClusterService/Invoke",
            request_serializer=lambda x: x,
            response_deserializer=lambda x: x,
        )
        res_bytes = invoker(req_bytes)
        return json.loads(res_bytes.decode("utf-8"))

    def start(self) -> None:
        """Starts worker registration, polling loop, and heartbeat thread."""
        self._running = True
        # 1. Register with coordinator
        res = self._call_rpc(
            "RegisterWorker",
            {
                "worker_id": self.worker_id,
                "endpoint": self.coordinator_endpoint or "in-process",
                "capabilities": [c.value for c in self.capabilities],
                "max_concurrency": self.max_concurrency,
                "metadata": {"hostname": socket.gethostname()},
            },
        )
        if res.get("status") != "ok":
            raise RuntimeError(f"Worker registration failed: {res}")

        # 2. Start heartbeat thread
        self._heartbeat_thread = threading.Thread(target=self._heartbeat_loop, daemon=True)
        self._heartbeat_thread.start()

        # 3. Start task poll loop
        self._poll_thread = threading.Thread(target=self._poll_loop, daemon=True)
        self._poll_thread.start()

    def stop(self) -> None:
        """Deregister and stop all background threads."""
        self._running = False
        try:
            self._call_rpc("DeregisterWorker", {"worker_id": self.worker_id})
        except Exception:
            pass
        if self._grpc_channel:
            self._grpc_channel.close()
            self._grpc_channel = None

    def _heartbeat_loop(self) -> None:
        while self._running:
            try:
                with self._lock:
                    active = self._active_tasks
                self._call_rpc(
                    "Heartbeat",
                    {
                        "worker_id": self.worker_id,
                        "active_tasks": active,
                        "status": WorkerStatus.ONLINE.value,
                    },
                )
            except Exception as e:
                logger.error(f"Worker {self.worker_id} heartbeat failure: {e}")
            time.sleep(1.0)

    def _poll_loop(self) -> None:
        while self._running:
            try:
                res = self._call_rpc("PollTask", {"worker_id": self.worker_id})
                task_data = res.get("task")
                if task_data:
                    task = TaskEnvelope.from_dict(task_data)
                    self._execute_task_async(task)
                else:
                    time.sleep(0.05)
            except Exception as e:
                logger.debug(f"Worker {self.worker_id} poll error: {e}")
                time.sleep(0.1)

    def _execute_task_async(self, task: TaskEnvelope) -> None:
        def worker_exec() -> None:
            with self._lock:
                self._active_tasks += 1
            result = None
            error = None
            try:
                handler = self._handlers.get(task.task_type)
                if not handler:
                    raise NotImplementedError(f"No handler registered for {task.task_type}")
                result = handler(task.payload)
            except Exception as e:
                error = str(e)
            finally:
                with self._lock:
                    self._active_tasks = max(0, self._active_tasks - 1)
                try:
                    self._call_rpc(
                        "CompleteTask",
                        {
                            "worker_id": self.worker_id,
                            "task_id": task.task_id,
                            "result": result,
                            "error": error,
                        },
                    )
                except Exception as e:
                    logger.error(f"Failed to report task completion for {task.task_id}: {e}")

        t = threading.Thread(target=worker_exec, daemon=True)
        t.start()
