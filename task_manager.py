"""task_manager.py - Durable Task Manager & Concurrency Controller for Homie.

Replaces unmanaged daemon-thread fan-out and raw boolean flags with:
- Unique durable task IDs (e.g. task_7f8a1c)
- Serialized / bounded execution pool (ThreadPoolExecutor)
- Explicit task lifecycle states (PENDING, RUNNING, COMPLETED, FAILED, CANCELLED)
- Cooperative cancellation tokens via threading.Event
- Real-time task inspection for desktop and remote UIs
"""

import time
import secrets
import logging
import threading
from enum import Enum
from concurrent.futures import ThreadPoolExecutor, Future
from typing import Callable, Any, Optional, Dict, List

logger = logging.getLogger("homie.task_manager")


class TaskStatus(str, Enum):
    PENDING = "PENDING"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"


class Task:
    def __init__(self, task_id: str, name: str, func: Callable, args: tuple, kwargs: dict):
        self.task_id = task_id
        self.name = name
        self.func = func
        self.args = args
        self.kwargs = kwargs
        self.status = TaskStatus.PENDING
        self.created_at = time.time()
        self.started_at: Optional[float] = None
        self.completed_at: Optional[float] = None
        self.result: Any = None
        self.error: Optional[str] = None
        self.cancel_event = threading.Event()
        self.future: Optional[Future] = None

    def cancel(self):
        """Signals cooperative cancellation and cancels future if pending."""
        self.cancel_event.set()
        if self.future and not self.future.running():
            self.future.cancel()
        if self.status in (TaskStatus.PENDING, TaskStatus.RUNNING):
            self.status = TaskStatus.CANCELLED
            self.completed_at = time.time()
            logger.info("Task %s (%s) cancelled", self.task_id, self.name)

    def is_cancelled(self) -> bool:
        return self.cancel_event.is_set()

    def to_dict(self) -> Dict[str, Any]:
        duration = None
        if self.started_at:
            end = self.completed_at or time.time()
            duration = round((end - self.started_at) * 1000, 2)
        return {
            "task_id": self.task_id,
            "name": self.name,
            "status": self.status.value,
            "created_at": self.created_at,
            "started_at": self.started_at,
            "completed_at": self.completed_at,
            "duration_ms": duration,
            "error": self.error
        }


class TaskManager:
    """Bounded, durable concurrency controller for Homie."""

    def __init__(self, max_workers: int = 4):
        self._executor = ThreadPoolExecutor(max_workers=max_workers, thread_name_prefix="HomieTaskWorker")
        self._tasks: Dict[str, Task] = {}
        self._lock = threading.Lock()

    def submit_task(
        self,
        name: str,
        func: Callable,
        *args,
        callback: Optional[Callable[[Task], None]] = None,
        **kwargs
    ) -> Task:
        """Submits a function for tracked, bounded execution."""
        task_id = f"task_{secrets.token_hex(4)}"
        task = Task(task_id, name, func, args, kwargs)

        with self._lock:
            # Prune completed history if over 100 items
            if len(self._tasks) > 100:
                finished = [tid for tid, t in self._tasks.items() if t.status in (TaskStatus.COMPLETED, TaskStatus.FAILED, TaskStatus.CANCELLED)]
                for tid in finished[:30]:
                    del self._tasks[tid]
            self._tasks[task_id] = task

        def _worker_wrapper():
            if task.is_cancelled():
                return
            task.status = TaskStatus.RUNNING
            task.started_at = time.time()
            logger.debug("Task %s (%s) started execution", task.task_id, task.name)
            try:
                # Inject cancel_event if function accepts it
                import inspect
                sig = inspect.signature(task.func)
                if "cancel_event" in sig.parameters:
                    task.kwargs["cancel_event"] = task.cancel_event

                task.result = task.func(*task.args, **task.kwargs)
                if not task.is_cancelled():
                    task.status = TaskStatus.COMPLETED
            except Exception as e:
                task.status = TaskStatus.FAILED
                task.error = str(e)
                logger.error("Task %s (%s) failed: %s", task.task_id, task.name, e)
            finally:
                task.completed_at = time.time()
                if callback:
                    try:
                        callback(task)
                    except Exception as cb_err:
                        logger.warning("Task %s callback error: %s", task.task_id, cb_err)

        task.future = self._executor.submit(_worker_wrapper)
        return task

    def cancel_task(self, task_id: str) -> bool:
        """Cancels a specific task by ID."""
        with self._lock:
            task = self._tasks.get(task_id)
            if task:
                task.cancel()
                return True
        return False

    def cancel_all_active(self) -> int:
        """Cancels all currently running or pending tasks."""
        cancelled_count = 0
        with self._lock:
            for task in self._tasks.values():
                if task.status in (TaskStatus.PENDING, TaskStatus.RUNNING):
                    task.cancel()
                    cancelled_count += 1
        return cancelled_count

    def is_busy(self) -> bool:
        """Returns True if any task is currently pending or executing."""
        with self._lock:
            return any(t.status in (TaskStatus.PENDING, TaskStatus.RUNNING) for t in self._tasks.values())

    def get_task(self, task_id: str) -> Optional[Task]:
        with self._lock:
            return self._tasks.get(task_id)

    def get_active_tasks(self) -> List[Dict[str, Any]]:
        with self._lock:
            return [
                t.to_dict() for t in self._tasks.values()
                if t.status in (TaskStatus.PENDING, TaskStatus.RUNNING)
            ]

    def shutdown(self, wait: bool = False):
        self.cancel_all_active()
        self._executor.shutdown(wait=wait)


_GLOBAL_TASK_MANAGER: Optional[TaskManager] = None

def get_task_manager() -> TaskManager:
    global _GLOBAL_TASK_MANAGER
    if _GLOBAL_TASK_MANAGER is None:
        _GLOBAL_TASK_MANAGER = TaskManager(max_workers=4)
    return _GLOBAL_TASK_MANAGER
