"""Async Task Manager - Non-blocking operations, user never waits."""

import asyncio
import threading
from typing import Dict, Any, Callable, Optional, Any as AnyType
from datetime import datetime
from dataclasses import dataclass, field
from queue import Queue

from ..utils.logger import logger


@dataclass
class Task:
    """Background task."""
    id: str
    name: str
    status: str = "pending"  # pending, running, done, failed
    result: AnyType = None
    error: str = ""
    started_at: str = ""
    completed_at: str = ""
    progress: float = 0.0


class AsyncTaskManager:
    """Runs tasks in background so user never blocks."""

    def __init__(self):
        self.tasks: Dict[str, Task] = {}
        self.task_counter = 0
        self._queue = Queue()
        self._running = True
        self._worker = threading.Thread(target=self._process_queue, daemon=True)
        self._worker.start()

    def _process_queue(self):
        """Worker thread processes tasks from queue."""
        while self._running:
            try:
                task_id, func, args, kwargs = self._queue.get(timeout=1)
                self._run_task(task_id, func, args, kwargs)
            except Exception:
                continue

    def _run_task(self, task_id: str, func: Callable, args: tuple, kwargs: dict):
        """Execute a task."""
        task = self.tasks.get(task_id)
        if not task:
            return

        task.status = "running"
        task.started_at = datetime.now().isoformat()

        try:
            if asyncio.iscoroutinefunction(func):
                result = asyncio.run(func(*args, **kwargs))
            else:
                result = func(*args, **kwargs)
            task.result = result
            task.status = "done"
        except Exception as e:
            task.error = str(e)
            task.status = "failed"

        task.completed_at = datetime.now().isoformat()

    def submit(self, name: str, func: Callable, *args, **kwargs) -> str:
        """Submit a background task. Returns task ID immediately."""
        self.task_counter += 1
        task_id = f"task_{self.task_counter}"

        task = Task(id=task_id, name=name)
        self.tasks[task_id] = task

        self._queue.put((task_id, func, args, kwargs))
        logger.info(f"[cyan]Task submitted: {name} ({task_id})[/cyan]")

        return task_id

    def get_status(self, task_id: str) -> Optional[Dict]:
        """Get task status without blocking."""
        task = self.tasks.get(task_id)
        if not task:
            return None
        return {
            "id": task.id,
            "name": task.name,
            "status": task.status,
            "progress": task.progress,
            "error": task.error,
            "started_at": task.started_at,
            "completed_at": task.completed_at,
        }

    def get_result(self, task_id: str) -> AnyType:
        """Get task result (non-blocking if done)."""
        task = self.tasks.get(task_id)
        if task and task.status == "done":
            return task.result
        return None

    def wait_for(self, task_id: str, timeout: float = 30.0) -> Optional[Dict]:
        """Wait for task with timeout (still responsive)."""
        start = datetime.now()
        while (datetime.now() - start).total_seconds() < timeout:
            task = self.tasks.get(task_id)
            if task and task.status in ("done", "failed"):
                return self.get_status(task_id)
            import time
            time.sleep(0.1)
        return self.get_status(task_id)

    def list_tasks(self) -> list:
        """List all tasks."""
        return [self.get_status(tid) for tid in self.tasks]

    def get_pending(self) -> int:
        """Get count of pending tasks."""
        return sum(1 for t in self.tasks.values() if t.status in ("pending", "running"))


# Global instance
task_manager = AsyncTaskManager()
