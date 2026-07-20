"""Task Scheduler - Automated task execution."""

from datetime import datetime, timedelta
from typing import Callable, Dict, Any, List, Optional
import threading
import time

from ..utils.logger import logger


class ScheduledTask:
    """Represents a scheduled task."""

    def __init__(self, name: str, func: Callable, interval: int, **kwargs):
        self.name = name
        self.func = func
        self.interval = interval  # seconds
        self.kwargs = kwargs
        self.last_run: Optional[datetime] = None
        self.run_count = 0

    def should_run(self) -> bool:
        """Check if task should run."""
        if self.last_run is None:
            return True
        return datetime.now() - self.last_run >= timedelta(seconds=self.interval)


class TaskScheduler:
    """Scheduler for automated tasks."""

    def __init__(self):
        self.tasks: List[ScheduledTask] = []
        self.running = False
        self.thread: Optional[threading.Thread] = None

    def add_task(self, name: str, func: Callable, interval: int, **kwargs) -> ScheduledTask:
        """Add a scheduled task."""
        task = ScheduledTask(name, func, interval, **kwargs)
        self.tasks.append(task)
        logger.info(f"Added scheduled task: {name} (every {interval}s)")
        return task

    def remove_task(self, name: str):
        """Remove a scheduled task."""
        self.tasks = [t for t in self.tasks if t.name != name]

    def _run_loop(self):
        """Main scheduler loop."""
        while self.running:
            for task in self.tasks:
                if task.should_run():
                    try:
                        logger.info(f"Running task: {task.name}")
                        task.func(**task.kwargs)
                        task.last_run = datetime.now()
                        task.run_count += 1
                    except Exception as e:
                        logger.error(f"Task {task.name} failed: {e}")
            time.sleep(1)

    def start(self):
        """Start the scheduler."""
        if self.running:
            return

        self.running = True
        self.thread = threading.Thread(target=self._run_loop, daemon=True)
        self.thread.start()
        logger.info("[green]Scheduler started[/green]")

    def stop(self):
        """Stop the scheduler."""
        self.running = False
        if self.thread:
            self.thread.join(timeout=5)
        logger.info("[yellow]Scheduler stopped[/yellow]")

    def get_status(self) -> Dict[str, Any]:
        """Get scheduler status."""
        return {
            "running": self.running,
            "tasks": len(self.tasks),
            "task_details": [
                {
                    "name": t.name,
                    "interval": t.interval,
                    "last_run": t.last_run.isoformat() if t.last_run else None,
                    "run_count": t.run_count
                }
                for t in self.tasks
            ]
        }
