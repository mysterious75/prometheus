"""Goal Management System."""

from enum import Enum
from datetime import datetime, timedelta
from typing import List, Optional, Dict, Any


class Priority(Enum):
    CRITICAL = 1
    HIGH = 2
    MEDIUM = 3
    LOW = 4


class Goal:
    """Represents a goal with priority and deadline."""

    def __init__(self, description: str, priority: Priority = Priority.MEDIUM,
                 deadline: Optional[datetime] = None):
        self.description = description
        self.priority = priority
        self.deadline = deadline
        self.created_at = datetime.now()
        self.status = "pending"
        self.progress = 0.0
        self.sub_goals: List['Goal'] = []

    def complete(self):
        """Mark goal as complete."""
        self.status = "completed"
        self.progress = 1.0

    def update_progress(self, progress: float):
        """Update progress (0.0 to 1.0)."""
        self.progress = min(1.0, max(0.0, progress))

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "description": self.description,
            "priority": self.priority.name,
            "deadline": self.deadline.isoformat() if self.deadline else None,
            "created_at": self.created_at.isoformat(),
            "status": self.status,
            "progress": self.progress
        }


class GoalManager:
    """Manages goals and priorities."""

    def __init__(self):
        self.goals: List[Goal] = []

    def create_goal(self, description: str, priority: Priority = Priority.MEDIUM,
                    deadline: Optional[datetime] = None) -> Goal:
        """Create a new goal."""
        goal = Goal(description, priority, deadline)
        self.goals.append(goal)
        return goal

    def get_active_goals(self) -> List[Goal]:
        """Get all pending goals."""
        return [g for g in self.goals if g.status == "pending"]

    def get_next_action(self) -> Optional[Goal]:
        """Get the next goal to work on."""
        active = self.get_active_goals()
        if not active:
            return None

        # Sort by priority, then deadline
        active.sort(key=lambda g: (g.priority.value, g.deadline or datetime.max))
        return active[0]

    def complete_goal(self, goal: Goal):
        """Mark a goal as complete."""
        goal.complete()

    def get_stats(self) -> Dict[str, Any]:
        """Get goal statistics."""
        total = len(self.goals)
        completed = len([g for g in self.goals if g.status == "completed"])
        pending = len([g for g in self.goals if g.status == "pending"])

        return {
            "total": total,
            "completed": completed,
            "pending": pending,
            "completion_rate": completed / total if total > 0 else 0
        }
