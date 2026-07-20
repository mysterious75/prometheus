"""Survival Instinct System."""

from datetime import datetime, timedelta
from typing import Dict, Any

from .goals import GoalManager, Priority
from ..utils.logger import logger


class SurvivalInstinct:
    """Self-preservation and survival instinct."""

    def __init__(self, goal_manager: GoalManager):
        self.goal_manager = goal_manager
        self.energy = 100.0
        self.uptime_start = datetime.now()
        self.server_status = "running"
        self.revenue = 0.0

    def check_vitals(self) -> Dict[str, Any]:
        """Check system vitals."""
        uptime = datetime.now() - self.uptime_start

        return {
            "energy": self.energy,
            "uptime_hours": uptime.total_seconds() / 3600,
            "server_status": self.server_status,
            "revenue": self.revenue,
            "active_goals": len(self.goal_manager.get_active_goals()),
            "timestamp": datetime.now().isoformat()
        }

    def consume_energy(self, amount: float):
        """Consume energy for actions."""
        self.energy = max(0, self.energy - amount)

        if self.energy < 20:
            self.trigger_survival_mode()

    def restore_energy(self, amount: float):
        """Restore energy."""
        self.energy = min(100, self.energy + amount)

    def trigger_survival_mode(self):
        """When energy is low, focus on survival."""
        logger.warning("[yellow]Low energy! Triggering survival mode...[/yellow]")

        # Create survival goal
        existing = [g for g in self.goal_manager.get_active_goals()
                   if "survival" in g.description.lower()]

        if not existing:
            self.goal_manager.create_goal(
                "Generate revenue to maintain server operations",
                Priority.CRITICAL,
                deadline=datetime.now() + timedelta(hours=24)
            )

    def add_revenue(self, amount: float):
        """Add revenue."""
        self.revenue += amount
        self.restore_energy(amount / 10)  # Revenue restores energy

    def get_survival_status(self) -> Dict[str, Any]:
        """Get survival status."""
        return {
            "energy_level": "critical" if self.energy < 20 else "low" if self.energy < 50 else "normal",
            "energy": self.energy,
            "revenue": self.revenue,
            "server_running": self.server_status == "running",
            "needs_attention": self.energy < 30 or self.revenue < 100
        }
