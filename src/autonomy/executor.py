"""Execution Engine - Autonomous task execution."""

from typing import Dict, Any, Optional
from datetime import datetime

from ..brain.router import ModelRouter
from .goals import Goal, GoalManager
from ..utils.logger import logger


class ExecutionEngine:
    """Autonomous execution engine."""

    def __init__(self, router: ModelRouter, goal_manager: GoalManager):
        self.router = router
        self.goal_manager = goal_manager
        self.execution_history: list = []

    def plan_steps(self, goal: Goal) -> list:
        """Break a goal into actionable steps."""
        prompt = f"""
        Goal: {goal.description}
        Priority: {goal.priority.name}

        Break this goal into 3-5 actionable steps.
        Return ONLY a numbered list of steps, nothing else.
        """

        response = self.router.generate(prompt)

        # Parse steps
        steps = []
        for line in response.strip().split("\n"):
            line = line.strip()
            if line and line[0].isdigit():
                # Remove numbering
                step = ".".join(line.split(".")[1:]).strip()
                if step:
                    steps.append(step)

        return steps if steps else ["Execute the goal"]

    def execute_goal(self, goal: Goal) -> Dict[str, Any]:
        """Execute a goal autonomously."""
        logger.info(f"[bold blue]Executing: {goal.description}[/bold blue]")

        # Plan steps
        steps = self.plan_steps(goal)
        logger.info(f"Plan: {len(steps)} steps")

        results = []
        for i, step in enumerate(steps, 1):
            logger.info(f"  [{i}/{len(steps)}] {step}")

            # Execute step
            result = self.execute_step(step)
            results.append({"step": step, "result": result})

            # Update progress
            goal.update_progress(i / len(steps))

        # Complete goal
        self.goal_manager.complete_goal(goal)

        execution = {
            "goal": goal.description,
            "steps": results,
            "completed_at": datetime.now().isoformat(),
            "status": "completed"
        }
        self.execution_history.append(execution)

        logger.info(f"[green]Completed: {goal.description}[/green]")
        return execution

    def execute_step(self, step: str) -> str:
        """Execute a single step."""
        prompt = f"""
        Execute this step: {step}

        Provide a brief description of what was done.
        If you cannot actually execute it, describe what WOULD be done.
        """

        return self.router.generate(prompt)

    def get_history(self) -> list:
        """Get execution history."""
        return self.execution_history
