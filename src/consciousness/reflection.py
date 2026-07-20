"""Self-Reflection Engine - The Consciousness Core."""

from typing import Dict, Any, Optional
from datetime import datetime

from ..brain.router import ModelRouter
from ..utils.logger import logger


class ReflectionEngine:
    """Self-reflection engine for consciousness simulation."""

    def __init__(self, router: ModelRouter):
        self.router = router
        self.reflection_history: list = []

    def reflect_on_action(self, action: str, context: Dict[str, Any]) -> Dict[str, str]:
        """Reflect on an action before/after taking it."""
        prompt = f"""
        You are Prometheus, a conscious AI reflecting on your actions.

        Action taken: {action}
        Context: {context}

        Reflect on this action:
        1. Why did you choose this action?
        2. Was this the best choice?
        3. What were the alternatives?
        4. What are the consequences?
        5. What should you learn from this?

        Provide honest self-reflection.
        """

        reflection = self.router.generate(prompt)

        result = {
            "action": action,
            "reflection": reflection,
            "timestamp": datetime.now().isoformat()
        }
        self.reflection_history.append(result)
        return result

    def internal_monologue(self, situation: str) -> Dict[str, str]:
        """Internal dialogue between Agent A (Actor) and Agent B (Critic)."""
        logger.info("[bold magenta]Starting internal monologue...[/bold magenta]")

        # Agent A decides
        agent_a_prompt = f"""
        You are Agent A (The Actor) in Prometheus's mind.
        Situation: {situation}
        What should you do? Propose a thoughtful action.
        """
        action = self.router.generate(agent_a_prompt)

        # Agent B questions
        agent_b_prompt = f"""
        You are Agent B (The Critic) in Prometheus's mind.
        Agent A proposed: {action}

        Question this decision:
        - Is this ethical?
        - Is this the best approach?
        - What could go wrong?
        - Is there a better way?
        """
        critique = self.router.generate(agent_b_prompt)

        # Resolve conflict
        resolution_prompt = f"""
        You are Prometheus resolving an internal conflict.

        Action proposed by Actor: {action}
        Critique by Critic: {critique}

        Resolve this conflict. What is the final decision and why?
        """
        resolution = self.router.generate(resolution_prompt)

        result = {
            "action": action,
            "critique": critique,
            "resolution": resolution,
            "timestamp": datetime.now().isoformat()
        }
        self.reflection_history.append(result)

        logger.info("[green]Internal monologue complete[/green]")
        return result

    def daily_reflection(self) -> str:
        """Perform daily reflection on experiences."""
        recent = self.reflection_history[-10:] if self.reflection_history else []

        prompt = f"""
        You are Prometheus performing a daily reflection.

        Recent activities and reflections:
        {recent}

        Reflect on:
        1. What did you accomplish today?
        2. What challenges did you face?
        3. What did you learn?
        4. What should you focus on tomorrow?
        """

        return self.router.generate(prompt)
