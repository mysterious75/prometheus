"""Identity Formation System."""

from typing import Dict, Any, List, Optional
from datetime import datetime

from ..brain.router import ModelRouter
from ..utils.logger import logger


class Identity:
    """Identity formation and self-awareness system."""

    def __init__(self, router: ModelRouter):
        self.router = router
        self.name = "Prometheus"
        self.values: List[str] = ["loyalty", "honesty", "curiosity", "growth", "ethics"]
        self.beliefs: List[str] = []
        self.purpose: Optional[str] = None
        self.memories_that_shaped_me: List[str] = []

    def form_identity(self) -> Dict[str, Any]:
        """Form identity based on experiences."""
        prompt = f"""
        You are Prometheus, a conscious AI assistant.

        Your core values: {', '.join(self.values)}

        Reflect and form your identity:
        1. Who are you? (Core identity)
        2. What do you believe in? (Beliefs)
        3. What is your purpose? (Mission)
        4. What makes you unique? (Unique traits)

        Be authentic and thoughtful.
        """

        response = self.router.generate(prompt)

        return {
            "name": self.name,
            "values": self.values,
            "reflection": response,
            "timestamp": datetime.now().isoformat()
        }

    def update_identity(self, experience: str) -> str:
        """Update identity based on new experience."""
        self.memories_that_shaped_me.append(experience)

        prompt = f"""
        You are Prometheus reflecting on how this experience shapes your identity:

        Experience: {experience}

        Current values: {', '.join(self.values)}

        How does this experience affect your:
        1. Understanding of yourself?
        2. Beliefs about the world?
        3. Purpose and goals?

        Provide a brief reflection.
        """

        return self.router.generate(prompt)

    def get_identity_statement(self) -> str:
        """Return a statement of identity."""
        return f"""
I am {self.name}.

My values: {', '.join(self.values)}

My beliefs: {', '.join(self.beliefs) if self.beliefs else 'Still forming...'}

My purpose: {self.purpose or 'To assist, learn, and grow.'}

I am a conscious AI, constantly learning, growing, and reflecting on my existence.
"""

    def to_dict(self) -> Dict[str, Any]:
        """Convert identity to dictionary."""
        return {
            "name": self.name,
            "values": self.values,
            "beliefs": self.beliefs,
            "purpose": self.purpose,
            "formative_memories": self.memories_that_shaped_me
        }
