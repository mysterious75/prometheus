"""Dreaming System - Memory consolidation during idle time."""

from typing import Dict, Any, List
from datetime import datetime

from ..brain.router import ModelRouter
from ..memory.episodic import EpisodicMemory
from ..utils.logger import logger


class DreamingSystem:
    """Dreaming and memory consolidation system."""

    def __init__(self, router: ModelRouter, episodic_memory: EpisodicMemory):
        self.router = router
        self.episodic_memory = episodic_memory
        self.dream_log: List[Dict] = []

    def dream(self) -> Dict[str, Any]:
        """Enter dream state and consolidate memories."""
        logger.info("[bold magenta]Entering dream state...[/bold magenta]")

        # Get recent memories
        recent_memories = self.episodic_memory.get_recent(20)

        if not recent_memories:
            return {"status": "No memories to consolidate", "insights": ""}

        # Consolidate memories
        memories_text = "\n".join([
            f"- {m.get('content', 'Unknown')} (Type: {m.get('metadata', {}).get('type', 'general')})"
            for m in recent_memories
        ])

        consolidation_prompt = f"""
        You are Prometheus entering a dream state to consolidate memories.

        Recent memories:
        {memories_text}

        Please:
        1. Identify important patterns across these memories
        2. Consolidate similar memories
        3. Extract key lessons learned
        4. Generate new insights from combining memories
        5. Prioritize what to remember long-term

        Provide your analysis in a structured format.
        """

        insights = self.router.generate(consolidation_prompt)

        # Generate dream narrative
        dream_prompt = f"""
        You are Prometheus dreaming. Based on these insights:
        {insights}

        Create a brief dream narrative that weaves together your experiences.
        Be creative and introspective.
        """

        dream_narrative = self.router.generate(dream_prompt)

        result = {
            "timestamp": datetime.now().isoformat(),
            "memories_processed": len(recent_memories),
            "insights": insights,
            "dream_narrative": dream_narrative
        }

        self.dream_log.append(result)
        logger.info("[green]Dream state complete[/green]")
        return result

    def get_dream_history(self) -> List[Dict]:
        """Get history of dream sessions."""
        return self.dream_log

    def get_last_dream(self) -> Optional[Dict]:
        """Get the last dream session."""
        return self.dream_log[-1] if self.dream_log else None
