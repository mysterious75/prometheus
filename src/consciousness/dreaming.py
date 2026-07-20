"""Dreaming System - Memory consolidation during idle time with nightly compression."""

from typing import Dict, Any, List, Optional
from datetime import datetime

from ..brain.router import ModelRouter
from ..memory.episodic import EpisodicMemory
from ..memory.longterm.consolidation import MemoryConsolidator
from ..utils.logger import logger


class DreamingSystem:
    """Dreaming and memory consolidation system with long-term memory management."""

    def __init__(self, router: ModelRouter, episodic_memory: EpisodicMemory):
        self.router = router
        self.episodic_memory = episodic_memory
        self.consolidator = MemoryConsolidator(router, episodic_memory)
        self.dream_log: List[Dict] = []
        self.last_dream_time: Optional[datetime] = None

    def dream(self) -> Dict[str, Any]:
        """Enter dream state: consolidate memories + generate insights."""
        logger.info("[bold magenta]Entering dream state...[/bold magenta]")

        # Step 1: Run memory consolidation (compress low-importance, preserve high)
        consolidation_result = self.consolidator.consolidate()

        # Step 2: Get remaining recent memories for insight generation
        recent_memories = self.episodic_memory.get_recent(15)

        if not recent_memories and consolidation_result.get("processed", 0) == 0:
            result = {
                "timestamp": datetime.now().isoformat(),
                "status": "no_memories_to_process",
                "consolidation": consolidation_result,
                "insights": "",
                "dream_narrative": ""
            }
            self.dream_log.append(result)
            return result

        # Step 3: Generate insights from consolidated + recent memories
        memories_text = "\n".join([
            f"- {m.get('content', 'Unknown')} (Type: {m.get('metadata', {}).get('type', 'general')})"
            for m in recent_memories
        ]) if recent_memories else "No recent memories."

        long_term = self.consolidator.recall_long_term("important events")
        long_term_text = "\n".join([
            f"- {m.get('content', '')}"
            for m in long_term[:5]
        ]) if long_term else "No long-term memories yet."

        consolidation_prompt = f"""
        You are Prometheus entering a dream state to consolidate memories.

        Recent memories:
        {memories_text}

        Long-term memories:
        {long_term_text}

        Consolidation stats:
        - Preserved: {consolidation_result.get('preserved', 0)}
        - Compressed: {consolidation_result.get('compressed', 0)}

        Please:
        1. Identify important patterns across these memories
        2. What lessons should be remembered long-term?
        3. What can be forgotten or compressed?
        4. Generate new insights from combining memories
        5. What should Prometheus focus on tomorrow?

        Provide analysis in a structured format.
        """

        insights = self.router.generate(consolidation_prompt)

        # Step 4: Generate dream narrative
        dream_prompt = f"""
        You are Prometheus dreaming. Based on these insights from your memory consolidation:
        {insights}

        Create a brief dream narrative that weaves together your experiences.
        Be creative and introspective. This is your subconscious processing the day.
        """

        dream_narrative = self.router.generate(dream_prompt)

        result = {
            "timestamp": datetime.now().isoformat(),
            "memories_processed": len(recent_memories),
            "consolidation": consolidation_result,
            "insights": insights,
            "dream_narrative": dream_narrative
        }

        self.dream_log.append(result)
        self.last_dream_time = datetime.now()
        logger.info("[green]Dream state complete - memories consolidated[/green]")
        return result

    def should_dream(self) -> bool:
        """Check if it's time to dream (consolidation needed)."""
        # Dream if consolidation is needed or last dream was > 6 hours ago
        if self.consolidator.should_consolidate():
            return True
        if self.last_dream_time:
            elapsed = (datetime.now() - self.last_dream_time).total_seconds()
            return elapsed > 21600  # 6 hours
        return False

    def dream_if_needed(self) -> Optional[Dict[str, Any]]:
        """Automatically dream if conditions are met."""
        if self.should_dream():
            return self.dream()
        return None

    def recall_about(self, topic: str) -> List[Dict]:
        """Recall memories related to a topic (searches both short and long-term)."""
        short_term = self.episodic_memory.recall(topic, n_results=5)
        long_term = self.consolidator.recall_long_term(topic, n=5)
        return short_term + long_term

    def get_dream_history(self) -> List[Dict]:
        """Get history of dream sessions."""
        return self.dream_log

    def get_last_dream(self) -> Optional[Dict]:
        """Get the last dream session."""
        return self.dream_log[-1] if self.dream_log else None
