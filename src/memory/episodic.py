"""Episodic Memory - Stores experiences and events."""

from datetime import datetime
from typing import Optional, Dict, Any, List
from .chroma import VectorMemory


class EpisodicMemory:
    """Episodic memory for storing experiences and events."""

    def __init__(self, vector_memory: VectorMemory):
        self.vector_memory = vector_memory
        self.events: List[Dict] = []

    def store_event(self, event: str, event_type: str = "general",
                    importance: float = 0.5, metadata: Optional[Dict] = None) -> str:
        """Store an event/experience."""
        meta = {
            "type": event_type,
            "importance": importance,
            "timestamp": datetime.now().isoformat(),
            **(metadata or {})
        }

        doc_id = self.vector_memory.store(event, meta, collection="episodic")
        self.events.append({"id": doc_id, "event": event, "type": event_type})
        return doc_id

    def recall(self, query: str, n_results: int = 5) -> List[Dict]:
        """Recall related experiences."""
        return self.vector_memory.search(query, n_results, collection="episodic")

    def get_recent(self, n: int = 10) -> List[Dict]:
        """Get most recent events."""
        all_events = self.vector_memory.get_all(collection="episodic")
        return sorted(all_events, key=lambda x: x.get("metadata", {}).get("timestamp", ""), reverse=True)[:n]

    def get_important(self, min_importance: float = 0.7) -> List[Dict]:
        """Get important events."""
        all_events = self.vector_memory.get_all(collection="episodic")
        return [e for e in all_events if e.get("metadata", {}).get("importance", 0) >= min_importance]
