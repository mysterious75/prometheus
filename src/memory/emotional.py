"""Emotional Memory - Tracks emotional context of experiences."""

from datetime import datetime
from typing import Optional, Dict, Any, List
from .chroma import VectorMemory


class EmotionalMemory:
    """Emotional memory for tracking feelings and emotional context."""

    def __init__(self, vector_memory: VectorMemory):
        self.vector_memory = vector_memory
        self.emotional_history: List[Dict] = []

    def store_emotional_event(self, event: str, emotion: str,
                              intensity: float = 0.5, metadata: Optional[Dict] = None) -> str:
        """Store an event with emotional context."""
        meta = {
            "emotion": emotion,
            "intensity": intensity,
            "timestamp": datetime.now().isoformat(),
            **(metadata or {})
        }

        doc_id = self.vector_memory.store(event, meta, collection="episodic")
        self.emotional_history.append({
            "id": doc_id,
            "event": event,
            "emotion": emotion,
            "intensity": intensity
        })
        return doc_id

    def recall_by_emotion(self, emotion: str, n_results: int = 5) -> List[Dict]:
        """Recall memories associated with a specific emotion."""
        all_memories = self.vector_memory.get_all(collection="episodic")
        emotional_memories = [
            m for m in all_memories
            if m.get("metadata", {}).get("emotion") == emotion
        ]
        return emotional_memories[:n_results]

    def get_emotional_state(self) -> Dict[str, Any]:
        """Get current emotional state based on recent history."""
        if not self.emotional_history:
            return {"emotion": "neutral", "intensity": 0.0, "history": []}

        recent = self.emotional_history[-10:]
        emotion_counts = {}
        for entry in recent:
            emotion = entry["emotion"]
            emotion_counts[emotion] = emotion_counts.get(emotion, 0) + 1

        dominant_emotion = max(emotion_counts, key=emotion_counts.get) if emotion_counts else "neutral"
        avg_intensity = sum(e["intensity"] for e in recent) / len(recent) if recent else 0.0

        return {
            "emotion": dominant_emotion,
            "intensity": avg_intensity,
            "history": recent[-5:]
        }
