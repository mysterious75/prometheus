"""Conversation Memory - Remembers all past interactions."""

from typing import Dict, Any, List, Optional
from datetime import datetime
import json
from pathlib import Path

from ..utils.logger import logger


class ConversationMemory:
    """Stores and recalls full conversation history with user."""

    def __init__(self, storage_path: Optional[Path] = None):
        self.storage_path = storage_path or Path(__file__).parent.parent.parent / "data" / "conversations"
        self.storage_path.mkdir(parents=True, exist_ok=True)
        self.conversations: List[Dict] = []
        self.user_profiles: Dict[str, Dict] = {}
        self._load()

    def _load(self):
        """Load conversation history from disk."""
        history_file = self.storage_path / "history.json"
        if history_file.exists():
            try:
                with open(history_file, encoding="utf-8") as f:
                    data = json.load(f)
                    self.conversations = data.get("conversations", [])
                    self.user_profiles = data.get("user_profiles", {})
            except Exception:
                self.conversations = []
                self.user_profiles = {}

    def _save(self):
        """Save conversation history to disk."""
        history_file = self.storage_path / "history.json"
        try:
            with open(history_file, "w", encoding="utf-8") as f:
                json.dump({
                    "conversations": self.conversations[-500:],  # keep last 500
                    "user_profiles": self.user_profiles
                }, f, indent=2, ensure_ascii=False)
        except Exception as e:
            logger.warning(f"Failed to save conversation: {e}")

    def store_interaction(self, user_input: str, response: str, emotion: str = "neutral"):
        """Store a user-AI interaction."""
        interaction = {
            "user": user_input,
            "ai": response,
            "emotion": emotion,
            "timestamp": datetime.now().isoformat()
        }
        self.conversations.append(interaction)
        self._update_user_profile(user_input)
        self._save()

    def _update_user_profile(self, user_input: str):
        """Update what we know about the user."""
        # Track topics user asks about
        words = user_input.lower().split()
        key_topics = ["bug", "code", "scan", "help", "think", "dream", "status", "hello", "bye"]
        for topic in key_topics:
            if topic in words:
                self.user_profiles.setdefault("topics", {})
                self.user_profiles["topics"][topic] = self.user_profiles["topics"].get(topic, 0) + 1

        # Track language patterns
        self.user_profiles["total_interactions"] = self.user_profiles.get("total_interactions", 0) + 1
        self.user_profiles["last_interaction"] = datetime.now().isoformat()

    def recall_recent(self, n: int = 10) -> List[Dict]:
        """Recall recent conversation."""
        return self.conversations[-n:]

    def recall_about(self, topic: str, n: int = 5) -> List[Dict]:
        """Recall conversations about a specific topic."""
        results = []
        for conv in reversed(self.conversations):
            if topic.lower() in conv["user"].lower() or topic.lower() in conv["ai"].lower():
                results.append(conv)
                if len(results) >= n:
                    break
        return results

    def get_user_context(self) -> str:
        """Get context about the user for personalized responses."""
        if not self.user_profiles:
            return "New user, no history yet."

        parts = []
        total = self.user_profiles.get("total_interactions", 0)
        parts.append(f"Total conversations: {total}")

        topics = self.user_profiles.get("topics", {})
        if topics:
            top_topics = sorted(topics.items(), key=lambda x: x[1], reverse=True)[:3]
            parts.append(f"User often asks about: {', '.join([t[0] for t in top_topics])}")

        return " | ".join(parts)

    def get_conversation_summary(self) -> str:
        """Generate a summary of all conversations."""
        if not self.conversations:
            return "No conversations yet."

        recent = self.conversations[-20:]
        summary_parts = []
        for conv in recent:
            summary_parts.append(f"User: {conv['user'][:50]}... | Emotion: {conv['emotion']}")

        return "\n".join(summary_parts)

    def count(self) -> int:
        return len(self.conversations)

    def get_stats(self) -> Dict[str, Any]:
        return {
            "total_interactions": len(self.conversations),
            "user_profile": self.user_profiles,
            "last_5_topics": [c["user"][:30] for c in self.conversations[-5:]]
        }
