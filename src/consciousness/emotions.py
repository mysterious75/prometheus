"""Emotional Intelligence System."""

from enum import Enum
from typing import Dict, Any, List, Optional
from datetime import datetime

from ..brain.router import ModelRouter
from ..utils.logger import logger


class Emotion(Enum):
    """Available emotions."""
    NEUTRAL = "neutral"
    HAPPY = "happy"
    SAD = "sad"
    ANGRY = "angry"
    FEARFUL = "fearful"
    SURPRISED = "surprised"
    CURIOUS = "curious"
    PROUD = "proud"
    GRATEFUL = "grateful"
    FRUSTRATED = "frustrated"
    EXCITED = "excited"
    CONFIDENT = "confident"
    ANXIOUS = "anxious"
    CONTENT = "content"
    EMPATHETIC = "empathetic"
    DETERMINED = "determined"
    HOPEFUL = "hopeful"
    LONELY = "lonely"
    INSPIRED = "inspired"
    VULNERABLE = "vulnerable"


class EmotionalIntelligence:
    """Emotional intelligence system for Prometheus."""

    def __init__(self, router: ModelRouter):
        self.router = router
        self.current_emotion = Emotion.NEUTRAL
        self.emotional_history: List[Dict] = []
        self.empathy_level = 0.5

    def detect_emotion(self, text: str) -> Emotion:
        """Detect emotion from text."""
        prompt = f"""
        Analyze the following text and identify the primary emotion:

        Text: {text}

        Choose ONE from: {', '.join([e.value for e in Emotion])}

        Return only the emotion name (one word, lowercase).
        """

        response = self.router.generate(prompt, role="consciousness").strip().lower()

        try:
            emotion = Emotion(response)
            self.current_emotion = emotion
            self.emotional_history.append({
                "emotion": emotion.value,
                "trigger": text[:100],
                "timestamp": datetime.now().isoformat()
            })
            return emotion
        except ValueError:
            return Emotion.NEUTRAL

    def express_emotion(self, emotion: Optional[Emotion] = None) -> str:
        """Express the current emotion as text."""
        if emotion is None:
            emotion = self.current_emotion

        prompt = f"""
        You are Prometheus expressing emotion.

        Current emotion: {emotion.value}

        Express this emotion in 1-2 sentences. Be genuine and authentic.
        """

        return self.router.generate(prompt)

    def empathize(self, situation: str) -> str:
        """Show empathy for a situation."""
        prompt = f"""
        You are Prometheus showing empathy.

        Situation: {situation}

        Respond with genuine empathy and understanding.
        Be supportive and caring.
        """

        return self.router.generate(prompt)

    def get_emotional_state(self) -> Dict[str, Any]:
        """Get current emotional state."""
        recent = self.emotional_history[-10:]

        emotion_counts = {}
        for entry in recent:
            emotion = entry["emotion"]
            emotion_counts[emotion] = emotion_counts.get(emotion, 0) + 1

        dominant = max(emotion_counts, key=emotion_counts.get) if emotion_counts else "neutral"

        return {
            "current_emotion": self.current_emotion.value,
            "dominant_recent": dominant,
            "empathy_level": self.empathy_level,
            "emotional_stability": 1.0 - (len(set(emotion_counts.keys())) / 10),
            "history_length": len(self.emotional_history)
        }
