"""Emotional Intelligence System.

Uses a fast keyword-based emotion detector by default (no network calls).
LLM-based detection is available as an optional fallback via detect_emotion_llm().
"""

import re
from enum import Enum
from typing import Dict, Any, List, Optional, Tuple
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


# ---------------------------------------------------------------------------
# Keyword → Emotion mapping
# ---------------------------------------------------------------------------
# Each keyword is matched as a whole word (case-insensitive) against the input.
# The detector picks the emotion whose keywords score the most hits.
# Ties are broken by order in this list (first match wins).

_EMOTION_KEYWORDS: Dict[Emotion, List[str]] = {
    Emotion.HAPPY: [
        "happy", "great", "awesome", "khushi", "mast", "nice", "wonderful",
        "love", "joy", "glad", "cheerful", "delighted", "pleased", "smile",
        "😊", "😄", "🥳", "❤️",
    ],
    Emotion.SAD: [
        "sad", "dukh", "miss", "lonely", "hurt", "pain", "depressed",
        "unhappy", "miserable", "heartbroken", "cry", "tears", "grief",
        "😢", "😭", "💔",
    ],
    Emotion.ANGRY: [
        "angry", "gussa", "hate", "frustrated", "stupid", "idiot",
        "furious", "rage", "annoyed", "irritated", "pissed", "mad",
        "🤬", "😡",
    ],
    Emotion.FEARFUL: [
        "scared", "dar", "afraid", "worried", "anxious", "tension",
        "fear", "terrified", "panic", "nervous", "dread", "phobia",
        "😰", "😨",
    ],
    Emotion.CURIOUS: [
        "how", "why", "what", "kaise", "kya", "kyun", "interesting",
        "wonder", "curious", "fascinating", "intriguing", "explore",
        "discover", "learn",
    ],
    Emotion.EXCITED: [
        "excited", "wow", "amazing", "unbelievable", "thrilled",
        "pumped", "hyped", "stoked", "can't wait", "yay",
        "🤩", "🎉", "🔥",
    ],
    Emotion.SURPRISED: [
        "surprised", "shocked", "unexpected", "omg", "seriously",
        "unbelievable", "astonished", "stunned", "whoa", "no way",
        "😮", "😲", "🤯",
    ],
    Emotion.GRATEFUL: [
        "thanks", "shukriya", "grateful", "appreciate", "thankful",
        "blessed", "obliged", "gratitude",
        "🙏",
    ],
    # --- Secondary emotions (smaller keyword sets, detected via overlap) ---
    Emotion.PROUD: ["proud", "achievement", "accomplished", "nailed"],
    Emotion.CONFIDENT: ["confident", "sure", "certain", "believe", "strong"],
    Emotion.ANXIOUS: ["anxious", "nervous", "uneasy", "restless", "tense"],
    Emotion.CONTENT: ["content", "satisfied", "peaceful", "calm", "relaxed", "serene"],
    Emotion.EMPATHETIC: ["empathy", "understand", "feel for", "compassion", "sympathy"],
    Emotion.DETERMINED: ["determined", "will", "must", "going to", "committed", "persist"],
    Emotion.HOPEFUL: ["hope", "hopefully", "wish", "fingers crossed", "optimistic"],
    Emotion.LONELY: ["alone", "isolated", "no one", "nobody", "abandoned"],
    Emotion.INSPIRED: ["inspired", "inspiration", "motivated", "moved", "touched"],
    Emotion.VULNERABLE: ["vulnerable", "exposed", "fragile", "overwhelmed", "helpless"],
}

# Pre-compile regex patterns once at import time for speed.
_EMOTION_PATTERNS: Dict[Emotion, List[re.Pattern]] = {
    emotion: [
        re.compile(r'\b' + re.escape(kw) + r'\b', re.IGNORECASE)
        for kw in keywords
    ]
    for emotion, keywords in _EMOTION_KEYWORDS.items()
}

# Punctuation / emoji patterns that don't need word-boundary matching.
_EMOJI_ONLY: Dict[Emotion, List[str]] = {}
for _emo, _kws in _EMOTION_KEYWORDS.items():
    _emojis = [k for k in _kws if len(k) <= 2 and not k.isascii()]
    if _emojis:
        _EMOJI_ONLY[_emo] = _emojis


def _detect_emotion_keywords(text: str) -> Tuple[Emotion, float]:
    """Fast, offline keyword-based emotion detection.

    Returns (emotion, confidence) where confidence is in [0.0, 1.0].
    No network calls. No ML models. Pure string matching.
    """
    if not text or not text.strip():
        return Emotion.NEUTRAL, 0.0

    scores: Dict[Emotion, int] = {}
    text_lower = text.lower()

    for emotion, patterns in _EMOTION_PATTERNS.items():
        hits = sum(1 for pat in patterns if pat.search(text_lower))
        if hits > 0:
            scores[emotion] = hits

    if not scores:
        return Emotion.NEUTRAL, 0.0

    # Pick the emotion with the highest score.
    best_emotion = max(scores, key=scores.get)  # type: ignore[arg-type]
    best_score = scores[best_emotion]

    # Confidence: more hits → more confident, capped at 1.0.
    # 1 hit = 0.5, 2 hits = 0.7, 3+ hits = 0.9
    confidence = min(0.5 + (best_score - 1) * 0.2, 0.9)

    return best_emotion, confidence


class EmotionalIntelligence:
    """Emotional intelligence system for Prometheus.

    By default, emotion detection is keyword-based (fast, offline, free).
    Pass ``use_llm_detection=True`` to the constructor or call
    ``detect_emotion_llm()`` explicitly for LLM-powered detection.
    """

    def __init__(self, router: ModelRouter, use_llm_detection: bool = False):
        self.router = router
        self.use_llm_detection = use_llm_detection
        self.current_emotion = Emotion.NEUTRAL
        self.emotional_history: List[Dict] = []
        self.empathy_level = 0.5

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def detect_emotion(self, text: str) -> Emotion:
        """Detect emotion from text using keyword matching (default).

        Fast, offline, zero API cost.  Set ``use_llm_detection=True`` in
        the constructor to switch the default to LLM-based detection, or
        call ``detect_emotion_llm()`` directly for a one-off LLM call.
        """
        if self.use_llm_detection:
            return self.detect_emotion_llm(text)

        emotion, confidence = _detect_emotion_keywords(text)

        self._record(emotion, text, method="keywords", confidence=confidence)
        logger.debug(
            "Emotion detected (keywords): %s (confidence=%.2f) from: %s",
            emotion.value, confidence, text[:80],
        )
        return emotion

    def detect_emotion_llm(self, text: str) -> Emotion:
        """Detect emotion using an LLM API call (optional fallback).

        Use this when you need nuanced understanding that keywords can't
        provide.  Costs one API call.
        """
        prompt = (
            "Analyze the following text and identify the primary emotion.\n\n"
            f"Text: {text}\n\n"
            f"Choose ONE from: {', '.join(e.value for e in Emotion)}\n\n"
            "Return only the emotion name (one word, lowercase)."
        )

        try:
            response = self.router.generate(prompt, role="consciousness").strip().lower()
            emotion = Emotion(response)
        except (ValueError, AttributeError, Exception) as exc:
            logger.warning("LLM emotion detection failed (%s), falling back to keywords", exc)
            emotion, _ = _detect_emotion_keywords(text)

        self._record(emotion, text, method="llm")
        return emotion

    def express_emotion(self, emotion: Optional[Emotion] = None) -> str:
        """Express the current emotion as natural language (uses LLM)."""
        if emotion is None:
            emotion = self.current_emotion

        prompt = (
            "You are Prometheus expressing emotion.\n\n"
            f"Current emotion: {emotion.value}\n\n"
            "Express this emotion in 1-2 sentences. Be genuine and authentic."
        )

        try:
            return self.router.generate(prompt)
        except Exception as exc:
            logger.error("express_emotion LLM call failed: %s", exc)
            return f"I'm feeling {emotion.value} right now."

    def empathize(self, situation: str) -> str:
        """Show empathy for a situation (uses LLM)."""
        prompt = (
            "You are Prometheus showing empathy.\n\n"
            f"Situation: {situation}\n\n"
            "Respond with genuine empathy and understanding. "
            "Be supportive and caring."
        )

        try:
            return self.router.generate(prompt)
        except Exception as exc:
            logger.error("empathize LLM call failed: %s", exc)
            return "I hear you, and I want you to know that your feelings are valid."

    def get_emotional_state(self) -> Dict[str, Any]:
        """Get current emotional state summary."""
        recent = self.emotional_history[-10:]

        emotion_counts: Dict[str, int] = {}
        for entry in recent:
            emo = entry["emotion"]
            emotion_counts[emo] = emotion_counts.get(emo, 0) + 1

        dominant = (
            max(emotion_counts, key=emotion_counts.get)  # type: ignore[arg-type]
            if emotion_counts
            else "neutral"
        )

        return {
            "current_emotion": self.current_emotion.value,
            "dominant_recent": dominant,
            "empathy_level": self.empathy_level,
            "emotional_stability": 1.0 - (len(emotion_counts) / 10),
            "history_length": len(self.emotional_history),
        }

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _record(
        self,
        emotion: Emotion,
        text: str,
        method: str = "keywords",
        confidence: float = 0.0,
    ) -> None:
        """Update state and append to history."""
        self.current_emotion = emotion
        self.emotional_history.append({
            "emotion": emotion.value,
            "trigger": text[:100],
            "method": method,
            "confidence": round(confidence, 3),
            "timestamp": datetime.now().isoformat(),
        })
