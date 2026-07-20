"""Vision Emotion Detection - Analyze facial expressions using Gemini Vision."""

import base64
from typing import Dict, Any, Optional
from datetime import datetime

from ..brain.router import ModelRouter
from ..utils.logger import logger


class VisionEmotionDetector:
    """Detects emotions from facial expressions using webcam + Gemini Vision."""

    # Mapping between vision-detected emotions and internal Emotion enum
    EMOTION_MAP = {
        "happy": "happy",
        "sad": "sad",
        "angry": "angry",
        "fear": "fearful",
        "surprise": "surprised",
        "neutral": "neutral",
        "disgust": "frustrated",
        "contempt": "frustrated",
        "confusion": "curious",
        "excited": "excited",
    }

    def __init__(self, router: ModelRouter):
        self.router = router
        self.detection_history: list = []
        self.last_emotion = "neutral"
        self.confidence = 0.0

    def detect_from_image(self, image_bytes: bytes, mime_type: str = "image/jpeg") -> Dict[str, Any]:
        """Detect emotions from raw image bytes using Gemini Vision."""
        # Check if Gemini provider supports vision
        gemini = self.router.get_provider("gemini")
        if not gemini or not hasattr(gemini, 'generate_with_image'):
            return {"emotion": "neutral", "confidence": 0.0, "error": "Gemini vision not available"}

        prompt = """Analyze this image of a person's face and detect their emotional state.

Return ONLY a JSON object with these fields:
{
    "emotion": "<one of: happy, sad, angry, fear, surprise, neutral, disgust, contempt, confusion, excited>",
    "confidence": <0.0 to 1.0>,
    "facial_features": "<brief description of key facial features observed>",
    "body_language": "<brief note on body language if visible>"
}

Be precise and consider micro-expressions."""

        try:
            response = gemini.generate_with_image(prompt, image_bytes, mime_type)
            # Parse JSON from response
            import json
            # Try to extract JSON from response
            response = response.strip()
            if response.startswith("```"):
                response = response.split("```")[1]
                if response.startswith("json"):
                    response = response[4:]
            result = json.loads(response)

            self.last_emotion = result.get("emotion", "neutral")
            self.confidence = result.get("confidence", 0.0)

            detection = {
                **result,
                "timestamp": datetime.now().isoformat(),
                "source": "vision"
            }
            self.detection_history.append(detection)
            return detection

        except json.JSONDecodeError:
            # Fallback: use text-based detection
            return self._fallback_detect(image_bytes)
        except Exception as e:
            logger.error(f"Vision emotion detection error: {e}")
            return {"emotion": "neutral", "confidence": 0.0, "error": str(e)}

    def _fallback_detect(self, image_bytes: bytes) -> Dict[str, Any]:
        """Fallback detection when JSON parsing fails."""
        gemini = self.router.get_provider("gemini")
        if not gemini:
            return {"emotion": "neutral", "confidence": 0.0}

        prompt = "What emotion is this person feeling? Reply with just one word: happy/sad/angry/neutral/surprise/fear"
        try:
            response = gemini.generate_with_image(prompt, image_bytes)
            emotion = response.strip().lower()
            mapped = self.EMOTION_MAP.get(emotion, "neutral")
            return {"emotion": mapped, "confidence": 0.5, "source": "vision_fallback"}
        except Exception:
            return {"emotion": "neutral", "confidence": 0.0}

    def detect_from_base64(self, base64_string: str) -> Dict[str, Any]:
        """Detect emotions from base64-encoded image."""
        image_bytes = base64.b64decode(base64_string)
        return self.detect_from_image(image_bytes)

    def get_mood_summary(self) -> Dict[str, Any]:
        """Get a summary of recent emotional states from vision."""
        if not self.detection_history:
            return {"dominant_emotion": "neutral", "stability": 1.0, "detections": 0}

        recent = self.detection_history[-20:]
        emotion_counts = {}
        for d in recent:
            e = d.get("emotion", "neutral")
            emotion_counts[e] = emotion_counts.get(e, 0) + 1

        dominant = max(emotion_counts, key=emotion_counts.get)
        stability = 1.0 - (len(emotion_counts) / 10) if len(emotion_counts) > 1 else 1.0

        return {
            "dominant_emotion": dominant,
            "stability": max(0.0, stability),
            "detections": len(self.detection_history),
            "recent_emotions": emotion_counts
        }
