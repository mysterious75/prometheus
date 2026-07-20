"""Vision module - Multi-modal senses for Prometheus."""

from .camera import WebcamCapture
from .emotion import VisionEmotionDetector

__all__ = ["WebcamCapture", "VisionEmotionDetector"]
