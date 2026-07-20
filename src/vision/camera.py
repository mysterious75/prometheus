"""Webcam Capture - OpenCV-based camera input for AI vision."""

import io
import time
from typing import Optional
from pathlib import Path

from ..utils.logger import logger


class WebcamCapture:
    """Captures frames from webcam using OpenCV."""

    def __init__(self, camera_index: int = 0):
        self.camera_index = camera_index
        self.cap = None
        self.is_connected = False

    def connect(self) -> bool:
        """Connect to webcam."""
        try:
            import cv2
            self.cap = cv2.VideoCapture(self.camera_index)
            if self.cap.isOpened():
                self.is_connected = True
                logger.info("[green]Webcam connected[/green]")
                return True
            else:
                logger.warning("[yellow]Webcam not available[/yellow]")
                return False
        except ImportError:
            logger.warning("[yellow]OpenCV not installed: pip install opencv-python[/yellow]")
            return False
        except Exception as e:
            logger.warning(f"[yellow]Webcam error: {e}[/yellow]")
            return False

    def capture_frame(self) -> Optional[bytes]:
        """Capture a single frame and return as JPEG bytes."""
        if not self.is_connected or not self.cap:
            return None

        try:
            import cv2
            ret, frame = self.cap.read()
            if not ret:
                return None

            # Encode frame as JPEG
            _, buffer = cv2.imencode('.jpg', frame)
            return buffer.tobytes()
        except Exception as e:
            logger.error(f"Frame capture error: {e}")
            return None

    def capture_frame_base64(self) -> Optional[str]:
        """Capture a frame and return as base64 string."""
        import base64
        frame_bytes = self.capture_frame()
        if frame_bytes:
            return base64.b64encode(frame_bytes).decode('utf-8')
        return None

    def capture_periodically(self, interval_seconds: float = 2.0, max_captures: int = 5):
        """Capture frames at intervals (generator)."""
        for _ in range(max_captures):
            frame = self.capture_frame()
            if frame:
                yield frame
            time.sleep(interval_seconds)

    def disconnect(self):
        """Disconnect from webcam."""
        if self.cap:
            self.cap.release()
            self.is_connected = False
            logger.info("Webcam disconnected")

    def __enter__(self):
        self.connect()
        return self

    def __exit__(self, *args):
        self.disconnect()
