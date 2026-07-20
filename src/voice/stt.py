"""Speech-to-Text using Whisper."""

import os
from typing import Optional
from pathlib import Path

try:
    import whisper
    WHISPER_AVAILABLE = True
except ImportError:
    WHISPER_AVAILABLE = False

from ..utils.logger import logger


class SpeechToText:
    """Speech-to-text using OpenAI Whisper."""

    def __init__(self, model_size: str = "base"):
        self.model_size = model_size
        self.model = None

        if WHISPER_AVAILABLE:
            try:
                logger.info(f"Loading Whisper model: {model_size}")
                self.model = whisper.load_model(model_size)
                logger.info(f"[green]✓ Whisper {model_size} loaded[/green]")
            except Exception as e:
                logger.warning(f"[yellow]⚠ Could not load Whisper: {e}[/yellow]")
        else:
            logger.warning("[yellow]⚠ Whisper not installed. Run: pip install openai-whisper[/yellow]")

    def transcribe(self, audio_path: str, language: Optional[str] = None) -> str:
        """Transcribe an audio file to text."""
        if not self.model:
            return "[ERROR] Whisper model not loaded"

        try:
            options = {}
            if language:
                options["language"] = language

            result = self.model.transcribe(audio_path, **options)
            return result["text"]
        except Exception as e:
            return f"[STT Error] {str(e)}"

    def is_available(self) -> bool:
        """Check if STT is available."""
        return self.model is not None
