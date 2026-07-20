"""Text-to-Speech using Kokoro."""

import os
from typing import Optional

try:
    from kokoro import KPipeline
    KOKORO_AVAILABLE = True
except ImportError:
    KOKORO_AVAILABLE = False

try:
    import soundfile as sf
    SOUNDFILE_AVAILABLE = True
except ImportError:
    SOUNDFILE_AVAILABLE = False

from ..utils.logger import logger


class TextToSpeech:
    """Text-to-speech using Kokoro."""

    def __init__(self):
        self.pipeline = None

        if KOKORO_AVAILABLE:
            try:
                logger.info("Loading Kokoro TTS pipeline")
                self.pipeline = KPipeline(lang_code='a')
                logger.info("[green]✓ Kokoro TTS loaded[/green]")
            except Exception as e:
                logger.warning(f"[yellow]⚠ Could not load Kokoro: {e}[/yellow]")
        else:
            logger.warning("[yellow]⚠ Kokoro not installed. Run: pip install kokoro[/yellow]")

    def speak(self, text: str, output_path: Optional[str] = None, voice: str = "af_heart") -> Optional[str]:
        """Convert text to speech and save to file."""
        if not self.pipeline:
            logger.warning("[yellow]TTS not available[/yellow]")
            return None

        try:
            # Generate audio
            audio_data = None
            for i, (gs, ps, audio) in enumerate(self.pipeline(text, voice=voice)):
                audio_data = audio
                break

            if audio_data is None:
                return None

            # Save to file
            if output_path is None:
                output_path = "output_tts.wav"

            if SOUNDFILE_AVAILABLE:
                sf.write(output_path, audio_data, 24000)
            else:
                # Fallback: save raw bytes
                import wave
                import numpy as np
                audio_int16 = (audio_data * 32767).astype(np.int16)
                with wave.open(output_path, 'w') as wf:
                    wf.setnchannels(1)
                    wf.setsampwidth(2)
                    wf.setframerate(24000)
                    wf.writeframes(audio_int16.tobytes())

            logger.info(f"[green]✓ Audio saved to {output_path}[/green]")
            return output_path
        except Exception as e:
            logger.error(f"[red]TTS Error: {e}[/red]")
            return None

    def is_available(self) -> bool:
        """Check if TTS is available."""
        return self.pipeline is not None
