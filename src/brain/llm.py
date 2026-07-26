"""LLM Provider integration for Project Prometheus.

Supports 13+ providers with auto-detection, key testing, and smart routing.
Primary: DeepSeek (long context, cheap)
Fast: Google Gemini (3 keys for rotation)
"""

import os
import json
import time
import re
import concurrent.futures
from abc import ABC, abstractmethod
from typing import Optional, Dict, Any, List, Tuple
from pathlib import Path
from datetime import datetime, timedelta

from dotenv import load_dotenv
env_path = Path(__file__).parent.parent.parent / ".env"
load_dotenv(env_path)

from ..utils.logger import logger


def _redact_api_keys(text: str) -> str:
    """Redact common API key patterns (sk-..., pk-...) from error strings."""
    return re.sub(r'(sk-|pk-)[A-Za-z0-9]{3,}', r'\1***', str(text))


class LLMProvider(ABC):
    """Abstract base class for LLM providers."""

    def __init__(self, name: str, api_key: str, model: str = "", base_url: str = ""):
        self.name = name
        self.api_key = api_key
        self.model = model
        self.base_url = base_url
        self.total_tokens_used = 0
        self.daily_tokens_used = 0
        self.daily_reset = datetime.now() + timedelta(days=1)
        self.role = ""
        self.available = False
        self.last_error = ""
        self.models_available = []
        self.tokens_remaining = None

    def __repr__(self):
        masked = self.api_key[:6] + "..." + self.api_key[-4:] if len(self.api_key) > 12 else self.api_key[:4] + "..." + self.api_key[-4:] if len(self.api_key) > 8 else "***"
        return f"{self.__class__.__name__}(name='{self.name}', api_key='{masked}')"

    @abstractmethod
    def generate(self, prompt: str, **kwargs) -> str:
        pass

    @abstractmethod
    def generate_stream(self, prompt: str, **kwargs):
        pass

    def test_key(self) -> Tuple[bool, str, List[str]]:
        """Test if API key works. Returns (success, message, models_available)."""
        return False, "Not implemented", []

    def get_usage(self) -> Dict[str, Any]:
        # Reset daily counter if needed
        if datetime.now() > self.daily_reset:
            self.daily_tokens_used = 0
            self.daily_reset = datetime.now() + timedelta(days=1)

        return {
            "provider": self.name,
            "model": self.model,
            "role": self.role,
            "available": self.available,
            "total_tokens": self.total_tokens_used,
            "daily_tokens": self.daily_tokens_used,
            "tokens_remaining": self.tokens_remaining,
            "models": self.models_available[:5],
        }


class OpenAICompatibleProvider(LLMProvider):
    """Generic OpenAI-compatible API provider (works with most providers)."""

    def __init__(self, name: str, api_key: str, model: str = "",
                 base_url: str = "", role: str = "", **kwargs):
        super().__init__(name, api_key, model, base_url)
        self.role = role
        self._client = None

    def _get_client(self):
        if self._client is None:
            try:
                from openai import OpenAI
                self._client = OpenAI(
                    base_url=self.base_url,
                    api_key=self.api_key,
                    timeout=30,
                )
            except ImportError:
                raise ImportError("Install openai: pip install openai")
        return self._client

    def test_key(self) -> Tuple[bool, str, List[str]]:
        try:
            client = self._get_client()
            models = client.models.list()
            model_ids = [m.id for m in models.data][:20]
            self.models_available = model_ids
            self.available = True

            # Check if our model is in the list
            if self.model and self.model not in model_ids:
                # Try anyway with the configured model
                pass

            return True, f"{len(model_ids)} models available", model_ids
        except Exception as e:
            self.last_error = _redact_api_keys(str(e))
            self.available = False
            return False, str(e), []

    def generate(self, prompt: str, **kwargs) -> str:
        last_exception = None
        for attempt in range(3):
            try:
                client = self._get_client()
                # Free models have very limited tokens - use lower max_tokens
                is_free = ":free" in (self.model or "") or "free" in (self.model or "").lower()
                default_tokens = 200 if is_free else 1024
                response = client.chat.completions.create(
                    model=self.model,
                    messages=[{"role": "user", "content": prompt}],
                    max_tokens=kwargs.get("max_tokens", default_tokens),
                    temperature=kwargs.get("temperature", 0.7)
                )
                tokens = 0
                if response and hasattr(response, 'usage') and response.usage:
                    tokens = response.usage.total_tokens
                self.total_tokens_used += tokens
                self.daily_tokens_used += tokens
                content = response.choices[0].message.content
                if content is None or (isinstance(content, str) and len(content.strip()) == 0):
                    msg = response.choices[0].message
                    if hasattr(msg, 'reasoning') and msg.reasoning:
                        lines = msg.reasoning.strip().split('\n')
                        content = lines[-1] if lines else msg.reasoning
                return content or ""
            except Exception as e:
                last_exception = e
                error_str = str(e).lower()
                is_retryable = (
                    "429" in error_str
                    or "rate limit" in error_str
                    or "timeout" in error_str
                    or "connection" in error_str
                    or "service unavailable" in error_str
                    or "too many requests" in error_str
                )
                if is_retryable and attempt < 2:
                    time.sleep(2 ** attempt)
                    continue
                break
        return f"[{self.name} Error] {_redact_api_keys(str(last_exception))}"

    def generate_stream(self, prompt: str, **kwargs):
        try:
            client = self._get_client()
            is_free = ":free" in (self.model or "")
            default_tokens = 100 if is_free else 1024
            response = client.chat.completions.create(
                model=self.model,
                messages=[{"role": "user", "content": prompt}],
                max_tokens=kwargs.get("max_tokens", default_tokens),
                temperature=kwargs.get("temperature", 0.7),
                stream=True
            )
            for chunk in response:
                if chunk.choices[0].delta.content:
                    yield chunk.choices[0].delta.content
        except Exception as e:
            yield f"[{self.name} Error] {str(e)}"


class GeminiProvider(LLMProvider):
    """Google Gemini - Fast responses (free tier: ~150K tokens/day)."""

    def __init__(self, api_key: str, model: str = "gemini-2.0-flash",
                 key_name: str = "gemini_1", role: str = "fast"):
        super().__init__(key_name, api_key, model)
        self.role = role
        self.genai = None

    def _init_genai(self):
        if self.genai is None:
            try:
                import google.generativeai as genai
                genai.configure(api_key=self.api_key)
                self.genai = genai
            except ImportError:
                raise ImportError("Install google-generativeai: pip install google-generativeai")

    def test_key(self) -> Tuple[bool, str, List[str]]:
        try:
            self._init_genai()
            models = self.genai.list_models()
            model_ids = [m.name.replace("models/", "") for m in models
                        if "generateContent" in [m.supported_generation_methods[i]
                        for i in range(len(m.supported_generation_methods))]]
            self.models_available = model_ids[:20]
            self.available = True
            return True, f"{len(model_ids)} models available", model_ids
        except Exception as e:
            # Try simpler approach
            try:
                self._init_genai()
                model = self.genai.GenerativeModel(self.model)
                response = model.generate_content("Say hi in 3 words")
                self.available = True
                self.models_available = [self.model]
                return True, "Key works (single model test)", [self.model]
            except Exception as e2:
                self.last_error = _redact_api_keys(str(e2))
                self.available = False
                return False, str(e2), []

    def generate(self, prompt: str, **kwargs) -> str:
        last_exception = None
        for attempt in range(3):
            try:
                self._init_genai()
                model = self.genai.GenerativeModel(self.model)
                response = model.generate_content(prompt)
                tokens = 0
                if response and hasattr(response, 'usage_metadata') and response.usage_metadata:
                    tokens = response.usage_metadata.total_token_count
                self.total_tokens_used += tokens
                self.daily_tokens_used += tokens
                return response.text
            except Exception as e:
                last_exception = e
                error_str = str(e).lower()
                is_retryable = (
                    "429" in error_str
                    or "rate limit" in error_str
                    or "timeout" in error_str
                    or "connection" in error_str
                    or "service unavailable" in error_str
                )
                if is_retryable and attempt < 2:
                    time.sleep(2 ** attempt)
                    continue
                break
        return f"[Gemini Error] {_redact_api_keys(str(last_exception))}"

    def generate_stream(self, prompt: str, **kwargs):
        try:
            self._init_genai()
            model = self.genai.GenerativeModel(self.model)
            response = model.generate_content(prompt, stream=True)
            for chunk in response:
                if chunk.text:
                    yield chunk.text
        except Exception as e:
            yield f"[Gemini Error] {str(e)}"

    def generate_with_image(self, prompt: str, image_bytes: bytes, mime_type: str = "image/jpeg") -> str:
        """Generate response with image input (vision capability)."""
        try:
            self._init_genai()
            from google.generativeai.types import Part
            image_part = Part.from_data(data=image_bytes, mime_type=mime_type)
            model = self.genai.GenerativeModel(self.model)
            response = model.generate_content([prompt, image_part])
            tokens = 0
            if response and hasattr(response, 'usage_metadata') and response.usage_metadata:
                tokens = response.usage_metadata.total_token_count
            self.total_tokens_used += tokens
            self.daily_tokens_used += tokens
            return response.text
        except Exception as e:
            return f"[Gemini Vision Error] {str(e)}"


# ============================================================
# Provider Factory - creates providers from config
# ============================================================

def create_provider(name: str, config: Dict) -> Optional[LLMProvider]:
    """Create a provider from config dict."""
    api_key_env = config.get("api_key_env", "")
    api_key = os.getenv(api_key_env, "")
    if not api_key:
        return None

    model = config.get("model", "")
    base_url = config.get("base_url", "")
    role = config.get("role", "")

    # Special handling for Gemini
    if "gemini" in name.lower() or "google" in name.lower():
        return GeminiProvider(api_key, model, name, role)

    # Everything else uses OpenAI-compatible API
    return OpenAICompatibleProvider(name, api_key, model, base_url, role)
