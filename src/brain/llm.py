"""LLM Provider integration for Project Prometheus."""

import os
import json
import concurrent.futures
from abc import ABC, abstractmethod
from typing import Optional, Dict, Any, List
from pathlib import Path

from dotenv import load_dotenv
env_path = Path(__file__).parent.parent.parent / ".env"
load_dotenv(env_path)


class LLMProvider(ABC):
    """Abstract base class for LLM providers."""

    def __init__(self, name: str, api_key: str, model: str = ""):
        self.name = name
        self.api_key = api_key
        self.model = model
        self.total_tokens_used = 0
        self.daily_tokens_used = 0
        self.role = ""  # assigned by router: logic, senses, guardrail

    @abstractmethod
    def generate(self, prompt: str, **kwargs) -> str:
        pass

    @abstractmethod
    def generate_stream(self, prompt: str, **kwargs):
        pass

    def get_usage(self) -> Dict[str, Any]:
        return {
            "provider": self.name,
            "model": self.model,
            "role": self.role,
            "total_tokens": self.total_tokens_used,
            "daily_tokens": self.daily_tokens_used
        }


class GeminiProvider(LLMProvider):
    """Google Gemini - The Conscious Actor & Senses (vision, large context)."""

    def __init__(self, api_key: Optional[str] = None):
        key = api_key or os.getenv("GEMINI_API_KEY", "")
        super().__init__("gemini", key, "gemini-2.0-flash")
        self.role = "senses"
        if not self.api_key:
            raise ValueError("GEMINI_API_KEY not found in environment")

        try:
            import google.generativeai as genai
            genai.configure(api_key=self.api_key)
            self.model_obj = genai.GenerativeModel(self.model)
            self.genai = genai
        except ImportError:
            raise ImportError("Install google-generativeai: pip install google-generativeai")

    def generate(self, prompt: str, **kwargs) -> str:
        try:
            response = self.model_obj.generate_content(prompt)
            tokens = response.usage_metadata.total_token_count
            self.total_tokens_used += tokens
            self.daily_tokens_used += tokens
            return response.text
        except Exception as e:
            return f"[Gemini Error] {str(e)}"

    def generate_stream(self, prompt: str, **kwargs):
        try:
            response = self.model_obj.generate_content(prompt, stream=True)
            for chunk in response:
                if chunk.text:
                    yield chunk.text
        except Exception as e:
            yield f"[Gemini Error] {str(e)}"

    def generate_with_image(self, prompt: str, image_bytes: bytes, mime_type: str = "image/jpeg") -> str:
        """Generate response with image input (vision capability)."""
        try:
            from google.generativeai.types import Part
            image_part = Part.from_data(data=image_bytes, mime_type=mime_type)
            response = self.model_obj.generate_content([prompt, image_part])
            tokens = response.usage_metadata.total_token_count
            self.total_tokens_used += tokens
            self.daily_tokens_used += tokens
            return response.text
        except Exception as e:
            return f"[Gemini Vision Error] {str(e)}"


class OpenRouterProvider(LLMProvider):
    """OpenRouter API provider for free models."""

    def __init__(self, api_key: Optional[str] = None, model: Optional[str] = None,
                 role: str = ""):
        key = api_key or os.getenv("OPENROUTER_API_KEY", "")
        model_name = model or os.getenv("OPENROUTER_MODEL", "meta-llama/llama-3.1-8b-instruct:free")
        super().__init__("openrouter", key, model_name)
        self.role = role
        if not self.api_key:
            raise ValueError("OPENROUTER_API_KEY not found in environment")

        try:
            from openai import OpenAI
            self.client = OpenAI(
                base_url="https://openrouter.ai/api/v1",
                api_key=self.api_key
            )
        except ImportError:
            raise ImportError("Install openai: pip install openai")

    def generate(self, prompt: str, **kwargs) -> str:
        try:
            response = self.client.chat.completions.create(
                model=self.model,
                messages=[{"role": "user", "content": prompt}],
                max_tokens=kwargs.get("max_tokens", 1024),
                temperature=kwargs.get("temperature", 0.7)
            )
            tokens = response.usage.total_tokens if response.usage else 0
            self.total_tokens_used += tokens
            self.daily_tokens_used += tokens
            return response.choices[0].message.content
        except Exception as e:
            return f"[OpenRouter Error] {str(e)}"

    def generate_stream(self, prompt: str, **kwargs):
        try:
            response = self.client.chat.completions.create(
                model=self.model,
                messages=[{"role": "user", "content": prompt}],
                max_tokens=kwargs.get("max_tokens", 1024),
                temperature=kwargs.get("temperature", 0.7),
                stream=True
            )
            for chunk in response:
                if chunk.choices[0].delta.content:
                    yield chunk.choices[0].delta.content
        except Exception as e:
            yield f"[OpenRouter Error] {str(e)}"


class DeepSeekProvider(OpenRouterProvider):
    """DeepSeek V4 Flash - The Subconscious & Logic Engine."""

    def __init__(self, api_key: Optional[str] = None):
        super().__init__(
            api_key=api_key,
            model="deepseek/deepseek-chat:free",
            role="logic"
        )
        self.name = "deepseek"


class MistralProvider(OpenRouterProvider):
    """Mistral 7B - Reasoning & Analysis via OpenRouter free tier."""

    def __init__(self, api_key: Optional[str] = None):
        super().__init__(
            api_key=api_key,
            model="mistralai/mistral-7b-instruct:free",
            role="reasoning"
        )
        self.name = "mistral"
