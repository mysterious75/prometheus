"""LLM Provider integration for Project Prometheus."""

import os
import json
from abc import ABC, abstractmethod
from typing import Optional, Dict, Any
from pathlib import Path

# Load environment
from dotenv import load_dotenv
env_path = Path(__file__).parent.parent.parent / ".env"
load_dotenv(env_path)


class LLMProvider(ABC):
    """Abstract base class for LLM providers."""

    def __init__(self, name: str, api_key: str):
        self.name = name
        self.api_key = api_key
        self.total_tokens_used = 0
        self.daily_tokens_used = 0

    @abstractmethod
    def generate(self, prompt: str, **kwargs) -> str:
        """Generate a response from the LLM."""
        pass

    @abstractmethod
    def generate_stream(self, prompt: str, **kwargs):
        """Generate a streaming response."""
        pass

    def get_usage(self) -> Dict[str, Any]:
        """Get token usage statistics."""
        return {
            "provider": self.name,
            "total_tokens": self.total_tokens_used,
            "daily_tokens": self.daily_tokens_used
        }


class GeminiProvider(LLMProvider):
    """Google Gemini API provider."""

    def __init__(self, api_key: Optional[str] = None):
        super().__init__("gemini", api_key or os.getenv("GEMINI_API_KEY", ""))
        if not self.api_key:
            raise ValueError("GEMINI_API_KEY not found in environment")

        try:
            import google.generativeai as genai
            genai.configure(api_key=self.api_key)
            self.model = genai.GenerativeModel("gemini-2.0-flash")
            self.genai = genai
        except ImportError:
            raise ImportError("Install google-generativeai: pip install google-generativeai")

    def generate(self, prompt: str, **kwargs) -> str:
        """Generate response using Gemini."""
        try:
            response = self.model.generate_content(prompt)
            self.total_tokens_used += response.usage_metadata.total_token_count
            self.daily_tokens_used += response.usage_metadata.total_token_count
            return response.text
        except Exception as e:
            return f"[Gemini Error] {str(e)}"

    def generate_stream(self, prompt: str, **kwargs):
        """Generate streaming response using Gemini."""
        try:
            response = self.model.generate_content(prompt, stream=True)
            for chunk in response:
                if chunk.text:
                    yield chunk.text
        except Exception as e:
            yield f"[Gemini Error] {str(e)}"


class OpenRouterProvider(LLMProvider):
    """OpenRouter API provider (free models)."""

    def __init__(self, api_key: Optional[str] = None, model: Optional[str] = None):
        super().__init__("openrouter", api_key or os.getenv("OPENROUTER_API_KEY", ""))
        if not self.api_key:
            raise ValueError("OPENROUTER_API_KEY not found in environment")

        self.model = model or os.getenv("OPENROUTER_MODEL", "meta-llama/llama-3.1-8b-instruct:free")

        try:
            from openai import OpenAI
            self.client = OpenAI(
                base_url="https://openrouter.ai/api/v1",
                api_key=self.api_key
            )
        except ImportError:
            raise ImportError("Install openai: pip install openai")

    def generate(self, prompt: str, **kwargs) -> str:
        """Generate response using OpenRouter."""
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
        """Generate streaming response using OpenRouter."""
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
