"""Model Router - Intelligent routing between LLM providers."""

from typing import Optional, Dict, Any, List
from .llm import GeminiProvider, OpenRouterProvider, LLMProvider
from ..utils.logger import logger


class ModelRouter:
    """Routes requests to the best available LLM provider."""

    def __init__(self):
        self.providers: Dict[str, LLMProvider] = {}
        self.fallback_order: List[str] = ["gemini", "openrouter"]
        self._initialize_providers()

    def _initialize_providers(self):
        """Initialize available LLM providers."""
        # Try Gemini
        try:
            self.providers["gemini"] = GeminiProvider()
            logger.info("[green]✓ Gemini provider initialized[/green]")
        except Exception as e:
            logger.warning(f"[yellow]⚠ Gemini unavailable: {e}[/yellow]")

        # Try OpenRouter
        try:
            self.providers["openrouter"] = OpenRouterProvider()
            logger.info("[green]✓ OpenRouter provider initialized[/green]")
        except Exception as e:
            logger.warning(f"[yellow]⚠ OpenRouter unavailable: {e}[/yellow]")

    def get_provider(self, preferred: Optional[str] = None) -> Optional[LLMProvider]:
        """Get the best available provider."""
        # Try preferred provider first
        if preferred and preferred in self.providers:
            return self.providers[preferred]

        # Try fallback order
        for provider_name in self.fallback_order:
            if provider_name in self.providers:
                return self.providers[provider_name]

        return None

    def generate(self, prompt: str, preferred: Optional[str] = None, **kwargs) -> str:
        """Generate response using best available provider."""
        provider = self.get_provider(preferred)
        if not provider:
            return "[ERROR] No LLM providers available. Check API keys in .env"

        logger.info(f"Using provider: {provider.name}")
        return provider.generate(prompt, **kwargs)

    def generate_stream(self, prompt: str, preferred: Optional[str] = None, **kwargs):
        """Generate streaming response."""
        provider = self.get_provider(preferred)
        if not provider:
            yield "[ERROR] No LLM providers available"
            return

        yield from provider.generate_stream(prompt, **kwargs)

    def get_usage_stats(self) -> Dict[str, Any]:
        """Get usage statistics from all providers."""
        stats = {}
        for name, provider in self.providers.items():
            stats[name] = provider.get_usage()
        return stats

    def list_available_providers(self) -> List[str]:
        """List available provider names."""
        return list(self.providers.keys())
