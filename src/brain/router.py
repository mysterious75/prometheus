"""Model Router - Multi-model consensus routing with Critic Agent."""

from typing import Optional, Dict, Any, List
from .llm import GeminiProvider, OpenRouterProvider, DeepSeekProvider, MistralProvider, LLMProvider
from .critic import CriticAgent, ConsensusResult
from ..utils.logger import logger


class ModelRouter:
    """Routes requests to multiple LLM providers with consensus-based decision making."""

    def __init__(self, use_consensus: bool = True):
        self.providers: Dict[str, LLMProvider] = {}
        self.fallback_order: List[str] = ["gemini", "deepseek", "mistral", "openrouter"]
        self.use_consensus = use_consensus
        self.critic: Optional[CriticAgent] = None
        self._initialize_providers()
        if use_consensus and len(self.providers) >= 2:
            self.critic = CriticAgent(self.providers)

    def _initialize_providers(self):
        """Initialize all available LLM providers."""
        # Gemini - The Conscious Actor & Senses
        try:
            self.providers["gemini"] = GeminiProvider()
            logger.info("[green]Gemini (senses) initialized[/green]")
        except Exception as e:
            logger.warning(f"[yellow]Gemini unavailable: {e}[/yellow]")

        # DeepSeek - The Subconscious & Logic Engine
        try:
            self.providers["deepseek"] = DeepSeekProvider()
            logger.info("[green]DeepSeek (logic) initialized[/green]")
        except Exception as e:
            logger.warning(f"[yellow]DeepSeek unavailable: {e}[/yellow]")

        # Mistral - Reasoning & Analysis
        try:
            self.providers["mistral"] = MistralProvider()
            logger.info("[green]Mistral (reasoning) initialized[/green]")
        except Exception as e:
            logger.warning(f"[yellow]Mistral unavailable: {e}[/yellow]")

        # OpenRouter - Guardrail / Backup
        try:
            self.providers["openrouter"] = OpenRouterProvider(role="guardrail")
            logger.info("[green]OpenRouter (guardrail) initialized[/green]")
        except Exception as e:
            logger.warning(f"[yellow]OpenRouter unavailable: {e}[/yellow]")

    def get_provider(self, preferred: Optional[str] = None) -> Optional[LLMProvider]:
        """Get the best available provider (single model mode)."""
        if preferred and preferred in self.providers:
            return self.providers[preferred]

        for provider_name in self.fallback_order:
            if provider_name in self.providers:
                return self.providers[provider_name]

        return None

    def generate(self, prompt: str, preferred: Optional[str] = None,
                 use_consensus: Optional[bool] = None, **kwargs) -> str:
        """Generate response - uses consensus if enabled and multiple providers available."""
        consensus_flag = use_consensus if use_consensus is not None else self.use_consensus

        if consensus_flag and self.critic and len(self.providers) >= 2:
            result = self.critic.debate(prompt)
            return result.consensus

        # Single model fallback
        provider = self.get_provider(preferred)
        if not provider:
            return "[ERROR] No LLM providers available. Check API keys in .env"

        logger.info(f"Using provider: {provider.name}")
        return provider.generate(prompt, **kwargs)

    def generate_stream(self, prompt: str, preferred: Optional[str] = None, **kwargs):
        """Generate streaming response (single model only)."""
        provider = self.get_provider(preferred)
        if not provider:
            yield "[ERROR] No LLM providers available"
            return
        yield from provider.generate_stream(prompt, **kwargs)

    def self_reflect(self, last_response: str, user_input: str) -> str:
        """Run self-reflection on last response using critic."""
        if self.critic:
            return self.critic.self_reflect(last_response, user_input)
        return "No critic available for self-reflection."

    def debate(self, prompt: str, rounds: int = 1) -> ConsensusResult:
        """Explicitly run a debate on a prompt."""
        if self.critic:
            return self.critic.debate(prompt, rounds)
        # Fallback
        result = ConsensusResult(query=prompt)
        provider = self.get_provider()
        if provider:
            result.consensus = provider.generate(prompt)
            result.selected_provider = provider.name
        return result

    def get_usage_stats(self) -> Dict[str, Any]:
        """Get usage statistics from all providers."""
        stats = {}
        for name, provider in self.providers.items():
            stats[name] = provider.get_usage()
        if self.critic:
            stats["consensus"] = self.critic.get_stats()
        return stats

    def list_available_providers(self) -> List[str]:
        """List available provider names."""
        return list(self.providers.keys())
