"""Model Router - Auto-configures from ANY API keys available.

Works with 1 key or 13 keys. Auto-detects, tests, assigns roles.
No fixed provider list - whatever works, gets used.
"""

import json
import random
from typing import Optional, Dict, Any, List
from pathlib import Path

from .llm import LLMProvider, GeminiProvider, OpenAICompatibleProvider
from .critic import CriticAgent, ConsensusResult
from ..utils.config import config
from ..utils.logger import logger, console


# Role assignment priority based on provider name patterns
ROLE_PATTERNS = {
    "consciousness": ["gemini", "google"],
    "coding": ["opencode", "code"],
    "reasoning": ["zen", "reason"],
    "primary": ["deepseek"],
    "backup": ["openai", "anthropic", "openrouter", "qwen", "kimi", "glm",
               "xiaomi", "nvidia", "nemotron"],
}


def assign_role(name: str, models: list) -> str:
    """Auto-assign role based on provider name and available models."""
    name_lower = name.lower()

    for role, patterns in ROLE_PATTERNS.items():
        for pattern in patterns:
            if pattern in name_lower:
                return role

    # If it has many models, make it primary
    if len(models) > 5:
        return "primary"

    return "backup"


class ModelRouter:
    """Auto-configuring router - uses whatever keys are available."""

    def __init__(self, use_consensus: bool = False):
        self.providers: Dict[str, LLMProvider] = {}
        self.routing: Dict[str, Any] = {}
        self.use_consensus = use_consensus
        self.critic: Optional[CriticAgent] = None
        self._initialize()
        if use_consensus and len(self.providers) >= 2:
            self.critic = CriticAgent(self.providers)

    def _initialize(self):
        """Auto-detect and test all available keys."""
        console.print("[bold blue]Auto-detecting AI providers...[/bold blue]")

        all_keys = config.get_all_keys()
        if not all_keys:
            console.print("[red]No API keys found in .env![/red]")
            return

        for name, key_info in all_keys.items():
            key = key_info["key"]
            base_url = key_info.get("base_url", "")
            model = key_info.get("model", "")
            provider_type = key_info.get("type", "openai")

            provider = self._create_provider(name, key, base_url, model, provider_type)
            if provider is None:
                continue

            # Test the key
            try:
                success, msg, models = provider.test_key()
            except Exception as e:
                console.print(f"  [red]-[/red] {name:15s} test failed: {str(e)[:40]}")
                continue

            if success:
                # Auto-assign role
                role = assign_role(name, models)
                provider.role = role
                provider.models_available = models

                # Auto-select model if not set
                if not provider.model and models:
                    provider.model = models[0]

                self.providers[name] = provider

                models_str = ", ".join(models[:3])
                if len(models) > 3:
                    models_str += f" +{len(models)-3} more"
                console.print(f"  [green]+[/green] {name:15s} [{role:15s}] {models_str}")
            else:
                console.print(f"  [red]-[/red] {name:15s} {msg[:50]}")

        # Build routing config
        self._build_routing()

        count = len(self.providers)
        console.print(f"\n  [bold green]{count} provider(s) active[/bold green]")

        if count == 0:
            console.print("[red]No working keys! Check .env file.[/red]")

    def _create_provider(self, name: str, key: str, base_url: str,
                         model: str, provider_type: str) -> Optional[LLMProvider]:
        """Create a provider instance."""
        if provider_type == "gemini":
            return GeminiProvider(key, model or "gemini-2.0-flash", name, "consciousness")

        if provider_type == "anthropic":
            # Anthropic uses different API format - use OpenAI compatible endpoint
            if not base_url:
                base_url = "https://api.anthropic.com/v1"
            return OpenAICompatibleProvider(name, key, model, base_url)

        # Everything else: OpenAI-compatible
        return OpenAICompatibleProvider(name, key, model, base_url)

    def _build_routing(self):
        """Build routing chains from available providers."""
        by_role = {}
        for name, provider in self.providers.items():
            role = provider.role
            if role not in by_role:
                by_role[role] = []
            by_role[role].append(name)

        self.routing = {
            "by_role": by_role,
            "primary": by_role.get("primary", [])[0] if by_role.get("primary") else
                       (list(self.providers.keys())[0] if self.providers else ""),
            "consciousness": by_role.get("consciousness", []),
            "all": list(self.providers.keys()),
        }

    def get_provider(self, role: str = "", preferred: Optional[str] = None) -> Optional[LLMProvider]:
        """Get best provider for a role."""
        if preferred and preferred in self.providers:
            return self.providers[preferred]

        by_role = self.routing.get("by_role", {})

        # Try exact role match
        if role in by_role and by_role[role]:
            return self.providers[by_role[role][0]]

        # Try role aliases
        role_map = {
            "primary": ["primary", "backup"],
            "logic": ["primary", "backup"],
            "chat": ["primary", "backup"],
            "coding": ["coding", "primary", "backup"],
            "consciousness": ["consciousness", "backup"],
            "emotions": ["consciousness", "backup"],
            "mood": ["consciousness", "backup"],
            "reasoning": ["reasoning", "primary", "backup"],
            "guardrail": ["backup", "primary"],
            "vision": ["consciousness", "backup"],
        }

        for alias_role in role_map.get(role, ["primary", "backup"]):
            if alias_role in by_role and by_role[alias_role]:
                return self.providers[by_role[alias_role][0]]

        # Last resort: any provider
        if self.providers:
            return list(self.providers.values())[0]

        return None

    def generate(self, prompt: str, role: str = "", preferred: Optional[str] = None,
                 use_consensus: Optional[bool] = None, **kwargs) -> str:
        """Generate response with auto-routing."""
        consensus_flag = use_consensus if use_consensus is not None else self.use_consensus
        if consensus_flag and self.critic and len(self.providers) >= 2:
            result = self.critic.debate(prompt)
            return result.consensus

        provider = self.get_provider(role, preferred)
        if not provider:
            return "[ERROR] No LLM providers available. Add API key to .env"

        logger.info(f"Using {provider.name} ({provider.role})")
        return provider.generate(prompt, **kwargs)

    def generate_stream(self, prompt: str, role: str = "", preferred: Optional[str] = None, **kwargs):
        provider = self.get_provider(role, preferred)
        if not provider:
            yield "[ERROR] No LLM providers available"
            return
        yield from provider.generate_stream(prompt, **kwargs)

    def self_reflect(self, last_response: str, user_input: str) -> str:
        if self.critic:
            return self.critic.self_reflect(last_response, user_input)
        provider = self.get_provider("reasoning")
        if provider:
            return provider.generate(
                f"Reflect briefly on this response (2-3 lines max):\n"
                f"User: {user_input}\nResponse: {last_response[:500]}"
            )
        return "No critic available."

    def debate(self, prompt: str, rounds: int = 1) -> ConsensusResult:
        if self.critic:
            return self.critic.debate(prompt, rounds)
        result = ConsensusResult(query=prompt)
        provider = self.get_provider()
        if provider:
            result.consensus = provider.generate(prompt)
            result.selected_provider = provider.name
        return result

    def get_usage_stats(self) -> Dict[str, Any]:
        stats = {}
        for name, provider in self.providers.items():
            stats[name] = provider.get_usage()
        if self.critic:
            stats["consensus"] = self.critic.get_stats()
        return stats

    def list_available_providers(self) -> List[str]:
        return list(self.providers.keys())

    def get_status(self) -> str:
        lines = ["AI Provider Status:", ""]
        for name, provider in self.providers.items():
            status = "[OK]" if provider.available else "[--]"
            role = provider.role or "?"
            models = ", ".join(provider.models_available[:3]) if provider.models_available else provider.model or "?"
            tokens = f"{provider.daily_tokens_used} used" if provider.daily_tokens_used else "0"
            lines.append(f"  {status} {name:15s} [{role:10s}] {models} ({tokens})")

        if not self.providers:
            lines.append("  No providers. Add API key to .env")
        return "\n".join(lines)
