"""Model Router - Smart routing with auto-detection and role-based selection.

Primary: DeepSeek (all tasks)
Consciousness: Google Gemini (3 keys rotate, free tier)
Fallback: OpenCode, Qwen, GLM, Kimi, OpenRouter
"""

import json
import random
from typing import Optional, Dict, Any, List
from pathlib import Path
from datetime import datetime

from .llm import LLMProvider, GeminiProvider, create_provider
from .critic import CriticAgent, ConsensusResult
from ..utils.logger import logger, console


class ModelRouter:
    """Smart router - auto-detects keys, tests them, routes by role."""

    def __init__(self, use_consensus: bool = False):
        self.providers: Dict[str, LLMProvider] = {}
        self.config = self._load_config()
        self.use_consensus = use_consensus
        self.critic: Optional[CriticAgent] = None
        self.routing = self.config.get("routing", {})
        self._gemini_rotation_index = 0
        self._initialize_providers()
        if use_consensus and len(self.providers) >= 2:
            self.critic = CriticAgent(self.providers)

    def _load_config(self) -> Dict:
        config_path = Path(__file__).parent.parent.parent / "config" / "models.json"
        if config_path.exists():
            return json.loads(config_path.read_text(encoding="utf-8"))
        return {"providers": {}, "routing": {}}

    def _initialize_providers(self):
        """Auto-detect and initialize all available providers."""
        console.print("[bold blue]Detecting AI providers...[/bold blue]")

        providers_config = self.config.get("providers", {})

        for name, config in providers_config.items():
            provider = create_provider(name, config)
            if provider is None:
                continue

            # Test the key
            success, msg, models = provider.test_key()
            if success:
                provider.role = config.get("role", "")
                self.providers[name] = provider
                models_str = ", ".join(models[:3])
                if len(models) > 3:
                    models_str += f" +{len(models)-3} more"
                console.print(f"  [green]+[/green] {name:15s} [{provider.role:15s}] {models_str}")
            else:
                console.print(f"  [red]-[/red] {name:15s} {msg[:50]}")

        count = len(self.providers)
        console.print(f"\n  [bold green]{count} provider(s) active[/bold green]")

        if count == 0:
            console.print("[red]No API keys found! Add keys to .env file.[/red]")

    def get_provider(self, role: str = "", preferred: Optional[str] = None) -> Optional[LLMProvider]:
        """Get best provider for a role.

        Roles:
        - 'primary' / 'logic' / 'coding': DeepSeek first
        - 'consciousness' / 'emotions': Gemini (rotates between 3 keys)
        - 'reasoning': DeepSeek or OpenCode Zen
        - 'guardrail': OpenRouter or fallback
        - 'vision': Gemini
        - '': first available
        """
        if preferred and preferred in self.providers:
            return self.providers[preferred]

        # Get routing config
        primary = self.routing.get("primary_for_all", "deepseek")
        consciousness = self.routing.get("consciousness_providers", [])
        coding = self.routing.get("coding_providers", [])
        reasoning = self.routing.get("reasoning_providers", [])
        guardrail = self.routing.get("guardrail_providers", [])
        fallback_chain = self.routing.get("fallback_chain", [])

        # Route by role
        if role in ("primary", "logic", "coding", "chat", "generate", "learn"):
            # Try primary first
            if primary in self.providers:
                return self.providers[primary]
            # Try coding providers
            for name in coding:
                if name in self.providers:
                    return self.providers[name]

        elif role in ("consciousness", "emotions", "mood", "feel", "dream"):
            # Rotate between Gemini keys
            if consciousness:
                available_gemini = [n for n in consciousness if n in self.providers]
                if available_gemini:
                    idx = self._gemini_rotation_index % len(available_gemini)
                    self._gemini_rotation_index += 1
                    return self.providers[available_gemini[idx]]

        elif role in ("reasoning", "think", "debate"):
            for name in reasoning:
                if name in self.providers:
                    return self.providers[name]

        elif role in ("guardrail", "safety", "critic"):
            for name in guardrail:
                if name in self.providers:
                    return self.providers[name]

        elif role in ("vision", "image", "camera"):
            # Any Gemini key works for vision
            gemini_keys = [n for n in self.providers if "gemini" in n]
            if gemini_keys:
                return self.providers[random.choice(gemini_keys)]

        # Fallback: try the full chain
        for name in fallback_chain:
            if name in self.providers:
                return self.providers[name]

        # Last resort: any available
        if self.providers:
            return list(self.providers.values())[0]

        return None

    def generate(self, prompt: str, role: str = "", preferred: Optional[str] = None,
                 use_consensus: Optional[bool] = None, **kwargs) -> str:
        """Generate response with smart routing."""
        # Consensus mode (if enabled)
        consensus_flag = use_consensus if use_consensus is not None else self.use_consensus
        if consensus_flag and self.critic and len(self.providers) >= 2:
            result = self.critic.debate(prompt)
            return result.consensus

        # Smart routing
        provider = self.get_provider(role, preferred)
        if not provider:
            return "[ERROR] No LLM providers available. Add API keys to .env"

        logger.info(f"Using {provider.name} ({provider.role}) for: {role or 'default'}")
        return provider.generate(prompt, **kwargs)

    def generate_stream(self, prompt: str, role: str = "", preferred: Optional[str] = None, **kwargs):
        """Generate streaming response."""
        provider = self.get_provider(role, preferred)
        if not provider:
            yield "[ERROR] No LLM providers available"
            return
        yield from provider.generate_stream(prompt, **kwargs)

    def self_reflect(self, last_response: str, user_input: str) -> str:
        """Run self-reflection on last response."""
        if self.critic:
            return self.critic.self_reflect(last_response, user_input)
        # Use any available provider
        provider = self.get_provider("reasoning")
        if provider:
            return provider.generate(
                f"Reflect on this response and suggest improvements.\n"
                f"User asked: {user_input}\nResponse given: {last_response[:500]}\n"
                f"Provide brief feedback (2-3 lines):"
            )
        return "No critic available for self-reflection."

    def debate(self, prompt: str, rounds: int = 1) -> ConsensusResult:
        """Explicitly run a debate on a prompt."""
        if self.critic:
            return self.critic.debate(prompt, rounds)
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

    def get_status(self) -> str:
        """Get human-readable status of all providers."""
        lines = ["AI Provider Status:", ""]
        for name, provider in self.providers.items():
            status = "[OK]" if provider.available else "[--]"
            role = provider.role or "unassigned"
            models = ", ".join(provider.models_available[:3]) if provider.models_available else provider.model
            tokens = f"{provider.daily_tokens_used} today" if provider.daily_tokens_used else "0"
            lines.append(f"  {status} {name:15s} [{role:15s}] {models} ({tokens})")

        if not self.providers:
            lines.append("  No providers available. Add API keys to .env")

        return "\n".join(lines)
