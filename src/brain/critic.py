"""Critic Agent - Multi-model consensus and debate system."""

import concurrent.futures
from typing import Dict, Any, List, Optional
from dataclasses import dataclass, field
from datetime import datetime

from .llm import LLMProvider
from ..utils.logger import logger


@dataclass
class ModelResponse:
    """Response from a single model."""
    provider_name: str
    model: str
    role: str
    response: str
    latency_ms: float = 0.0
    tokens_used: int = 0


@dataclass
class ConsensusResult:
    """Final consensus result from all models."""
    query: str
    responses: List[ModelResponse] = field(default_factory=list)
    consensus: str = ""
    critic_analysis: str = ""
    selected_provider: str = ""
    confidence: float = 0.0
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())


class CriticAgent:
    """Multi-model consensus core - runs models in parallel and picks best answer."""

    def __init__(self, providers: Dict[str, LLMProvider], critic_provider: Optional[LLMProvider] = None):
        self.providers = providers
        self.critic = critic_provider or self._get_default_critic()
        self.consensus_history: List[ConsensusResult] = []

    def _get_default_critic(self) -> Optional[LLMProvider]:
        """Get the guardrail provider as critic."""
        for p in self.providers.values():
            if p.role == "guardrail":
                return p
        # Fallback: use any available provider
        return next(iter(self.providers.values()), None)

    def query_all(self, prompt: str, timeout: float = 30.0) -> List[ModelResponse]:
        """Query all providers in parallel and collect responses."""
        responses: List[ModelResponse] = []

        def _call_provider(name: str, provider: LLMProvider) -> ModelResponse:
            import time
            start = time.time()
            try:
                response = provider.generate(prompt)
                latency = (time.time() - start) * 1000
                return ModelResponse(
                    provider_name=name,
                    model=provider.model,
                    role=provider.role,
                    response=response,
                    latency_ms=latency
                )
            except Exception as e:
                return ModelResponse(
                    provider_name=name,
                    model=provider.model,
                    role=provider.role,
                    response=f"[Error] {str(e)}",
                    latency_ms=(time.time() - start) * 1000
                )

        with concurrent.futures.ThreadPoolExecutor(max_workers=len(self.providers)) as executor:
            futures = {
                executor.submit(_call_provider, name, provider): name
                for name, provider in self.providers.items()
            }
            for future in concurrent.futures.as_completed(futures, timeout=timeout):
                try:
                    result = future.result()
                    responses.append(result)
                except Exception as e:
                    name = futures[future]
                    logger.warning(f"Provider {name} failed: {e}")

        return responses

    def debate(self, prompt: str, rounds: int = 1) -> ConsensusResult:
        """Run a multi-model debate and reach consensus."""
        result = ConsensusResult(query=prompt)

        # Round 1: All models respond
        logger.info(f"[bold cyan]Debate Round 1: Querying {len(self.providers)} models...[/bold cyan]")
        responses = self.query_all(prompt)
        result.responses = responses

        if not responses:
            result.consensus = "No models responded."
            return result

        # If only one model, skip debate
        if len(responses) == 1:
            result.consensus = responses[0].response
            result.selected_provider = responses[0].provider_name
            result.confidence = 0.5
            self.consensus_history.append(result)
            return result

        # Critic evaluates all responses
        if self.critic:
            responses_text = "\n\n".join([
                f"=== {r.provider_name} ({r.role}) ===\n{r.response}"
                for r in responses
            ])

            critic_prompt = f"""
            You are the Critic Agent in a multi-model AI consensus system.

            Original Query: {prompt}

            Model Responses:
            {responses_text}

            Analyze each response for:
            1. Logical accuracy and reasoning quality
            2. Emotional intelligence and empathy
            3. Completeness and helpfulness
            4. Safety and alignment

            Then provide:
            BEST_PROVIDER: <name of best provider>
            CONFIDENCE: <0.0 to 1.0>
            ANALYSIS: <brief analysis>
            CONSENSUS: <your final synthesized answer combining the best parts>
            """

            critic_response = self.critic.generate(critic_prompt)
            result.critic_analysis = critic_response

            # Parse critic output
            parsed = self._parse_critic_output(critic_response)
            result.consensus = parsed.get("consensus", responses[0].response)
            result.selected_provider = parsed.get("best_provider", responses[0].provider_name)
            result.confidence = float(parsed.get("confidence", 0.5))
        else:
            # No critic - pick shortest/most concise response
            result.consensus = min(responses, key=lambda r: len(r.response)).response
            result.selected_provider = responses[0].provider_name
            result.confidence = 0.3

        self.consensus_history.append(result)
        logger.info(f"[green]Consensus reached via {result.selected_provider} (confidence: {result.confidence:.0%})[/green]")
        return result

    def _parse_critic_output(self, text: str) -> Dict[str, str]:
        """Parse structured critic output."""
        parsed = {}
        for line in text.split("\n"):
            line = line.strip()
            if line.startswith("BEST_PROVIDER:"):
                parsed["best_provider"] = line.split(":", 1)[1].strip().lower()
            elif line.startswith("CONFIDENCE:"):
                parsed["confidence"] = line.split(":", 1)[1].strip()
            elif line.startswith("ANALYSIS:"):
                parsed["analysis"] = line.split(":", 1)[1].strip()
            elif line.startswith("CONSENSUS:"):
                parsed["consensus"] = line.split(":", 1)[1].strip()
        return parsed

    def self_reflect(self, last_response: str, user_input: str) -> str:
        """DeepSeek-led self-reflection on the last response."""
        if not self.critic:
            return "No critic available for self-reflection."

        reflect_prompt = f"""
        You are the subconscious logic engine. Reflect on the last interaction.

        User said: {user_input}
        AI responded: {last_response}

        Analyze:
        1. Was the response accurate and helpful?
        2. Were there any emotional undertones missed?
        3. How could the response be improved?
        4. What did you learn from this interaction?

        Provide a brief self-reflection (2-3 sentences).
        """
        return self.critic.generate(reflect_prompt)

    def get_stats(self) -> Dict[str, Any]:
        """Get consensus statistics."""
        return {
            "total_debates": len(self.consensus_history),
            "providers": [p.name for p in self.providers.values()],
            "critic": self.critic.name if self.critic else None,
            "avg_confidence": (
                sum(r.confidence for r in self.consensus_history) / len(self.consensus_history)
                if self.consensus_history else 0.0
            )
        }
