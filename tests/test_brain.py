"""Tests for the Brain module — ModelRouter, LLM providers, and CriticAgent.

All tests mock external API calls. No real network requests.
"""

import pytest
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch, PropertyMock

PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT))


# ---------------------------------------------------------------------------
# LLMProvider (abstract base)
# ---------------------------------------------------------------------------

class TestLLMProviderBase:
    """Test LLMProvider abstract class properties."""

    def test_provider_has_required_attributes(self):
        from src.brain.llm import LLMProvider
        # LLMProvider is abstract, can't instantiate directly
        # but we can check the interface
        assert hasattr(LLMProvider, 'generate')
        assert hasattr(LLMProvider, 'generate_stream')
        assert hasattr(LLMProvider, 'test_key')
        assert hasattr(LLMProvider, 'get_usage')

    def test_provider_is_abstract(self):
        from src.brain.llm import LLMProvider
        import abc
        assert hasattr(LLMProvider, '__abstractmethods__')
        assert 'generate' in LLMProvider.__abstractmethods__


# ---------------------------------------------------------------------------
# OpenAICompatibleProvider
# ---------------------------------------------------------------------------

class TestOpenAICompatibleProvider:
    """Test OpenAI-compatible provider without real API calls."""

    @pytest.fixture
    def provider(self):
        from src.brain.llm import OpenAICompatibleProvider
        return OpenAICompatibleProvider(
            name="test_provider",
            api_key="test-key-12345",
            model="gpt-4",
            base_url="https://api.test.com/v1",
            role="primary",
        )

    def test_provider_init(self, provider):
        assert provider.name == "test_provider"
        assert provider.model == "gpt-4"
        assert provider.base_url == "https://api.test.com/v1"
        assert provider.role == "primary"
        assert provider.available is False

    def test_provider_default_values(self, provider):
        assert provider.total_tokens_used == 0
        assert provider.daily_tokens_used == 0
        assert provider.last_error == ""
        assert provider.models_available == []

    def test_get_usage_structure(self, provider):
        usage = provider.get_usage()
        assert "provider" in usage
        assert "model" in usage
        assert "role" in usage
        assert "available" in usage
        assert "total_tokens" in usage
        assert "daily_tokens" in usage
        assert usage["provider"] == "test_provider"

    def test_generate_success(self, provider):
        mock_client = MagicMock()
        mock_response = MagicMock()
        mock_response.choices = [MagicMock()]
        mock_response.choices[0].message.content = "Hello world"
        mock_response.usage.total_tokens = 15
        mock_client.chat.completions.create.return_value = mock_response
        provider._client = mock_client
        result = provider.generate("Say hello")
        assert result == "Hello world"

    def test_generate_tracks_tokens(self, provider):
        mock_client = MagicMock()
        mock_response = MagicMock()
        mock_response.choices = [MagicMock()]
        mock_response.choices[0].message.content = "Response"
        mock_response.usage.total_tokens = 50
        mock_client.chat.completions.create.return_value = mock_response
        provider._client = mock_client
        provider.generate("Test prompt")
        assert provider.total_tokens_used == 50
        assert provider.daily_tokens_used == 50

    def test_generate_handles_exception(self, provider):
        with patch.object(provider, '_get_client', side_effect=Exception("No API")):
            result = provider.generate("test")
            assert "Error" in result


# ---------------------------------------------------------------------------
# GeminiProvider
# ---------------------------------------------------------------------------

class TestGeminiProvider:
    """Test Gemini provider initialization and attributes."""

    def test_provider_init(self):
        from src.brain.llm import GeminiProvider
        p = GeminiProvider(api_key="test-key", model="gemini-2.0-flash",
                          key_name="gemini_1", role="fast")
        assert p.name == "gemini_1"
        assert p.model == "gemini-2.0-flash"
        assert p.role == "fast"
        assert p.api_key == "test-key"

    def test_provider_default_model(self):
        from src.brain.llm import GeminiProvider
        p = GeminiProvider(api_key="key")
        assert p.model == "gemini-2.0-flash"

    def test_provider_default_role(self):
        from src.brain.llm import GeminiProvider
        p = GeminiProvider(api_key="key")
        assert p.role == "fast"


# ---------------------------------------------------------------------------
# create_provider factory
# ---------------------------------------------------------------------------

class TestCreateProvider:
    """Test the provider factory function."""

    def test_create_openai_provider(self):
        from src.brain.llm import create_provider, OpenAICompatibleProvider
        config = {
            "api_key_env": "TEST_OPENAI_KEY",
            "model": "gpt-4",
            "base_url": "https://api.openai.com/v1",
            "role": "primary",
        }
        with patch.dict('os.environ', {"TEST_OPENAI_KEY": "sk-test123"}):
            provider = create_provider("openai", config)
            assert provider is not None
            assert provider.name == "openai"
            assert provider.model == "gpt-4"

    def test_create_gemini_provider(self):
        from src.brain.llm import create_provider, GeminiProvider
        config = {
            "api_key_env": "TEST_GEMINI_KEY",
            "model": "gemini-2.0-flash",
            "role": "fast",
        }
        with patch.dict('os.environ', {"TEST_GEMINI_KEY": "gemini-key-123"}):
            provider = create_provider("gemini", config)
            assert provider is not None
            assert provider.model == "gemini-2.0-flash"

    def test_create_provider_no_key_returns_none(self):
        from src.brain.llm import create_provider
        config = {"api_key_env": "NONEXISTENT_KEY_XYZ"}
        provider = create_provider("test", config)
        assert provider is None


# ---------------------------------------------------------------------------
# CriticAgent
# ---------------------------------------------------------------------------

class TestCriticAgent:
    """Test CriticAgent debate and consensus logic."""

    @pytest.fixture
    def mock_providers(self):
        p1 = MagicMock()
        p1.name = "deepseek"
        p1.model = "deepseek-chat"
        p1.role = "primary"
        p1.generate.return_value = "DeepSeek says: SQL injection can be prevented with parameterized queries."

        p2 = MagicMock()
        p2.name = "gemini"
        p2.model = "gemini-2.0-flash"
        p2.role = "fast"
        p2.generate.return_value = "Gemini says: Use prepared statements to prevent SQLi."

        return {"deepseek": p1, "gemini": p2}

    def test_critic_init(self, mock_providers):
        from src.brain.critic import CriticAgent
        agent = CriticAgent(mock_providers)
        assert len(agent.providers) == 2

    def test_query_all_returns_responses(self, mock_providers):
        from src.brain.critic import CriticAgent
        agent = CriticAgent(mock_providers)
        responses = agent.query_all("How to prevent SQL injection?")
        assert len(responses) == 2
        for r in responses:
            assert r.provider_name in ("deepseek", "gemini")
            assert len(r.response) > 0

    def test_debate_with_single_provider(self):
        from src.brain.critic import CriticAgent
        p = MagicMock()
        p.name = "solo"
        p.model = "test"
        p.role = "primary"
        p.generate.return_value = "Solo answer"
        agent = CriticAgent({"solo": p})
        result = agent.debate("What is XSS?")
        assert result.consensus == "Solo answer"
        assert result.selected_provider == "solo"
        assert result.confidence == 0.5

    def test_debate_returns_consensus_result(self, mock_providers):
        from src.brain.critic import CriticAgent, ConsensusResult
        # Set up critic provider
        critic_p = MagicMock()
        critic_p.name = "critic"
        critic_p.model = "test"
        critic_p.role = "guardrail"
        critic_p.generate.return_value = (
            "BEST_PROVIDER: deepseek\n"
            "CONFIDENCE: 0.85\n"
            "ANALYSIS: Both responses are good.\n"
            "CONSENSUS: Use parameterized queries to prevent SQL injection."
        )
        mock_providers["critic"] = critic_p

        agent = CriticAgent(mock_providers, critic_provider=critic_p)
        result = agent.debate("How to prevent SQL injection?")
        assert isinstance(result, ConsensusResult)
        assert result.confidence > 0
        assert len(result.consensus) > 0

    def test_parse_critic_output(self, mock_providers):
        from src.brain.critic import CriticAgent
        agent = CriticAgent(mock_providers)
        text = (
            "BEST_PROVIDER: deepseek\n"
            "CONFIDENCE: 0.9\n"
            "ANALYSIS: Good response\n"
            "CONSENSUS: Final answer here"
        )
        parsed = agent._parse_critic_output(text)
        assert parsed["best_provider"] == "deepseek"
        assert parsed["confidence"] == "0.9"
        assert parsed["consensus"] == "Final answer here"

    def test_get_stats_structure(self, mock_providers):
        from src.brain.critic import CriticAgent
        agent = CriticAgent(mock_providers)
        stats = agent.get_stats()
        assert "total_debates" in stats
        assert "providers" in stats
        assert "avg_confidence" in stats
        assert stats["total_debates"] == 0

    def test_self_reflect_without_critic(self, mock_providers):
        from src.brain.critic import CriticAgent
        agent = CriticAgent(mock_providers)
        agent.critic = None
        result = agent.self_reflect("last response", "user input")
        assert "No critic" in result


# ---------------------------------------------------------------------------
# ConsensusResult
# ---------------------------------------------------------------------------

class TestConsensusResult:
    """Test ConsensusResult dataclass."""

    def test_default_values(self):
        from src.brain.critic import ConsensusResult
        result = ConsensusResult(query="test query")
        assert result.query == "test query"
        assert result.consensus == ""
        assert result.confidence == 0.0
        assert result.responses == []
        assert result.timestamp  # auto-generated

    def test_with_values(self):
        from src.brain.critic import ConsensusResult, ModelResponse
        mr = ModelResponse(provider_name="test", model="m", role="r", response="hi")
        result = ConsensusResult(
            query="q",
            responses=[mr],
            consensus="answer",
            confidence=0.8,
        )
        assert len(result.responses) == 1
        assert result.consensus == "answer"


# ---------------------------------------------------------------------------
# ModelRouter
# ---------------------------------------------------------------------------
from src.brain.router import ModelRouter

class TestModelRouter:
    """Test ModelRouter initialization and provider routing."""

    @pytest.fixture
    def mock_config(self):
        """Provide a mock config with test API keys."""
        with patch('src.brain.router.config') as mock_cfg:
            mock_cfg.get_all_keys.return_value = {
                "deepseek": {
                    "key": "sk-test-deepseek",
                    "base_url": "https://api.deepseek.com/v1",
                    "model": "deepseek-chat",
                    "type": "openai",
                },
                "gemini": {
                    "key": "gemini-test-key",
                    "model": "gemini-2.0-flash",
                    "type": "gemini",
                },
            }
            yield mock_cfg

    def test_router_init_no_providers(self):
        """Router should handle no available keys gracefully."""
        with patch('src.brain.router.config') as mock_cfg:
            mock_cfg.get_all_keys.return_value = {}
            router = ModelRouter.__new__(ModelRouter)
            router.providers = {}
            router.routing = {}
            router.use_consensus = False
            router.critic = None
            assert len(router.providers) == 0

    def test_get_provider_returns_none_when_empty(self):
        with patch('src.brain.router.config') as mock_cfg:
            mock_cfg.get_all_keys.return_value = {}
            router = ModelRouter.__new__(ModelRouter)
            router.providers = {}
            router.routing = {"by_role": {}, "primary": "", "all": []}
            router.use_consensus = False
            router.critic = None
            assert router.get_provider() is None

    def test_get_provider_by_preferred(self):
        router = ModelRouter.__new__(ModelRouter)
        mock_p = MagicMock()
        mock_p.name = "preferred"
        router.providers = {"preferred": mock_p, "other": MagicMock()}
        router.routing = {"by_role": {"primary": ["preferred"]}, "primary": "preferred", "all": ["preferred", "other"]}
        router.use_consensus = False
        router.critic = None
        result = router.get_provider(preferred="preferred")
        assert result is mock_p

    def test_get_provider_by_role(self):
        router = ModelRouter.__new__(ModelRouter)
        mock_p = MagicMock()
        mock_p.name = "fast_provider"
        router.providers = {"fast_provider": mock_p}
        router.routing = {"by_role": {"fast": ["fast_provider"]}, "primary": "fast_provider", "all": ["fast_provider"]}
        router.use_consensus = False
        router.critic = None
        result = router.get_provider(role="fast")
        assert result is mock_p

    def test_get_provider_fallback_to_any(self):
        router = ModelRouter.__new__(ModelRouter)
        mock_p = MagicMock()
        router.providers = {"fallback": mock_p}
        router.routing = {"by_role": {}, "primary": "fallback", "all": ["fallback"]}
        router.use_consensus = False
        router.critic = None
        result = router.get_provider(role="nonexistent_role")
        assert result is mock_p

    def test_generate_no_providers_returns_error(self):
        router = ModelRouter.__new__(ModelRouter)
        router.providers = {}
        router.routing = {"by_role": {}, "primary": "", "all": []}
        router.use_consensus = False
        router.critic = None
        result = router.generate("Hello")
        assert "ERROR" in result or "No LLM" in result

    def test_generate_delegates_to_provider(self):
        router = ModelRouter.__new__(ModelRouter)
        mock_p = MagicMock()
        mock_p.name = "test"
        mock_p.role = "primary"
        mock_p.generate.return_value = "Generated response"
        router.providers = {"test": mock_p}
        router.routing = {"by_role": {"primary": ["test"]}, "primary": "test", "all": ["test"]}
        router.use_consensus = False
        router.critic = None
        result = router.generate("Hello")
        assert result == "Generated response"
        mock_p.generate.assert_called_once_with("Hello")

    def test_list_available_providers(self):
        router = ModelRouter.__new__(ModelRouter)
        router.providers = {"a": MagicMock(), "b": MagicMock()}
        router.routing = {}
        router.use_consensus = False
        router.critic = None
        names = router.list_available_providers()
        assert "a" in names
        assert "b" in names

    def test_get_status_returns_string(self):
        router = ModelRouter.__new__(ModelRouter)
        mock_p = MagicMock()
        mock_p.name = "test"
        mock_p.available = True
        mock_p.role = "primary"
        mock_p.model = "test-model"
        mock_p.models_available = ["test-model"]
        mock_p.daily_tokens_used = 100
        router.providers = {"test": mock_p}
        router.routing = {}
        router.use_consensus = False
        router.critic = None
        status = router.get_status()
        assert "test" in status
        assert "primary" in status

    def test_get_usage_stats(self):
        router = ModelRouter.__new__(ModelRouter)
        mock_p = MagicMock()
        mock_p.name = "test"
        mock_p.get_usage.return_value = {"provider": "test", "total_tokens": 50}
        router.providers = {"test": mock_p}
        router.routing = {}
        router.use_consensus = False
        router.critic = None
        stats = router.get_usage_stats()
        assert "test" in stats


# ---------------------------------------------------------------------------
# assign_role helper
# ---------------------------------------------------------------------------

class TestAssignRole:
    """Test role assignment based on provider name patterns."""

    def test_deepseek_gets_primary(self):
        from src.brain.router import assign_role
        assert assign_role("deepseek", []) == "primary"

    def test_openai_gets_primary(self):
        from src.brain.router import assign_role
        assert assign_role("openai", []) == "primary"

    def test_gemini_gets_fast(self):
        from src.brain.router import assign_role
        assert assign_role("gemini", []) == "fast"

    def test_google_gets_fast(self):
        from src.brain.router import assign_role
        assert assign_role("google_ai", []) == "fast"

    def test_openrouter_gets_reasoning(self):
        from src.brain.router import assign_role
        assert assign_role("openrouter", []) == "reasoning"

    def test_glm_gets_backup(self):
        from src.brain.router import assign_role
        assert assign_role("glm", []) == "backup"

    def test_many_models_gets_primary(self):
        from src.brain.router import assign_role
        models = [f"model_{i}" for i in range(10)]
        assert assign_role("unknown_provider", models) == "primary"

    def test_unknown_gets_backup(self):
        from src.brain.router import assign_role
        assert assign_role("something_xyz", ["m1"]) == "backup"


# ---------------------------------------------------------------------------
# ModelRouter.generate with consensus
# ---------------------------------------------------------------------------

class TestModelRouterConsensus:
    """Test consensus generation path."""

    def test_generate_uses_consensus_when_enabled(self):
        router = ModelRouter.__new__(ModelRouter)
        mock_critic = MagicMock()
        from src.brain.critic import ConsensusResult
        mock_result = ConsensusResult(query="test", consensus="consensus answer")
        mock_critic.debate.return_value = mock_result

        router.providers = {"p1": MagicMock(), "p2": MagicMock()}
        router.routing = {}
        router.use_consensus = True
        router.critic = mock_critic

        result = router.generate("test prompt")
        assert result == "consensus answer"
        mock_critic.debate.assert_called_once()

    def test_generate_stream_delegates_to_provider(self):
        router = ModelRouter.__new__(ModelRouter)
        mock_p = MagicMock()
        mock_p.generate_stream = MagicMock(return_value=iter(["chunk1", "chunk2"]))
        router.providers = {"test": mock_p}
        router.routing = {"by_role": {"primary": ["test"]}, "primary": "test", "all": ["test"]}
        router.use_consensus = False
        router.critic = None

        chunks = list(router.generate_stream("Hello"))
        assert chunks == ["chunk1", "chunk2"]
