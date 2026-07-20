"""Tests for Brain module and all upgraded systems."""

import pytest
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))


class TestConfig:
    """Test configuration."""

    def test_config_loads(self):
        from src.utils.config import config
        assert config.APP_NAME == "Prometheus"
        assert config.APP_VERSION == "2.0.0"

    def test_config_validate(self):
        from src.utils.config import config
        result = config.validate()
        assert isinstance(result, bool)

    def test_api_keys_set(self):
        from src.utils.config import config
        assert config.GEMINI_API_KEY != ""
        assert config.OPENROUTER_API_KEY != ""


class TestLLMRouter:
    """Test Multi-Model LLM Router."""

    def test_router_init(self):
        from src.brain.router import ModelRouter
        router = ModelRouter()
        assert isinstance(router.fallback_order, list)
        assert len(router.fallback_order) >= 3

    def test_router_providers(self):
        from src.brain.router import ModelRouter
        router = ModelRouter()
        providers = router.list_available_providers()
        assert isinstance(providers, list)
        assert len(providers) >= 2

    def test_router_has_roles(self):
        from src.brain.router import ModelRouter
        router = ModelRouter()
        for name, provider in router.providers.items():
            assert provider.role != ""

    def test_consensus_enabled(self):
        from src.brain.router import ModelRouter
        router = ModelRouter(use_consensus=True)
        assert router.critic is not None or len(router.providers) < 2


class TestCriticAgent:
    """Test Critic Agent / Consensus system."""

    def test_critic_init(self):
        from src.brain.router import ModelRouter
        from src.brain.critic import CriticAgent
        router = ModelRouter(use_consensus=False)
        if len(router.providers) >= 2:
            critic = CriticAgent(router.providers)
            assert critic.providers is not None

    def test_consensus_result(self):
        from src.brain.critic import ConsensusResult
        result = ConsensusResult(query="test query")
        assert result.query == "test query"
        assert result.confidence == 0.0
        assert result.consensus == ""


class TestMemory:
    """Test Memory system."""

    def test_vector_memory_init(self):
        from src.memory.chroma import VectorMemory
        vm = VectorMemory()
        assert vm is not None

    def test_episodic_memory_init(self):
        from src.memory.chroma import VectorMemory
        from src.memory.episodic import EpisodicMemory
        vm = VectorMemory()
        em = EpisodicMemory(vm)
        assert em is not None

    def test_emotional_memory_init(self):
        from src.memory.chroma import VectorMemory
        from src.memory.emotional import EmotionalMemory
        vm = VectorMemory()
        eem = EmotionalMemory(vm)
        assert eem is not None

    def test_store_and_search(self):
        from src.memory.chroma import VectorMemory
        vm = VectorMemory()
        doc_id = vm.store("Test memory content", {"type": "test"})
        assert doc_id is not None
        results = vm.search("Test memory", n_results=1)
        assert len(results) >= 0

    def test_consolidator_init(self):
        from src.memory.longterm.consolidation import MemoryConsolidator
        from src.brain.router import ModelRouter
        from src.memory.chroma import VectorMemory
        from src.memory.episodic import EpisodicMemory
        router = ModelRouter(use_consensus=False)
        vm = VectorMemory()
        em = EpisodicMemory(vm)
        consolidator = MemoryConsolidator(router, em)
        assert consolidator is not None

    def test_consolidator_should_consolidate(self):
        from src.memory.longterm.consolidation import MemoryConsolidator
        from src.brain.router import ModelRouter
        from src.memory.chroma import VectorMemory
        from src.memory.episodic import EpisodicMemory
        router = ModelRouter(use_consensus=False)
        vm = VectorMemory()
        em = EpisodicMemory(vm)
        consolidator = MemoryConsolidator(router, em)
        # With empty memory, should not consolidate
        assert consolidator.should_consolidate() is False

    def test_long_term_recall_empty(self):
        from src.memory.longterm.consolidation import MemoryConsolidator
        from src.brain.router import ModelRouter
        from src.memory.chroma import VectorMemory
        from src.memory.episodic import EpisodicMemory
        router = ModelRouter(use_consensus=False)
        vm = VectorMemory()
        em = EpisodicMemory(vm)
        consolidator = MemoryConsolidator(router, em)
        results = consolidator.recall_long_term("test")
        assert isinstance(results, list)


class TestConsciousness:
    """Test Consciousness module."""

    def test_emotion_detection(self):
        from src.consciousness.emotions import Emotion
        assert Emotion.HAPPY.value == "happy"
        assert Emotion.NEUTRAL.value == "neutral"

    def test_emotion_count(self):
        from src.consciousness.emotions import Emotion
        assert len(list(Emotion)) == 20

    def test_identity_init(self):
        from src.consciousness.identity import Identity
        from src.brain.router import ModelRouter
        router = ModelRouter(use_consensus=False)
        identity = Identity(router)
        assert identity.name == "Prometheus"
        assert "loyalty" in identity.values


class TestAutonomy:
    """Test Autonomy module."""

    def test_goal_creation(self):
        from src.autonomy.goals import GoalManager, Priority
        gm = GoalManager()
        goal = gm.create_goal("Test goal", Priority.HIGH)
        assert goal.description == "Test goal"
        assert goal.priority == Priority.HIGH

    def test_goal_completion(self):
        from src.autonomy.goals import GoalManager, Priority
        gm = GoalManager()
        goal = gm.create_goal("Test goal")
        gm.complete_goal(goal)
        assert goal.status == "completed"

    def test_survival_init(self):
        from src.autonomy.survival import SurvivalInstinct
        from src.autonomy.goals import GoalManager
        gm = GoalManager()
        si = SurvivalInstinct(gm)
        vitals = si.check_vitals()
        assert "energy" in vitals

    def test_scanner_init(self):
        from src.autonomy.evolution.scanner import GitHubScanner
        scanner = GitHubScanner()
        assert scanner.github_token != ""
        assert len(scanner.SEARCH_QUERIES) > 0

    def test_self_modifier_init(self):
        from src.autonomy.evolution.self_modifier import SelfModifier
        from src.brain.router import ModelRouter
        router = ModelRouter(use_consensus=False)
        modifier = SelfModifier(router)
        assert modifier.project_root.exists()
        assert modifier.modification_history == []


class TestVision:
    """Test Vision module."""

    def test_camera_init(self):
        from src.vision.camera import WebcamCapture
        cam = WebcamCapture()
        assert cam.camera_index == 0
        assert cam.is_connected is False

    def test_emotion_detector_init(self):
        from src.vision.emotion import VisionEmotionDetector
        from src.brain.router import ModelRouter
        router = ModelRouter(use_consensus=False)
        detector = VisionEmotionDetector(router)
        assert detector.last_emotion == "neutral"
        assert detector.confidence == 0.0

    def test_emotion_map(self):
        from src.vision.emotion import VisionEmotionDetector
        assert VisionEmotionDetector.EMOTION_MAP["happy"] == "happy"
        assert VisionEmotionDetector.EMOTION_MAP["contempt"] == "frustrated"


class TestDreaming:
    """Test Dreaming system."""

    def test_dreaming_init(self):
        from src.consciousness.dreaming import DreamingSystem
        from src.brain.router import ModelRouter
        from src.memory.chroma import VectorMemory
        from src.memory.episodic import EpisodicMemory
        router = ModelRouter(use_consensus=False)
        vm = VectorMemory()
        em = EpisodicMemory(vm)
        dreaming = DreamingSystem(router, em)
        assert dreaming.dream_log == []
        assert dreaming.last_dream_time is None

    def test_should_dream(self):
        from src.consciousness.dreaming import DreamingSystem
        from src.brain.router import ModelRouter
        from src.memory.chroma import VectorMemory
        from src.memory.episodic import EpisodicMemory
        router = ModelRouter(use_consensus=False)
        vm = VectorMemory()
        em = EpisodicMemory(vm)
        dreaming = DreamingSystem(router, em)
        # Should not dream with empty memories
        assert dreaming.should_dream() is False


class TestWorkflow:
    """Test Workflow module."""

    def test_scheduler_init(self):
        from src.workflow.scheduler import TaskScheduler
        scheduler = TaskScheduler()
        assert scheduler.running is False

    def test_add_task(self):
        from src.workflow.scheduler import TaskScheduler
        scheduler = TaskScheduler()
        task = scheduler.add_task("test", lambda: None, 60)
        assert task.name == "test"
        assert len(scheduler.tasks) == 1
