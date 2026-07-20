"""Tests for Brain module."""

import pytest
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))


class TestConfig:
    """Test configuration."""

    def test_config_loads(self):
        """Test that config loads correctly."""
        from src.utils.config import config
        assert config.APP_NAME == "Prometheus"
        assert config.APP_VERSION == "1.0.0"

    def test_config_validate(self):
        """Test config validation."""
        from src.utils.config import config
        # Should not raise
        result = config.validate()
        assert isinstance(result, bool)


class TestLLMRouter:
    """Test LLM Router."""

    def test_router_init(self):
        """Test router initialization."""
        from src.brain.router import ModelRouter
        router = ModelRouter()
        assert isinstance(router.fallback_order, list)

    def test_router_providers(self):
        """Test provider listing."""
        from src.brain.router import ModelRouter
        router = ModelRouter()
        providers = router.list_available_providers()
        assert isinstance(providers, list)


class TestMemory:
    """Test Memory system."""

    def test_vector_memory_init(self):
        """Test VectorMemory initialization."""
        from src.memory.chroma import VectorMemory
        vm = VectorMemory()
        assert vm is not None

    def test_episodic_memory_init(self):
        """Test EpisodicMemory initialization."""
        from src.memory.chroma import VectorMemory
        from src.memory.episodic import EpisodicMemory
        vm = VectorMemory()
        em = EpisodicMemory(vm)
        assert em is not None

    def test_emotional_memory_init(self):
        """Test EmotionalMemory initialization."""
        from src.memory.chroma import VectorMemory
        from src.memory.emotional import EmotionalMemory
        vm = VectorMemory()
        eem = EmotionalMemory(vm)
        assert eem is not None

    def test_store_and_search(self):
        """Test storing and searching memories."""
        from src.memory.chroma import VectorMemory
        vm = VectorMemory()
        doc_id = vm.store("Test memory content", {"type": "test"})
        assert doc_id is not None

        results = vm.search("Test memory", n_results=1)
        assert len(results) >= 0


class TestConsciousness:
    """Test Consciousness module."""

    def test_emotion_detection(self):
        """Test emotion detection."""
        from src.consciousness.emotions import Emotion
        assert Emotion.HAPPY.value == "happy"
        assert Emotion.NEUTRAL.value == "neutral"

    def test_identity_init(self):
        """Test identity initialization."""
        from src.consciousness.identity import Identity
        from src.brain.router import ModelRouter
        router = ModelRouter()
        identity = Identity(router)
        assert identity.name == "Prometheus"
        assert "loyalty" in identity.values


class TestAutonomy:
    """Test Autonomy module."""

    def test_goal_creation(self):
        """Test goal creation."""
        from src.autonomy.goals import GoalManager, Priority
        gm = GoalManager()
        goal = gm.create_goal("Test goal", Priority.HIGH)
        assert goal.description == "Test goal"
        assert goal.priority == Priority.HIGH

    def test_goal_completion(self):
        """Test goal completion."""
        from src.autonomy.goals import GoalManager, Priority
        gm = GoalManager()
        goal = gm.create_goal("Test goal")
        gm.complete_goal(goal)
        assert goal.status == "completed"

    def test_survival_init(self):
        """Test survival instinct."""
        from src.autonomy.survival import SurvivalInstinct
        from src.autonomy.goals import GoalManager
        gm = GoalManager()
        si = SurvivalInstinct(gm)
        vitals = si.check_vitals()
        assert "energy" in vitals


class TestWorkflow:
    """Test Workflow module."""

    def test_scheduler_init(self):
        """Test scheduler initialization."""
        from src.workflow.scheduler import TaskScheduler
        scheduler = TaskScheduler()
        assert scheduler.running is False

    def test_add_task(self):
        """Test adding a task."""
        from src.workflow.scheduler import TaskScheduler
        scheduler = TaskScheduler()
        task = scheduler.add_task("test", lambda: None, 60)
        assert task.name == "test"
        assert len(scheduler.tasks) == 1
