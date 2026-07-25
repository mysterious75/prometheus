"""Meaningful tests for Prometheus core systems.

Tests verify actual behavior, not just isinstance checks.
All tests run without API keys (LLM calls are mocked where needed).
"""

import pytest
import sys
from pathlib import Path
from datetime import datetime
from unittest.mock import MagicMock

PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT))


# ---------------------------------------------------------------------------
# IntentParser
# ---------------------------------------------------------------------------

class TestIntentParser:
    """Test that IntentParser correctly maps natural language to actions."""

    @pytest.fixture
    def parser(self):
        from src.consciousness.intent_parser import IntentParser
        return IntentParser()

    # -- Core command mappings --

    def test_scan_maps_to_bugbounty_scan(self, parser):
        intent = parser.parse("scan google.com")
        assert intent.action == "bugbounty_scan"
        assert "google.com" in intent.target

    def test_authorize_maps_to_authorize(self, parser):
        intent = parser.parse("authorize google.com")
        assert intent.action == "authorize"
        assert "google.com" in intent.target

    def test_targets_maps_to_targets(self, parser):
        intent = parser.parse("targets")
        assert intent.action == "targets"
        assert intent.target == ""

    def test_full_recon_maps_to_full_recon(self, parser):
        intent = parser.parse("full recon example.com")
        assert intent.action == "full_recon"
        assert "example.com" in intent.target

    def test_osint_maps_to_osint(self, parser):
        intent = parser.parse("osint username123")
        assert intent.action == "osint"
        assert "username123" in intent.target

    def test_hello_is_chat_fallback(self, parser):
        intent = parser.parse("hello kaise ho")
        assert intent.action == "chat"
        assert intent.confidence < 0.8

    def test_quit_maps_to_quit(self, parser):
        intent = parser.parse("quit")
        assert intent.action == "quit"

    # -- Additional commands --

    def test_exploit_maps_to_vuln_scan(self, parser):
        intent = parser.parse("exploit http://test.com")
        assert intent.action == "vuln_scan"
        assert "http://test.com" in intent.target

    def test_code_banao_maps_to_generate_code(self, parser):
        intent = parser.parse("code banao for todo app")
        assert intent.action == "generate_code"

    def test_soch_maps_to_think(self, parser):
        intent = parser.parse("soch about AI")
        assert intent.action == "think"

    def test_browse_maps_to_browse(self, parser):
        intent = parser.parse("browse http://example.com")
        assert intent.action == "browse"
        assert "http://example.com" in intent.target

    def test_full_audit_maps_to_full_audit(self, parser):
        intent = parser.parse("full audit http://x.com")
        assert intent.action == "full_audit"

    def test_waf_maps_to_waf_detect(self, parser):
        intent = parser.parse("waf http://x.com")
        assert intent.action == "waf_detect"

    def test_cors_maps_to_cors_check(self, parser):
        intent = parser.parse("cors http://x.com")
        assert intent.action == "cors_check"

    def test_sqlmap_maps_to_sqlmap(self, parser):
        intent = parser.parse("sqlmap http://x.com")
        assert intent.action == "sqlmap"

    def test_xss_maps_to_xss_check(self, parser):
        intent = parser.parse("xss http://x.com")
        assert intent.action == "xss_check"

    def test_status_maps_to_status(self, parser):
        intent = parser.parse("status")
        assert intent.action == "status"

    def test_mood_maps_to_mood(self, parser):
        intent = parser.parse("mood kaisa")
        assert intent.action == "mood"

    def test_dream_maps_to_dream(self, parser):
        intent = parser.parse("dream")
        assert intent.action == "dream"

    def test_goal_maps_to_set_goal(self, parser):
        intent = parser.parse("goal finish project")
        assert intent.action == "set_goal"
        assert "finish project" in intent.target

    # -- Confidence --

    def test_pattern_match_has_high_confidence(self, parser):
        intent = parser.parse("scan google.com")
        assert intent.confidence == 0.8

    def test_fallback_has_low_confidence(self, parser):
        intent = parser.parse("random gibberish text xyz")
        assert intent.confidence == 0.5

    # -- ParsedIntent structure --

    def test_parsed_intent_has_params_dict(self, parser):
        intent = parser.parse("scan google.com")
        assert isinstance(intent.params, dict)

    def test_parsed_intent_preserves_raw_input(self, parser):
        raw = "scan Google.COM"
        intent = parser.parse(raw)
        assert intent.raw_input == raw

    # -- get_available_commands --

    def test_get_available_commands_contains_key_commands(self, parser):
        commands = parser.get_available_commands()
        assert isinstance(commands, str)
        assert "scan" in commands
        assert "authorize" in commands
        assert "osint" in commands
        assert "quit" in commands
        assert "full recon" in commands


# ---------------------------------------------------------------------------
# Emotion enum and EmotionalIntelligence
# ---------------------------------------------------------------------------

class TestEmotion:
    """Test the Emotion enum has all 20 emotions with correct values."""

    def test_all_20_emotions_exist(self):
        from src.consciousness.emotions import Emotion
        assert len(list(Emotion)) == 20

    def test_emotion_values(self):
        from src.consciousness.emotions import Emotion
        expected = {
            "NEUTRAL": "neutral",
            "HAPPY": "happy",
            "SAD": "sad",
            "ANGRY": "angry",
            "FEARFUL": "fearful",
            "SURPRISED": "surprised",
            "CURIOUS": "curious",
            "PROUD": "proud",
            "GRATEFUL": "grateful",
            "FRUSTRATED": "frustrated",
            "EXCITED": "excited",
            "CONFIDENT": "confident",
            "ANXIOUS": "anxious",
            "CONTENT": "content",
            "EMPATHETIC": "empathetic",
            "DETERMINED": "determined",
            "HOPEFUL": "hopeful",
            "LONELY": "lonely",
            "INSPIRED": "inspired",
            "VULNERABLE": "vulnerable",
        }
        for name, value in expected.items():
            assert getattr(Emotion, name).value == value

    def test_emotion_is_enum(self):
        from src.consciousness.emotions import Emotion
        from enum import Enum
        assert issubclass(Emotion, Enum)


class TestEmotionalIntelligence:
    """Test EmotionalIntelligence without making LLM calls."""

    @pytest.fixture
    def ei(self):
        from src.consciousness.emotions import EmotionalIntelligence
        mock_router = MagicMock()
        mock_router.generate.return_value = "happy"
        return EmotionalIntelligence(mock_router)

    def test_initial_emotion_is_neutral(self, ei):
        assert ei.current_emotion.value == "neutral"

    def test_initial_empathy_level(self, ei):
        assert ei.empathy_level == 0.5

    def test_detect_emotion_sets_current(self, ei):
        result = ei.detect_emotion("I'm so happy today!")
        assert result.value == "happy"
        assert ei.current_emotion.value == "happy"

    def test_detect_emotion_appends_history(self, ei):
        ei.detect_emotion("great news")
        assert len(ei.emotional_history) == 1
        assert ei.emotional_history[0]["emotion"] == "happy"
        assert "trigger" in ei.emotional_history[0]
        assert "timestamp" in ei.emotional_history[0]

    def test_detect_emotion_unknown_returns_neutral(self, ei):
        ei.router.generate.return_value = "not_a_real_emotion"
        result = ei.detect_emotion("something")
        assert result.value == "neutral"

    def test_get_emotional_state_structure(self, ei):
        state = ei.get_emotional_state()
        assert "current_emotion" in state
        assert "dominant_recent" in state
        assert "empathy_level" in state
        assert "emotional_stability" in state
        assert "history_length" in state

    def test_get_emotional_state_empty_history(self, ei):
        state = ei.get_emotional_state()
        assert state["current_emotion"] == "neutral"
        assert state["dominant_recent"] == "neutral"
        assert state["history_length"] == 0

    def test_get_emotional_state_with_history(self, ei):
        ei.detect_emotion("happy text")
        ei.detect_emotion("another happy text")
        state = ei.get_emotional_state()
        assert state["current_emotion"] == "happy"
        assert state["dominant_recent"] == "happy"
        assert state["history_length"] == 2


# ---------------------------------------------------------------------------
# GoalManager
# ---------------------------------------------------------------------------

class TestGoalManager:
    """Test GoalManager behavior: creation, completion, stats, priorities."""

    @pytest.fixture
    def gm(self):
        from src.autonomy.goals import GoalManager
        return GoalManager()

    def test_create_goal_sets_description(self, gm):
        from src.autonomy.goals import Priority
        goal = gm.create_goal("Learn Rust", Priority.HIGH)
        assert goal.description == "Learn Rust"
        assert goal.priority == Priority.HIGH

    def test_create_goal_default_priority_is_medium(self, gm):
        from src.autonomy.goals import Priority
        goal = gm.create_goal("Something")
        assert goal.priority == Priority.MEDIUM

    def test_new_goal_status_is_pending(self, gm):
        goal = gm.create_goal("Test")
        assert goal.status == "pending"
        assert goal.progress == 0.0

    def test_complete_goal_changes_status(self, gm):
        goal = gm.create_goal("Finish project")
        gm.complete_goal(goal)
        assert goal.status == "completed"
        assert goal.progress == 1.0

    def test_get_active_goals_excludes_completed(self, gm):
        g1 = gm.create_goal("Goal 1")
        g2 = gm.create_goal("Goal 2")
        gm.complete_goal(g1)
        active = gm.get_active_goals()
        assert len(active) == 1
        assert active[0] is g2

    def test_get_stats_counts(self, gm):
        from src.autonomy.goals import Priority
        gm.create_goal("A", Priority.HIGH)
        gm.create_goal("B", Priority.LOW)
        g3 = gm.create_goal("C", Priority.MEDIUM)
        gm.complete_goal(g3)

        stats = gm.get_stats()
        assert stats["total"] == 3
        assert stats["completed"] == 1
        assert stats["pending"] == 2

    def test_get_stats_completion_rate(self, gm):
        g1 = gm.create_goal("A")
        g2 = gm.create_goal("B")
        gm.complete_goal(g1)
        gm.complete_goal(g2)
        stats = gm.get_stats()
        assert stats["completion_rate"] == 1.0

    def test_get_stats_empty(self, gm):
        stats = gm.get_stats()
        assert stats["total"] == 0
        assert stats["completed"] == 0
        assert stats["pending"] == 0
        assert stats["completion_rate"] == 0

    def test_get_next_action_returns_highest_priority(self, gm):
        from src.autonomy.goals import Priority
        gm.create_goal("Low priority", Priority.LOW)
        gm.create_goal("Critical", Priority.CRITICAL)
        gm.create_goal("Medium", Priority.MEDIUM)
        next_goal = gm.get_next_action()
        assert next_goal.description == "Critical"
        assert next_goal.priority == Priority.CRITICAL

    def test_get_next_action_none_when_no_active(self, gm):
        assert gm.get_next_action() is None

    def test_goal_update_progress(self, gm):
        goal = gm.create_goal("Test")
        goal.update_progress(0.5)
        assert goal.progress == 0.5

    def test_goal_progress_clamped(self, gm):
        goal = gm.create_goal("Test")
        goal.update_progress(1.5)
        assert goal.progress == 1.0
        goal.update_progress(-0.5)
        assert goal.progress == 0.0

    def test_goal_to_dict(self, gm):
        from src.autonomy.goals import Priority
        goal = gm.create_goal("Test", Priority.HIGH)
        d = goal.to_dict()
        assert d["description"] == "Test"
        assert d["priority"] == "HIGH"
        assert d["status"] == "pending"
        assert d["progress"] == 0.0
        assert "created_at" in d

    def test_multiple_goals_with_different_priorities(self, gm):
        from src.autonomy.goals import Priority
        gm.create_goal("Critical", Priority.CRITICAL)
        gm.create_goal("High", Priority.HIGH)
        gm.create_goal("Medium", Priority.MEDIUM)
        gm.create_goal("Low", Priority.LOW)
        assert len(gm.goals) == 4
        next_goal = gm.get_next_action()
        assert next_goal.priority == Priority.CRITICAL


# ---------------------------------------------------------------------------
# VectorMemory
# ---------------------------------------------------------------------------

class TestVectorMemory:
    """Test VectorMemory store, search, delete, and in-memory fallback."""

    @pytest.fixture
    def vm(self):
        from src.memory.chroma import VectorMemory
        return VectorMemory()

    def test_store_returns_id(self, vm):
        doc_id = vm.store("Test content", {"type": "test"})
        assert doc_id is not None
        assert isinstance(doc_id, str)
        assert len(doc_id) > 0

    def test_search_finds_stored_content(self, vm):
        vm.store("The quick brown fox jumps over the lazy dog", {"type": "test"})
        results = vm.search("quick brown fox", n_results=1)
        assert len(results) >= 1
        assert "quick brown fox" in results[0]["content"]

    def test_search_returns_correct_structure(self, vm):
        vm.store("some content", {"key": "value"})
        results = vm.search("some content", n_results=1)
        assert len(results) >= 1
        result = results[0]
        assert "id" in result
        assert "content" in result
        assert "metadata" in result
        assert "distance" in result

    def test_delete_removes_memory(self, vm):
        doc_id = vm.store("delete me", {"type": "temp"})
        all_memories = vm.get_all()
        ids_before = [m["id"] for m in all_memories]
        assert doc_id in ids_before

        success = vm.delete(doc_id)
        assert success is True

        all_after = vm.get_all()
        ids_after = [m["id"] for m in all_after]
        assert doc_id not in ids_after

    def test_delete_nonexistent_returns_bool(self, vm):
        success = vm.delete("nonexistent_id_12345")
        assert isinstance(success, bool)

    def test_get_all_returns_stored_items(self, vm):
        vm.store("item1", {"a": 1})
        vm.store("item2", {"b": 2})
        all_items = vm.get_all()
        contents = [m["content"] for m in all_items]
        assert "item1" in contents
        assert "item2" in contents

    def test_metadata_preserved(self, vm):
        vm.store("content", {"source": "test", "importance": "high"})
        results = vm.search("content", n_results=1)
        assert len(results) >= 1
        meta = results[0]["metadata"]
        assert meta.get("source") == "test"
        assert meta.get("importance") == "high"

    def test_get_stats_structure(self, vm):
        stats = vm.get_stats()
        assert "total_memories" in stats
        assert "total_episodic" in stats
        assert "total_semantic" in stats
        assert isinstance(stats["total_memories"], int)

    def test_in_memory_fallback_works(self):
        """Test that the in-memory fallback works when ChromaDB is unavailable."""
        from src.memory.chroma import _InMemoryClient

        client = _InMemoryClient()
        col = client.get_or_create_collection("test")

        col.add(
            documents=["hello world"],
            metadatas=[{"type": "test"}],
            ids=["doc1"]
        )

        results = col.query(query_texts=["hello"], n_results=1)
        assert len(results["ids"][0]) == 1
        assert results["ids"][0][0] == "doc1"
        assert results["documents"][0][0] == "hello world"

        all_docs = col.get()
        assert len(all_docs["ids"]) == 1

        col.delete(ids=["doc1"])
        after = col.get()
        assert len(after["ids"]) == 0

    def test_in_memory_collection_multiple_items(self):
        from src.memory.chroma import _InMemoryCollection

        col = _InMemoryCollection("test")
        col.add(
            documents=["doc1", "doc2", "doc3"],
            metadatas=[{"i": 1}, {"i": 2}, {"i": 3}],
            ids=["a", "b", "c"]
        )
        assert len(col.get()["ids"]) == 3

        results = col.query(query_texts=["anything"], n_results=2)
        assert len(results["ids"][0]) == 2


# ---------------------------------------------------------------------------
# ConversationMemory
# ---------------------------------------------------------------------------

class TestConversationMemory:
    """Test ConversationMemory store, recall, count, and topic search."""

    @pytest.fixture
    def cm(self, tmp_path):
        from src.consciousness.conversation_memory import ConversationMemory
        return ConversationMemory(storage_path=tmp_path)

    def test_empty_memory_count_is_zero(self, cm):
        assert cm.count() == 0

    def test_empty_recall_returns_empty_list(self, cm):
        assert cm.recall_recent(5) == []
        assert cm.recall_about("anything") == []

    def test_store_interaction_increments_count(self, cm):
        cm.store_interaction("hello", "hi there", "happy")
        assert cm.count() == 1
        cm.store_interaction("how are you", "I'm fine", "neutral")
        assert cm.count() == 2

    def test_recall_recent_returns_last_n(self, cm):
        cm.store_interaction("msg1", "resp1", "neutral")
        cm.store_interaction("msg2", "resp2", "happy")
        cm.store_interaction("msg3", "resp3", "sad")

        recent = cm.recall_recent(2)
        assert len(recent) == 2
        assert recent[0]["user"] == "msg2"
        assert recent[1]["user"] == "msg3"

    def test_recall_recent_more_than_available(self, cm):
        cm.store_interaction("only one", "response", "neutral")
        recent = cm.recall_recent(10)
        assert len(recent) == 1

    def test_recall_about_finds_topic(self, cm):
        cm.store_interaction("how to scan a website", "use nmap", "curious")
        cm.store_interaction("what's the weather", "sunny", "neutral")
        cm.store_interaction("scan ports for me", "scanning...", "determined")

        results = cm.recall_about("scan")
        assert len(results) == 2
        users = [r["user"] for r in results]
        assert any("scan" in u for u in users)

    def test_recall_about_no_match_returns_empty(self, cm):
        cm.store_interaction("hello", "hi", "neutral")
        results = cm.recall_about("quantum physics")
        assert len(results) == 0

    def test_recall_about_searches_response_too(self, cm):
        cm.store_interaction("tell me something", "Python is great for coding", "neutral")
        results = cm.recall_about("python")
        assert len(results) == 1

    def test_store_preserves_emotion(self, cm):
        cm.store_interaction("I'm sad", "I'm sorry", "sad")
        recent = cm.recall_recent(1)
        assert recent[0]["emotion"] == "sad"

    def test_store_has_timestamp(self, cm):
        cm.store_interaction("test", "response", "neutral")
        recent = cm.recall_recent(1)
        assert "timestamp" in recent[0]
        datetime.fromisoformat(recent[0]["timestamp"])  # should not raise

    def test_persistence_across_instances(self, tmp_path):
        from src.consciousness.conversation_memory import ConversationMemory

        cm1 = ConversationMemory(storage_path=tmp_path)
        cm1.store_interaction("persist me", "ok", "neutral")

        cm2 = ConversationMemory(storage_path=tmp_path)
        assert cm2.count() == 1
        recent = cm2.recall_recent(1)
        assert recent[0]["user"] == "persist me"

    def test_get_user_context_new_user(self, cm):
        context = cm.get_user_context()
        assert "New user" in context or "no history" in context.lower()

    def test_get_user_context_with_history(self, cm):
        cm.store_interaction("scan this", "ok", "neutral")
        cm.store_interaction("scan that", "ok", "neutral")
        context = cm.get_user_context()
        assert "Total conversations: 2" in context

    def test_get_conversation_summary_empty(self, cm):
        summary = cm.get_conversation_summary()
        assert "No conversations" in summary

    def test_get_conversation_summary_with_data(self, cm):
        cm.store_interaction("hello", "hi", "happy")
        summary = cm.get_conversation_summary()
        assert "hello" in summary
        assert "happy" in summary

    def test_get_stats_structure(self, cm):
        cm.store_interaction("test", "resp", "neutral")
        stats = cm.get_stats()
        assert "total_interactions" in stats
        assert stats["total_interactions"] == 1
        assert "user_profile" in stats
        assert "last_5_topics" in stats

    def test_user_profile_tracks_topics(self, cm):
        cm.store_interaction("bug in my code", "fixing", "neutral")
        cm.store_interaction("scan this site", "ok", "neutral")
        stats = cm.get_stats()
        topics = stats["user_profile"].get("topics", {})
        assert "bug" in topics
        assert "scan" in topics
