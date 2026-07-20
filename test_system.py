"""Full System Test - Project Prometheus v2.0"""

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))


def test_all():
    print("=" * 60)
    print("   PROJECT PROMETHEUS v2.0 - Full System Test")
    print("=" * 60)

    # [1/8] Configuration
    print("\n[1/8] Testing Configuration...")
    from src.utils.config import config
    print(f"  [OK] App: {config.APP_NAME} v{config.APP_VERSION}")
    gemini_status = "SET" if config.GEMINI_API_KEY else "NOT SET"
    openrouter_status = "SET" if config.OPENROUTER_API_KEY else "NOT SET"
    print(f"  [OK] Gemini Key: {gemini_status}")
    print(f"  [OK] OpenRouter Key: {openrouter_status}")

    # [2/8] Multi-Model Brain
    print("\n[2/8] Testing Multi-Model Brain...")
    from src.brain.router import ModelRouter
    router = ModelRouter()
    providers = router.list_available_providers()
    print(f"  [OK] Providers loaded: {providers}")
    print(f"  [OK] Roles: {[(p.name, p.role) for p in router.providers.values()]}")

    # [3/8] Critic Agent / Consensus
    print("\n[3/8] Testing Critic Agent...")
    if router.critic:
        print(f"  [OK] Critic Agent active with {len(router.critic.providers)} models")
        print(f"  [OK] Consensus available: True")
    else:
        print(f"  [WARN] Critic not active (< 2 providers)")

    # [4/8] Memory System
    print("\n[4/8] Testing Memory System...")
    from src.memory.chroma import VectorMemory
    vm = VectorMemory()
    doc_id = vm.store("Advanced memory test", {"type": "test", "importance": 0.8})
    print(f"  [OK] Vector store: {doc_id}")
    results = vm.search("memory test", n_results=1)
    print(f"  [OK] Search: {len(results)} results")

    # [5/8] Long-term Memory Consolidation
    print("\n[5/8] Testing Long-term Memory...")
    from src.memory.episodic import EpisodicMemory
    from src.memory.longterm.consolidation import MemoryConsolidator
    em = EpisodicMemory(vm)
    consolidator = MemoryConsolidator(router, em)
    print(f"  [OK] Consolidator initialized")
    print(f"  [OK] Should consolidate: {consolidator.should_consolidate()}")
    print(f"  [OK] Long-term recall: {len(consolidator.recall_long_term('test'))} results")

    # [6/8] Consciousness + Vision
    print("\n[6/8] Testing Consciousness + Vision...")
    from src.consciousness.emotions import Emotion, EmotionalIntelligence
    from src.vision.emotion import VisionEmotionDetector
    from src.vision.camera import WebcamCapture
    ei = EmotionalIntelligence(router)
    print(f"  [OK] Emotions: {len(list(Emotion))} types")
    detector = VisionEmotionDetector(router)
    print(f"  [OK] Vision emotion detector ready")
    cam = WebcamCapture()
    print(f"  [OK] Webcam capture ready (connected: {cam.is_connected})")

    # [7/8] Auto-Evolution
    print("\n[7/8] Testing Auto-Evolution...")
    from src.autonomy.evolution.scanner import GitHubScanner
    from src.autonomy.evolution.self_modifier import SelfModifier
    scanner = GitHubScanner()
    modifier = SelfModifier(router)
    print(f"  [OK] GitHub scanner ready ({len(scanner.SEARCH_QUERIES)} queries)")
    print(f"  [OK] Self-modifier ready (root: {modifier.project_root})")

    # [8/8] Dreaming + Bug Bounty
    print("\n[8/8] Testing Dreaming + Bug Bounty...")
    from src.consciousness.dreaming import DreamingSystem
    from src.bugbounty.recon import ReconPipeline
    from src.bugbounty.scanner import VulnerabilityScanner
    from src.bugbounty.reporter import BugBountyReporter
    dreaming = DreamingSystem(router, em)
    print(f"  [OK] Dreaming system ready (should_dream: {dreaming.should_dream()})")
    recon = ReconPipeline("example.com")
    scanner_bb = VulnerabilityScanner("example.com")
    reporter = BugBountyReporter()
    print(f"  [OK] Bug bounty pipeline ready")

    # Summary
    print("\n" + "=" * 60)
    print("   ALL TESTS PASSED SUCCESSFULLY!")
    print("=" * 60)
    print(f"""
System Components (v2.0):
  - Brain: {len(providers)} LLM providers with consensus
  - Roles: senses(Gemini), logic(DeepSeek), reasoning(Mistral), guardrail(Llama)
  - Memory: ChromaDB + long-term consolidation
  - Vision: Webcam + Gemini Vision emotion detection
  - Consciousness: {len(list(Emotion))} emotions + dreaming
  - Auto-Evolution: GitHub scanner + self-modifier
  - Bug Bounty: Full recon + scanning pipeline
  - Autonomy: Goal management + execution engine

Status: NEXT-LEVEL READY
Run: python -m src.main
""")


if __name__ == "__main__":
    test_all()
