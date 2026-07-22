"""Test all systems with OpenRouter key."""
import sys
sys.path.insert(0, ".")

print("=" * 60)
print("PROMETHEUS - FULL SYSTEM TEST")
print("=" * 60)

# 1. Config
print("\n[1] CONFIG TEST")
from src.utils.config import config
print(f"  App: {config.APP_NAME} v{config.APP_VERSION}")
keys = config.get_all_keys()
print(f"  Keys found: {len(keys)}")
for name, info in keys.items():
    key_prev = info['key'][:20] + '...' if len(info['key']) > 20 else info['key']
    print(f"    {name}: {key_prev} (type={info.get('type', 'openai')})")
valid = config.validate()
print(f"  Validate: {valid}")

# 2. Router
print("\n[2] ROUTER TEST")
from src.brain.router import ModelRouter
router = ModelRouter()
providers = router.list_available_providers()
print(f"  Active providers: {len(providers)}")
for p in providers:
    prov = router.providers[p]
    print(f"    {p}: role={prov.role}, model={prov.model}")
print(f"  Status:\n{router.get_status()}")

# 3. LLM Generate
print("\n[3] LLM GENERATE TEST")
if providers:
    response = router.generate("Say hello in 5 words", role="primary")
    print(f"  Primary response: {response[:200]}")
else:
    print("  SKIPPED - no providers")

# 4. Intent Parser
print("\n[4] INTENT PARSER TEST")
from src.consciousness.intent_parser import IntentParser
parser = IntentParser()
intents = ["scan google.com", "code banao for app", "hello kaise ho", "status dikhao", "recon google.com"]
for text in intents:
    intent = parser.parse(text)
    print(f"  '{text}' -> {intent.action} (target={intent.target})")

# 5. Memory
print("\n[5] MEMORY TEST")
from src.memory.chroma import VectorMemory
vm = VectorMemory()
doc_id = vm.store("Test memory for OpenRouter", {"type": "test"})
print(f"  Stored: {doc_id}")
results = vm.search("Test memory", n_results=1)
print(f"  Search results: {len(results)}")

# 6. Episodic Memory
print("\n[6] EPISODIC MEMORY TEST")
from src.memory.episodic import EpisodicMemory
em = EpisodicMemory(vm)
em.store_event("User tested OpenRouter", "System responded well", "positive")
print(f"  Episodes: {len(em.get_recent(10))}")

# 7. Emotional Memory
print("\n[7] EMOTIONAL MEMORY TEST")
from src.memory.emotional import EmotionalMemory
eem = EmotionalMemory(vm)
print(f"  Emotional memory initialized: OK")

# 8. Goals
print("\n[8] GOALS TEST")
from src.autonomy.goals import GoalManager, Priority
gm = GoalManager()
goal = gm.create_goal("Test OpenRouter integration", Priority.HIGH)
print(f"  Created: {goal.description} ({goal.priority})")
gm.complete_goal(goal)
print(f"  Completed: {goal.status}")

# 9. Survival
print("\n[9] SURVIVAL TEST")
from src.autonomy.survival import SurvivalInstinct
si = SurvivalInstinct(gm)
vitals = si.check_vitals()
print(f"  Vitals: {vitals}")

# 10. Bug Bounty Knowledge
print("\n[10] BUG BOUNTY KNOWLEDGE TEST")
from src.bugbounty.knowledge import BugBountyKnowledge
kb = BugBountyKnowledge()
stats = kb.get_stats()
print(f"  Total entries: {stats.get('total_entries', 0)}")
print(f"  Vuln types: {len(stats.get('vuln_types', {}))}")
print(f"  Severities: {stats.get('severities', {})}")

# 11. ToolKit
print("\n[11] TOOLKIT TEST")
from src.bugbounty.toolkit import PythonToolkit
toolkit = PythonToolkit()
print(f"  Toolkit initialized: OK")

# 12. Emotions
print("\n[12] EMOTIONS TEST")
from src.consciousness.emotions import EmotionalIntelligence, Emotion
ei = EmotionalIntelligence(router)
print(f"  EmotionalIntelligence initialized: OK")
print(f"  Emotions available: {len(list(Emotion))}")

# 13. Consciousness
print("\n[13] CONSCIOUSNESS TEST")
from src.consciousness.identity import Identity
identity = Identity(router)
print(f"  Name: {identity.name}")
print(f"  Values: {identity.values}")

# 14. Dreaming
print("\n[14] DREAMING TEST")
from src.consciousness.dreaming import DreamingSystem
dreaming = DreamingSystem(router, em)
print(f"  Should dream: {dreaming.should_dream()}")

# 15. Monologue
print("\n[15] MONOLOGUE TEST")
from src.consciousness.monologue import InternalMonologue
monologue = InternalMonologue(router)
print(f"  Thoughts: {len(monologue.thoughts)}")

# 16. Workflow
print("\n[16] WORKFLOW TEST")
from src.workflow.scheduler import TaskScheduler
scheduler = TaskScheduler()
task = scheduler.add_task("test_task", lambda: None, 60)
print(f"  Task added: {task.name}")

# 17. Vision
print("\n[17] VISION TEST")
from src.vision.camera import WebcamCapture
cam = WebcamCapture()
print(f"  Camera: index={cam.camera_index}, connected={cam.is_connected}")

# 18. Consensus
print("\n[18] CONSENSUS TEST")
from src.brain.critic import CriticAgent, ConsensusResult
result = ConsensusResult(query="test")
print(f"  ConsensusResult: query={result.query}, confidence={result.confidence}")

print("\n" + "=" * 60)
print("ALL TESTS COMPLETE!")
print("=" * 60)
