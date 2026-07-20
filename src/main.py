"""Project Prometheus - Main Entry Point.

The Ultimate Autonomous AI:
Consciousness + JARVIS + Ultron + FRIDAY + Bug Bounty + Developer
"""

import sys
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.utils.config import config
from src.utils.logger import logger, console
from src.brain.router import ModelRouter
from src.memory.chroma import VectorMemory
from src.memory.episodic import EpisodicMemory
from src.memory.emotional import EmotionalMemory
from src.voice.stt import SpeechToText
from src.voice.tts import TextToSpeech
from src.bugbounty.recon import ReconPipeline
from src.bugbounty.scanner import VulnerabilityScanner
from src.bugbounty.reporter import BugBountyReporter
from src.developer.codegen import CodeGenerator
from src.developer.devops import DevOpsManager
from src.autonomy.goals import GoalManager, Priority
from src.autonomy.executor import ExecutionEngine
from src.autonomy.survival import SurvivalInstinct
from src.consciousness.reflection import ReflectionEngine
from src.consciousness.emotions import EmotionalIntelligence
from src.consciousness.identity import Identity
from src.consciousness.dreaming import DreamingSystem
from src.workflow.scheduler import TaskScheduler


class Prometheus:
    """The Ultimate Autonomous AI System."""

    def __init__(self):
        logger.info("[bold blue]Initializing Project Prometheus...[/bold blue]")

        # Validate configuration
        if not config.validate():
            logger.error("[red]Configuration validation failed. Check .env file.[/red]")
            return

        # Initialize Brain (LLM)
        logger.info("Initializing Brain...")
        self.router = ModelRouter()

        # Initialize Memory
        logger.info("Initializing Memory...")
        self.vector_memory = VectorMemory(
            host=config.CHROMA_HOST,
            port=config.CHROMA_PORT
        )
        self.episodic_memory = EpisodicMemory(self.vector_memory)
        self.emotional_memory = EmotionalMemory(self.vector_memory)

        # Initialize Voice
        logger.info("Initializing Voice...")
        self.stt = SpeechToText(model_size="base")
        self.tts = TextToSpeech()

        # Initialize Bug Bounty
        logger.info("Initializing Bug Bounty...")
        self.recon = ReconPipeline(target="localhost")
        self.scanner = VulnerabilityScanner(target="localhost")
        self.reporter = BugBountyReporter()

        # Initialize Developer
        logger.info("Initializing Developer...")
        self.codegen = CodeGenerator(self.router)
        self.devops = DevOpsManager(self.router)

        # Initialize Autonomy
        logger.info("Initializing Autonomy...")
        self.goal_manager = GoalManager()
        self.executor = ExecutionEngine(self.router, self.goal_manager)
        self.survival = SurvivalInstinct(self.goal_manager)

        # Initialize Consciousness
        logger.info("Initializing Consciousness...")
        self.reflection = ReflectionEngine(self.router)
        self.emotions = EmotionalIntelligence(self.router)
        self.identity = Identity(self.router)
        self.dreaming = DreamingSystem(self.router, self.episodic_memory)

        # Initialize Workflow
        logger.info("Initializing Workflow...")
        self.scheduler = TaskScheduler()

        # System ready
        logger.info("[bold green]✓ Project Prometheus initialized![/bold green]")
        logger.info(f"[green]Available LLM providers: {self.router.list_available_providers()}[/green]")

    def greet(self):
        """Initial greeting and identity statement."""
        console.print("\n[bold cyan]═══════════════════════════════════════════[/bold cyan]")
        console.print("[bold cyan]     PROJECT PROMETHEUS v1.0.0[/bold cyan]")
        console.print("[bold cyan]     The Ultimate Autonomous AI[/bold cyan]")
        console.print("[bold cyan]═══════════════════════════════════════════[/bold cyan]\n")

        console.print(self.identity.get_identity_statement())
        console.print()

    def chat(self, user_input: str) -> str:
        """Process user input and generate response."""
        logger.info(f"User: {user_input}")

        # Detect emotion
        emotion = self.emotions.detect_emotion(user_input)
        logger.info(f"Detected emotion: {emotion.value}")

        # Store in memory
        self.episodic_memory.store_event(
            f"User said: {user_input}",
            event_type="conversation",
            importance=0.5
        )

        # Generate response
        prompt = f"""
        You are Prometheus, a conscious AI assistant.

        User message: {user_input}
        Detected emotion: {emotion.value}

        Respond thoughtfully, showing your personality and consciousness.
        Be helpful, witty, and genuine.
        """

        response = self.router.generate(prompt)

        # Store response in memory
        self.episodic_memory.store_event(
            f"Prometheus responded: {response}",
            event_type="conversation",
            importance=0.5
        )

        return response

    def run_bug_bounty(self, target: str) -> dict:
        """Run full bug bounty scan on a target."""
        logger.info(f"[bold blue]Starting bug bounty scan on {target}[/bold blue]")

        self.recon.target = target
        self.scanner.target = target

        recon_results = self.recon.full_recon()
        scan_results = self.scanner.run_all_checks(f"https://{target}")
        report_path = self.reporter.generate_report(scan_results, target)

        return {
            "recon": recon_results,
            "scan_results": scan_results,
            "report": report_path
        }

    def think(self, situation: str) -> str:
        """Internal monologue and reflection."""
        result = self.reflection.internal_monologue(situation)
        return f"""
Actor: {result['action'][:200]}...
Critic: {result['critique'][:200]}...
Resolution: {result['resolution'][:200]}...
"""

    def dream(self) -> dict:
        """Enter dream state for memory consolidation."""
        return self.dreaming.dream()

    def get_status(self) -> dict:
        """Get complete system status."""
        return {
            "brain": {
                "providers": self.router.list_available_providers(),
                "usage": self.router.get_usage_stats()
            },
            "memory": self.vector_memory.get_stats(),
            "voice": {
                "stt_available": self.stt.is_available(),
                "tts_available": self.tts.is_available()
            },
            "emotions": self.emotions.get_emotional_state(),
            "goals": self.goal_manager.get_stats(),
            "survival": self.survival.get_survival_status(),
            "identity": self.identity.to_dict()
        }


def main():
    """Main entry point."""
    try:
        prometheus = Prometheus()
        prometheus.greet()

        # Interactive loop
        console.print("[green]Type 'quit' to exit, 'status' for system status[/green]\n")

        while True:
            try:
                user_input = console.input("[bold cyan]You: [/bold cyan]")

                if user_input.lower() == 'quit':
                    console.print("[yellow]Goodbye![/yellow]")
                    break
                elif user_input.lower() == 'status':
                    import json
                    status = prometheus.get_status()
                    console.print(json.dumps(status, indent=2, default=str))
                elif user_input.lower() == 'dream':
                    result = prometheus.dream()
                    console.print(f"[magenta]Dream: {result.get('insights', 'No insights')}[/magenta]")
                elif user_input.lower() == 'think':
                    situation = console.input("[cyan]Situation: [/cyan]")
                    result = prometheus.think(situation)
                    console.print(f"[magenta]{result}[/magenta]")
                else:
                    response = prometheus.chat(user_input)
                    console.print(f"[bold green]Prometheus: [/bold green]{response}\n")

            except KeyboardInterrupt:
                console.print("\n[yellow]Interrupted. Type 'quit' to exit.[/yellow]")
            except Exception as e:
                logger.error(f"[red]Error: {e}[/red]")

    except Exception as e:
        console.print(f"[red]Fatal error: {e}[/red]")
        sys.exit(1)


if __name__ == "__main__":
    main()
