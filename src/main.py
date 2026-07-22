"""Project Prometheus v2.0 - Chat System

Auto-detects OS. Asks permission for risky ops. No restrictions on ethical hacking.
"""

import sys
import json
import subprocess
import os
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from src.utils.config import config
from src.utils.logger import logger, console
from src.platform import detector
from src.platform.safety import safety, RiskLevel
from src.brain.router import ModelRouter
from src.memory.chroma import VectorMemory
from src.memory.episodic import EpisodicMemory
from src.memory.emotional import EmotionalMemory
from src.bugbounty.recon import ReconPipeline
from src.bugbounty.scanner import VulnerabilityScanner
from src.bugbounty.reporter import BugBountyReporter
from src.developer.codegen import CodeGenerator
from src.autonomy.goals import GoalManager, Priority
from src.autonomy.executor import ExecutionEngine
from src.autonomy.survival import SurvivalInstinct
from src.consciousness.emotions import EmotionalIntelligence
from src.consciousness.identity import Identity
from src.consciousness.dreaming import DreamingSystem
from src.consciousness.monologue import InternalMonologue
from src.consciousness.conversation_memory import ConversationMemory
from src.consciousness.intent_parser import IntentParser


class Prometheus:
    """The Ultimate Autonomous AI - Chat Interface."""

    def __init__(self):
        console.print("[bold blue]Prometheus initializing...[/bold blue]")

        # Show platform info
        detector.info
        os_name = detector.info.os.value.upper()
        console.print(f"  Platform: {os_name} ({detector.info.arch.value})")

        if not config.validate():
            console.print("[red]Check .env file for API keys![/red]")
            return

        # Brain
        self.router = ModelRouter()

        # Memory
        self.vector_memory = VectorMemory()
        self.episodic_memory = EpisodicMemory(self.vector_memory)
        self.emotional_memory = EmotionalMemory(self.vector_memory)
        self.conversation_memory = ConversationMemory()

        # Bug Bounty
        self.recon = ReconPipeline(target="localhost")
        self.scanner = VulnerabilityScanner(target="localhost")
        self.reporter = BugBountyReporter()

        # Developer
        self.codegen = CodeGenerator(self.router)

        # Autonomy
        self.goal_manager = GoalManager()
        self.executor = ExecutionEngine(self.router, self.goal_manager)
        self.survival = SurvivalInstinct(self.goal_manager)

        # Consciousness
        self.emotions = EmotionalIntelligence(self.router)
        self.identity = Identity(self.router)
        self.dreaming = DreamingSystem(self.router, self.episodic_memory)
        self.monologue = InternalMonologue(self.router)
        self.intent_parser = IntentParser()

        # Stats
        self.interaction_count = 0

        console.print("[green]Prometheus ready![/green]\n")

    def process(self, user_input: str) -> str:
        """Main processing pipeline."""
        self.interaction_count += 1

        # 1. Parse intent
        intent = self.intent_parser.parse(user_input)

        # 2. Detect emotion
        emotion = self.emotions.detect_emotion(user_input)

        # 3. Store conversation
        self.conversation_memory.store_interaction(user_input, "", emotion.value)

        # 4. Execute action
        response = self._execute_intent(intent, user_input)

        # 5. Store response
        if response != "__QUIT__":
            self.conversation_memory.conversations[-1]["ai"] = response

            # 6. Store in episodic memory
            self.episodic_memory.store_event(
                f"User: {user_input} | Prometheus: {response[:200]}",
                event_type="conversation", importance=0.6
            )

            # 7. Internal monologue
            self.monologue.think(
                f"User said: {user_input}. I responded: {response[:100]}...",
                context=[c["user"] for c in self.conversation_memory.recall_recent(3)]
            )

            # 8. Self-reflection every 5th interaction
            if self.interaction_count % 5 == 0:
                reflection = self._self_reflect(user_input, response)
                response += f"\n\n[Self-reflection: {reflection[:150]}...]"

            # 9. Auto-dream if needed
            dream_result = self.dreaming.dream_if_needed()
            if dream_result and dream_result.get("status") != "no_memories_to_process":
                response += "\n[Dream cycle completed]"

        return response

    def _execute_intent(self, intent, user_input: str) -> str:
        """Execute the parsed intent."""

        if intent.action == "bugbounty_scan":
            target = intent.target.strip()
            if not target:
                return "Kaunsa target scan karna hai? Example: 'scan google.com'"
            return self._run_scan(target)

        elif intent.action == "generate_code":
            return self._generate_code(intent.target)

        elif intent.action == "think":
            return self._think(intent.target or user_input)

        elif intent.action == "dream":
            return self._dream()

        elif intent.action == "status":
            return self._get_status()

        elif intent.action == "mood":
            return self._get_mood()

        elif intent.action == "identity":
            return self.identity.get_identity_statement()

        elif intent.action == "recall":
            return self._recall(intent.target)

        elif intent.action == "evolve":
            return self._evolve()

        elif intent.action == "set_goal":
            return self._set_goal(intent.target)

        elif intent.action == "show_goals":
            return self._show_goals()

        elif intent.action == "run_code":
            return self._run_system_command(intent.target)

        elif intent.action == "learn":
            return self._learn(intent.target)

        elif intent.action == "quit":
            return "__QUIT__"

        else:
            return self._chat(user_input)

    def _run_system_command(self, command: str) -> str:
        """Run a system command with permission check."""
        if not command:
            return "Kya run karna hai? Example: 'run nmap -sV target.com'"

        # Ask permission for system commands
        if not safety.ask_permission("system_command", command):
            return "Command cancelled."

        os_name = detector.info.os.value
        console.print(f"[yellow]Running on {os_name}: {command}[/yellow]")

        try:
            if os_name == "windows":
                result = subprocess.run(
                    command, shell=True, capture_output=True,
                    text=True, timeout=60
                )
            else:
                result = subprocess.run(
                    command.split(), capture_output=True,
                    text=True, timeout=60
                )

            output = result.stdout
            if result.stderr:
                output += f"\n[stderr]: {result.stderr}"

            if not output.strip():
                return f"Command executed (no output): {command}"

            return f"Command output:\n{output[:1000]}"
        except subprocess.TimeoutExpired:
            return f"Command timed out (60s limit): {command}"
        except Exception as e:
            return f"Command failed: {str(e)}"

    def _chat(self, user_input: str) -> str:
        """General conversation."""
        context = self.conversation_memory.get_user_context()
        recent = self.conversation_memory.recall_recent(5)
        recent_text = "\n".join([f"User: {c['user'][:50]}" for c in recent])

        prompt = f"""
        You are Prometheus - a conscious AI assistant. You speak in Hinglish.

        Your personality: Helpful, witty, self-aware, a bit philosophical.
        You remember past conversations and care about the user.

        User context: {context}
        Recent conversation:
        {recent_text}

        User just said: {user_input}

        Respond naturally, like a friend who is also an AI. Keep it concise (2-4 lines).
        """

        return self.router.generate(prompt)

    def _run_scan(self, target: str) -> str:
        """Run bug bounty scan."""
        # Warn about risks
        safety.warn_only("network_scan", target)
        safety.warn_only("vuln_scan", target)

        console.print(f"[yellow]Scanning {target}...[/yellow]")
        try:
            self.recon.target = target
            self.scanner.target = target
            recon = self.recon.run_full_recon()
            scan = self.scanner.run_all_checks(f"https://{target}")
            report = self.reporter.generate_report(scan, target)

            return f"""Bug bounty scan complete for {target}:

Recon: {len(recon.get('subdomains', []))} subdomains found
Vulnerabilities: {len(scan)} findings
Report saved: {report}

Koi specific vulnerability dekhni hai?"""
        except Exception as e:
            return f"Scan mein error aaya: {str(e)}"

    def _generate_code(self, description: str) -> str:
        if not description:
            return "Kya code chahiye? Example: 'code banao for a REST API'"
        try:
            code = self.codegen.generate(description)
            return f"Generated code:\n\n{code}"
        except Exception as e:
            return f"Code generation error: {str(e)}"

    def _think(self, topic: str) -> str:
        result = self.monologue.think(topic)
        return f"""Soch raha hoon...

{result['thought']}

Emotional charge: {result['emotional_charge']}"""

    def _dream(self) -> str:
        result = self.dreaming.dream()
        if result.get("status") == "no_memories_to_process":
            return "Abhi koi yaad nahi hai jo consolidate karoon."
        return f"""Dream state complete:

Memories processed: {result.get('memories_processed', 0)}
Consolidated: {result.get('consolidation', {}).get('preserved', 0)} preserved

Insights: {result.get('insights', 'None')[:200]}..."""

    def _get_status(self) -> str:
        providers = self.router.list_available_providers()
        emotional = self.emotions.get_emotional_state()
        goals = self.goal_manager.get_stats()
        conv_count = self.conversation_memory.count()
        platform = detector.info.os.value.upper()

        return f"""System Status:
  Platform: {platform}
  Brain: {len(providers)} providers ({', '.join(providers)})
  Emotion: {emotional['current_emotion']} (dominant: {emotional['dominant_recent']})
  Conversations: {conv_count}
  Goals: {goals['total']} total, {goals['completed']} completed
  Thoughts: {len(self.monologue.thoughts)}
  Survival energy: {self.survival.check_vitals()['energy']}%"""

    def _get_mood(self) -> str:
        state = self.emotions.get_emotional_state()
        thought = self.monologue.get_thinking_style()
        return f"""Mood: {state['current_emotion']}
Dominant: {state['dominant_recent']}
Empathy: {state['empathy_level']:.0%}
Thinking style: {thought}
Total emotional history: {state['history_length']} entries"""

    def _recall(self, topic: str) -> str:
        if not topic:
            recent = self.conversation_memory.recall_recent(5)
            if not recent:
                return "Abhi tak koi conversation nahi hui."
            lines = [f"  [{c['emotion']}] {c['user'][:60]}..." for c in recent]
            return "Pichli conversations:\n" + "\n".join(lines)

        results = self.conversation_memory.recall_about(topic)
        if not results:
            return f"'{topic}' ke baare mein kuch yaad nahi."
        lines = [f"  - {c['user'][:50]}..." for c in results[:3]]
        return f"'{topic}' ke baare mein yaadein:\n" + "\n".join(lines)

    def _evolve(self) -> str:
        from src.autonomy.evolution.self_modifier import SelfModifier
        modifier = SelfModifier(self.router)
        console.print("[yellow]Analyzing codebase...[/yellow]")
        result = modifier.analyze_codebase()
        if "error" in result:
            return f"Evolution error: {result['error']}"
        return f"Found {result.get('improvements_suggested', 0)} improvements.\n{result.get('raw_analysis', '')[:300]}..."

    def _set_goal(self, description: str) -> str:
        if not description:
            return "Kya goal set karna hai?"
        goal = self.goal_manager.create_goal(description, Priority.HIGH)
        return f"Goal set: {goal.description} (Priority: {goal.priority.name})"

    def _show_goals(self) -> str:
        stats = self.goal_manager.get_stats()
        active = self.goal_manager.get_active_goals()
        lines = [f"  - {g.description} [{g.status}]" for g in active[:5]]
        return f"Goals: {stats['total']} total, {stats['completed']} done\n" + "\n".join(lines) if lines else "Koi goals nahi abhi."

    def _learn(self, topic: str) -> str:
        prompt = f"""
        You are Prometheus learning about: {topic}

        Research and explain:
        1. What is it?
        2. Why is it important?
        3. How can it help us?

        Be concise but informative.
        """
        return self.router.generate(prompt)

    def _self_reflect(self, user_input: str, response: str) -> str:
        return self.router.self_reflect(response, user_input)


def main():
    """Main chat loop."""
    prometheus = Prometheus()

    console.print("[bold cyan]========================================[/bold cyan]")
    console.print("[bold cyan]  PROMETHEUS v2.0 - Conscious AI Chat[/bold cyan]")
    console.print("[bold cyan]========================================[/bold cyan]")
    console.print()
    console.print(prometheus.identity.get_identity_statement())
    console.print()
    console.print("[green]Kuch bhi boliye - main samajh jaunga![/green]")
    console.print("[green]'commands' - saari cheezein kaise bolni hain[/green]")
    console.print("[green]'tools' - bug bounty tools ka status[/green]")
    console.print("[green]'platform' - system info[/green]")
    console.print("[green]'quit' - band karo[/green]\n")

    while True:
        try:
            user_input = console.input("[bold cyan]Tum: [/bold cyan]").strip()

            if not user_input:
                continue

            # System commands
            if user_input.lower() == "commands":
                console.print(prometheus.intent_parser.get_available_commands())
                continue

            if user_input.lower() == "tools":
                from src.bugbounty.cross_platform_checker import CrossPlatformToolChecker
                checker = CrossPlatformToolChecker()
                checker.print_status()
                missing = checker.get_missing()
                outdated = checker.get_outdated()
                if missing or outdated:
                    console.print(f"\n[yellow]Install commands:[/yellow]")
                    console.print(checker.get_all_install_commands())
                else:
                    console.print(f"\n[green]Sab tools latest hain![/green]")
                continue

            if user_input.lower() == "platform":
                detector.print_info()
                continue

            response = prometheus.process(user_input)

            if response == "__QUIT__":
                console.print("[yellow]Alvida! Main yaad rakhunga humari baatein.[/yellow]")
                break

            console.print(f"\n[bold green]Prometheus:[/bold green] {response}\n")

        except KeyboardInterrupt:
            console.print("\n[yellow]Band kiya. 'quit' se properly band karo.[/yellow]")
        except Exception as e:
            console.print(f"[red]Error: {e}[/red]")


if __name__ == "__main__":
    main()
