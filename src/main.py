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
from src.web.proxy import ProxyInterceptor
from src.web.vuln_scanner import VulnScanner as WebVulnScanner
from src.web.osint import OSINTFinder
from src.web.brute_force import SmartBruteForce
from src.web.browser import BrowserAutomation


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

        # Web tools
        self.proxy = ProxyInterceptor()
        self.web_scanner = WebVulnScanner()
        self.osint = OSINTFinder()
        self.brute = SmartBruteForce()
        self.browser = BrowserAutomation()

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

        elif intent.action == "full_recon":
            target = intent.target.strip()
            if not target:
                return "Full recon ke liye target do: 'full recon google.com'"
            return self._full_recon(target)

        elif intent.action == "vuln_scan":
            target = intent.target.strip()
            if not target:
                return "Vuln scan ke liye target do: 'exploit http://target.com'"
            return self._vuln_scan(target)

        elif intent.action == "proxy_intercept":
            return self._proxy_intercept(intent.target)

        elif intent.action == "proxy_replay":
            return self._proxy_replay(intent.target)

        elif intent.action == "proxy_stats":
            return self._proxy_stats()

        elif intent.action == "osint":
            target = intent.target.strip()
            if not target:
                return "OSINT ke liye target do: 'osint username123' ya 'osint google.com'"
            return self._run_osint(target)

        elif intent.action == "osint_help":
            return "OSINT usage: 'osint username123' (username search) ya 'osint google.com' (domain recon)"

        elif intent.action == "brute_force":
            target = intent.target.strip()
            if not target:
                return "Brute force ke liye target do: 'brute http://target.com login'"
            return self._run_brute(target)

        elif intent.action == "brute_help":
            return "Brute force usage: 'brute http://target.com login' (URL + optional username)"

        elif intent.action == "browse":
            return self._browse(intent.target)

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

    def _full_recon(self, target: str) -> str:
        """Full recon: OSINT + vuln scan + report."""
        safety.warn_only("network_scan", target)
        safety.warn_only("vuln_scan", target)

        console.print(f"[yellow]Full recon on {target}...[/yellow]")
        try:
            # OSINT
            info = self.osint.gather_target_info(target)

            # Vuln scan
            url = f"https://{target}"
            findings = self.web_scanner.scan_full(url)

            report = {
                "target": target,
                "osint": {
                    "subdomains": info.get("subdomains", []),
                    "emails": info.get("emails", []),
                    "tech_stack": info.get("tech_stack", []),
                },
                "vulns": {
                    "total": len(findings),
                    "critical": len([f for f in findings if f.severity == "CRITICAL"]),
                    "high": len([f for f in findings if f.severity == "HIGH"]),
                }
            }

            lines = [f"Full Recon Report: {target}", ""]
            lines.append(f"Subdomains: {len(info.get('subdomains', []))}")
            lines.append(f"Emails: {len(info.get('emails', []))}")
            lines.append(f"Tech: {', '.join(info.get('tech_stack', [])[:3])}")
            lines.append(f"Vulns: {report['vulns']['total']} ({report['vulns']['critical']} critical, {report['vulns']['high']} high)")

            if findings:
                lines.append("")
                lines.append("Top findings:")
                for f in findings[:5]:
                    lines.append(f"  [{f.severity}] {f.vuln_type}: {f.url}")

            return "\n".join(lines)
        except Exception as e:
            return f"Full recon error: {str(e)}"

    def _vuln_scan(self, target: str) -> str:
        """Automated SQLi/XSS/SSRF scan."""
        safety.warn_only("vuln_scan", target)

        if not target.startswith("http"):
            target = f"https://{target}"

        console.print(f"[yellow]Vuln scan on {target}...[/yellow]")
        try:
            findings = self.web_scanner.scan_full(target)

            if not findings:
                return f"No vulnerabilities found on {target}. Clean hai!"

            lines = [f"Vuln Scan Results: {target}", ""]
            for f in findings:
                lines.append(f"[{f.severity}] {f.vuln_type}")
                lines.append(f"  URL: {f.url}")
                lines.append(f"  Payload: {f.payload[:80]}")
                lines.append(f"  Fix: {f.remediation}")
                lines.append("")

            return "\n".join(lines)
        except Exception as e:
            return f"Vuln scan error: {str(e)}"

    def _proxy_intercept(self, target: str) -> str:
        """Intercept an HTTP request."""
        parts = target.split(maxsplit=1)
        if len(parts) < 2:
            return "Usage: 'intercept GET http://target.com' ya 'intercept POST http://target.com'"

        method = parts[0].upper()
        url = parts[1]

        console.print(f"[yellow]Intercepting {method} {url}...[/yellow]")
        try:
            req = self.proxy.intercept(method, url, notes=f"Manual intercept")
            sent = self.proxy.send(req.id)

            lines = [
                f"Request #{req.id}: {method} {url}",
                f"Status: {sent.response_status}",
                f"Time: {sent.response_time_ms:.0f}ms",
                f"Response size: {len(sent.response_body)} bytes",
                "",
                "Response preview:",
                sent.response_body[:500],
            ]
            return "\n".join(lines)
        except Exception as e:
            return f"Proxy error: {str(e)}"

    def _proxy_replay(self, request_id_str: str) -> str:
        """Replay a request."""
        try:
            request_id = int(request_id_str)
        except ValueError:
            return "Usage: 'replay 1' (request ID number)"

        console.print(f"[yellow]Replaying request #{request_id}...[/yellow]")
        try:
            result = self.proxy.replay(request_id)
            return f"Replay #{request_id}: Status {result.response_status}, Time: {result.response_time_ms:.0f}ms\n{result.response_body[:500]}"
        except ValueError:
            return f"Request #{request_id} nahi mila."
        except Exception as e:
            return f"Replay error: {str(e)}"

    def _proxy_stats(self) -> str:
        """Show proxy stats."""
        stats = self.proxy.get_stats()
        return f"""Proxy Stats:
  Intercepted: {stats['total_intercepted']}
  Modified: {stats['modified']}
  Rules: {stats['rules']}
  Avg response: {stats['avg_response_ms']:.0f}ms"""

    def _run_osint(self, target: str) -> str:
        """Run OSINT on target."""
        console.print(f"[yellow]OSINT on {target}...[/yellow]")
        try:
            # Check if it looks like a domain
            if "." in target and " " not in target:
                info = self.osint.gather_target_info(target)
                lines = [f"OSINT Report: {target}", ""]
                lines.append(f"Subdomains ({len(info.get('subdomains', []))}):")
                for sub in info.get("subdomains", [])[:10]:
                    lines.append(f"  - {sub}")
                lines.append(f"\nEmails ({len(info.get('emails', []))}):")
                for email in info.get("emails", [])[:10]:
                    lines.append(f"  - {email}")
                if info.get("tech_stack"):
                    lines.append(f"\nTech: {', '.join(info['tech_stack'])}")
                return "\n".join(lines)
            else:
                # Username search
                profiles = self.osint.find_username(target)
                found = [p for p in profiles if p.exists]
                lines = [f"Username OSINT: {target}", f"Found on {len(found)}/{len(profiles)} platforms:", ""]
                for p in found:
                    lines.append(f"  [+] {p.platform}: {p.url}")
                not_found = [p for p in profiles if not p.exists]
                if not_found:
                    lines.append(f"\nNot found on: {', '.join(p.platform for p in not_found[:5])}")
                return "\n".join(lines)
        except Exception as e:
            return f"OSINT error: {str(e)}"

    def _run_brute(self, target: str) -> str:
        """Run OSINT-powered brute force."""
        parts = target.split()
        url = parts[0] if parts else ""
        username = parts[1] if len(parts) > 1 else "admin"

        if not url:
            return "Usage: 'brute http://target.com login'"

        if not url.startswith("http"):
            url = f"http://{url}"

        safety.warn_only("brute_force", url)

        console.print(f"[yellow]Smart brute force on {url} (user: {username})...[/yellow]")
        try:
            # First do OSINT
            from urllib.parse import urlparse
            parsed = urlparse(url)
            domain = parsed.hostname or url
            info = self.osint.gather_target_info(domain)

            # Generate smart passwords
            passwords = self.brute.generate_passwords(info)
            console.print(f"Generated {len(passwords)} passwords from OSINT")

            # Try login
            results = self.brute.smart_brute(url, [username], info, max_attempts=50)

            if results:
                lines = ["CRACKED!", ""]
                for r in results:
                    lines.append(f"  Username: {r.username}")
                    lines.append(f"  Password: {r.password}")
                    lines.append(f"  Status: {r.status_code}")
                return "\n".join(lines)
            else:
                return f"Brute force complete. {self.brute.get_stats()['total_attempts']} attempts, no credentials found."
        except Exception as e:
            return f"Brute force error: {str(e)}"

    def _browse(self, url: str) -> str:
        """Browse a URL with Cloudflare bypass."""
        if not url.startswith("http"):
            url = f"https://{url}"

        console.print(f"[yellow]Browsing {url} (Cloudflare bypass)...[/yellow]")
        try:
            import asyncio
            result = asyncio.run(self._async_browse(url))
            return result
        except Exception as e:
            return f"Browser error: {str(e)}"

    async def _async_browse(self, url: str) -> str:
        """Async browser navigation."""
        started = await self.browser.start(headless=True)
        if not started:
            return "Playwright install nahi hai. 'pip install playwright && playwright install' chalao."

        try:
            result = await self.browser.navigate(url)
            if result.get("status") == "ok":
                return f"Page: {result.get('title', 'N/A')}\nURL: {result.get('url', url)}\n\nContent preview:\n{result.get('content', '')[:1000]}"
            else:
                return f"Browser failed: {result.get('error', 'unknown')}"
        finally:
            await self.browser.close()

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
    console.print("[green]'hacker' - all hacker tools database[/green]")
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

            if user_input.lower() == "hacker":
                from src.bugbounty.hacker_tools import HackerTools
                ht = HackerTools()
                ht.print_status()
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
