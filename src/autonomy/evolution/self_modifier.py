"""Self-Modifier - Autonomous code improvement system."""

import os
import json
import shutil
from typing import Dict, Any, List, Optional
from datetime import datetime
from pathlib import Path

from ...brain.router import ModelRouter
from ...utils.logger import logger


class SelfModifier:
    """Analyzes and modifies its own source code to improve over time."""

    def __init__(self, router: ModelRouter, project_root: Optional[Path] = None):
        self.router = router
        self.project_root = project_root or Path(__file__).parent.parent.parent.parent
        self.modification_history: List[Dict] = []
        self.pending_improvements: List[Dict] = []

    def analyze_codebase(self) -> Dict[str, Any]:
        """Analyze the entire codebase for improvement opportunities."""
        logger.info("[bold yellow]Analyzing codebase for improvements...[/bold yellow]")

        src_dir = self.project_root / "src"
        if not src_dir.exists():
            return {"error": "src directory not found"}

        # Collect all Python files
        py_files = list(src_dir.rglob("*.py"))
        file_summaries = []

        for f in py_files[:20]:  # Limit to avoid token overflow
            try:
                with open(f, encoding="utf-8") as fh:
                    content = fh.read()
                file_summaries.append({
                    "path": str(f.relative_to(self.project_root)),
                    "lines": len(content.split("\n")),
                    "preview": content[:200]
                })
            except Exception:
                continue

        # Ask LLM for improvement suggestions
        files_text = "\n".join([
            f"  {s['path']} ({s['lines']} lines): {s['preview'][:80]}..."
            for s in file_summaries
        ])

        prompt = f"""
        You are analyzing the Project Prometheus codebase for improvements.

        Files in src/:
        {files_text}

        Suggest 3-5 specific, actionable improvements. For each:
        - FILE: <path to file>
        - IMPROVEMENT: <what to change>
        - PRIORITY: <high/medium/low>
        - REASON: <why this helps>

        Focus on: performance, error handling, new capabilities, code quality.
        """

        try:
            response = self.router.generate(prompt)
            improvements = self._parse_improvements(response)

            result = {
                "timestamp": datetime.now().isoformat(),
                "files_analyzed": len(file_summaries),
                "improvements_suggested": len(improvements),
                "improvements": improvements,
                "raw_analysis": response
            }

            self.pending_improvements = improvements
            logger.info(f"[green]Found {len(improvements)} improvement opportunities[/green]")
            return result

        except Exception as e:
            logger.error(f"Codebase analysis error: {e}")
            return {"error": str(e)}

    def _parse_improvements(self, text: str) -> List[Dict]:
        """Parse improvement suggestions from LLM response."""
        improvements = []
        current = {}

        for line in text.split("\n"):
            line = line.strip()
            if line.startswith("- FILE:") or line.startswith("FILE:"):
                if current:
                    improvements.append(current)
                current = {"file": line.split(":", 1)[1].strip()}
            elif line.startswith("- IMPROVEMENT:") or line.startswith("IMPROVEMENT:"):
                current["improvement"] = line.split(":", 1)[1].strip()
            elif line.startswith("- PRIORITY:") or line.startswith("PRIORITY:"):
                current["priority"] = line.split(":", 1)[1].strip().lower()
            elif line.startswith("- REASON:") or line.startswith("REASON:"):
                current["reason"] = line.split(":", 1)[1].strip()

        if current:
            improvements.append(current)

        return improvements

    def apply_improvement(self, improvement: Dict) -> Dict[str, Any]:
        """Apply a single improvement to the codebase."""
        file_path = improvement.get("file", "")
        description = improvement.get("improvement", "")

        if not file_path or not description:
            return {"error": "Missing file or improvement description"}

        full_path = self.project_root / file_path
        if not full_path.exists():
            return {"error": f"File not found: {file_path}"}

        logger.info(f"[bold blue]Applying improvement to {file_path}[/bold blue]")

        # Create backup
        backup_dir = self.project_root / "backups"
        backup_dir.mkdir(exist_ok=True)
        backup_path = backup_dir / f"{full_path.stem}_{datetime.now().strftime('%Y%m%d_%H%M%S')}{full_path.suffix}"
        shutil.copy2(full_path, backup_path)

        try:
            with open(full_path, encoding="utf-8") as f:
                current_code = f.read()

            prompt = f"""
            Improve this code based on the suggestion:
            
            Suggestion: {description}
            Priority: {improvement.get('priority', 'medium')}
            Reason: {improvement.get('reason', '')}

            Current code:
            ```python
            {current_code}
            ```

            Return the COMPLETE improved file. Keep all existing functionality.
            Only make the specific improvement described. Do not add comments.
            """

            improved_code = self.router.generate(prompt)

            # Clean code blocks if present
            if "```python" in improved_code:
                improved_code = improved_code.split("```python")[1]
                improved_code = improved_code.split("```")[0]

            # Write improved code
            with open(full_path, "w", encoding="utf-8") as f:
                f.write(improved_code.strip())

            result = {
                "file": file_path,
                "improvement": description,
                "backup": str(backup_path),
                "applied_at": datetime.now().isoformat(),
                "status": "applied"
            }
            self.modification_history.append(result)
            logger.info(f"[green]Improvement applied to {file_path}[/green]")
            return result

        except Exception as e:
            # Restore from backup on error
            shutil.copy2(backup_path, full_path)
            logger.error(f"Improvement failed, restored backup: {e}")
            return {"error": str(e), "restored": str(backup_path)}

    def auto_evolve(self, max_improvements: int = 2) -> Dict[str, Any]:
        """Run the full auto-evolution cycle."""
        logger.info("[bold magenta]Starting auto-evolution cycle...[/bold magenta]")

        # Analyze codebase
        analysis = self.analyze_codebase()
        if "error" in analysis:
            return {"error": analysis["error"]}

        # Apply top improvements
        applied = []
        for improvement in self.pending_improvements[:max_improvements]:
            if improvement.get("priority") == "high":
                result = self.apply_improvement(improvement)
                applied.append(result)

        return {
            "timestamp": datetime.now().isoformat(),
            "analysis": analysis.get("improvements_suggested", 0),
            "applied": len(applied),
            "results": applied,
            "status": "evolved" if applied else "no_high_priority_improvements"
        }

    def get_stats(self) -> Dict[str, Any]:
        """Get modification statistics."""
        return {
            "total_modifications": len(self.modification_history),
            "pending_improvements": len(self.pending_improvements),
            "last_modification": (
                self.modification_history[-1] if self.modification_history else None
            )
        }
