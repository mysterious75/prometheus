"""Skill Loader — discovers and loads security testing skills on demand.

Skills are YAML files containing structured methodology, payloads,
detection patterns, and remediation for vulnerability classes.
"""

import logging
from dataclasses import dataclass, field
from typing import List, Dict, Optional
from pathlib import Path

from src.core.logger import logger

try:
    import yaml
    HAS_YAML = True
except ImportError:
    HAS_YAML = False


@dataclass
class Skill:
    """A structured security testing skill."""
    name: str
    category: str  # web, api, cloud, mobile, network
    description: str
    severity_range: List[str] = field(default_factory=lambda: ["LOW", "MEDIUM", "HIGH", "CRITICAL"])
    tools: List[str] = field(default_factory=list)
    methodology: List[str] = field(default_factory=list)
    payloads: List[str] = field(default_factory=list)
    detection_patterns: List[str] = field(default_factory=list)
    remediation: str = ""
    references: List[str] = field(default_factory=list)
    triggers: List[str] = field(default_factory=list)
    _raw: Dict = field(default_factory=dict, repr=False)

    def to_dict(self) -> Dict:
        return {
            "name": self.name,
            "category": self.category,
            "description": self.description,
            "severity_range": self.severity_range,
            "tools": self.tools,
            "methodology": self.methodology,
            "payloads": self.payloads,
            "detection_patterns": self.detection_patterns,
            "remediation": self.remediation,
            "references": self.references,
            "triggers": self.triggers,
        }


class SkillLoader:
    """Loads and manages security testing skills on demand.

    Skills are YAML files in the skills directory. They are discovered
    lazily and loaded on first request.
    """

    def __init__(self, skills_dir: str = None):
        self.skills_dir = Path(skills_dir) if skills_dir else Path(__file__).parent
        self.loaded_skills: Dict[str, Skill] = {}
        self.available_skills: List[str] = []
        self._discovered = False

    # ------------------------------------------------------------------
    # Discovery
    # ------------------------------------------------------------------

    def discover(self) -> List[str]:
        """Discover all available skill files (YAML) in the skills directory.

        Returns list of skill names (filenames without extension).
        """
        if not HAS_YAML:
            logger.warning("PyYAML not installed — skill loading unavailable")
            return []

        self.available_skills = []
        for f in sorted(self.skills_dir.iterdir()):
            if f.suffix in (".yml", ".yaml") and f.is_file():
                self.available_skills.append(f.stem)

        self._discovered = True
        logger.info(f"Discovered {len(self.available_skills)} skills: {self.available_skills}")
        return self.available_skills

    # ------------------------------------------------------------------
    # Loading
    # ------------------------------------------------------------------

    def load(self, skill_name: str) -> Optional[Skill]:
        """Load a specific skill by name.

        Returns the Skill object, or None if not found / load error.
        """
        if not HAS_YAML:
            logger.error("PyYAML not installed — cannot load skills")
            return None

        # Return cached
        if skill_name in self.loaded_skills:
            return self.loaded_skills[skill_name]

        # Find the file
        for ext in (".yml", ".yaml"):
            path = self.skills_dir / f"{skill_name}{ext}"
            if path.exists():
                return self._load_file(path)

        logger.warning(f"Skill not found: {skill_name}")
        return None

    def load_for_target(self, target_info: Dict) -> List[Skill]:
        """Auto-load relevant skills based on target information.

        Args:
            target_info: Dict with keys like 'tech_stack', 'headers',
                        'url', 'ports', 'services', etc.

        Returns list of loaded Skill objects.
        """
        if not self._discovered:
            self.discover()

        relevant = []
        target_str = " ".join(str(v) for v in target_info.values()).lower()

        for name in self.available_skills:
            skill = self.load(name)
            if not skill:
                continue

            # Check triggers
            for trigger in skill.triggers:
                trigger_lower = trigger.lower()
                if trigger_lower in target_str:
                    relevant.append(skill)
                    break

        logger.info(f"Auto-loaded {len(relevant)} skills for target")
        return relevant

    def get_skill(self, name: str) -> Optional[Skill]:
        """Get a loaded skill by name (no loading, just lookup)."""
        return self.loaded_skills.get(name)

    def get_all_loaded(self) -> List[Skill]:
        """Return all currently loaded skills."""
        return list(self.loaded_skills.values())

    def list_skills(self) -> List[Dict]:
        """List all available skills with metadata."""
        if not self._discovered:
            self.discover()

        result = []
        for name in self.available_skills:
            skill = self.load(name)
            if skill:
                result.append({
                    "name": skill.name,
                    "category": skill.category,
                    "description": skill.description,
                    "triggers": skill.triggers,
                    "loaded": True,
                })
        return result

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _load_file(self, path: Path) -> Optional[Skill]:
        """Load and parse a single skill YAML file."""
        try:
            raw = yaml.safe_load(path.read_text())
            if not isinstance(raw, dict):
                logger.error(f"Skill file {path} is not a valid YAML dict")
                return None

            skill = Skill(
                name=raw.get("name", path.stem),
                category=raw.get("category", "web"),
                description=raw.get("description", ""),
                severity_range=raw.get("severity_range", ["LOW", "MEDIUM", "HIGH", "CRITICAL"]),
                tools=raw.get("tools", []),
                methodology=raw.get("methodology", []),
                payloads=raw.get("payloads", []),
                detection_patterns=raw.get("detection_patterns", []),
                remediation=raw.get("remediation", ""),
                references=raw.get("references", []),
                triggers=raw.get("triggers", []),
                _raw=raw,
            )

            self.loaded_skills[skill.name] = skill
            logger.debug(f"Loaded skill: {skill.name} ({skill.category})")
            return skill

        except Exception as e:
            logger.error(f"Failed to load skill {path}: {e}")
            return None

    def __repr__(self) -> str:
        return (
            f"SkillLoader(dir={self.skills_dir}, "
            f"available={len(self.available_skills)}, "
            f"loaded={len(self.loaded_skills)})"
        )
