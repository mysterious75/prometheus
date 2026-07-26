"""Skills — structured security testing knowledge loaded on demand.

Each skill file (YAML) contains methodology, payloads, detection
patterns, and remediation for a specific vulnerability class.
"""

from src.skills.loader import SkillLoader, Skill

__all__ = ["SkillLoader", "Skill"]
