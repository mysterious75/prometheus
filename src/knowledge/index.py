"""Knowledge Index — search and retrieve from the 1242+ reports knowledge base.

Provides RAG-style retrieval: given a target or finding context,
return relevant attack patterns from the knowledge base.
"""

import json
from pathlib import Path
from typing import List, Dict, Any, Optional
from dataclasses import dataclass

from ..core.config import config
from ..core.logger import logger


@dataclass
class KnowledgeEntry:
    """A single entry from the knowledge base."""
    id: str
    title: str
    vuln_type: str
    severity: str
    description: str
    attack_vector: str
    remediation: str
    tags: List[str]
    source: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "title": self.title,
            "vuln_type": self.vuln_type,
            "severity": self.severity,
            "description": self.description,
            "attack_vector": self.attack_vector,
            "remediation": self.remediation,
            "tags": self.tags,
        }


class KnowledgeIndex:
    """Search and retrieve attack intelligence from the knowledge base.

    The knowledge base contains 1242+ bug bounty reports organized by
    vulnerability type, attack technique, and affected technology.
    """

    def __init__(self, kb_dir: Optional[Path] = None):
        self.kb_dir = kb_dir or config.knowledge_base_dir
        self.entries: List[KnowledgeEntry] = []
        self._loaded = False

    def load(self) -> int:
        """Load knowledge base entries from disk."""
        if self._loaded:
            return len(self.entries)

        # Load from JSON knowledge base
        kb_json = self.kb_dir / "knowledge_base.json"
        if kb_json.exists():
            try:
                with open(kb_json) as f:
                    data = json.load(f)
                for item in data:
                    self.entries.append(KnowledgeEntry(
                        id=item.get("id", ""),
                        title=item.get("title", ""),
                        vuln_type=item.get("vuln_type", item.get("type", "")),
                        severity=item.get("severity", "MEDIUM"),
                        description=item.get("description", ""),
                        attack_vector=item.get("attack_vector", item.get("attack", "")),
                        remediation=item.get("remediation", ""),
                        tags=item.get("tags", []),
                        source="knowledge_base.json",
                    ))
            except (json.JSONDecodeError, KeyError) as e:
                logger.warning(f"Failed to load knowledge base: {e}")

        # Load from patterns directory
        patterns_dir = self.kb_dir / "patterns"
        if patterns_dir.exists():
            for f in patterns_dir.glob("*.md"):
                self._load_pattern_file(f)
            for f in patterns_dir.glob("*.json"):
                self._load_pattern_json(f)

        self._loaded = True
        logger.info(f"Knowledge base loaded: {len(self.entries)} entries")
        return len(self.entries)

    def _load_pattern_file(self, path: Path):
        """Load a markdown pattern file."""
        try:
            content = path.read_text()
            # Extract title from first heading
            title = ""
            for line in content.split("\n"):
                if line.startswith("#"):
                    title = line.lstrip("#").strip()
                    break

            self.entries.append(KnowledgeEntry(
                id=path.stem,
                title=title or path.stem,
                vuln_type=path.stem.replace("_", " ").replace("-", " ").title(),
                severity="INFO",
                description=content[:500],
                attack_vector="",
                remediation="",
                tags=[path.stem],
                source=str(path),
            ))
        except Exception as e:
            logger.debug(f"Failed to load pattern {path}: {e}")

    def _load_pattern_json(self, path: Path):
        """Load a JSON pattern file."""
        try:
            with open(path) as f:
                data = json.load(f)
            if isinstance(data, list):
                for item in data:
                    self.entries.append(KnowledgeEntry(
                        id=item.get("id", path.stem),
                        title=item.get("title", ""),
                        vuln_type=item.get("type", ""),
                        severity=item.get("severity", "INFO"),
                        description=item.get("description", ""),
                        attack_vector=item.get("attack", ""),
                        remediation=item.get("fix", ""),
                        tags=item.get("tags", []),
                        source=str(path),
                    ))
        except Exception as e:
            logger.debug(f"Failed to load pattern JSON {path}: {e}")

    def search(self, query: str, limit: int = 10) -> List[KnowledgeEntry]:
        """Search knowledge base by keyword relevance.

        Simple TF-based ranking (no ML dependency).
        """
        if not self._loaded:
            self.load()

        query_lower = query.lower()
        query_words = set(query_lower.split())

        scored = []
        for entry in self.entries:
            score = 0
            searchable = (
                f"{entry.title} {entry.vuln_type} {entry.description} "
                f"{entry.attack_vector} {' '.join(entry.tags)}"
            ).lower()

            # Exact substring match (high weight)
            if query_lower in searchable:
                score += 10

            # Word overlap
            entry_words = set(searchable.split())
            overlap = query_words & entry_words
            score += len(overlap) * 2

            # Tag match (medium weight)
            for tag in entry.tags:
                if tag.lower() in query_lower or query_lower in tag.lower():
                    score += 5

            if score > 0:
                scored.append((score, entry))

        scored.sort(key=lambda x: x[0], reverse=True)
        return [entry for _, entry in scored[:limit]]

    def get_playbook(self, vuln_type: str) -> Dict[str, Any]:
        """Get an attack playbook for a specific vulnerability type."""
        entries = self.search(vuln_type, limit=5)

        if not entries:
            return {
                "vuln_type": vuln_type,
                "found": False,
                "message": f"No playbook found for {vuln_type}",
            }

        return {
            "vuln_type": vuln_type,
            "found": True,
            "entries": [e.to_dict() for e in entries],
            "attack_vectors": [e.attack_vector for e in entries if e.attack_vector],
            "remediations": [e.remediation for e in entries if e.remediation],
        }

    def get_tech_attacks(self, tech: str) -> List[KnowledgeEntry]:
        """Get known attacks for a specific technology."""
        return self.search(tech, limit=10)

    def get_stats(self) -> Dict[str, Any]:
        """Get knowledge base statistics."""
        if not self._loaded:
            self.load()

        vuln_types = {}
        severities = {}
        for entry in self.entries:
            vuln_types[entry.vuln_type] = vuln_types.get(entry.vuln_type, 0) + 1
            severities[entry.severity] = severities.get(entry.severity, 0) + 1

        return {
            "total_entries": len(self.entries),
            "vuln_types": len(vuln_types),
            "top_vuln_types": sorted(
                vuln_types.items(), key=lambda x: x[1], reverse=True
            )[:10],
            "severities": severities,
        }


# Singleton
knowledge = KnowledgeIndex()
