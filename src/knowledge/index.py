"""Knowledge Index — graph-based search and retrieval from the knowledge base.

Uses a NetworkX directed graph to model semantic relationships between
vulnerability types, attack techniques, frameworks, and payloads.

Graph structure:
  - Node types: vuln_type, technique, framework, payload, dbms, severity
  - Edge types: has_technique, targets_framework, uses_payload, has_dbms, has_severity
  - Edges carry weight for ranking (higher = more relevant)

Backward compatible with the original search() and get_playbook() API.
"""

import json
import re
from pathlib import Path
from typing import List, Dict, Any, Optional, Set, Tuple
from dataclasses import dataclass, field

import networkx as nx

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
    """Graph-based knowledge index for attack intelligence.

    Builds a NetworkX directed graph where nodes represent security concepts
    and edges represent semantic relationships. Supports semantic search,
    attack suggestion from tech stacks, and attack chain traversal.
    """

    def __init__(self, kb_dir: Optional[Path] = None):
        self.kb_dir = kb_dir or config.knowledge_base_dir
        self.entries: List[KnowledgeEntry] = []
        self._loaded = False

        # The knowledge graph
        self.graph = nx.DiGraph()

        # Index maps for fast lookup
        self._vuln_type_nodes: Dict[str, str] = {}   # normalized -> node_id
        self._framework_nodes: Dict[str, str] = {}
        self._technique_nodes: Dict[str, str] = {}
        self._payload_nodes: Dict[str, str] = {}
        self._dbms_nodes: Dict[str, str] = {}
        self._tag_nodes: Dict[str, str] = {}

        # Payload database (loaded from patterns)
        self._payload_db: Dict[str, Any] = {}

        # Playbook data
        self._playbooks: Dict[str, Any] = {}

        # Tech stack patterns
        self._tech_patterns: Dict[str, Any] = {}

    # ------------------------------------------------------------------
    # Loading
    # ------------------------------------------------------------------

    def load(self) -> int:
        """Load knowledge base entries from disk and build the graph."""
        if self._loaded:
            return len(self.entries)

        # Load from JSON knowledge base
        self._load_knowledge_base()
        # Load from patterns directory
        self._load_patterns()

        # Build the graph from loaded data
        self._build_graph()

        self._loaded = True
        logger.info(
            f"Knowledge base loaded: {len(self.entries)} entries, "
            f"{self.graph.number_of_nodes()} nodes, "
            f"{self.graph.number_of_edges()} edges"
        )
        return len(self.entries)

    def _load_knowledge_base(self):
        """Load entries from knowledge_base.json."""
        kb_json = self.kb_dir / "knowledge_base.json"
        if not kb_json.exists():
            return
        try:
            with open(kb_json) as f:
                data = json.load(f)
            for item in data:
                self.entries.append(KnowledgeEntry(
                    id=str(item.get("id", "")),
                    title=item.get("title", ""),
                    vuln_type=item.get("vulnerability_type", item.get("vuln_type", item.get("type", ""))),
                    severity=item.get("severity", "MEDIUM"),
                    description=item.get("description", ""),
                    attack_vector=item.get("discovery_technique", item.get("attack_vector", item.get("attack", ""))),
                    remediation=(
                        "; ".join(item.get("remediation_advice", []))
                        if isinstance(item.get("remediation_advice"), list)
                        else item.get("remediation", "")
                    ),
                    tags=item.get("tags", []),
                    source="knowledge_base.json",
                ))
        except (json.JSONDecodeError, KeyError) as e:
            logger.warning(f"Failed to load knowledge base: {e}")

    def _load_patterns(self):
        """Load pattern files from the patterns directory."""
        patterns_dir = self.kb_dir / "patterns"
        if not patterns_dir.exists():
            return

        for f in patterns_dir.glob("*.md"):
            self._load_pattern_file(f)
        for f in patterns_dir.glob("*.json"):
            self._load_pattern_json(f)

    def _load_pattern_file(self, path: Path):
        """Load a markdown pattern file."""
        try:
            content = path.read_text()
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
        """Load a JSON pattern file and store structured data."""
        try:
            with open(path) as f:
                content = f.read()
            # Try strict JSON first, fall back to lenient parsing
            try:
                data = json.loads(content)
            except json.JSONDecodeError:
                # Attempt to fix common JSON issues (unescaped quotes in strings)
                data = self._lenient_json_parse(content, path)
                if data is None:
                    return

            # Store structured data for graph building
            source_str = str(path)
            if path.name == "payload_database.json":
                self._payload_db = data.get("payloads", data)
                # Add a summary entry so pattern sources are tracked
                self.entries.append(KnowledgeEntry(
                    id=f"pattern_{path.stem}",
                    title="Payload Database",
                    vuln_type="Payloads",
                    severity="INFO",
                    description=f"Payload database with {len(self._payload_db)} categories",
                    attack_vector="",
                    remediation="",
                    tags=["payloads", "patterns"],
                    source=source_str,
                ))
            elif path.name == "attack_playbooks.json":
                self._playbooks = data.get("playbooks", data)
                self.entries.append(KnowledgeEntry(
                    id=f"pattern_{path.stem}",
                    title="Attack Playbooks",
                    vuln_type="Playbooks",
                    severity="INFO",
                    description=f"Attack playbooks with {len(self._playbooks)} entries",
                    attack_vector="",
                    remediation="",
                    tags=["playbooks", "patterns"],
                    source=source_str,
                ))
            elif path.name == "tech_stack_patterns.json":
                self._tech_patterns = data.get("technology_stacks", data)
                self.entries.append(KnowledgeEntry(
                    id=f"pattern_{path.stem}",
                    title="Tech Stack Patterns",
                    vuln_type="Tech Patterns",
                    severity="INFO",
                    description=f"Technology stack patterns for {len(self._tech_patterns)} stacks",
                    attack_vector="",
                    remediation="",
                    tags=["tech", "patterns"],
                    source=source_str,
                ))
            elif path.name == "vuln_cheatsheet.json":
                # Also extract vuln types for graph nodes
                vuln_types = data.get("vulnerability_types", {})
                for vtype, info in vuln_types.items():
                    self._add_vuln_type_entry(vtype, info, source=source_str)

            # Convert pattern data into entries
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
            elif isinstance(data, dict) and not any(
                path.name == n for n in (
                    "payload_database.json", "attack_playbooks.json",
                    "tech_stack_patterns.json", "vuln_cheatsheet.json",
                )
            ):
                # Generic dict pattern file — add a summary entry
                self.entries.append(KnowledgeEntry(
                    id=f"pattern_{path.stem}",
                    title=path.stem.replace("_", " ").replace("-", " ").title(),
                    vuln_type=path.stem.replace("_", " ").title(),
                    severity="INFO",
                    description=f"Pattern data from {path.name}",
                    attack_vector="",
                    remediation="",
                    tags=[path.stem, "patterns"],
                    source=str(path),
                ))
        except Exception as e:
            logger.debug(f"Failed to load pattern JSON {path}: {e}")

    def _add_vuln_type_entry(self, vtype: str, info: dict, source: str = "vuln_cheatsheet.json"):
        """Add a vulnerability type entry from the cheatsheet."""
        self.entries.append(KnowledgeEntry(
            id=f"cheatsheet_{vtype.lower().replace(' ', '_')}",
            title=vtype,
            vuln_type=vtype,
            severity=info.get("severity_range", ["MEDIUM"])[0] if isinstance(info.get("severity_range"), list) else "MEDIUM",
            description=info.get("description", ""),
            attack_vector=info.get("testing_approach", ""),
            remediation="",
            tags=[vtype.lower().replace(" ", "_")],
            source=source,
        ))

    # ------------------------------------------------------------------
    # Graph Construction
    # ------------------------------------------------------------------

    def _build_graph(self):
        """Build the NetworkX knowledge graph from loaded data."""
        # 1. Add vulnerability type nodes from entries
        for entry in self.entries:
            vt = entry.vuln_type
            if not vt:
                continue
            vt_norm = self._normalize(vt)
            if vt_norm not in self._vuln_type_nodes:
                node_id = f"vuln:{vt_norm}"
                self.graph.add_node(node_id, node_type="vuln_type", label=vt, data=entry.to_dict())
                self._vuln_type_nodes[vt_norm] = node_id

            # Add severity edge
            sev = entry.severity.upper()
            sev_norm = self._normalize(sev)
            if sev_norm not in self._dbms_nodes:
                sev_node = f"severity:{sev_norm}"
                self.graph.add_node(sev_node, node_type="severity", label=sev)
            sev_node = f"severity:{sev_norm}"
            self.graph.add_edge(self._vuln_type_nodes[vt_norm], sev_node, relation="has_severity", weight=1.0)

            # Add tag nodes and edges
            for tag in entry.tags:
                tag_norm = self._normalize(tag)
                if tag_norm not in self._tag_nodes:
                    tag_node = f"tag:{tag_norm}"
                    self.graph.add_node(tag_node, node_type="tag", label=tag)
                    self._tag_nodes[tag_norm] = tag_node
                self.graph.add_edge(self._vuln_type_nodes[vt_norm], self._tag_nodes[tag_norm], relation="has_tag", weight=0.5)

        # 2. Build relationships from tech_stack_patterns.json
        self._build_tech_graph()

        # 3. Build relationships from payload_database.json
        self._build_payload_graph()

        # 4. Build relationships from attack_playbooks.json
        self._build_playbook_graph()

    def _build_tech_graph(self):
        """Add framework and technique nodes from tech stack patterns."""
        if not self._tech_patterns:
            return

        for tech_key, tech_info in self._tech_patterns.items():
            # Framework node
            fw_norm = self._normalize(tech_key)
            if fw_norm not in self._framework_nodes:
                fw_node = f"framework:{fw_norm}"
                lang = tech_info.get("language", tech_key)
                self.graph.add_node(fw_node, node_type="framework", label=lang, language=tech_key)
                self._framework_nodes[fw_norm] = fw_node

            # Link framework to vulnerability patterns
            vuln_patterns = tech_info.get("vulnerability_patterns", {})
            for vtype_name, vtype_info in vuln_patterns.items():
                vt_norm = self._normalize(vtype_name)
                if vt_norm not in self._vuln_type_nodes:
                    vt_node = f"vuln:{vt_norm}"
                    self.graph.add_node(vt_node, node_type="vuln_type", label=vtype_name)
                    self._vuln_type_nodes[vt_norm] = vt_node

                # Edge: vuln_type -> framework (targets)
                self.graph.add_edge(
                    self._vuln_type_nodes[vt_norm],
                    self._framework_nodes[fw_norm],
                    relation="targets_framework",
                    weight=2.0,
                    details=vtype_info,
                )

            # Link common_vulns
            for cv in tech_info.get("common_vulns", []):
                cv_norm = self._normalize(cv)
                if cv_norm not in self._vuln_type_nodes:
                    cv_node = f"vuln:{cv_norm}"
                    self.graph.add_node(cv_node, node_type="vuln_type", label=cv)
                    self._vuln_type_nodes[cv_norm] = cv_node
                self.graph.add_edge(
                    self._framework_nodes[fw_norm],
                    self._vuln_type_nodes[cv_norm],
                    relation="common_vuln",
                    weight=1.5,
                )

    def _build_payload_graph(self):
        """Add payload nodes from the payload database."""
        if not self._payload_db:
            return

        for vuln_category, techniques in self._payload_db.items():
            vc_norm = self._normalize(vuln_category)
            if vc_norm not in self._vuln_type_nodes:
                vc_node = f"vuln:{vc_norm}"
                self.graph.add_node(vc_node, node_type="vuln_type", label=vuln_category)
                self._vuln_type_nodes[vc_norm] = vc_node

            if isinstance(techniques, dict):
                for technique_name, payloads in techniques.items():
                    # Technique node
                    tech_norm = self._normalize(technique_name)
                    if tech_norm not in self._technique_nodes:
                        tech_node = f"technique:{tech_norm}"
                        self.graph.add_node(tech_node, node_type="technique", label=technique_name)
                        self._technique_nodes[tech_norm] = tech_node

                    # Edge: vuln_type -> technique
                    self.graph.add_edge(
                        self._vuln_type_nodes[vc_norm],
                        self._technique_nodes[tech_norm],
                        relation="has_technique",
                        weight=2.0,
                    )

                    # Payload nodes
                    if isinstance(payloads, list):
                        for i, payload in enumerate(payloads[:20]):  # cap per technique
                            pl_id = f"payload:{vc_norm}:{tech_norm}:{i}"
                            self.graph.add_node(
                                pl_id,
                                node_type="payload",
                                label=payload[:60],
                                payload=payload,
                                category=vuln_category,
                                technique=technique_name,
                            )
                            self.graph.add_edge(
                                self._technique_nodes[tech_norm],
                                pl_id,
                                relation="uses_payload",
                                weight=1.0,
                            )
                            # Also connect payload back to vuln_type for easy lookup
                            self.graph.add_edge(
                                pl_id,
                                self._vuln_type_nodes[vc_norm],
                                relation="belongs_to",
                                weight=0.5,
                            )

    def _build_playbook_graph(self):
        """Add edges from attack playbooks."""
        if not self._playbooks:
            return

        for playbook_key, playbook_data in self._playbooks.items():
            pb_norm = self._normalize(playbook_key)
            # Map playbook to vuln type
            vuln_name = playbook_data.get("name", playbook_key).replace(" Attack Playbook", "").replace(" Playbook", "")
            vt_norm = self._normalize(vuln_name)

            if vt_norm not in self._vuln_type_nodes:
                vt_node = f"vuln:{vt_norm}"
                self.graph.add_node(vt_node, node_type="vuln_type", label=vuln_name)
                self._vuln_type_nodes[vt_norm] = vt_node

            # Link phases as techniques
            phases = playbook_data.get("phases", {})
            for phase_name, phase_data in phases.items():
                phase_norm = self._normalize(phase_name)
                if phase_norm not in self._technique_nodes:
                    phase_node = f"technique:{phase_norm}"
                    self.graph.add_node(phase_node, node_type="technique", label=phase_name, phase_data=phase_data)
                    self._technique_nodes[phase_norm] = phase_node

                self.graph.add_edge(
                    self._vuln_type_nodes[vt_norm],
                    self._technique_nodes[phase_norm],
                    relation="has_phase",
                    weight=2.5,
                )

                # Add payloads from playbook phases
                phase_payloads = phase_data.get("payloads", {})
                if isinstance(phase_payloads, dict):
                    for payload_group, payload_list in phase_payloads.items():
                        if isinstance(payload_list, list):
                            for i, payload in enumerate(payload_list[:10]):
                                pl_id = f"payload:playbook:{pb_norm}:{phase_norm}:{payload_group}:{i}"
                                self.graph.add_node(
                                    pl_id,
                                    node_type="payload",
                                    label=payload[:60],
                                    payload=payload,
                                    category=vuln_name,
                                    technique=phase_name,
                                )
                                self.graph.add_edge(
                                    self._technique_nodes[phase_norm],
                                    pl_id,
                                    relation="uses_payload",
                                    weight=1.0,
                                )

    # ------------------------------------------------------------------
    # Search (backward compatible)
    # ------------------------------------------------------------------

    def search(self, query: str, limit: int = 10) -> List[KnowledgeEntry]:
        """Search knowledge base by keyword relevance.

        Uses graph connectivity + text matching for ranking.
        """
        if not self._loaded:
            self.load()

        query_lower = query.lower()
        query_words = set(query_lower.split())

        # Find matching nodes in graph
        matching_nodes: Set[str] = set()
        for node_id, attrs in self.graph.nodes(data=True):
            label = attrs.get("label", "").lower()
            if query_lower in label or label in query_lower:
                matching_nodes.add(node_id)
            # Also check word overlap
            node_words = set(label.split())
            if query_words & node_words:
                matching_nodes.add(node_id)

        # Expand: get neighbors of matching nodes (1 hop)
        expanded_nodes: Set[str] = set(matching_nodes)
        for node_id in matching_nodes:
            for neighbor in self.graph.neighbors(node_id):
                expanded_nodes.add(neighbor)
            for predecessor in self.graph.predecessors(node_id):
                expanded_nodes.add(predecessor)

        # Score entries
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

            # Graph bonus: if entry's vuln_type matches a graph node
            vt_norm = self._normalize(entry.vuln_type)
            if f"vuln:{vt_norm}" in expanded_nodes:
                score += 8
            if f"vuln:{vt_norm}" in matching_nodes:
                score += 5

            # Graph connectivity bonus (more connected = more relevant)
            vuln_node = f"vuln:{vt_norm}"
            if vuln_node in self.graph:
                degree = self.graph.degree(vuln_node)
                score += min(degree, 10)  # cap the bonus

            if score > 0:
                scored.append((score, entry))

        scored.sort(key=lambda x: x[0], reverse=True)
        return [entry for _, entry in scored[:limit]]

    def get_playbook(self, vuln_type: str) -> Dict[str, Any]:
        """Get an attack playbook for a specific vulnerability type."""
        if not self._loaded:
            self.load()

        entries = self.search(vuln_type, limit=5)

        # Also try to find playbook data from graph
        vt_norm = self._normalize(vuln_type)
        playbook_phases = []

        if vt_norm in self._vuln_type_nodes:
            vuln_node = self._vuln_type_nodes[vt_norm]
            for _, target, data in self.graph.out_edges(vuln_node, data=True):
                if data.get("relation") in ("has_phase", "has_technique"):
                    phase_data = self.graph.nodes[target].get("phase_data", {})
                    playbook_phases.append({
                        "phase": self.graph.nodes[target].get("label", ""),
                        "steps": phase_data.get("steps", []),
                        "payloads": phase_data.get("payloads", {}),
                    })

        if not entries and not playbook_phases:
            return {
                "vuln_type": vuln_type,
                "found": False,
                "message": f"No playbook found for {vuln_type}",
            }

        result = {
            "vuln_type": vuln_type,
            "found": True,
            "entries": [e.to_dict() for e in entries],
            "attack_vectors": [e.attack_vector for e in entries if e.attack_vector],
            "remediations": [e.remediation for e in entries if e.remediation],
        }

        if playbook_phases:
            result["playbook_phases"] = playbook_phases

        return result

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
            "graph_nodes": self.graph.number_of_nodes(),
            "graph_edges": self.graph.number_of_edges(),
        }

    # ------------------------------------------------------------------
    # NEW: Graph-based methods
    # ------------------------------------------------------------------

    def suggest_attacks(self, tech_stack: list) -> List[Dict[str, Any]]:
        """Given a target's tech stack, auto-suggest relevant attack patterns.

        Args:
            tech_stack: List of technologies, e.g. ["php", "mysql", "laravel"]

        Returns:
            List of suggested attacks with vulnerability type, techniques,
            payloads, and relevance score.
        """
        if not self._loaded:
            self.load()

        suggestions: Dict[str, Dict[str, Any]] = {}

        for tech in tech_stack:
            tech_norm = self._normalize(tech)
            if tech_norm not in self._framework_nodes:
                # Try partial match
                for fw_norm, fw_node in self._framework_nodes.items():
                    if tech_norm in fw_norm or fw_norm in tech_norm:
                        tech_norm = fw_norm
                        break
                else:
                    continue

            fw_node = self._framework_nodes[tech_norm]

            # Find vuln types connected to this framework
            for predecessor in self.graph.predecessors(fw_node):
                pred_attrs = self.graph.nodes[predecessor]
                edge_data = self.graph.get_edge_data(predecessor, fw_node, default={})

                if pred_attrs.get("node_type") == "vuln_type":
                    vt_label = pred_attrs.get("label", "")
                    vt_norm = self._normalize(vt_label)

                    if vt_norm not in suggestions:
                        suggestions[vt_norm] = {
                            "vuln_type": vt_label,
                            "relevance_score": 0,
                            "matching_tech": [],
                            "techniques": [],
                            "payloads": [],
                            "severity": "MEDIUM",
                        }

                    sugg = suggestions[vt_norm]
                    weight = edge_data.get("weight", 1.0)
                    sugg["relevance_score"] += weight
                    if tech not in sugg["matching_tech"]:
                        sugg["matching_tech"].append(tech)

                    # Get techniques for this vuln type
                    for _, tech_target, tech_data in self.graph.out_edges(predecessor, data=True):
                        if tech_data.get("relation") in ("has_technique", "has_phase"):
                            tech_label = self.graph.nodes[tech_target].get("label", "")
                            if tech_label and tech_label not in sugg["techniques"]:
                                sugg["techniques"].append(tech_label)

                            # Collect payloads
                            for _, pl_target, pl_data in self.graph.out_edges(tech_target, data=True):
                                if pl_data.get("relation") == "uses_payload":
                                    payload = self.graph.nodes[pl_target].get("payload", "")
                                    if payload and payload not in sugg["payloads"]:
                                        sugg["payloads"].append(payload)

            # Also check for vuln types connected via common_vuln edges
            for successor in self.graph.successors(fw_node):
                succ_attrs = self.graph.nodes[successor]
                edge_data = self.graph.get_edge_data(fw_node, successor, default={})

                if succ_attrs.get("node_type") == "vuln_type":
                    vt_label = succ_attrs.get("label", "")
                    vt_norm = self._normalize(vt_label)

                    if vt_norm not in suggestions:
                        suggestions[vt_norm] = {
                            "vuln_type": vt_label,
                            "relevance_score": 0,
                            "matching_tech": [],
                            "techniques": [],
                            "payloads": [],
                            "severity": "MEDIUM",
                        }

                    sugg = suggestions[vt_norm]
                    weight = edge_data.get("weight", 1.0)
                    sugg["relevance_score"] += weight
                    if tech not in sugg["matching_tech"]:
                        sugg["matching_tech"].append(tech)

        # Sort by relevance
        result = sorted(suggestions.values(), key=lambda x: x["relevance_score"], reverse=True)
        return result

    def get_attack_chain(self, vuln_type: str) -> List[Dict[str, Any]]:
        """Get the attack chain (phases/steps) for a vulnerability type.

        Traverses the graph from the vuln_type node through technique/phase
        nodes to build an ordered attack chain.

        Args:
            vuln_type: e.g. "SQL Injection", "XSS", "SSRF"

        Returns:
            Ordered list of attack phases with steps and payloads.
        """
        if not self._loaded:
            self.load()

        vt_norm = self._normalize(vuln_type)
        chain = []

        # Find the vuln node (try exact then partial)
        vuln_node = None
        if vt_norm in self._vuln_type_nodes:
            vuln_node = self._vuln_type_nodes[vt_norm]
        else:
            # Partial match
            for norm, node_id in self._vuln_type_nodes.items():
                if vt_norm in norm or norm in vt_norm:
                    vuln_node = node_id
                    break

        if not vuln_node:
            return chain

        # BFS through technique/phase nodes
        visited: Set[str] = set()
        queue = [vuln_node]

        while queue:
            current = queue.pop(0)
            if current in visited:
                continue
            visited.add(current)

            attrs = self.graph.nodes[current]
            node_type = attrs.get("node_type", "")

            if node_type in ("technique",):
                phase_info = {
                    "phase": attrs.get("label", ""),
                    "node_id": current,
                    "steps": [],
                    "payloads": [],
                }

                # Get phase_data if available (from playbooks)
                phase_data = attrs.get("phase_data", {})
                if phase_data:
                    phase_info["steps"] = phase_data.get("steps", [])

                # Get payloads
                for _, target, data in self.graph.out_edges(current, data=True):
                    if data.get("relation") == "uses_payload":
                        payload = self.graph.nodes[target].get("payload", "")
                        if payload:
                            phase_info["payloads"].append(payload)

                chain.append(phase_info)

            # Continue traversal
            for _, target, data in self.graph.out_edges(current, data=True):
                rel = data.get("relation", "")
                if rel in ("has_technique", "has_phase"):
                    queue.append(target)

        return chain

    def get_payloads(self, vuln_type: str, dbms: str = "") -> List[str]:
        """Get payloads for a vulnerability type, optionally filtered by DBMS.

        Args:
            vuln_type: e.g. "SQL Injection", "XSS"
            dbms: Optional DBMS filter, e.g. "MySQL", "PostgreSQL", "MSSQL"

        Returns:
            List of payload strings.
        """
        if not self._loaded:
            self.load()

        vt_norm = self._normalize(vuln_type)
        payloads: List[str] = []
        seen: Set[str] = set()

        # Find matching vuln node
        vuln_node = None
        if vt_norm in self._vuln_type_nodes:
            vuln_node = self._vuln_type_nodes[vt_norm]
        else:
            for norm, node_id in self._vuln_type_nodes.items():
                if vt_norm in norm or norm in vt_norm:
                    vuln_node = node_id
                    break

        if not vuln_node:
            return payloads

        # BFS to find payload nodes
        visited: Set[str] = set()
        queue = [vuln_node]
        dbms_lower = dbms.lower() if dbms else ""

        while queue:
            current = queue.pop(0)
            if current in visited:
                continue
            visited.add(current)

            attrs = self.graph.nodes[current]
            if attrs.get("node_type") == "payload":
                payload = attrs.get("payload", "")
                technique = attrs.get("technique", "").lower()

                # Filter by DBMS if specified
                if dbms_lower:
                    if dbms_lower in technique or dbms_lower in payload.lower():
                        if payload not in seen:
                            payloads.append(payload)
                            seen.add(payload)
                else:
                    if payload not in seen:
                        payloads.append(payload)
                        seen.add(payload)

            # Continue traversal
            for _, target, data in self.graph.out_edges(current, data=True):
                rel = data.get("relation", "")
                if rel in ("has_technique", "has_phase", "uses_payload"):
                    queue.append(target)

            # Also traverse backwards (payload -> vuln)
            for predecessor in self.graph.predecessors(current):
                pred_data = self.graph.get_edge_data(predecessor, current, default={})
                if pred_data.get("relation") == "belongs_to":
                    # This is a payload belonging to our vuln type
                    pred_attrs = self.graph.nodes[predecessor]
                    if pred_attrs.get("node_type") == "payload":
                        payload = pred_attrs.get("payload", "")
                        if payload and payload not in seen:
                            if dbms_lower:
                                if dbms_lower in payload.lower():
                                    payloads.append(payload)
                                    seen.add(payload)
                            else:
                                payloads.append(payload)
                                seen.add(payload)

        return payloads

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _lenient_json_parse(self, content: str, path: Path) -> Optional[dict]:
        """Attempt to parse JSON with common issues (unescaped quotes, trailing commas)."""
        import re as _re
        try:
            # Try removing trailing commas before } or ]
            fixed = _re.sub(r',\s*([}\]])', r'\1', content)
            return json.loads(fixed)
        except json.JSONDecodeError:
            pass

        # Try a more aggressive approach: extract top-level structure
        # This handles files where individual string values have unescaped quotes
        try:
            # For large JSON objects, try line-by-line fixing
            lines = content.split('\n')
            fixed_lines = []
            for line in lines:
                stripped = line.strip()
                # Fix lines that have unescaped quotes inside string values
                # Pattern: "key": "value with "quotes" inside"
                if stripped.startswith('"') and stripped.endswith('",'):
                    # Count quotes - if more than 4, there are embedded quotes
                    quote_count = stripped.count('"')
                    if quote_count > 4:
                        # Escape inner quotes
                        parts = stripped[1:-2].split('": ', 1)
                        if len(parts) == 2:
                            key = parts[0]
                            val = parts[1]
                            if val.startswith('"') and val.endswith('"'):
                                inner = val[1:-1]
                                inner = inner.replace('"', '\\"')
                                stripped = f'"{key}": "{inner}",'
                fixed_lines.append(stripped)
            fixed = '\n'.join(fixed_lines)
            return json.loads(fixed)
        except (json.JSONDecodeError, Exception):
            logger.debug(f"Could not leniently parse {path.name}")
            return None

    @staticmethod
    def _normalize(text: str) -> str:
        """Normalize text for graph node matching."""
        return re.sub(r'[^a-z0-9]', '', text.lower().strip())


# Singleton
knowledge = KnowledgeIndex()
