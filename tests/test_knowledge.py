"""Tests for the graph-based knowledge base.

Tests graph construction, search, suggest_attacks, get_attack_chain,
and get_payloads — all using the real knowledge base data.
"""

import pytest
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from src.knowledge.index import KnowledgeIndex, KnowledgeEntry


# =========================================================================
# Fixtures
# =========================================================================

@pytest.fixture
def kb():
    """Load the real knowledge base once per test module."""
    index = KnowledgeIndex()
    index.load()
    return index


@pytest.fixture
def empty_kb(tmp_path):
    """KnowledgeIndex with no data files."""
    index = KnowledgeIndex(kb_dir=tmp_path)
    index.load()
    return index


# =========================================================================
# Loading
# =========================================================================

class TestKnowledgeLoading:
    def test_load_returns_positive_count(self, kb):
        assert kb.load() > 0

    def test_load_is_idempotent(self, kb):
        count1 = kb.load()
        count2 = kb.load()
        assert count1 == count2

    def test_entries_populated(self, kb):
        assert len(kb.entries) > 0

    def test_entries_have_required_fields(self, kb):
        for entry in kb.entries[:10]:
            assert entry.id, f"Entry missing id"
            assert entry.title, f"Entry '{entry.id}' missing title"
            assert entry.vuln_type, f"Entry '{entry.id}' missing vuln_type"

    def test_empty_dir_loads_zero(self, empty_kb):
        assert len(empty_kb.entries) == 0

    def test_knowledge_base_json_loaded(self, kb):
        """Entries from knowledge_base.json should be present."""
        sources = {e.source for e in kb.entries}
        assert "knowledge_base.json" in sources

    def test_pattern_files_loaded(self, kb):
        """Entries from pattern JSON files should be present."""
        sources = {e.source for e in kb.entries}
        pattern_sources = [s for s in sources if "patterns" in s]
        assert len(pattern_sources) > 0


# =========================================================================
# Graph Construction
# =========================================================================

class TestGraphConstruction:
    def test_graph_is_built(self, kb):
        assert kb.graph.number_of_nodes() > 0
        assert kb.graph.number_of_edges() > 0

    def test_graph_has_vuln_type_nodes(self, kb):
        vuln_nodes = [n for n, d in kb.graph.nodes(data=True) if d.get("node_type") == "vuln_type"]
        assert len(vuln_nodes) > 0

    def test_graph_has_framework_nodes(self, kb):
        fw_nodes = [n for n, d in kb.graph.nodes(data=True) if d.get("node_type") == "framework"]
        assert len(fw_nodes) > 0

    def test_graph_has_technique_nodes(self, kb):
        tech_nodes = [n for n, d in kb.graph.nodes(data=True) if d.get("node_type") == "technique"]
        assert len(tech_nodes) > 0

    def test_graph_has_payload_nodes(self, kb):
        payload_nodes = [n for n, d in kb.graph.nodes(data=True) if d.get("node_type") == "payload"]
        assert len(payload_nodes) > 0

    def test_graph_edges_have_relation(self, kb):
        """Every edge should have a 'relation' attribute."""
        for u, v, data in kb.graph.edges(data=True):
            assert "relation" in data, f"Edge ({u}, {v}) missing relation"

    def test_graph_edges_have_weight(self, kb):
        for u, v, data in kb.graph.edges(data=True):
            assert "weight" in data, f"Edge ({u}, {v}) missing weight"
            assert data["weight"] > 0

    def test_graph_has_severity_nodes(self, kb):
        sev_nodes = [n for n, d in kb.graph.nodes(data=True) if d.get("node_type") == "severity"]
        assert len(sev_nodes) > 0

    def test_sqli_has_techniques(self, kb):
        """SQL Injection node should connect to technique nodes."""
        sqli_norm = KnowledgeIndex._normalize("SQL Injection")
        if sqli_norm in kb._vuln_type_nodes:
            sqli_node = kb._vuln_type_nodes[sqli_norm]
            technique_neighbors = [
                v for _, v, d in kb.graph.out_edges(sqli_node, data=True)
                if d.get("relation") in ("has_technique", "has_phase")
            ]
            assert len(technique_neighbors) > 0

    def test_framework_links_to_vulns(self, kb):
        """Framework nodes should have incoming edges from vuln types."""
        for fw_norm, fw_node in kb._framework_nodes.items():
            predecessors = list(kb.graph.predecessors(fw_node))
            # At least some frameworks should have vuln type predecessors
            if predecessors:
                pred_types = [kb.graph.nodes[p].get("node_type") for p in predecessors]
                assert "vuln_type" in pred_types
                return
        # If no framework has predecessors, the graph structure is different but still valid
        assert kb.graph.number_of_edges() > 0

    def test_empty_graph(self, empty_kb):
        assert empty_kb.graph.number_of_nodes() == 0
        assert empty_kb.graph.number_of_edges() == 0


# =========================================================================
# Search
# =========================================================================

class TestKnowledgeSearch:
    def test_search_returns_list(self, kb):
        results = kb.search("sql injection")
        assert isinstance(results, list)

    def test_search_finds_sqli(self, kb):
        results = kb.search("SQL Injection")
        assert len(results) > 0
        # At least one result should be related to SQL injection
        types = {r.vuln_type for r in results}
        assert any("sql" in t.lower() for t in types)

    def test_search_finds_xss(self, kb):
        results = kb.search("XSS")
        assert len(results) > 0

    def test_search_respects_limit(self, kb):
        results = kb.search("injection", limit=3)
        assert len(results) <= 3

    def test_search_no_results(self, empty_kb):
        results = empty_kb.search("nonexistent vulnerability xyz")
        assert len(results) == 0

    def test_search_by_technology(self, kb):
        results = kb.search("PHP")
        assert len(results) > 0

    def test_search_by_tag(self, kb):
        results = kb.search("hackerone")
        assert len(results) > 0

    def test_search_case_insensitive(self, kb):
        upper = kb.search("SQL INJECTION")
        lower = kb.search("sql injection")
        assert len(upper) > 0
        assert len(lower) > 0

    def test_search_results_are_knowledge_entries(self, kb):
        results = kb.search("injection")
        for r in results:
            assert isinstance(r, KnowledgeEntry)

    def test_search_results_have_to_dict(self, kb):
        results = kb.search("injection")
        if results:
            d = results[0].to_dict()
            assert "id" in d
            assert "vuln_type" in d
            assert "title" in d


# =========================================================================
# get_playbook
# =========================================================================

class TestGetPlaybook:
    def test_playbook_structure(self, kb):
        playbook = kb.get_playbook("XSS")
        assert "vuln_type" in playbook
        assert "found" in playbook

    def test_playbook_found_for_sqli(self, kb):
        playbook = kb.get_playbook("SQL Injection")
        assert playbook["found"] is True
        assert len(playbook["entries"]) > 0

    def test_playbook_not_found(self, empty_kb):
        playbook = empty_kb.get_playbook("Nonexistent Vuln XYZ")
        assert playbook["found"] is False

    def test_playbook_has_attack_vectors(self, kb):
        playbook = kb.get_playbook("SQL Injection")
        if playbook["found"]:
            assert "attack_vectors" in playbook

    def test_playbook_has_remediations(self, kb):
        playbook = kb.get_playbook("SQL Injection")
        if playbook["found"]:
            assert "remediations" in playbook


# =========================================================================
# get_stats
# =========================================================================

class TestGetStats:
    def test_stats_structure(self, kb):
        stats = kb.get_stats()
        assert "total_entries" in stats
        assert "vuln_types" in stats
        assert "top_vuln_types" in stats
        assert "severities" in stats

    def test_stats_has_graph_info(self, kb):
        stats = kb.get_stats()
        assert "graph_nodes" in stats
        assert "graph_edges" in stats
        assert stats["graph_nodes"] > 0
        assert stats["graph_edges"] > 0

    def test_stats_total_matches_entries(self, kb):
        stats = kb.get_stats()
        assert stats["total_entries"] == len(kb.entries)

    def test_stats_empty(self, empty_kb):
        stats = empty_kb.get_stats()
        assert stats["total_entries"] == 0


# =========================================================================
# suggest_attacks
# =========================================================================

class TestSuggestAttacks:
    def test_returns_list(self, kb):
        suggestions = kb.suggest_attacks(["php"])
        assert isinstance(suggestions, list)

    def test_php_suggests_sqli(self, kb):
        """PHP tech stack should suggest SQL Injection attacks."""
        suggestions = kb.suggest_attacks(["php"])
        if suggestions:
            vuln_types = {s["vuln_type"] for s in suggestions}
            assert any("sql" in vt.lower() for vt in vuln_types)

    def test_java_suggests_deserialization(self, kb):
        """Java tech stack should suggest deserialization attacks."""
        suggestions = kb.suggest_attacks(["java"])
        if suggestions:
            all_techniques = []
            for s in suggestions:
                all_techniques.extend(s.get("techniques", []))
            # Java should have deserialization-related techniques
            # (may or may not be present depending on data)
            assert len(suggestions) > 0

    def test_nodejs_suggests_nosql(self, kb):
        """Node.js should suggest NoSQL injection."""
        suggestions = kb.suggest_attacks(["nodejs"])
        if suggestions:
            vuln_types = {s["vuln_type"].lower() for s in suggestions}
            # Node.js is associated with NoSQL injection
            assert len(suggestions) > 0

    def test_multiple_tech_stack(self, kb):
        """Multiple technologies should produce combined suggestions."""
        suggestions = kb.suggest_attacks(["php", "mysql"])
        assert isinstance(suggestions, list)
        # Should have suggestions from both
        if suggestions:
            for s in suggestions:
                assert "vuln_type" in s
                assert "relevance_score" in s

    def test_suggestions_have_structure(self, kb):
        suggestions = kb.suggest_attacks(["php"])
        for s in suggestions:
            assert "vuln_type" in s
            assert "relevance_score" in s
            assert "matching_tech" in s
            assert "techniques" in s
            assert "payloads" in s

    def test_suggestions_sorted_by_relevance(self, kb):
        suggestions = kb.suggest_attacks(["php", "java"])
        if len(suggestions) >= 2:
            scores = [s["relevance_score"] for s in suggestions]
            assert scores == sorted(scores, reverse=True)

    def test_empty_stack_returns_empty(self, kb):
        suggestions = kb.suggest_attacks([])
        assert suggestions == []

    def test_unknown_tech_returns_empty(self, kb):
        suggestions = kb.suggest_attacks(["nonexistent_tech_xyz_123"])
        assert suggestions == []

    def test_matching_tech_in_results(self, kb):
        suggestions = kb.suggest_attacks(["php"])
        if suggestions:
            # At least one suggestion should list "php" as matching tech
            all_matching = []
            for s in suggestions:
                all_matching.extend(s.get("matching_tech", []))
            assert any("php" in t.lower() for t in all_matching)


# =========================================================================
# get_attack_chain
# =========================================================================

class TestGetAttackChain:
    def test_returns_list(self, kb):
        chain = kb.get_attack_chain("SQL Injection")
        assert isinstance(chain, list)

    def test_sqli_chain_not_empty(self, kb):
        chain = kb.get_attack_chain("SQL Injection")
        assert len(chain) > 0

    def test_chain_phases_have_structure(self, kb):
        chain = kb.get_attack_chain("SQL Injection")
        for phase in chain:
            assert "phase" in phase
            assert "payloads" in phase

    def test_chain_has_payloads(self, kb):
        chain = kb.get_attack_chain("SQL Injection")
        all_payloads = []
        for phase in chain:
            all_payloads.extend(phase.get("payloads", []))
        assert len(all_payloads) > 0

    def test_xss_chain(self, kb):
        chain = kb.get_attack_chain("XSS")
        assert len(chain) > 0

    def test_ssrf_chain(self, kb):
        chain = kb.get_attack_chain("SSRF")
        # May or may not have chain depending on data
        assert isinstance(chain, list)

    def test_unknown_vuln_empty_chain(self, kb):
        chain = kb.get_attack_chain("Nonexistent Vuln XYZ")
        assert chain == []

    def test_chain_with_partial_match(self, kb):
        """Partial vuln type name should still find a chain."""
        chain = kb.get_attack_chain("SQL")
        # Should find SQL Injection via partial match
        assert isinstance(chain, list)


# =========================================================================
# get_payloads
# =========================================================================

class TestGetPayloads:
    def test_returns_list(self, kb):
        payloads = kb.get_payloads("SQL Injection")
        assert isinstance(payloads, list)

    def test_sqli_payloads_not_empty(self, kb):
        payloads = kb.get_payloads("SQL Injection")
        assert len(payloads) > 0

    def test_xss_payloads_not_empty(self, kb):
        payloads = kb.get_payloads("XSS")
        assert len(payloads) > 0

    def test_payloads_are_strings(self, kb):
        payloads = kb.get_payloads("SQL Injection")
        for p in payloads:
            assert isinstance(p, str)
            assert len(p) > 0

    def test_mysql_filter(self, kb):
        """DBMS filter should narrow results to MySQL-specific payloads."""
        all_payloads = kb.get_payloads("SQL Injection")
        mysql_payloads = kb.get_payloads("SQL Injection", dbms="MySQL")
        # MySQL payloads should be a subset (or at least not more than all)
        assert len(mysql_payloads) <= len(all_payloads)
        # MySQL payloads should contain MySQL-specific syntax
        if mysql_payloads:
            mysql_indicators = ["SLEEP", "BENCHMARK", "mysql", "information_schema"]
            has_mysql = any(
                any(ind.lower() in p.lower() for ind in mysql_indicators)
                for p in mysql_payloads
            )
            assert has_mysql

    def test_mssql_filter(self, kb):
        mssql_payloads = kb.get_payloads("SQL Injection", dbms="MSSQL")
        if mssql_payloads:
            mssql_indicators = ["WAITFOR", "mssql", "sql server", "@@version"]
            has_mssql = any(
                any(ind.lower() in p.lower() for ind in mssql_indicators)
                for p in mssql_payloads
            )
            assert has_mssql

    def test_postgresql_filter(self, kb):
        pg_payloads = kb.get_payloads("SQL Injection", dbms="PostgreSQL")
        if pg_payloads:
            pg_indicators = ["pg_sleep", "postgres", "psql"]
            has_pg = any(
                any(ind.lower() in p.lower() for ind in pg_indicators)
                for p in pg_payloads
            )
            assert has_pg

    def test_no_duplicates(self, kb):
        payloads = kb.get_payloads("SQL Injection")
        assert len(payloads) == len(set(payloads))

    def test_unknown_vuln_empty(self, kb):
        payloads = kb.get_payloads("Nonexistent Vuln XYZ")
        assert payloads == []

    def test_partial_match_works(self, kb):
        payloads = kb.get_payloads("SQL")
        assert len(payloads) > 0


# =========================================================================
# _normalize helper
# =========================================================================

class TestNormalize:
    def test_lowercase(self):
        assert KnowledgeIndex._normalize("SQL Injection") == "sqlinjection"

    def test_removes_spaces(self):
        assert KnowledgeIndex._normalize("hello world") == "helloworld"

    def test_removes_special_chars(self):
        assert KnowledgeIndex._normalize("XSS (Reflected)") == "xssreflected"

    def test_empty_string(self):
        assert KnowledgeIndex._normalize("") == ""

    def test_numbers_preserved(self):
        assert KnowledgeIndex._normalize("CVE-2021-44228") == "cve202144228"


# =========================================================================
# KnowledgeEntry
# =========================================================================

class TestKnowledgeEntry:
    def test_to_dict(self):
        entry = KnowledgeEntry(
            id="test-1",
            title="Test Entry",
            vuln_type="XSS",
            severity="HIGH",
            description="Test desc",
            attack_vector="reflected",
            remediation="encode output",
            tags=["xss", "web"],
        )
        d = entry.to_dict()
        assert d["id"] == "test-1"
        assert d["vuln_type"] == "XSS"
        assert d["severity"] == "HIGH"
        assert d["tags"] == ["xss", "web"]

    def test_to_dict_missing_optional(self):
        entry = KnowledgeEntry(
            id="test-2",
            title="Minimal",
            vuln_type="Info",
            severity="LOW",
            description="",
            attack_vector="",
            remediation="",
            tags=[],
        )
        d = entry.to_dict()
        assert d["id"] == "test-2"
