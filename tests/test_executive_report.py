"""Tests for Executive Report Generator."""
import pytest
from datetime import datetime
from src.scanner.findings import Finding, ScanResult
from src.scanner.executive_report import ExecutiveReportGenerator


class TestExecutiveReportGenerator:
    def test_init(self):
        gen = ExecutiveReportGenerator()
        assert gen is not None
        assert gen.NAME == "executive_report"

    def test_calculate_risk_no_findings(self):
        gen = ExecutiveReportGenerator()
        risk = gen._calculate_risk([])
        assert risk["risk_level"] == "SECURE"
        assert risk["total_findings"] == 0

    def test_calculate_risk_critical(self):
        gen = ExecutiveReportGenerator()
        findings = [
            Finding(vuln_type="SQLi", title="SQL Injection", severity="CRITICAL", cwe="CWE-89"),
        ]
        risk = gen._calculate_risk(findings)
        assert risk["risk_level"] == "CRITICAL"
        assert risk["severity_counts"]["CRITICAL"] == 1

    def test_calculate_risk_medium(self):
        gen = ExecutiveReportGenerator()
        findings = [
            Finding(vuln_type="Headers", title="Missing CSP", severity="MEDIUM"),
            Finding(vuln_type="Headers", title="Missing HSTS", severity="MEDIUM"),
            Finding(vuln_type="Headers", title="Missing X-Frame", severity="MEDIUM"),
            Finding(vuln_type="Headers", title="Missing X-XSS", severity="MEDIUM"),
        ]
        risk = gen._calculate_risk(findings)
        assert risk["risk_level"] == "MEDIUM"

    def test_map_compliance_owasp(self):
        gen = ExecutiveReportGenerator()
        findings = [
            Finding(vuln_type="XSS", title="Reflected XSS", severity="HIGH", cwe="CWE-79"),
            Finding(vuln_type="SQLi", title="SQL Injection", severity="CRITICAL", cwe="CWE-89"),
        ]
        compliance = gen._map_compliance(findings)
        assert "A03:2021" in compliance["owasp_top10"]
        assert compliance["owasp_compliant"] is False

    def test_map_compliance_clean(self):
        gen = ExecutiveReportGenerator()
        compliance = gen._map_compliance([])
        assert compliance["owasp_compliant"] is True

    def test_generate_remediation(self):
        gen = ExecutiveReportGenerator()
        findings = [
            Finding(vuln_type="SQLi", title="SQLi", severity="CRITICAL", cwe="CWE-89", remediation="Use prepared statements"),
            Finding(vuln_type="XSS", title="XSS", severity="HIGH", cwe="CWE-79", remediation="Encode output"),
        ]
        remediation = gen._generate_remediation(findings)
        assert len(remediation) == 2
        assert remediation[0]["priority"] <= remediation[1]["priority"]

    def test_estimate_effort(self):
        gen = ExecutiveReportGenerator()
        f_cwe = Finding(cwe="CWE-89")
        assert "High" in gen._estimate_effort(f_cwe)
        f_config = Finding(cwe="CWE-16")
        assert "Low" in gen._estimate_effort(f_config)

    def test_generate_report_creates_file(self, tmp_path):
        gen = ExecutiveReportGenerator()
        result = ScanResult(
            target="https://example.com",
            findings=[Finding(vuln_type="Test", title="Test", severity="LOW")],
            duration=1.0,
        )
        report_path = gen.generate_report(result, str(tmp_path))
        assert report_path is not None

    def test_owasp_top10_mapping(self):
        gen = ExecutiveReportGenerator()
        assert "A01:2021" in gen.OWASP_TOP10
        assert "A10:2021" in gen.OWASP_TOP10
        assert len(gen.OWASP_TOP10) == 10
