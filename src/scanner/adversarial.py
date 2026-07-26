"""Adversarial Validation System — Three-stage false positive elimination.

Inspired by Bug Hunter's Hunter-Skeptic-Referee pattern.
Stage 1 (Hunter):  Confirms the finding looks real.
Stage 2 (Skeptic): Tries to disprove the finding.
Stage 3 (Referee): Makes the final verdict.
"""

import re
import logging
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Any

from src.scanner.findings import Finding
from src.core.logger import logger


@dataclass
class ValidationResult:
    """Result of adversarial validation."""
    original_finding: Finding
    verdict: str  # confirmed | likely_false_positive | false_positive | needs_manual_review
    confidence: float  # 0.0 to 1.0
    hunter_notes: str = ""
    skeptic_notes: str = ""
    referee_reasoning: str = ""
    evidence_strength: str = "none"  # strong | moderate | weak | none
    stage_details: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "finding_id": self.original_finding.id,
            "vuln_type": self.original_finding.vuln_type,
            "url": self.original_finding.url,
            "verdict": self.verdict,
            "confidence": self.confidence,
            "evidence_strength": self.evidence_strength,
            "hunter_notes": self.hunter_notes,
            "skeptic_notes": self.skeptic_notes,
            "referee_reasoning": self.referee_reasoning,
        }


# --- Patterns that suggest false positives ---
_STATIC_PAGE_INDICATORS = [
    r"<title>\s*(?:404|403|500|not found|forbidden)\s*</title>",
    r"(?:coming soon|under construction|placeholder)",
    r"(?:Lorem ipsum|sample text|test page)",
]

_DOCUMENTATION_INDICATORS = [
    r"/(?:docs|documentation|wiki|faq|help|tutorials?|guides?)(?:/|$)",
    r"/(?:examples?|samples?|demo|mock|sandbox)(?:/|$)",
    r"/(?:blog|posts?|articles?|news)(?:/|$)",
]

_GENERIC_ERROR_PATTERNS = [
    r"(?:An error occurred|Something went wrong|Internal Server Error)",
    r"(?:Please try again|Contact support|System Error)",
    r"(?:stack trace|traceback|debug mode)",
]

# Payloads that are commonly reflected without being vulnerable
_BENIGN_REFLECTIONS = [
    r"(?:alert|confirm|prompt)\s*\(\s*\)",  # XSS payloads in WAF responses
    r"\b(?:SELECT|INSERT|UPDATE|DELETE|DROP)\s+",  # SQL keywords in error pages (word boundary)
    r"\b(?:etc/passwd|windows/system32)\b",  # Path traversal in docs
]


class AdversarialValidator:
    """Three-stage adversarial validation to eliminate false positives.

    The Hunter confirms evidence, the Skeptic attacks it, and the Referee
    weighs both sides to deliver a calibrated verdict.
    """

    def __init__(self, strict_mode: bool = False):
        self.strict_mode = strict_mode
        self.stats = {
            "total_validated": 0,
            "confirmed": 0,
            "false_positives": 0,
            "likely_false_positives": 0,
            "needs_review": 0,
        }

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def validate(self, finding: Finding) -> ValidationResult:
        """Run a single finding through all 3 stages."""
        self.stats["total_validated"] += 1

        hunter_result = self._hunter_analysis(finding)
        skeptic_result = self._skeptic_analysis(finding, hunter_result)
        result = self._referee_verdict(finding, hunter_result, skeptic_result)

        # Update stats
        if result.verdict == "confirmed":
            self.stats["confirmed"] += 1
        elif result.verdict == "false_positive":
            self.stats["false_positives"] += 1
        elif result.verdict == "likely_false_positive":
            self.stats["likely_false_positives"] += 1
        else:
            self.stats["needs_review"] += 1

        return result

    def validate_batch(self, findings: List[Finding]) -> List[ValidationResult]:
        """Validate multiple findings."""
        results = []
        for finding in findings:
            try:
                results.append(self.validate(finding))
            except Exception as e:
                logger.error(f"Validation failed for finding {finding.id}: {e}")
                results.append(ValidationResult(
                    original_finding=finding,
                    verdict="needs_manual_review",
                    confidence=0.0,
                    hunter_notes=f"Validation error: {e}",
                    referee_reasoning="Validation process encountered an error.",
                ))
        return results

    # ------------------------------------------------------------------
    # Stage 1: Hunter
    # ------------------------------------------------------------------

    def _hunter_analysis(self, finding: Finding) -> Dict:
        """Hunter confirms the finding looks real.

        Checks for positive indicators: evidence present, payload reflected,
        response anomalies, etc.
        """
        score = 0.0
        notes = []
        evidence_flags = []

        # 1. Basic evidence check
        if finding.evidence and len(finding.evidence.strip()) > 10:
            score += 0.2
            evidence_flags.append("has_evidence")
            notes.append("Finding has non-trivial evidence.")
        else:
            notes.append("WARNING: Evidence is missing or very short.")

        # 2. Payload reflection
        if finding.payload and finding.response_snippet:
            if finding.payload in finding.response_snippet:
                score += 0.25
                evidence_flags.append("payload_reflected")
                notes.append(f"Payload '{finding.payload[:50]}...' found in response.")
            elif self._payload_partial_match(finding.payload, finding.response_snippet):
                score += 0.15
                evidence_flags.append("payload_partial")
                notes.append("Partial payload match in response.")

        # 2b. Server error evidence (strong indicator of real vuln)
        response_lower = (finding.response_snippet or "").lower()
        error_indicators = [
            r"sql syntax", r"mysql_fetch", r"ora-\d{5}", r"postgresql",
            r"sqlite3", r"unclosed quotation", r"microsoft ole db",
            r"odbc sql server", r"you have an error in your sql",
            r"pg_query", r"sqlstate",
        ]
        for err_pat in error_indicators:
            if re.search(err_pat, response_lower):
                score += 0.15
                evidence_flags.append("server_error_evidence")
                notes.append(f"Server error pattern found in response: {err_pat}")
                break

        # 3. Severity consistency
        sev_scores = {"CRITICAL": 0.2, "HIGH": 0.15, "MEDIUM": 0.1, "LOW": 0.05, "INFO": 0.0}
        score += sev_scores.get(finding.severity.upper(), 0.0)
        if finding.severity.upper() in ("CRITICAL", "HIGH"):
            notes.append(f"Severity is {finding.severity} — high-priority finding.")

        # 4. CVE/CWE reference
        if finding.cwe:
            score += 0.1
            evidence_flags.append("has_cwe")
            notes.append(f"CWE reference present: {finding.cwe}")

        # 5. CVSS score
        if finding.cvss >= 7.0:
            score += 0.15
            evidence_flags.append("high_cvss")
            notes.append(f"CVSS {finding.cvss} indicates high severity.")
        elif finding.cvss >= 4.0:
            score += 0.08
            notes.append(f"CVSS {finding.cvss} indicates medium severity.")

        # 6. Reproducibility hint (has request)
        if finding.request and len(finding.request.strip()) > 20:
            score += 0.1
            evidence_flags.append("reproducible")
            notes.append("Full request captured — reproducible.")

        return {
            "score": min(score, 1.0),
            "notes": notes,
            "evidence_flags": evidence_flags,
        }

    # ------------------------------------------------------------------
    # Stage 2: Skeptic
    # ------------------------------------------------------------------

    def _skeptic_analysis(self, finding: Finding, hunter_result: Dict) -> Dict:
        """Skeptic tries to disprove the finding.

        Looks for false-positive indicators: static pages, documentation,
        weak evidence, benign reflections, generic errors.
        """
        penalty = 0.0
        notes = []
        fp_flags = []

        response = (finding.response_snippet or "").lower()
        evidence = (finding.evidence or "").lower()
        url_lower = finding.url.lower()

        # 1. Is the payload actually reflected in the response?
        if finding.payload:
            if finding.payload not in (finding.response_snippet or ""):
                penalty += 0.25
                fp_flags.append("payload_not_reflected")
                notes.append("Payload is NOT actually in the response — weak evidence.")
            else:
                # Check if it's a benign reflection (WAF message, docs, etc.)
                for pattern in _BENIGN_REFLECTIONS:
                    if re.search(pattern, response, re.IGNORECASE):
                        penalty += 0.15
                        fp_flags.append("benign_reflection")
                        notes.append(f"Reflection matches known benign pattern: {pattern}")
                        break

        # 2. Static page detection
        for pattern in _STATIC_PAGE_INDICATORS:
            if re.search(pattern, response, re.IGNORECASE):
                penalty += 0.2
                fp_flags.append("static_page")
                notes.append(f"Response looks like a static/error page: {pattern}")
                break

        # 3. Documentation/blog detection
        for pattern in _DOCUMENTATION_INDICATORS:
            if re.search(pattern, url_lower, re.IGNORECASE):
                penalty += 0.15
                fp_flags.append("documentation_page")
                notes.append(f"URL suggests documentation/content page: {pattern}")
                break

        # 4. Generic error page
        for pattern in _GENERIC_ERROR_PATTERNS:
            if re.search(pattern, response, re.IGNORECASE):
                penalty += 0.15
                fp_flags.append("generic_error")
                notes.append(f"Response matches generic error pattern: {pattern}")
                break

        # 5. Evidence quality
        if not evidence or len(evidence.strip()) < 5:
            penalty += 0.2
            fp_flags.append("no_real_evidence")
            notes.append("Evidence is empty or trivially short.")
        elif len(evidence.strip()) < 20:
            penalty += 0.1
            fp_flags.append("weak_evidence")
            notes.append("Evidence is quite short — may be insufficient.")

        # 6. Check if evidence is just the payload repeated
        if finding.payload and evidence:
            if finding.payload.lower() in evidence and len(evidence) < len(finding.payload) + 30:
                penalty += 0.15
                fp_flags.append("evidence_just_payload")
                notes.append("Evidence is essentially just the payload — no real confirmation.")

        # 7. Confidence downgrade for known scanner noise
        noisy_tools = {"nuclei", "nikto", "nmap", "whatweb", "wappalyzer"}
        if finding.tool and finding.tool.lower() in noisy_tools:
            penalty += 0.05
            fp_flags.append("noisy_tool")
            notes.append(f"Tool '{finding.tool}' is known for higher false-positive rates.")

        return {
            "penalty": min(penalty, 1.0),
            "notes": notes,
            "fp_flags": fp_flags,
        }

    # ------------------------------------------------------------------
    # Stage 3: Referee
    # ------------------------------------------------------------------

    def _referee_verdict(
        self,
        finding: Finding,
        hunter: Dict,
        skeptic: Dict,
    ) -> ValidationResult:
        """Referee weighs Hunter score vs Skeptic penalty for final verdict."""
        hunter_score = hunter["score"]
        skeptic_penalty = skeptic["penalty"]
        net_score = max(0.0, hunter_score - skeptic_penalty)

        # Determine evidence strength
        if net_score >= 0.7:
            evidence_strength = "strong"
        elif net_score >= 0.45:
            evidence_strength = "moderate"
        elif net_score >= 0.2:
            evidence_strength = "weak"
        else:
            evidence_strength = "none"

        # Determine verdict
        fp_flags = skeptic.get("fp_flags", [])

        if net_score >= 0.6 and evidence_strength in ("strong", "moderate"):
            verdict = "confirmed"
            confidence = min(0.95, 0.6 + net_score * 0.4)
        elif "static_page" in fp_flags or "documentation_page" in fp_flags:
            verdict = "false_positive"
            confidence = min(0.9, 0.5 + skeptic_penalty * 0.4)
        elif net_score < 0.2 or evidence_strength == "none":
            verdict = "false_positive"
            confidence = min(0.85, 0.4 + (1.0 - net_score) * 0.5)
        elif net_score < 0.45 or "payload_not_reflected" in fp_flags:
            verdict = "likely_false_positive"
            confidence = min(0.8, 0.4 + (0.45 - net_score) * 2)
        elif len(fp_flags) >= 3:
            verdict = "likely_false_positive"
            confidence = 0.6
        else:
            verdict = "needs_manual_review"
            confidence = max(0.3, min(0.7, net_score))

        # In strict mode, require higher bar for confirmation
        if self.strict_mode and verdict == "confirmed" and net_score < 0.75:
            verdict = "needs_manual_review"
            confidence = max(0.3, confidence - 0.2)

        # Build reasoning
        reasoning_parts = [
            f"Hunter score: {hunter_score:.2f} | Skeptic penalty: {skeptic_penalty:.2f} | Net: {net_score:.2f}",
            f"Evidence strength: {evidence_strength}",
        ]
        if fp_flags:
            reasoning_parts.append(f"False-positive flags: {', '.join(fp_flags)}")
        reasoning_parts.append(f"Verdict: {verdict} (confidence: {confidence:.0%})")

        return ValidationResult(
            original_finding=finding,
            verdict=verdict,
            confidence=round(confidence, 3),
            hunter_notes=" | ".join(hunter["notes"]),
            skeptic_notes=" | ".join(skeptic["notes"]),
            referee_reasoning=" | ".join(reasoning_parts),
            evidence_strength=evidence_strength,
            stage_details={
                "hunter_score": hunter_score,
                "skeptic_penalty": skeptic_penalty,
                "net_score": net_score,
                "fp_flags": fp_flags,
                "evidence_flags": hunter.get("evidence_flags", []),
            },
        )

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _payload_partial_match(payload: str, response: str) -> bool:
        """Check if significant fragments of payload appear in response."""
        if not payload or not response:
            return False
        # Check for fragments of at least 8 chars
        for i in range(len(payload) - 7):
            fragment = payload[i : i + 8]
            if fragment in response:
                return True
        return False

    def get_stats(self) -> Dict[str, Any]:
        """Return validation statistics."""
        return dict(self.stats)

    def __repr__(self) -> str:
        return (
            f"AdversarialValidator(strict={self.strict_mode}, "
            f"validated={self.stats['total_validated']})"
        )
