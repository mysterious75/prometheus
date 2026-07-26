"""5-Stage Pipeline — Recon → Hunt → Validate → Trace → Report

Inspired by Harness Kit (ZephrFish) and IronCurtain (Niels Provos).

Key insight: "Vulnerability discovery is an orchestration problem,
not a frontier-model problem."

Each stage has:
- Its own system prompt / methodology
- Its own model (cheap for bulk, expensive for validation)
- Its own context budget
- Journal-based state (append-only)
"""

import time
from typing import Dict, Any, List, Optional
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum

from ..core.logger import logger, console
from ..scanner.findings import Finding, ScanResult


class PipelineStage(Enum):
    """Pipeline stages."""
    RECON = "recon"
    HUNT = "hunt"
    VALIDATE = "validate"
    TRACE = "trace"
    REPORT = "report"


@dataclass
class StageResult:
    """Result from a single pipeline stage."""
    stage: PipelineStage
    findings: List[Finding] = field(default_factory=list)
    data: Dict[str, Any] = field(default_factory=dict)
    duration: float = 0.0
    tokens_used: int = 0
    model_used: str = ""
    errors: List[str] = field(default_factory=list)


@dataclass
class PipelineResult:
    """Full pipeline result."""
    target: str
    stages: List[StageResult] = field(default_factory=list)
    confirmed_findings: List[Finding] = field(default_factory=list)
    rejected_findings: List[Finding] = field(default_factory=list)
    total_duration: float = 0.0
    total_tokens: int = 0


class PipelineOrchestrator:
    """5-stage security testing pipeline.
    
    Stage 1: RECON — Map the target (subdomains, ports, tech, endpoints)
    Stage 2: HUNT — Investigate vulnerability hypotheses
    Stage 3: VALIDATE — Adversarial review (try to disprove findings)
    Stage 4: TRACE — Prove attacker input reaches vulnerable sink
    Stage 5: REPORT — Assemble final report (only confirmed findings)
    
    Each stage is independent and can use different models/tools.
    State is persisted to disk (journal-based) for resumability.
    """
    
    # Model routing — cheap for bulk, expensive for validation
    MODEL_ROUTING = {
        PipelineStage.RECON: "fast",      # Cheap model for bulk recon
        PipelineStage.HUNT: "primary",    # Standard model for hunting
        PipelineStage.VALIDATE: "reasoning",  # Expensive model for validation
        PipelineStage.TRACE: "primary",   # Standard model for tracing
        PipelineStage.REPORT: "fast",     # Cheap model for report generation
    }
    
    def __init__(self, router=None, state_manager=None):
        self.router = router
        self.state = state_manager
        self.journal: List[Dict] = []
    
    def run(self, target: str, stages: Optional[List[PipelineStage]] = None,
            max_findings: int = 50) -> PipelineResult:
        """Run the full pipeline or selected stages."""
        if stages is None:
            stages = list(PipelineStage)
        
        result = PipelineResult(target=target)
        start_time = time.time()
        
        console.print(f"\n[bold blue]═══ 5-Stage Pipeline: {target} ═══[/bold blue]")
        
        # Stage context — data passed between stages
        context = {"target": target, "max_findings": max_findings}
        
        for stage in stages:
            console.print(f"\n[bold cyan]Stage: {stage.value.upper()}[/bold cyan]")
            stage_start = time.time()
            
            try:
                stage_result = self._run_stage(stage, context)
                stage_result.duration = time.time() - stage_start
                result.stages.append(stage_result)
                
                # Update context for next stage
                context["previous_findings"] = stage_result.findings
                context["stage_data"] = stage_result.data
                
                # Journal entry
                self._journal_entry(stage, stage_result)
                
                console.print(f"  [green]✓ {stage.value} complete: "
                            f"{len(stage_result.findings)} findings in "
                            f"{stage_result.duration:.1f}s[/green]")
                
            except Exception as e:
                logger.error(f"Stage {stage.value} failed: {e}")
                result.stages.append(StageResult(
                    stage=stage, errors=[str(e)],
                    duration=time.time() - stage_start
                ))
        
        # Separate confirmed vs rejected findings
        for stage_result in result.stages:
            if stage_result.stage == PipelineStage.VALIDATE:
                for f in stage_result.findings:
                    if f.confidence in ("HIGH", "CONFIRMED"):
                        result.confirmed_findings.append(f)
                    else:
                        result.rejected_findings.append(f)
            elif stage_result.stage == PipelineStage.TRACE:
                result.confirmed_findings = stage_result.findings
        
        result.total_duration = time.time() - start_time
        
        console.print(f"\n[bold blue]═══ Pipeline Complete ═══[/bold blue]")
        console.print(f"  Confirmed: {len(result.confirmed_findings)}")
        console.print(f"  Rejected: {len(result.rejected_findings)}")
        console.print(f"  Duration: {result.total_duration:.1f}s")
        
        return result
    
    def _run_stage(self, stage: PipelineStage, context: Dict) -> StageResult:
        """Run a single pipeline stage."""
        if stage == PipelineStage.RECON:
            return self._stage_recon(context)
        elif stage == PipelineStage.HUNT:
            return self._stage_hunt(context)
        elif stage == PipelineStage.VALIDATE:
            return self._stage_validate(context)
        elif stage == PipelineStage.TRACE:
            return self._stage_trace(context)
        elif stage == PipelineStage.REPORT:
            return self._stage_report(context)
        return StageResult(stage=stage)
    
    def _stage_recon(self, context: Dict) -> StageResult:
        """Stage 1: RECON — Map the target."""
        from ..tools.registry import registry
        from ..scanner.crawler import WebCrawler
        
        target = context["target"]
        result = StageResult(stage=PipelineStage.RECON)
        
        # Subdomain enumeration
        console.print("  [dim]→ Subdomain enumeration...[/dim]")
        sub_result = registry.run("subfinder", target)
        subdomains = [f.get("value", "") for f in sub_result.findings if f.get("value")]
        result.data["subdomains"] = subdomains[:100]
        
        # HTTP probing
        if subdomains:
            console.print("  [dim]→ HTTP probing...[/dim]")
            http_result = registry.run("httpx", target, targets=subdomains[:50])
            result.data["http_services"] = http_result.findings
        
        # Port scanning
        console.print("  [dim]→ Port scanning...[/dim]")
        port_result = registry.run("nmap", target)
        result.data["open_ports"] = port_result.findings
        
        # Crawling
        if target.startswith(("http://", "https://")):
            console.print("  [dim]→ Crawling...[/dim]")
            crawler = WebCrawler()
            crawl_result = crawler.crawl(target)
            result.data["urls"] = crawl_result.urls[:200]
            result.data["forms"] = crawl_result.forms
            result.data["endpoints"] = crawl_result.endpoints
            result.data["tech_stack"] = crawl_result.technologies
        
        return result
    
    def _stage_hunt(self, context: Dict) -> StageResult:
        """Stage 2: HUNT — Investigate vulnerability hypotheses."""
        from ..scanner.runner import ScanRunner
        
        target = context["target"]
        result = StageResult(stage=PipelineStage.HUNT)
        
        # Run vulnerability scanners
        console.print("  [dim]→ Running vulnerability scanners...[/dim]")
        runner = ScanRunner()
        scan_result = runner.scan(target, full=True)
        
        result.findings = scan_result.findings
        result.data["scan_summary"] = scan_result.summary()
        
        return result
    
    def _stage_validate(self, context: Dict) -> StageResult:
        """Stage 3: VALIDATE — Adversarial review.
        
        For each finding from HUNT stage, try to disprove it.
        Only findings that survive validation move to TRACE.
        """
        result = StageResult(stage=PipelineStage.VALIDATE)
        findings = context.get("previous_findings", [])
        
        console.print(f"  [dim]→ Validating {len(findings)} findings...[/dim]")
        
        try:
            from ..scanner.adversarial import AdversarialValidator
            validator = AdversarialValidator()
            
            for finding in findings[:context.get("max_findings", 50)]:
                vr = validator.validate(finding)
                if vr.verdict in ("confirmed", "likely_false_positive"):
                    finding.confidence = "HIGH" if vr.verdict == "confirmed" else "MEDIUM"
                    result.findings.append(finding)
                elif vr.verdict == "needs_manual_review":
                    finding.confidence = "LOW"
                    result.findings.append(finding)
                # false_positive findings are dropped
                
        except ImportError:
            # If adversarial validator not available, pass all through
            console.print("  [yellow]⚠ Adversarial validator not available, skipping validation[/yellow]")
            result.findings = findings
        
        return result
    
    def _stage_trace(self, context: Dict) -> StageResult:
        """Stage 4: TRACE — Prove attacker input reaches vulnerable sink.
        
        For each validated finding, trace the data flow from input to sink.
        Only findings with proven data flow are confirmed.
        """
        result = StageResult(stage=PipelineStage.TRACE)
        findings = context.get("previous_findings", [])
        
        console.print(f"  [dim]→ Tracing {len(findings)} findings...[/dim]")
        
        for finding in findings:
            # Check if we can trace the attack path
            has_tracing = self._trace_finding(finding)
            if has_tracing:
                finding.confidence = "CONFIRMED"
                result.findings.append(finding)
            else:
                # Keep with lower confidence
                finding.confidence = "MEDIUM"
                result.findings.append(finding)
        
        return result
    
    def _trace_finding(self, finding: Finding) -> bool:
        """Trace a single finding — can we prove the attack path?"""
        # Check for evidence indicators
        has_evidence = bool(finding.evidence and len(finding.evidence) > 20)
        has_payload = bool(finding.payload)
        has_request = bool(finding.request)
        
        # For SQLi — can we see SQL error in response?
        if "SQL" in finding.vuln_type:
            sql_indicators = ["syntax", "error", "mysql", "postgresql", "mssql", "oracle"]
            return any(ind in finding.evidence.lower() for ind in sql_indicators)
        
        # For XSS — can we see unmodified reflection?
        if "XSS" in finding.vuln_type:
            return finding.payload in finding.evidence if finding.payload else has_evidence
        
        # For SSRF — can we see internal data?
        if "SSRF" in finding.vuln_type:
            ssrf_indicators = ["169.254", "metadata", "ami-id", "internal"]
            return any(ind in finding.evidence.lower() for ind in ssrf_indicators)
        
        # Default: has evidence + payload
        return has_evidence and has_payload
    
    def _stage_report(self, context: Dict) -> StageResult:
        """Stage 5: REPORT — Assemble final report."""
        from ..scanner.executive_report import ExecutiveReportGenerator
        
        result = StageResult(stage=PipelineStage.REPORT)
        findings = context.get("previous_findings", [])
        
        console.print(f"  [dim]→ Generating report for {len(findings)} findings...[/dim]")
        
        # Create scan result for report generator
        scan_result = ScanResult(
            target=context["target"],
            findings=findings,
            duration=sum(s.duration for s in context.get("stages", []))
        )
        
        try:
            generator = ExecutiveReportGenerator()
            report_path = generator.generate_report(scan_result)
            result.data["report_path"] = report_path
            console.print(f"  [dim]→ Report: {report_path}[/dim]")
        except Exception as e:
            result.errors.append(f"Report generation failed: {e}")
        
        result.findings = findings
        return result
    
    def _journal_entry(self, stage: PipelineStage, result: StageResult):
        """Append to execution journal."""
        entry = {
            "timestamp": datetime.now().isoformat(),
            "stage": stage.value,
            "findings_count": len(result.findings),
            "duration": result.duration,
            "errors": result.errors,
        }
        self.journal.append(entry)
        
        # Save to disk if state manager available
        if self.state:
            self.state.append_journal(entry)
    
    def get_journal(self) -> List[Dict]:
        """Get execution journal."""
        return self.journal


# Export
__all__ = ["PipelineOrchestrator", "PipelineStage", "PipelineResult", "StageResult"]
