"""High-level audit orchestration shared by the CLI and dashboard."""

from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from pathlib import Path

from audit_engine.detectors import FirewallDetectorEngine
from audit_engine.models import AuditResult
from audit_engine.parser import FirewallConfigParser
from audit_engine.scoring import SecurityScorer
from compliance.compliance_engine import StandardsAlignmentEngine


class FirewallAuditService:
    def __init__(self) -> None:
        self.parser = FirewallConfigParser()
        self.detector = FirewallDetectorEngine()
        self.scorer = SecurityScorer()
        self.standards = StandardsAlignmentEngine()

    def audit_file(
        self, path: str | Path, input_format: str = "auto"
    ) -> AuditResult:
        file_path = Path(path)
        try:
            text = file_path.read_text(encoding="utf-8-sig")
        except UnicodeDecodeError as exc:
            raise ValueError("Configuration must be UTF-8 text.") from exc
        return self.audit_text(text, source_name=file_path.name, input_format=input_format)

    def audit_text(
        self, text: str, source_name: str = "uploaded-config", input_format: str = "auto"
    ) -> AuditResult:
        parsed = self.parser.parse_text(text, input_format=input_format)
        findings = tuple(self.detector.run(list(parsed.rules)))
        score, risk = self.scorer.calculate(findings)
        standards = tuple(self.standards.evaluate(list(parsed.rules), list(findings)))
        digest = hashlib.sha256(text.encode("utf-8")).hexdigest()
        return AuditResult(
            audit_id=f"FG-{digest[:12].upper()}",
            generated_at=datetime.now(timezone.utc).isoformat(timespec="seconds"),
            source_name=source_name,
            source_format=parsed.source_format,
            input_sha256=digest,
            rules=parsed.rules,
            findings=findings,
            posture_score=score,
            risk_classification=risk,
            standards=standards,
            parser_warnings=parsed.warnings,
        )
