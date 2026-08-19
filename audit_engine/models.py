"""Typed domain models for the FirewallGuard audit pipeline."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any


@dataclass(frozen=True)
class FirewallRule:
    """A normalized firewall rule from JSON or ``iptables-save`` input."""

    rule_id: str
    name: str
    action: str
    protocol: str
    source: str
    destination: str
    port: str
    enabled: bool
    description: str = ""
    chain: str = "UNSPECIFIED"
    direction: str = "unknown"
    kind: str = "rule"
    table: str = "filter"
    in_interface: str = "any"
    out_interface: str = "any"
    connection_states: tuple[str, ...] = ()
    raw: str = ""
    line_number: int | None = None

    @property
    def is_active_allow(self) -> bool:
        return self.enabled and self.action == "allow"

    @property
    def is_exposure_candidate(self) -> bool:
        """Exclude loopback and established/related return-traffic rules."""
        return (
            self.is_active_allow
            and self.in_interface != "lo"
            and not (
                self.connection_states
                and set(self.connection_states).issubset({"ESTABLISHED", "RELATED"})
            )
        )


@dataclass(frozen=True)
class StandardReference:
    framework: str
    version: str
    control_id: str
    title: str
    source_url: str


@dataclass(frozen=True)
class AttackReference:
    technique_id: str
    name: str
    relationship: str
    source_url: str


@dataclass(frozen=True)
class Finding:
    finding_id: str
    rule_id: str
    finding_type: str
    title: str
    severity: str
    description: str
    evidence: str
    recommendation: str
    risk_points: int
    likelihood: int
    impact: int
    confidence: str = "HIGH"
    standards: tuple[StandardReference, ...] = ()
    related_attack: tuple[AttackReference, ...] = ()


@dataclass(frozen=True)
class ControlCheck:
    framework: str
    version: str
    control_id: str
    title: str
    status: str
    evidence_count: int
    evidence: tuple[str, ...]
    source_url: str


@dataclass(frozen=True)
class FrameworkAssessment:
    framework: str
    version: str
    scope: str
    status: str
    checks_passed: int
    checks_flagged: int
    checks: tuple[ControlCheck, ...]
    disclaimer: str = (
        "Selected technical alignment checks only; this is not a compliance "
        "certification or an assessment of the complete framework."
    )


@dataclass(frozen=True)
class ParsedConfiguration:
    rules: tuple[FirewallRule, ...]
    source_format: str
    warnings: tuple[str, ...] = ()


@dataclass(frozen=True)
class AuditResult:
    audit_id: str
    generated_at: str
    source_name: str
    source_format: str
    input_sha256: str
    rules: tuple[FirewallRule, ...]
    findings: tuple[Finding, ...]
    posture_score: int
    risk_classification: str
    standards: tuple[FrameworkAssessment, ...]
    parser_warnings: tuple[str, ...] = ()
    methodology: str = (
        "Deterministic configuration analysis. The posture score is a transparent "
        "project-specific prioritization aid, not an industry certification."
    )

    @property
    def total_rules(self) -> int:
        return len(self.rules)

    @property
    def active_rules(self) -> int:
        return sum(rule.enabled for rule in self.rules)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
