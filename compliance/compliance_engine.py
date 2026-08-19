"""Evidence-backed standards alignment without claiming full compliance."""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass

from audit_engine.models import ControlCheck, Finding, FirewallRule, FrameworkAssessment


@dataclass(frozen=True)
class _ControlDefinition:
    framework: str
    version: str
    control_id: str
    title: str
    scope: str
    finding_types: frozenset[str]
    source_url: str


_NIST_SOURCE = "https://www.nist.gov/cyberframework"
_CIS_12_SOURCE = "https://www.cisecurity.org/controls/network-infrastructure-management"
_CIS_4_SOURCE = (
    "https://www.cisecurity.org/controls/secure-configuration-of-enterprise-assets-and-software"
)

CONTROL_DEFINITIONS = (
    _ControlDefinition(
        "NIST CSF",
        "2.0",
        "PR.IR-01",
        "Networks and environments are protected from unauthorized logical access and usage",
        "Technical review of access scope and exposed services",
        frozenset(
            {
                "UNRESTRICTED_ALLOW",
                "PUBLIC_ADMIN_SERVICE",
                "PUBLIC_DATABASE_SERVICE",
                "PUBLIC_SMB_SERVICE",
                "CLEARTEXT_SERVICE",
                "ALL_PORTS_ALLOWED",
            }
        ),
        _NIST_SOURCE,
    ),
    _ControlDefinition(
        "NIST CSF",
        "2.0",
        "PR.PS-01",
        "Configuration management practices are established and applied",
        "Rule lifecycle and duplication indicators",
        frozenset({"DUPLICATE_RULE", "SHADOWED_RULE", "DISABLED_RULE_HYGIENE"}),
        _NIST_SOURCE,
    ),
    _ControlDefinition(
        "CIS Controls",
        "8.1",
        "4.4",
        "Implement and Manage a Firewall on Servers",
        "Firewall exposure and least-privilege checks",
        frozenset(
            {
                "UNRESTRICTED_ALLOW",
                "PUBLIC_ADMIN_SERVICE",
                "PUBLIC_DATABASE_SERVICE",
                "PUBLIC_SMB_SERVICE",
                "CLEARTEXT_SERVICE",
                "ALL_PORTS_ALLOWED",
            }
        ),
        _CIS_4_SOURCE,
    ),
    _ControlDefinition(
        "CIS Controls",
        "8.1",
        "12.2",
        "Establish and Maintain a Secure Network Architecture",
        "Broad exposure and network-boundary rules",
        frozenset({"UNRESTRICTED_ALLOW", "ALL_PORTS_ALLOWED"}),
        _CIS_12_SOURCE,
    ),
    _ControlDefinition(
        "CIS Controls",
        "8.1",
        "12.3",
        "Securely Manage Network Infrastructure",
        "Management exposure, insecure services, and rule hygiene",
        frozenset(
            {
                "PUBLIC_ADMIN_SERVICE",
                "PUBLIC_DATABASE_SERVICE",
                "PUBLIC_SMB_SERVICE",
                "CLEARTEXT_SERVICE",
                "DUPLICATE_RULE",
                "SHADOWED_RULE",
                "DISABLED_RULE_HYGIENE",
            }
        ),
        _CIS_12_SOURCE,
    ),
)


class StandardsAlignmentEngine:
    """Evaluate only the selected technical checks implemented by FirewallGuard."""

    def evaluate(
        self, rules: list[FirewallRule], findings: list[Finding]
    ) -> list[FrameworkAssessment]:
        del rules  # Reserved for future checks that need clean-rule evidence.
        grouped: dict[tuple[str, str], list[ControlCheck]] = defaultdict(list)
        scopes: dict[tuple[str, str], set[str]] = defaultdict(set)

        for definition in CONTROL_DEFINITIONS:
            matched = tuple(
                finding.finding_id
                for finding in findings
                if finding.finding_type in definition.finding_types
            )
            grouped[(definition.framework, definition.version)].append(
                ControlCheck(
                    framework=definition.framework,
                    version=definition.version,
                    control_id=definition.control_id,
                    title=definition.title,
                    status="GAP" if matched else "NO_GAP_DETECTED",
                    evidence_count=len(matched),
                    evidence=matched,
                    source_url=definition.source_url,
                )
            )
            scopes[(definition.framework, definition.version)].add(definition.scope)

        assessments: list[FrameworkAssessment] = []
        for key, checks in grouped.items():
            flagged = sum(check.status == "GAP" for check in checks)
            assessments.append(
                FrameworkAssessment(
                    framework=key[0],
                    version=key[1],
                    scope="; ".join(sorted(scopes[key])),
                    status="ACTION_REQUIRED" if flagged else "NO_GAPS_DETECTED",
                    checks_passed=len(checks) - flagged,
                    checks_flagged=flagged,
                    checks=tuple(checks),
                )
            )
        return assessments


# Backward-compatible alias for earlier integrations.
ComplianceEngine = StandardsAlignmentEngine
