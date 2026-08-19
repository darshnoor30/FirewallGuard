"""Explainable, deterministic firewall misconfiguration detectors."""

from __future__ import annotations

import ipaddress
from collections.abc import Iterable

from audit_engine.models import (
    AttackReference,
    Finding,
    FirewallRule,
    StandardReference,
)

NIST_PR_IR_01 = StandardReference(
    framework="NIST CSF",
    version="2.0",
    control_id="PR.IR-01",
    title="Networks and environments are protected from unauthorized logical access and usage",
    source_url="https://www.nist.gov/cyberframework",
)
CIS_12_2 = StandardReference(
    framework="CIS Controls",
    version="8.1",
    control_id="12.2",
    title="Establish and Maintain a Secure Network Architecture",
    source_url="https://www.cisecurity.org/controls/network-infrastructure-management",
)
CIS_12_3 = StandardReference(
    framework="CIS Controls",
    version="8.1",
    control_id="12.3",
    title="Securely Manage Network Infrastructure",
    source_url="https://www.cisecurity.org/controls/network-infrastructure-management",
)
CIS_4_4 = StandardReference(
    framework="CIS Controls",
    version="8.1",
    control_id="4.4",
    title="Implement and Manage a Firewall on Servers",
    source_url="https://www.cisecurity.org/controls/secure-configuration-of-enterprise-assets-and-software",
)


def _attack(technique_id: str, name: str, relationship: str) -> AttackReference:
    path = technique_id.replace(".", "/")
    return AttackReference(
        technique_id=technique_id,
        name=name,
        relationship=relationship,
        source_url=f"https://attack.mitre.org/techniques/{path}/",
    )


ATTACK_REMOTE = {
    22: _attack("T1021.004", "SSH", "Exposure may enable adversary remote access; no activity was observed."),
    3389: _attack(
        "T1021.001", "Remote Desktop Protocol", "Exposure may enable remote access or lateral movement; no activity was observed."
    ),
    445: _attack(
        "T1021.002", "SMB/Windows Admin Shares", "Exposure may enable remote access or lateral movement; no activity was observed."
    ),
    5900: _attack("T1021.005", "VNC", "Exposure may enable remote access; no activity was observed."),
    5985: _attack(
        "T1021.006", "Windows Remote Management", "Exposure may enable remote access; no activity was observed."
    ),
    5986: _attack(
        "T1021.006", "Windows Remote Management", "Exposure may enable remote access; no activity was observed."
    ),
}


def ports_include(expression: str, candidates: Iterable[int]) -> set[int]:
    """Return candidate ports covered by a normalized expression."""
    candidate_set = set(candidates)
    if expression == "any":
        return candidate_set
    matches: set[int] = set()
    for part in expression.split(","):
        if "-" in part:
            start, end = (int(value) for value in part.split("-", maxsplit=1))
        else:
            start = end = int(part)
        matches.update(port for port in candidate_set if start <= port <= end)
    return matches


def _address_covers(broader: str, narrower: str) -> bool:
    if broader == "any":
        return True
    if narrower == "any":
        return False
    broad_network = ipaddress.ip_network(broader, strict=False)
    narrow_network = ipaddress.ip_network(narrower, strict=False)
    return broad_network.version == narrow_network.version and narrow_network.subnet_of(broad_network)


def _port_ranges(expression: str) -> list[tuple[int, int]]:
    if expression == "any":
        return [(1, 65535)]
    ranges: list[tuple[int, int]] = []
    for part in expression.split(","):
        if "-" in part:
            start, end = (int(value) for value in part.split("-", maxsplit=1))
        else:
            start = end = int(part)
        ranges.append((start, end))
    return ranges


def _ports_cover(broader: str, narrower: str) -> bool:
    broad_ranges = _port_ranges(broader)
    return all(
        any(broad_start <= start and end <= broad_end for broad_start, broad_end in broad_ranges)
        for start, end in _port_ranges(narrower)
    )


def _finding_id(finding_type: str, rule_id: str) -> str:
    return f"{finding_type}:{rule_id}"


class BaseDetector:
    def detect(self, rules: list[FirewallRule]) -> list[Finding]:
        raise NotImplementedError


class AnyAnyRuleDetector(BaseDetector):
    def detect(self, rules: list[FirewallRule]) -> list[Finding]:
        findings: list[Finding] = []
        for rule in rules:
            if not rule.is_exposure_candidate:
                continue
            if not (rule.source == rule.destination == rule.port == "any"):
                continue
            if rule.kind == "policy" and rule.chain == "OUTPUT":
                continue

            inbound = rule.direction in {"inbound", "forward", "unknown"}
            severity = "CRITICAL" if inbound else "HIGH"
            title = (
                f"Permissive default {rule.chain} policy"
                if rule.kind == "policy"
                else "Unrestricted any-to-any allow rule"
            )
            findings.append(
                Finding(
                    finding_id=_finding_id("UNRESTRICTED_ALLOW", rule.rule_id),
                    rule_id=rule.rule_id,
                    finding_type="UNRESTRICTED_ALLOW",
                    title=title,
                    severity=severity,
                    description=(
                        "The active rule permits every protocol and port from every source "
                        "to every destination in its scope."
                    ),
                    evidence=f"{rule.chain}: {rule.source} -> {rule.destination}, ports={rule.port}, action=allow",
                    recommendation=(
                        "Replace the rule with explicit source, destination, protocol, and port "
                        "requirements; use a default-deny policy for inbound and forwarded traffic."
                    ),
                    risk_points=28 if severity == "CRITICAL" else 20,
                    likelihood=5,
                    impact=5,
                    standards=(NIST_PR_IR_01, CIS_12_2, CIS_4_4),
                )
            )
        return findings


class PublicServiceExposureDetector(BaseDetector):
    ADMIN_PORTS = {
        22: "SSH",
        23: "Telnet",
        3389: "RDP",
        5900: "VNC",
        5985: "WinRM HTTP",
        5986: "WinRM HTTPS",
    }
    DATABASE_PORTS = {
        1433: "Microsoft SQL Server",
        1521: "Oracle Database",
        3306: "MySQL",
        5432: "PostgreSQL",
        6379: "Redis",
        9200: "Elasticsearch",
        27017: "MongoDB",
    }
    SMB_PORTS = {139: "NetBIOS/SMB", 445: "SMB"}

    def detect(self, rules: list[FirewallRule]) -> list[Finding]:
        findings: list[Finding] = []
        for rule in rules:
            if (
                not rule.is_exposure_candidate
                or rule.source != "any"
                or rule.direction == "outbound"
                or rule.kind == "policy"
                or rule.source == rule.destination == rule.port == "any"
            ):
                continue
            findings.extend(self._service_findings(rule, self.ADMIN_PORTS, "PUBLIC_ADMIN_SERVICE", 20))
            findings.extend(self._service_findings(rule, self.DATABASE_PORTS, "PUBLIC_DATABASE_SERVICE", 18))
            findings.extend(self._service_findings(rule, self.SMB_PORTS, "PUBLIC_SMB_SERVICE", 22))
        return findings

    def _service_findings(
        self,
        rule: FirewallRule,
        service_ports: dict[int, str],
        finding_type: str,
        risk_points: int,
    ) -> list[Finding]:
        matched = ports_include(rule.port, service_ports)
        if not matched:
            return []
        services = ", ".join(f"{service_ports[port]} ({port})" for port in sorted(matched))
        if finding_type == "PUBLIC_ADMIN_SERVICE":
            title = "Administrative service exposed to all sources"
            recommendation = (
                "Restrict management access to a VPN, bastion host, or explicit administrator CIDRs; "
                "require MFA where supported."
            )
        elif finding_type == "PUBLIC_DATABASE_SERVICE":
            title = "Database service exposed to all sources"
            recommendation = (
                "Place the database on a private network and allow access only from approved application "
                "or administration subnets."
            )
        else:
            title = "SMB service exposed to all sources"
            recommendation = (
                "Block SMB at the perimeter and restrict it to explicitly authorized internal segments."
            )
        related_by_id = {
            ATTACK_REMOTE[port].technique_id: ATTACK_REMOTE[port]
            for port in sorted(matched)
            if port in ATTACK_REMOTE
        }
        related = tuple(related_by_id.values())
        return [
            Finding(
                finding_id=_finding_id(finding_type, rule.rule_id),
                rule_id=rule.rule_id,
                finding_type=finding_type,
                title=title,
                severity="HIGH",
                description=f"The active allow rule exposes {services} to every source address.",
                evidence=f"{rule.chain}: source=any, destination={rule.destination}, ports={rule.port}",
                recommendation=recommendation,
                risk_points=risk_points,
                likelihood=4,
                impact=5 if finding_type == "PUBLIC_SMB_SERVICE" else 4,
                standards=(NIST_PR_IR_01, CIS_12_2, CIS_12_3, CIS_4_4),
                related_attack=related,
            )
        ]


class CleartextServiceDetector(BaseDetector):
    SERVICES = {21: "FTP", 23: "Telnet"}

    def detect(self, rules: list[FirewallRule]) -> list[Finding]:
        findings: list[Finding] = []
        for rule in rules:
            if (
                not rule.is_exposure_candidate
                or rule.direction == "outbound"
                or rule.source == rule.destination == rule.port == "any"
            ):
                continue
            matched = ports_include(rule.port, self.SERVICES)
            if not matched:
                continue
            services = ", ".join(f"{self.SERVICES[p]} ({p})" for p in sorted(matched))
            severity = "HIGH" if rule.source == "any" else "MEDIUM"
            findings.append(
                Finding(
                    finding_id=_finding_id("CLEARTEXT_SERVICE", rule.rule_id),
                    rule_id=rule.rule_id,
                    finding_type="CLEARTEXT_SERVICE",
                    title="Cleartext administrative or file-transfer service allowed",
                    severity=severity,
                    description=f"The rule permits {services}, which can expose credentials or session data.",
                    evidence=f"{rule.chain}: source={rule.source}, ports={rule.port}, protocol={rule.protocol}",
                    recommendation="Replace Telnet with SSH and FTP with SFTP/FTPS; restrict access to trusted sources.",
                    risk_points=16 if severity == "HIGH" else 8,
                    likelihood=4 if rule.source == "any" else 3,
                    impact=4,
                    standards=(NIST_PR_IR_01, CIS_12_3, CIS_4_4),
                )
            )
        return findings


class OverlyBroadServiceDetector(BaseDetector):
    def detect(self, rules: list[FirewallRule]) -> list[Finding]:
        findings: list[Finding] = []
        for rule in rules:
            if not rule.is_exposure_candidate or rule.kind == "policy" or rule.direction == "outbound":
                continue
            if rule.port != "any":
                continue
            if rule.source == "any" and rule.destination == "any":
                continue
            severity = "HIGH" if rule.source == "any" else "MEDIUM"
            findings.append(
                Finding(
                    finding_id=_finding_id("ALL_PORTS_ALLOWED", rule.rule_id),
                    rule_id=rule.rule_id,
                    finding_type="ALL_PORTS_ALLOWED",
                    title="All ports allowed by an active rule",
                    severity=severity,
                    description="The rule allows the full port range instead of the minimum services required.",
                    evidence=f"{rule.chain}: {rule.source} -> {rule.destination}, protocol={rule.protocol}, ports=any",
                    recommendation="Replace 'any' with an explicit, business-approved port list and protocol.",
                    risk_points=17 if severity == "HIGH" else 8,
                    likelihood=4 if severity == "HIGH" else 3,
                    impact=4,
                    standards=(NIST_PR_IR_01, CIS_12_2, CIS_4_4),
                )
            )
        return findings


class DisabledRuleDetector(BaseDetector):
    def detect(self, rules: list[FirewallRule]) -> list[Finding]:
        return [
            Finding(
                finding_id=_finding_id("DISABLED_RULE_HYGIENE", rule.rule_id),
                rule_id=rule.rule_id,
                finding_type="DISABLED_RULE_HYGIENE",
                title="Disabled rule requires lifecycle review",
                severity="INFO",
                description="The rule is inactive and is not treated as an active exposure.",
                evidence=f"Rule {rule.rule_id} enabled=false",
                recommendation="Confirm ownership and retention requirements, then document or remove the stale rule.",
                risk_points=0,
                likelihood=1,
                impact=1,
                confidence="HIGH",
                standards=(CIS_12_3,),
            )
            for rule in rules
            if not rule.enabled
        ]


class DuplicateRuleDetector(BaseDetector):
    def detect(self, rules: list[FirewallRule]) -> list[Finding]:
        findings: list[Finding] = []
        seen: dict[tuple[str, ...], str] = {}
        for rule in rules:
            if not rule.enabled or rule.kind == "policy":
                continue
            key = (
                rule.chain,
                rule.action,
                rule.protocol,
                rule.source,
                rule.destination,
                rule.port,
                rule.in_interface,
                rule.out_interface,
                ",".join(rule.connection_states),
            )
            if key in seen:
                original_id = seen[key]
                findings.append(
                    Finding(
                        finding_id=_finding_id("DUPLICATE_RULE", rule.rule_id),
                        rule_id=rule.rule_id,
                        finding_type="DUPLICATE_RULE",
                        title="Duplicate active rule",
                        severity="MEDIUM",
                        description=f"This rule has the same match and action as rule {original_id}.",
                        evidence=f"Duplicate of {original_id}: {rule.chain} {rule.source} -> {rule.destination} {rule.port}/{rule.protocol}",
                        recommendation="Remove the duplicate after confirming counters, logging, and change-control requirements.",
                        risk_points=5,
                        likelihood=2,
                        impact=2,
                        standards=(CIS_12_3,),
                    )
                )
            else:
                seen[key] = rule.rule_id
        return findings


class ShadowedRuleDetector(BaseDetector):
    """Conservatively identify later rules fully covered by an earlier terminal rule."""

    def detect(self, rules: list[FirewallRule]) -> list[Finding]:
        findings: list[Finding] = []
        previous: list[FirewallRule] = []
        for rule in rules:
            if not rule.enabled or rule.kind == "policy" or rule.action not in {"allow", "deny"}:
                continue
            for earlier in previous:
                if self._covers(earlier, rule):
                    conflicting = earlier.action != rule.action
                    findings.append(
                        Finding(
                            finding_id=_finding_id("SHADOWED_RULE", rule.rule_id),
                            rule_id=rule.rule_id,
                            finding_type="SHADOWED_RULE",
                            title=(
                                "Rule is unreachable because an earlier rule takes the opposite action"
                                if conflicting
                                else "Rule is fully shadowed by an earlier rule"
                            ),
                            severity="HIGH" if conflicting else "MEDIUM",
                            description=(
                                f"Earlier rule {earlier.rule_id} fully covers this rule and is evaluated first."
                            ),
                            evidence=(
                                f"{earlier.rule_id} ({earlier.action}) precedes {rule.rule_id} "
                                f"({rule.action}) in chain {rule.chain}."
                            ),
                            recommendation=(
                                "Review rule order and intended access. Narrow or move the earlier rule, "
                                "then remove any unreachable rule through change control."
                            ),
                            risk_points=14 if conflicting else 6,
                            likelihood=4 if conflicting else 3,
                            impact=4 if conflicting else 2,
                            standards=(NIST_PR_IR_01, CIS_12_3),
                        )
                    )
                    break
            previous.append(rule)
        return findings

    @staticmethod
    def _covers(earlier: FirewallRule, later: FirewallRule) -> bool:
        if earlier.chain != later.chain:
            return False
        if earlier.protocol not in {"any", later.protocol}:
            return False
        if earlier.in_interface not in {"any", later.in_interface}:
            return False
        if earlier.out_interface not in {"any", later.out_interface}:
            return False
        if earlier.connection_states and not (
            later.connection_states
            and set(later.connection_states).issubset(set(earlier.connection_states))
        ):
            return False
        if (
            earlier.action == later.action
            and earlier.protocol == later.protocol
            and earlier.source == later.source
            and earlier.destination == later.destination
            and earlier.port == later.port
            and earlier.in_interface == later.in_interface
            and earlier.out_interface == later.out_interface
            and earlier.connection_states == later.connection_states
        ):
            return False
        return (
            _address_covers(earlier.source, later.source)
            and _address_covers(earlier.destination, later.destination)
            and _ports_cover(earlier.port, later.port)
        )


class FirewallDetectorEngine:
    SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}

    def __init__(self) -> None:
        self.detectors: tuple[BaseDetector, ...] = (
            AnyAnyRuleDetector(),
            PublicServiceExposureDetector(),
            CleartextServiceDetector(),
            OverlyBroadServiceDetector(),
            DuplicateRuleDetector(),
            ShadowedRuleDetector(),
            DisabledRuleDetector(),
        )

    def run(self, rules: list[FirewallRule]) -> list[Finding]:
        findings = [finding for detector in self.detectors for finding in detector.detect(rules)]
        return sorted(
            findings,
            key=lambda finding: (
                self.SEVERITY_ORDER.get(finding.severity, 99),
                finding.rule_id,
                finding.finding_type,
            ),
        )
