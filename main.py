"""FirewallGuard command-line interface."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from audit_engine.parser import InvalidFirewallConfigError
from audit_engine.service import FirewallAuditService
from reports.pdf_reporter import PDFReporter

VERSION = "2.0.0"
SEVERITY_RANK = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Audit JSON or iptables-save firewall configurations."
    )
    parser.add_argument("config", type=Path, help="Path to the firewall configuration")
    parser.add_argument(
        "--format",
        choices=("auto", "json", "iptables"),
        default="auto",
        help="Input format (default: auto-detect)",
    )
    parser.add_argument("--json-output", type=Path, help="Write the complete result as JSON")
    parser.add_argument("--pdf", type=Path, help="Write a professional PDF report")
    parser.add_argument(
        "--fail-on",
        choices=("info", "low", "medium", "high", "critical"),
        help="Return exit code 2 when a finding meets or exceeds this severity",
    )
    parser.add_argument("--version", action="version", version=f"FirewallGuard {VERSION}")
    return parser


def _print_summary(result) -> None:  # noqa: ANN001
    print("=" * 72)
    print(f"FirewallGuard {VERSION} | {result.audit_id}")
    print("=" * 72)
    print(f"Source:          {result.source_name} ({result.source_format})")
    print(f"Rules analyzed:  {result.total_rules} ({result.active_rules} active)")
    print(f"Findings:        {len(result.findings)}")
    print(f"Posture score:   {result.posture_score}/100")
    print(f"Risk:            {result.risk_classification}")
    print("\nFindings")
    print("-" * 72)
    if not result.findings:
        print("No gaps detected by the implemented checks.")
    for finding in result.findings:
        print(f"[{finding.severity:<8}] {finding.rule_id:<12} {finding.title}")
        print(f"           Evidence: {finding.evidence}")
        print(f"           Fix:      {finding.recommendation}")
    print("\nSelected standards alignment (not certification)")
    print("-" * 72)
    for assessment in result.standards:
        print(
            f"{assessment.framework} {assessment.version}: {assessment.status} "
            f"({assessment.checks_passed} passed, {assessment.checks_flagged} flagged)"
        )


def run(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    service = FirewallAuditService()
    try:
        result = service.audit_file(args.config, input_format=args.format)
    except (OSError, InvalidFirewallConfigError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    _print_summary(result)
    if args.json_output:
        args.json_output.parent.mkdir(parents=True, exist_ok=True)
        args.json_output.write_text(
            json.dumps(result.to_dict(), indent=2), encoding="utf-8"
        )
        print(f"\nJSON report: {args.json_output}")
    if args.pdf:
        path = PDFReporter().write(result, args.pdf)
        print(f"PDF report:  {path}")

    if args.fail_on:
        threshold = SEVERITY_RANK[args.fail_on.upper()]
        if any(SEVERITY_RANK[finding.severity] >= threshold for finding in result.findings):
            return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(run())
