"""Professional, in-memory PDF reporting for FirewallGuard audits."""

from __future__ import annotations

from collections import Counter
from io import BytesIO
from pathlib import Path
from xml.sax.saxutils import escape

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import (
    KeepTogether,
    LongTable,
    PageBreak,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

from audit_engine.models import AuditResult, Finding

NAVY = colors.HexColor("#0B172A")
BLUE = colors.HexColor("#2563EB")
SLATE = colors.HexColor("#475569")
PALE = colors.HexColor("#EFF6FF")
GREEN = colors.HexColor("#15803D")
AMBER = colors.HexColor("#B45309")
RED = colors.HexColor("#B91C1C")
BORDER = colors.HexColor("#CBD5E1")

SEVERITY_COLORS = {
    "CRITICAL": colors.HexColor("#991B1B"),
    "HIGH": colors.HexColor("#C2410C"),
    "MEDIUM": colors.HexColor("#A16207"),
    "LOW": colors.HexColor("#1D4ED8"),
    "INFO": colors.HexColor("#475569"),
}


class PDFReporter:
    """Render an ``AuditResult`` without shared temporary report files."""

    def generate(self, result: AuditResult) -> bytes:
        buffer = BytesIO()
        doc = SimpleDocTemplate(
            buffer,
            pagesize=A4,
            rightMargin=18 * mm,
            leftMargin=18 * mm,
            topMargin=18 * mm,
            bottomMargin=18 * mm,
            title=f"FirewallGuard Audit {result.audit_id}",
            author="FirewallGuard",
            subject="Firewall configuration security posture assessment",
        )
        styles = self._styles()
        story: list[object] = []

        story.extend(self._title_block(result, styles))
        story.extend(self._executive_summary(result, styles))
        story.extend(self._findings_summary(result, styles))
        story.append(PageBreak())
        story.extend(self._detailed_findings(result, styles))
        story.extend(self._standards_alignment(result, styles))
        story.extend(self._methodology(result, styles))
        story.extend(self._rule_appendix(result, styles))

        def footer(canvas, document) -> None:  # noqa: ANN001
            canvas.saveState()
            canvas.setStrokeColor(BORDER)
            canvas.line(18 * mm, 13 * mm, A4[0] - 18 * mm, 13 * mm)
            canvas.setFont("Helvetica", 7.5)
            canvas.setFillColor(SLATE)
            canvas.drawString(18 * mm, 8.5 * mm, f"FirewallGuard | {result.audit_id}")
            canvas.drawRightString(
                A4[0] - 18 * mm, 8.5 * mm, f"Page {document.page} | UTC {result.generated_at}"
            )
            canvas.restoreState()

        doc.build(story, onFirstPage=footer, onLaterPages=footer)
        return buffer.getvalue()

    def write(self, result: AuditResult, output_file: str | Path) -> Path:
        path = Path(output_file)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(self.generate(result))
        return path

    @staticmethod
    def _styles() -> dict[str, ParagraphStyle]:
        base = getSampleStyleSheet()
        return {
            "title": ParagraphStyle(
                "FGTitle",
                parent=base["Title"],
                fontName="Helvetica-Bold",
                fontSize=23,
                leading=28,
                textColor=NAVY,
                spaceAfter=4,
            ),
            "subtitle": ParagraphStyle(
                "FGSubtitle",
                parent=base["BodyText"],
                fontSize=10,
                leading=14,
                textColor=SLATE,
                spaceAfter=12,
            ),
            "h1": ParagraphStyle(
                "FGH1",
                parent=base["Heading1"],
                fontName="Helvetica-Bold",
                fontSize=15,
                leading=19,
                textColor=NAVY,
                spaceBefore=10,
                spaceAfter=7,
            ),
            "h2": ParagraphStyle(
                "FGH2",
                parent=base["Heading2"],
                fontName="Helvetica-Bold",
                fontSize=11,
                leading=14,
                textColor=NAVY,
                spaceBefore=7,
                spaceAfter=4,
            ),
            "body": ParagraphStyle(
                "FGBody",
                parent=base["BodyText"],
                fontSize=8.7,
                leading=12,
                textColor=NAVY,
            ),
            "small": ParagraphStyle(
                "FGSmall",
                parent=base["BodyText"],
                fontSize=7.3,
                leading=10,
                textColor=SLATE,
            ),
            "metric": ParagraphStyle(
                "FGMetric",
                parent=base["BodyText"],
                alignment=TA_CENTER,
                fontName="Helvetica-Bold",
                fontSize=16,
                leading=20,
                textColor=NAVY,
            ),
            "metric_label": ParagraphStyle(
                "FGMetricLabel",
                parent=base["BodyText"],
                alignment=TA_CENTER,
                fontSize=7,
                leading=9,
                textColor=SLATE,
            ),
        }

    def _title_block(self, result: AuditResult, styles: dict[str, ParagraphStyle]) -> list[object]:
        metadata = [
            ["Audit ID", escape(result.audit_id), "Source", escape(result.source_name)],
            ["Input format", escape(result.source_format), "SHA-256", escape(result.input_sha256[:20] + "...")],
            ["Generated", escape(result.generated_at), "Rules analyzed", str(result.total_rules)],
        ]
        table = Table(metadata, colWidths=[25 * mm, 52 * mm, 28 * mm, 68 * mm])
        table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#F8FAFC")),
                    ("GRID", (0, 0), (-1, -1), 0.4, BORDER),
                    ("FONTNAME", (0, 0), (-1, -1), "Helvetica"),
                    ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
                    ("FONTNAME", (2, 0), (2, -1), "Helvetica-Bold"),
                    ("FONTSIZE", (0, 0), (-1, -1), 7.5),
                    ("TEXTCOLOR", (0, 0), (-1, -1), NAVY),
                    ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                    ("TOPPADDING", (0, 0), (-1, -1), 5),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
                ]
            )
        )
        return [
            Paragraph("FirewallGuard", styles["title"]),
            Paragraph(
                "Explainable firewall configuration posture assessment",
                styles["subtitle"],
            ),
            table,
            Spacer(1, 8),
        ]

    def _executive_summary(
        self, result: AuditResult, styles: dict[str, ParagraphStyle]
    ) -> list[object]:
        risk_color = {
            "LOW": GREEN,
            "MODERATE": AMBER,
            "HIGH": colors.HexColor("#C2410C"),
            "CRITICAL": RED,
        }[result.risk_classification]
        metrics = Table(
            [
                [
                    Paragraph(str(result.posture_score), styles["metric"]),
                    Paragraph(escape(result.risk_classification), styles["metric"]),
                    Paragraph(str(len(result.findings)), styles["metric"]),
                    Paragraph(str(result.active_rules), styles["metric"]),
                ],
                [
                    Paragraph("POSTURE SCORE / 100", styles["metric_label"]),
                    Paragraph("RISK CLASSIFICATION", styles["metric_label"]),
                    Paragraph("TOTAL FINDINGS", styles["metric_label"]),
                    Paragraph("ACTIVE RULES", styles["metric_label"]),
                ],
            ],
            colWidths=[43 * mm] * 4,
        )
        metrics.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, -1), PALE),
                    ("BOX", (0, 0), (-1, -1), 0.7, BLUE),
                    ("INNERGRID", (0, 0), (-1, -1), 0.4, BORDER),
                    ("TEXTCOLOR", (1, 0), (1, 0), risk_color),
                    ("TOPPADDING", (0, 0), (-1, 0), 10),
                    ("BOTTOMPADDING", (0, 1), (-1, 1), 8),
                ]
            )
        )
        critical_or_high = sum(
            finding.severity in {"CRITICAL", "HIGH"} for finding in result.findings
        )
        summary = (
            f"FirewallGuard analyzed <b>{result.total_rules}</b> normalized rules and found "
            f"<b>{critical_or_high}</b> critical/high-priority issue(s). Remediation should begin "
            "with unrestricted allow rules and public management, database, or SMB exposure."
            if critical_or_high
            else "No critical or high-priority gaps were detected by the implemented checks. "
            "Manual design review and environment-specific validation are still required."
        )
        return [
            Paragraph("Executive summary", styles["h1"]),
            metrics,
            Spacer(1, 7),
            Paragraph(summary, styles["body"]),
            Spacer(1, 5),
            Paragraph(
                "Important: this report evaluates selected technical configuration patterns. "
                "It is not a penetration test, proof of compromise, or compliance certification.",
                styles["small"],
            ),
        ]

    def _findings_summary(
        self, result: AuditResult, styles: dict[str, ParagraphStyle]
    ) -> list[object]:
        counts = Counter(finding.severity for finding in result.findings)
        severities = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
        data = [[severity, str(counts.get(severity, 0))] for severity in severities]
        table = Table([["Severity", "Count"], *data], colWidths=[70 * mm, 30 * mm], repeatRows=1)
        table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, 0), NAVY),
                    ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                    ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                    ("GRID", (0, 0), (-1, -1), 0.4, BORDER),
                    ("FONTNAME", (0, 1), (-1, -1), "Helvetica"),
                    ("FONTSIZE", (0, 0), (-1, -1), 8),
                    ("ALIGN", (1, 1), (1, -1), "CENTER"),
                    ("TOPPADDING", (0, 0), (-1, -1), 4),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
                ]
            )
        )
        for row, severity in enumerate(severities, start=1):
            table.setStyle(TableStyle([("TEXTCOLOR", (0, row), (0, row), SEVERITY_COLORS[severity])]))
        return [Paragraph("Finding distribution", styles["h1"]), table]

    def _detailed_findings(
        self, result: AuditResult, styles: dict[str, ParagraphStyle]
    ) -> list[object]:
        elements: list[object] = [Paragraph("Detailed findings", styles["h1"])]
        if not result.findings:
            return elements + [Paragraph("No findings were generated.", styles["body"])]
        for index, finding in enumerate(result.findings, start=1):
            elements.append(self._finding_block(index, finding, styles))
            elements.append(Spacer(1, 7))
        return elements

    def _finding_block(
        self, index: int, finding: Finding, styles: dict[str, ParagraphStyle]
    ) -> KeepTogether:
        standards = ", ".join(
            f"{reference.framework} {reference.version} {reference.control_id}"
            for reference in finding.standards
        ) or "None"
        attack = ", ".join(
            f"{reference.technique_id} {reference.name} (context only)"
            for reference in finding.related_attack
        ) or "No ATT&CK relationship assigned"
        title = Paragraph(
            f"<b>{index}. {escape(finding.title)}</b>",
            styles["h2"],
        )
        badge = Paragraph(
            f"<b>{escape(finding.severity)}</b>",
            ParagraphStyle(
                f"Badge{index}",
                parent=styles["small"],
                textColor=colors.white,
                alignment=TA_CENTER,
            ),
        )
        header = Table([[title, badge]], colWidths=[142 * mm, 30 * mm])
        header.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (1, 0), (1, 0), SEVERITY_COLORS[finding.severity]),
                    ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                    ("LEFTPADDING", (0, 0), (0, 0), 0),
                    ("RIGHTPADDING", (1, 0), (1, 0), 5),
                    ("TOPPADDING", (1, 0), (1, 0), 5),
                    ("BOTTOMPADDING", (1, 0), (1, 0), 5),
                ]
            )
        )
        rows = [
            ["Finding ID", escape(finding.finding_id)],
            ["Affected rule", escape(finding.rule_id)],
            ["Why it matters", escape(finding.description)],
            ["Evidence", escape(finding.evidence)],
            ["Remediation", escape(finding.recommendation)],
            ["Selected mappings", escape(standards)],
            ["Related ATT&CK", escape(attack)],
            ["Risk model", f"Likelihood {finding.likelihood}/5 | Impact {finding.impact}/5 | Confidence {escape(finding.confidence)}"],
        ]
        wrapped = [
            [Paragraph(f"<b>{escape(label)}</b>", styles["small"]), Paragraph(value, styles["small"])]
            for label, value in rows
        ]
        details = Table(wrapped, colWidths=[33 * mm, 139 * mm])
        details.setStyle(
            TableStyle(
                [
                    ("GRID", (0, 0), (-1, -1), 0.35, BORDER),
                    ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#F8FAFC")),
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                    ("TOPPADDING", (0, 0), (-1, -1), 4),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
                ]
            )
        )
        return KeepTogether([header, details])

    def _standards_alignment(
        self, result: AuditResult, styles: dict[str, ParagraphStyle]
    ) -> list[object]:
        elements: list[object] = [
            PageBreak(),
            Paragraph("Selected standards alignment", styles["h1"]),
            Paragraph(
                "These checks map detected evidence to selected framework outcomes. A pass means only "
                "that FirewallGuard found no gap for the implemented pattern; it does not establish full compliance.",
                styles["small"],
            ),
            Spacer(1, 6),
        ]
        rows: list[list[object]] = [["Framework", "Control", "Result", "Evidence"]]
        for assessment in result.standards:
            for check in assessment.checks:
                rows.append(
                    [
                        Paragraph(f"{escape(check.framework)} {escape(check.version)}", styles["small"]),
                        Paragraph(f"<b>{escape(check.control_id)}</b><br/>{escape(check.title)}", styles["small"]),
                        Paragraph(escape(check.status), styles["small"]),
                        Paragraph(
                            escape(", ".join(check.evidence) if check.evidence else "No mapped finding"),
                            styles["small"],
                        ),
                    ]
                )
        table = LongTable(rows, colWidths=[30 * mm, 77 * mm, 28 * mm, 37 * mm], repeatRows=1)
        table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, 0), NAVY),
                    ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                    ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                    ("FONTSIZE", (0, 0), (-1, 0), 7.5),
                    ("GRID", (0, 0), (-1, -1), 0.35, BORDER),
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                    ("TOPPADDING", (0, 0), (-1, -1), 4),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
                ]
            )
        )
        elements.append(table)
        return elements

    def _methodology(self, result: AuditResult, styles: dict[str, ParagraphStyle]) -> list[object]:
        warnings = (
            "<br/>".join(f"- {escape(warning)}" for warning in result.parser_warnings)
            if result.parser_warnings
            else "None"
        )
        return [
            Paragraph("Methodology and limitations", styles["h1"]),
            Paragraph(escape(result.methodology), styles["body"]),
            Spacer(1, 4),
            Paragraph(
                "The analyzer does not prove exploitability, adversary activity, organizational compliance, "
                "or business impact. NAT, routing, statefulness, identity controls, asset criticality, and "
                "compensating controls require environment-specific validation.",
                styles["body"],
            ),
            Paragraph("Parser warnings", styles["h2"]),
            Paragraph(warnings, styles["small"]),
        ]

    def _rule_appendix(self, result: AuditResult, styles: dict[str, ParagraphStyle]) -> list[object]:
        rows: list[list[object]] = [["ID", "Chain", "Action", "Protocol", "Source", "Destination", "Ports"]]
        for rule in result.rules:
            rows.append(
                [
                    Paragraph(escape(rule.rule_id), styles["small"]),
                    Paragraph(escape(rule.chain), styles["small"]),
                    Paragraph(escape(rule.action), styles["small"]),
                    Paragraph(escape(rule.protocol), styles["small"]),
                    Paragraph(escape(rule.source), styles["small"]),
                    Paragraph(escape(rule.destination), styles["small"]),
                    Paragraph(escape(rule.port), styles["small"]),
                ]
            )
        table = LongTable(
            rows,
            colWidths=[22 * mm, 20 * mm, 18 * mm, 20 * mm, 32 * mm, 35 * mm, 25 * mm],
            repeatRows=1,
        )
        table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, 0), NAVY),
                    ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                    ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                    ("FONTSIZE", (0, 0), (-1, 0), 7),
                    ("GRID", (0, 0), (-1, -1), 0.3, BORDER),
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                    ("TOPPADDING", (0, 0), (-1, -1), 3),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
                ]
            )
        )
        return [Paragraph("Appendix A - normalized rules", styles["h1"]), table]
