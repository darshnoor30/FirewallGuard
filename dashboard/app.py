"""Streamlit interface for the FirewallGuard audit engine."""

from __future__ import annotations

import json
import sys
from dataclasses import asdict
from pathlib import Path

import pandas as pd
import streamlit as st

ROOT_DIR = Path(__file__).resolve().parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from audit_engine.parser import InvalidFirewallConfigError  # noqa: E402
from audit_engine.service import FirewallAuditService  # noqa: E402
from dashboard.charts import (  # noqa: E402
    finding_type_chart,
    posture_gauge,
    risk_matrix,
    severity_chart,
    standards_chart,
)
from reports.pdf_reporter import PDFReporter  # noqa: E402

MAX_UPLOAD_BYTES = 2 * 1024 * 1024
SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]

st.set_page_config(
    page_title="FirewallGuard | Explainable Firewall Audit",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

st.markdown(
    """
    <style>
      .stApp { background: linear-gradient(135deg, #07101f 0%, #0f172a 55%, #111827 100%); }
      [data-testid="stMetric"] { background: rgba(15, 23, 42, .72); border: 1px solid #273449;
        border-radius: 14px; padding: 14px; }
      [data-testid="stMetricLabel"] { color: #94a3b8; }
      div[data-testid="stAlert"] { border-radius: 12px; }
      .fg-kicker { color: #60a5fa; font-weight: 700; letter-spacing: .12em; font-size: .78rem; }
      .fg-subtitle { color: #94a3b8; max-width: 850px; }
      .fg-badge { display: inline-block; padding: .25rem .65rem; border: 1px solid #334155;
        border-radius: 999px; color: #cbd5e1; margin: .15rem .25rem .15rem 0; font-size: .78rem; }
    </style>
    """,
    unsafe_allow_html=True,
)


@st.cache_data(show_spinner=False)
def run_audit(text: str, source_name: str, input_format: str):
    return FirewallAuditService().audit_text(
        text, source_name=source_name, input_format=input_format
    )


def load_input() -> tuple[str, str, str] | None:
    st.sidebar.markdown("## Analyze configuration")
    mode = st.sidebar.radio("Input source", ["Guided sample", "Upload file"])
    if mode == "Guided sample":
        samples = {
            "Vulnerable JSON - findings demo": ROOT_DIR / "sample_configs" / "vulnerable_firewall.json",
            "Hardened JSON - clean baseline": ROOT_DIR / "sample_configs" / "corporate_firewall.json",
            "Vulnerable iptables-save": ROOT_DIR / "sample_configs" / "iptables_vulnerable.rules",
            "Hardened iptables-save": ROOT_DIR / "sample_configs" / "iptables_hardened.rules",
        }
        label = st.sidebar.selectbox("Configuration", list(samples))
        path = samples[label]
        return path.read_text(encoding="utf-8"), path.name, "auto"

    uploaded = st.sidebar.file_uploader(
        "Upload JSON or iptables-save text",
        type=["json", "txt", "rules", "conf"],
        help="Maximum 2 MiB. Review sensitive configurations before uploading.",
    )
    selected_format = st.sidebar.selectbox("Format", ["auto", "json", "iptables"])
    if uploaded is None:
        return None
    raw = uploaded.getvalue()
    if len(raw) > MAX_UPLOAD_BYTES:
        st.sidebar.error("The file exceeds the 2 MiB safety limit.")
        return None
    try:
        return raw.decode("utf-8-sig"), uploaded.name, selected_format
    except UnicodeDecodeError:
        st.sidebar.error("Configuration must be UTF-8 text.")
        return None


st.markdown('<div class="fg-kicker">EXPLAINABLE NETWORK SECURITY</div>', unsafe_allow_html=True)
st.title("🛡️ FirewallGuard")
st.markdown(
    '<div class="fg-subtitle">Deterministic firewall policy analysis for custom JSON and real '
    'iptables-save configurations. Every finding includes evidence, remediation, selected standards '
    'references, and clearly labelled MITRE ATT&CK context.</div>',
    unsafe_allow_html=True,
)
st.markdown(
    '<span class="fg-badge">JSON + iptables-save</span>'
    '<span class="fg-badge">Explainable findings</span>'
    '<span class="fg-badge">In-memory PDF</span>'
    '<span class="fg-badge">No compliance overclaim</span>',
    unsafe_allow_html=True,
)

selected = load_input()
if selected is None:
    st.info("Choose a guided sample or upload a configuration to begin.")
    st.stop()

text, source_name, input_format = selected
try:
    result = run_audit(text, source_name, input_format)
except InvalidFirewallConfigError as exc:
    st.error(f"Configuration could not be analyzed: {exc}")
    st.stop()
except Exception:
    st.error("An unexpected analysis error occurred. Review the application logs for details.")
    st.stop()

st.sidebar.divider()
st.sidebar.caption(f"Audit {result.audit_id}")
st.sidebar.caption(f"Input SHA-256: {result.input_sha256[:16]}...")
st.sidebar.warning(
    "Selected technical alignment checks only. Results are not a compliance certification or proof of compromise."
)

critical = sum(f.severity == "CRITICAL" for f in result.findings)
high = sum(f.severity == "HIGH" for f in result.findings)
metric_columns = st.columns(5)
metric_columns[0].metric("Posture score", f"{result.posture_score}/100")
metric_columns[1].metric("Risk", result.risk_classification)
metric_columns[2].metric("Critical", critical)
metric_columns[3].metric("High", high)
metric_columns[4].metric("Rules", result.total_rules)

overview_tab, findings_tab, rules_tab, standards_tab, export_tab = st.tabs(
    ["Overview", "Findings", "Normalized rules", "Standards", "Export"]
)

with overview_tab:
    left, right = st.columns([0.9, 1.1])
    with left:
        st.plotly_chart(posture_gauge(result.posture_score), width="stretch")
    with right:
        st.plotly_chart(severity_chart(result.findings), width="stretch")
    left, right = st.columns(2)
    with left:
        st.plotly_chart(finding_type_chart(result.findings), width="stretch")
    with right:
        st.plotly_chart(risk_matrix(result.findings), width="stretch")
    if result.parser_warnings:
        with st.expander(f"Parser warnings ({len(result.parser_warnings)})"):
            for warning in result.parser_warnings:
                st.write(f"- {warning}")

with findings_tab:
    selected_severities = st.multiselect(
        "Severity filter", SEVERITIES, default=SEVERITIES
    )
    visible_findings = [
        finding for finding in result.findings if finding.severity in selected_severities
    ]
    if not visible_findings:
        st.success("No findings match the selected filter.")
    for finding in visible_findings:
        label = f"{finding.severity} | {finding.rule_id} | {finding.title}"
        with st.expander(label, expanded=finding.severity in {"CRITICAL", "HIGH"}):
            st.markdown(f"**Why it matters:** {finding.description}")
            st.code(finding.evidence, language=None)
            st.markdown(f"**Recommended action:** {finding.recommendation}")
            st.markdown(
                f"**Risk model:** likelihood {finding.likelihood}/5, impact {finding.impact}/5, "
                f"confidence {finding.confidence}"
            )
            if finding.standards:
                st.markdown(
                    "**Selected references:** "
                    + ", ".join(
                        f"{ref.framework} {ref.version} {ref.control_id}"
                        for ref in finding.standards
                    )
                )
            if finding.related_attack:
                st.markdown("**Related ATT&CK context (not observed activity):**")
                for reference in finding.related_attack:
                    st.markdown(
                        f"- [{reference.technique_id} - {reference.name}]({reference.source_url}): "
                        f"{reference.relationship}"
                    )

with rules_tab:
    rules_frame = pd.DataFrame([asdict(rule) for rule in result.rules])
    preferred = [
        "rule_id",
        "chain",
        "direction",
        "action",
        "protocol",
        "source",
        "destination",
        "port",
        "enabled",
        "name",
    ]
    st.dataframe(rules_frame[preferred], width="stretch", hide_index=True)

with standards_tab:
    st.warning(
        "A 'NO_GAP_DETECTED' result applies only to an implemented configuration pattern. "
        "It does not establish organizational compliance."
    )
    st.plotly_chart(standards_chart(result.standards), width="stretch")
    rows = []
    for assessment in result.standards:
        for check in assessment.checks:
            rows.append(
                {
                    "Framework": f"{check.framework} {check.version}",
                    "Control": check.control_id,
                    "Outcome": check.status,
                    "Evidence": ", ".join(check.evidence) or "No mapped finding",
                    "Reference": check.source_url,
                }
            )
    st.dataframe(pd.DataFrame(rows), width="stretch", hide_index=True)

with export_tab:
    st.subheader("Evidence package")
    st.write(
        "Exports include the audit ID, input hash, normalized rules, evidence, remediation, "
        "methodology, and standards-alignment disclaimer."
    )
    findings_frame = pd.DataFrame(
        [
            {
                "Finding ID": finding.finding_id,
                "Rule ID": finding.rule_id,
                "Severity": finding.severity,
                "Title": finding.title,
                "Evidence": finding.evidence,
                "Recommendation": finding.recommendation,
            }
            for finding in result.findings
        ]
    )
    col1, col2, col3 = st.columns(3)
    col1.download_button(
        "Download JSON",
        data=json.dumps(result.to_dict(), indent=2),
        file_name=f"{result.audit_id.lower()}-audit.json",
        mime="application/json",
        width="stretch",
    )
    col2.download_button(
        "Download findings CSV",
        data=findings_frame.to_csv(index=False),
        file_name=f"{result.audit_id.lower()}-findings.csv",
        mime="text/csv",
        width="stretch",
        disabled=findings_frame.empty,
    )
    col3.download_button(
        "Download PDF report",
        data=PDFReporter().generate(result),
        file_name=f"{result.audit_id.lower()}-report.pdf",
        mime="application/pdf",
        width="stretch",
    )

st.divider()
st.caption(
    "FirewallGuard 2.0 | Defensive configuration analysis | Results require human validation"
)
