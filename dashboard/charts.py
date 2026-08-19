"""Plotly visualizations for the FirewallGuard dashboard."""

from __future__ import annotations

from collections import Counter

import pandas as pd
import plotly.express as px
import plotly.graph_objects as go

SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
SEVERITY_COLORS = {
    "CRITICAL": "#DC2626",
    "HIGH": "#F97316",
    "MEDIUM": "#EAB308",
    "LOW": "#3B82F6",
    "INFO": "#64748B",
}


def _theme(fig: go.Figure, height: int = 390) -> go.Figure:
    fig.update_layout(
        height=height,
        margin=dict(l=20, r=20, t=55, b=30),
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(15,23,42,0.35)",
        font=dict(color="#E2E8F0"),
        title_font=dict(size=16),
        legend_title_text="",
    )
    return fig


def posture_gauge(score: int) -> go.Figure:
    fig = go.Figure(
        go.Indicator(
            mode="gauge+number",
            value=score,
            number={"suffix": "/100", "font": {"size": 34}},
            title={"text": "Configuration posture"},
            gauge={
                "axis": {"range": [0, 100]},
                "bar": {"color": "#60A5FA"},
                "steps": [
                    {"range": [0, 50], "color": "#7F1D1D"},
                    {"range": [50, 75], "color": "#9A3412"},
                    {"range": [75, 90], "color": "#854D0E"},
                    {"range": [90, 100], "color": "#166534"},
                ],
            },
        )
    )
    return _theme(fig, 315)


def severity_chart(findings) -> go.Figure:  # noqa: ANN001
    counts = Counter(finding.severity for finding in findings)
    frame = pd.DataFrame(
        {"Severity": SEVERITY_ORDER, "Count": [counts.get(level, 0) for level in SEVERITY_ORDER]}
    )
    fig = px.bar(
        frame,
        x="Severity",
        y="Count",
        color="Severity",
        color_discrete_map=SEVERITY_COLORS,
        title="Findings by severity",
        text_auto=True,
        category_orders={"Severity": SEVERITY_ORDER},
    )
    fig.update_traces(showlegend=False)
    return _theme(fig)


def finding_type_chart(findings) -> go.Figure:  # noqa: ANN001
    counts = Counter(finding.finding_type for finding in findings)
    frame = pd.DataFrame(
        sorted(counts.items(), key=lambda item: item[1], reverse=True),
        columns=["Finding type", "Count"],
    )
    if frame.empty:
        frame = pd.DataFrame({"Finding type": ["No findings"], "Count": [0]})
    fig = px.bar(
        frame,
        x="Count",
        y="Finding type",
        orientation="h",
        title="Most frequent finding types",
        text_auto=True,
        color_discrete_sequence=["#60A5FA"],
    )
    fig.update_layout(yaxis={"categoryorder": "total ascending"})
    return _theme(fig)


def risk_matrix(findings) -> go.Figure:  # noqa: ANN001
    matrix = [[0 for _ in range(5)] for _ in range(5)]
    labels: dict[tuple[int, int], list[str]] = {}
    for finding in findings:
        matrix[5 - finding.impact][finding.likelihood - 1] += 1
        labels.setdefault((finding.likelihood, finding.impact), []).append(finding.finding_id)
    hover = []
    for impact in range(5, 0, -1):
        hover.append(
            [
                "<br>".join(labels.get((likelihood, impact), [])) or "No findings"
                for likelihood in range(1, 6)
            ]
        )
    fig = go.Figure(
        data=go.Heatmap(
            z=matrix,
            x=[1, 2, 3, 4, 5],
            y=[5, 4, 3, 2, 1],
            text=hover,
            hovertemplate="Likelihood %{x}/5<br>Impact %{y}/5<br>%{text}<extra></extra>",
            colorscale=[
                [0.0, "#162033"],
                [0.25, "#1D4ED8"],
                [0.5, "#EAB308"],
                [0.75, "#F97316"],
                [1.0, "#DC2626"],
            ],
            colorbar={"title": "Findings"},
        )
    )
    fig.update_layout(
        title="Risk matrix: likelihood vs impact",
        xaxis_title="Likelihood",
        yaxis_title="Impact",
    )
    return _theme(fig)


def standards_chart(assessments) -> go.Figure:  # noqa: ANN001
    rows = []
    for assessment in assessments:
        label = f"{assessment.framework} {assessment.version}"
        rows.extend(
            [
                {"Framework": label, "Outcome": "No gap detected", "Checks": assessment.checks_passed},
                {"Framework": label, "Outcome": "Gap", "Checks": assessment.checks_flagged},
            ]
        )
    frame = pd.DataFrame(rows)
    fig = px.bar(
        frame,
        x="Framework",
        y="Checks",
        color="Outcome",
        barmode="stack",
        title="Implemented standards-alignment checks",
        color_discrete_map={"No gap detected": "#22C55E", "Gap": "#EF4444"},
        text_auto=True,
    )
    return _theme(fig)
