"""Transparent posture scoring for prioritization, not certification."""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Iterable

from audit_engine.models import Finding


class SecurityScorer:
    """Calculate a deterministic 0-100 posture score.

    Only the highest-risk finding per rule receives its full weight. Additional
    independent findings on the same rule add a small, capped penalty. This
    prevents a single broad rule from being counted repeatedly without hiding
    materially different weaknesses.
    """

    def calculate(self, findings: Iterable[Finding]) -> tuple[int, str]:
        grouped: dict[str, list[int]] = defaultdict(list)
        for finding in findings:
            if finding.risk_points > 0:
                grouped[finding.rule_id].append(finding.risk_points)

        penalty = 0
        for points in grouped.values():
            ordered = sorted(points, reverse=True)
            penalty += ordered[0]
            penalty += min(8, sum(max(1, value // 4) for value in ordered[1:]))

        score = max(0, 100 - min(100, penalty))
        if score >= 90:
            risk = "LOW"
        elif score >= 75:
            risk = "MODERATE"
        elif score >= 50:
            risk = "HIGH"
        else:
            risk = "CRITICAL"
        return score, risk
