import unittest

from audit_engine.models import Finding
from audit_engine.scoring import SecurityScorer


def finding(rule_id="R1", severity="HIGH", points=20, suffix="A"):
    return Finding(
        finding_id=f"F-{suffix}:{rule_id}",
        rule_id=rule_id,
        finding_type=f"F-{suffix}",
        title="Test",
        severity=severity,
        description="Test",
        evidence="Test",
        recommendation="Test",
        risk_points=points,
        likelihood=3,
        impact=3,
    )


class ScoringTests(unittest.TestCase):
    def setUp(self):
        self.scorer = SecurityScorer()

    def test_clean_configuration_scores_100(self):
        self.assertEqual(self.scorer.calculate([]), (100, "LOW"))

    def test_informational_findings_do_not_reduce_score(self):
        self.assertEqual(self.scorer.calculate([finding(severity="INFO", points=0)]), (100, "LOW"))

    def test_one_high_finding_is_moderate(self):
        self.assertEqual(self.scorer.calculate([finding(points=20)]), (80, "MODERATE"))

    def test_multiple_rules_accumulate(self):
        score, risk = self.scorer.calculate([finding("R1"), finding("R2")])
        self.assertEqual((score, risk), (60, "HIGH"))

    def test_same_rule_additional_findings_are_capped(self):
        score, _ = self.scorer.calculate(
            [finding("R1", points=28, suffix="A"), finding("R1", points=20, suffix="B"), finding("R1", points=18, suffix="C")]
        )
        self.assertEqual(score, 64)

    def test_score_never_drops_below_zero(self):
        findings = [finding(str(index), points=28) for index in range(10)]
        self.assertEqual(self.scorer.calculate(findings), (0, "CRITICAL"))


if __name__ == "__main__":
    unittest.main()
