import unittest

from audit_engine.detectors import FirewallDetectorEngine, ports_include
from audit_engine.models import FirewallRule


def rule(rule_id="R1", **overrides):
    values = {
        "rule_id": rule_id,
        "name": "test",
        "action": "allow",
        "protocol": "tcp",
        "source": "any",
        "destination": "10.0.0.10",
        "port": "443",
        "enabled": True,
        "chain": "INPUT",
        "direction": "inbound",
    }
    values.update(overrides)
    return FirewallRule(**values)


class DetectorTests(unittest.TestCase):
    def setUp(self):
        self.engine = FirewallDetectorEngine()

    def types(self, rules):
        return [finding.finding_type for finding in self.engine.run(rules)]

    def test_any_any_allow_is_critical(self):
        findings = self.engine.run([rule(source="any", destination="any", port="any")])
        self.assertEqual([f.severity for f in findings], ["CRITICAL"])

    def test_disabled_any_any_is_not_active_exposure(self):
        findings = self.engine.run(
            [rule(source="any", destination="any", port="any", enabled=False)]
        )
        self.assertEqual(self.types([rule(source="any", destination="any", port="any", enabled=False)]), ["DISABLED_RULE_HYGIENE"])
        self.assertEqual(findings[0].risk_points, 0)

    def test_deny_ssh_is_not_exposure(self):
        self.assertEqual(self.engine.run([rule(action="deny", port="22")]), [])

    def test_public_ssh_is_detected(self):
        findings = self.engine.run([rule(port="22")])
        self.assertIn("PUBLIC_ADMIN_SERVICE", [f.finding_type for f in findings])
        self.assertEqual(findings[0].related_attack[0].technique_id, "T1021.004")

    def test_public_rdp_uses_specific_attack_subtechnique(self):
        finding = self.engine.run([rule(port="3389")])[0]
        self.assertEqual(finding.related_attack[0].technique_id, "T1021.001")

    def test_public_database_is_detected(self):
        self.assertIn("PUBLIC_DATABASE_SERVICE", self.types([rule(port="3306")]))

    def test_public_smb_is_detected(self):
        self.assertIn("PUBLIC_SMB_SERVICE", self.types([rule(port="445")]))

    def test_internal_database_is_not_public_exposure(self):
        self.assertNotIn(
            "PUBLIC_DATABASE_SERVICE", self.types([rule(source="10.0.0.0/24", port="3306")])
        )

    def test_cleartext_internal_ftp_is_medium(self):
        findings = self.engine.run([rule(source="10.0.0.0/24", port="21")])
        cleartext = next(f for f in findings if f.finding_type == "CLEARTEXT_SERVICE")
        self.assertEqual(cleartext.severity, "MEDIUM")

    def test_loopback_any_any_is_not_exposure(self):
        self.assertEqual(
            self.engine.run(
                [rule(source="any", destination="any", port="any", in_interface="lo")]
            ),
            [],
        )

    def test_established_return_rule_is_not_exposure(self):
        self.assertEqual(
            self.engine.run(
                [
                    rule(
                        source="any",
                        destination="any",
                        port="any",
                        connection_states=("ESTABLISHED", "RELATED"),
                    )
                ]
            ),
            [],
        )

    def test_duplicate_rule_is_detected_once(self):
        findings = self.engine.run([rule("R1"), rule("R2")])
        self.assertEqual(self.types([rule("R1"), rule("R2")]).count("DUPLICATE_RULE"), 1)
        self.assertEqual(len([f for f in findings if f.finding_type == "SHADOWED_RULE"]), 0)

    def test_conflicting_shadowed_rule_is_high(self):
        broad = rule("R1", source="any", destination="any", port="any", action="deny")
        narrow = rule("R2", source="10.0.0.0/24", destination="10.0.0.10", port="443")
        finding = next(
            f for f in self.engine.run([broad, narrow]) if f.finding_type == "SHADOWED_RULE"
        )
        self.assertEqual(finding.severity, "HIGH")

    def test_interface_specific_rule_does_not_shadow_other_interfaces(self):
        loopback = rule("R1", source="any", destination="any", port="any", in_interface="lo")
        https = rule("R2", port="443", in_interface="eth0")
        self.assertNotIn("SHADOWED_RULE", self.types([loopback, https]))

    def test_port_range_overlap(self):
        self.assertEqual(ports_include("20-25,443", [21, 22, 80, 443]), {21, 22, 443})


if __name__ == "__main__":
    unittest.main()
