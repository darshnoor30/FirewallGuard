import unittest

from audit_engine.service import FirewallAuditService

HARDENED = """*filter
:INPUT DROP [0:0]
:FORWARD DROP [0:0]
:OUTPUT ACCEPT [0:0]
-A INPUT -p tcp -s 10.0.0.0/24 --dport 22 -j ACCEPT
COMMIT
"""

VULNERABLE = """*filter
:INPUT ACCEPT [0:0]
:FORWARD DROP [0:0]
:OUTPUT ACCEPT [0:0]
-A INPUT -p tcp -s 0.0.0.0/0 --dport 3389 -j ACCEPT
COMMIT
"""


class StandardsAlignmentTests(unittest.TestCase):
    def setUp(self):
        self.service = FirewallAuditService()

    def test_hardened_sample_has_no_mapped_gaps(self):
        result = self.service.audit_text(HARDENED, input_format="iptables")
        self.assertTrue(all(item.status == "NO_GAPS_DETECTED" for item in result.standards))

    def test_vulnerable_sample_requires_action(self):
        result = self.service.audit_text(VULNERABLE, input_format="iptables")
        self.assertTrue(all(item.status == "ACTION_REQUIRED" for item in result.standards))

    def test_framework_versions_are_explicit(self):
        result = self.service.audit_text(HARDENED, input_format="iptables")
        self.assertEqual([(a.framework, a.version) for a in result.standards], [("NIST CSF", "2.0"), ("CIS Controls", "8.1")])

    def test_assessments_include_non_certification_disclaimer(self):
        result = self.service.audit_text(HARDENED, input_format="iptables")
        self.assertTrue(all("not a compliance" in item.disclaimer for item in result.standards))


if __name__ == "__main__":
    unittest.main()
