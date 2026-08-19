import tempfile
import unittest
from pathlib import Path

from audit_engine.service import FirewallAuditService
from reports.pdf_reporter import PDFReporter

CONFIG = """{
  "rules": [{
    "rule_id": "R1", "name": "Public SSH", "action": "allow",
    "protocol": "tcp", "source": "any", "destination": "10.0.0.5",
    "port": "22", "enabled": true, "chain": "INPUT"
  }]
}"""


class ReportingTests(unittest.TestCase):
    def setUp(self):
        self.result = FirewallAuditService().audit_text(CONFIG, "test.json", "json")

    def test_pdf_is_generated_in_memory(self):
        payload = PDFReporter().generate(self.result)
        self.assertTrue(payload.startswith(b"%PDF"))
        self.assertGreater(len(payload), 5000)

    def test_pdf_writer_creates_parent_directory(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "nested" / "report.pdf"
            PDFReporter().write(self.result, target)
            self.assertTrue(target.is_file())

    def test_result_contains_reproducibility_metadata(self):
        self.assertTrue(self.result.audit_id.startswith("FG-"))
        self.assertEqual(len(self.result.input_sha256), 64)
        self.assertEqual(self.result.source_name, "test.json")


if __name__ == "__main__":
    unittest.main()
