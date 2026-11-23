import unittest
from linux_posture_audit import audit

class AuditTests(unittest.TestCase):
    def test_returns_structured_findings(self):
        findings = audit()
        self.assertIsInstance(findings, list)
        for finding in findings:
            self.assertIn("severity", finding)
            self.assertIn(finding["severity"], {"HIGH", "MEDIUM", "LOW", "INFO"})
            self.assertIn("recommendation", finding)

if __name__ == "__main__":
    unittest.main()
