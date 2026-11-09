import unittest

from aegis_on.engine import DetectionPipeline
from aegis_on.models import SecurityEvent
from aegis_on.privacy import redact_text


class AegisPipelineTests(unittest.TestCase):
    def test_sensitive_values_are_pseudonymized_for_display(self):
        result = redact_text("analyst@example.org connected to 10.20.30.40")
        self.assertNotIn("analyst@example.org", result)
        self.assertNotIn("10.20.30.40", result)
        self.assertIn("[EMAIL:", result)
        self.assertIn("[IP:", result)

    def test_data_destruction_requires_human_approval(self):
        event = SecurityEvent.from_mapping(
            {
                "timestamp": "2026-11-09T10:00:00Z",
                "host": "LAB-01",
                "user": "admin",
                "process": "cmd.exe",
                "command_line": "cmd.exe /c del /s /q C:\\temp",
            }
        )
        findings = DetectionPipeline().analyze([event])
        destructive = [finding for finding in findings if finding.technique == "T1485"]
        self.assertTrue(destructive)
        self.assertTrue(any(finding.requires_human_approval for finding in destructive))

    def test_fanout_is_correlated(self):
        events = [
            SecurityEvent.from_mapping(
                {
                    "timestamp": f"2026-11-09T10:0{index}:00Z",
                    "host": "LAB-01",
                    "user": "analyst",
                    "process": "net.exe",
                    "command_line": "net view",
                    "destination": f"10.0.0.{index + 10}",
                }
            )
            for index in range(3)
        ]
        findings = DetectionPipeline().analyze(events)
        self.assertTrue(any(finding.technique == "T1595" for finding in findings))


if __name__ == "__main__":
    unittest.main()
