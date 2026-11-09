import unittest
from datetime import datetime, timedelta, timezone

from aegis_on.engine import CorrelationEngine, RuleDetector
from aegis_on.models import SecurityEvent


def event(command="net view", *, minutes=0, seconds=0, destination="", event_id="event"):
    return SecurityEvent(
        timestamp=datetime(2026, 1, 1, tzinfo=timezone.utc) + timedelta(minutes=minutes, seconds=seconds),
        host="host-1",
        user="user",
        process="process",
        command_line=command,
        destination=destination,
        event_id=event_id,
    )


class DestructionRuleTests(unittest.TestCase):
    def test_non_recursive_rm_and_non_target_del_flags_do_not_match_path(self):
        for command in ("rm -f /tmp/report.txt", r"del /p C:\Users\test.txt"):
            with self.subTest(command=command):
                findings = RuleDetector().detect(event(command))
                self.assertFalse(any(item.technique == "T1485" for item in findings))

    def test_destructive_commands_still_match(self):
        for command in (
            "rm -rf /tmp/data", "rm -f -r /tmp/data", "rm --recursive /tmp/data",
            r"del /s /q C:\temp", "format C:", "mkfs /dev/sdb",
        ):
            with self.subTest(command=command):
                findings = RuleDetector().detect(event(command))
                self.assertTrue(any(item.technique == "T1485" for item in findings))

    def test_recursive_rm_with_long_option_value_is_detected(self):
        for command in (
            "rm --preserve-root=all -rf /tmp/data",
            "rm --interactive=never --recursive /tmp/data",
            "rm --verbose --interactive=never -rf /tmp/data",
        ):
            with self.subTest(command=command):
                findings = RuleDetector().detect(event(command))
                self.assertTrue(any(item.technique == "T1485" for item in findings))

    def test_long_option_value_containing_r_does_not_imply_recursive_rm(self):
        for command in (
            "rm --interactive=never -f /tmp/report.txt",
            "rm --preserve-root=all -f /tmp/data",
        ):
            with self.subTest(command=command):
                findings = RuleDetector().detect(event(command))
                self.assertFalse(any(item.technique == "T1485" for item in findings))


class CorrelationRegressionTests(unittest.TestCase):
    def test_separate_scan_windows_for_same_host_are_reported(self):
        events = [event(minutes=offset, destination=f"dst-{i}", event_id=f"e-{i}")
                  for i, offset in enumerate((0, 1, 2, 30, 31, 32))]
        findings = CorrelationEngine().detect_scan_fanout(events)
        self.assertEqual(2, len(findings))
        self.assertEqual([["e-0", "e-1", "e-2"], ["e-3", "e-4", "e-5"]],
                         [item.event_ids for item in findings])

    def test_window_includes_exactly_ten_minutes_but_not_later(self):
        first = [event(minutes=0, destination="a"), event(minutes=5, destination="b"),
                 event(minutes=10, destination="c")]
        second = [event(minutes=0, destination="a"), event(minutes=5, destination="b"),
                  event(minutes=10, seconds=1, destination="c")]
        self.assertEqual(1, len(CorrelationEngine().detect_scan_fanout(first)))
        self.assertEqual(0, len(CorrelationEngine().detect_scan_fanout(second)))

    def test_repeated_destinations_do_not_inflate_count_or_duplicate_alert(self):
        events = [event(minutes=i, destination=dst, event_id=f"e-{i}")
                  for i, dst in enumerate(("a", "a", "b", "c", "d"))]
        findings = CorrelationEngine().detect_scan_fanout(events)
        self.assertEqual(1, len(findings))
        self.assertEqual("4 unique destinations in ten minutes", findings[0].evidence[0])
        self.assertEqual([f"e-{i}" for i in range(5)], findings[0].event_ids)


if __name__ == "__main__":
    unittest.main()
