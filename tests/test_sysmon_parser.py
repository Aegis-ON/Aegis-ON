import copy
import json
import unittest
from pathlib import Path
from uuid import UUID

from aegis_on.sysmon import parse_sysmon


def fixture():
    return json.loads(Path("data/demo_sysmon.json").read_text(encoding="utf-8"))


class SysmonParserTests(unittest.TestCase):
    def test_fixture_normalizes_all_fields_and_preserves_references(self):
        payload = fixture()
        events, items = parse_sysmon(payload)
        self.assertEqual(len(events), 5)
        self.assertEqual([item["status"] for item in items], ["processed"] * 5)
        self.assertEqual([item["event_id"] for item in items], [event["event_id"] for event in events])
        self.assertEqual(len({event["event_id"] for event in events}), 5)
        for event in events:
            UUID(event["event_id"])
        first = events[0]
        self.assertEqual(first["timestamp"], "2026-11-09T10:00:00+00:00")
        self.assertEqual(first["host"], "LAB-01")
        self.assertEqual(first["user"], "LAB\\analyst")
        self.assertEqual(first["process"], "cmd.exe")
        self.assertEqual(first["process_path"], r"C:\Windows\System32\cmd.exe")
        self.assertEqual(first["parent_process"], "explorer.exe")
        self.assertEqual(first["parent_process_path"], r"C:\Windows\explorer.exe")
        self.assertEqual(first["parent_command_line"], "explorer.exe")
        network = events[2]
        self.assertEqual(network["command_line"], "")
        self.assertEqual(network["destination"], "198.51.100.10")
        self.assertEqual(network["source_metadata"]["record_id"], 3)
        self.assertEqual(network["source_metadata"]["sysmon_event_id"], 3)
        self.assertEqual(network["source_metadata"]["process_id"], 1234)
        self.assertEqual(network["source_metadata"]["source_ip"], "192.0.2.10")
        self.assertEqual(network["source_metadata"]["source_port"], 50000)
        self.assertEqual(network["source_metadata"]["destination_port"], 443)

    def test_top_level_contract(self):
        for payload in (None, [], {}, {"events": None}, {"events": [None] * 1001}):
            with self.subTest(kind=type(payload).__name__):
                with self.assertRaises(ValueError):
                    parse_sysmon(payload)
        _, items = parse_sysmon({"events": [None] * 1000})
        self.assertEqual(len(items), 1000)
        self.assertEqual(parse_sysmon({"events": []}), ([], []))

    def test_record_errors_are_isolated_and_do_not_echo_values(self):
        good = fixture()["events"][0]
        bad_timestamp = copy.deepcopy(good)
        bad_timestamp["EventData"]["UtcTime"] = "sensitive-secret"
        unsupported = copy.deepcopy(good)
        unsupported["System"]["EventID"] = 99
        invalid_shape = {"System": {}, "EventData": "secret-value"}
        events, items = parse_sysmon({"events": [bad_timestamp, unsupported, invalid_shape, good]})
        self.assertEqual([i["status"] for i in items], ["invalid", "unsupported", "invalid", "processed"])
        self.assertEqual(len(events), 1)
        self.assertNotIn("sensitive-secret", str(items))
        self.assertNotIn("secret-value", str(items))
        self.assertEqual([i["input_index"] for i in items], list(range(4)))

    def test_timestamps_use_sysmon_utc_then_offset_aware_system_time(self):
        first = fixture()["events"][0]
        first["System"]["TimeCreated"] = "2026-11-09T20:00:00+09:00"
        normalized, _ = parse_sysmon({"events": [first]})
        self.assertEqual(normalized[0]["timestamp"], "2026-11-09T10:00:00+00:00")
        first["EventData"]["UtcTime"] = ""
        normalized, _ = parse_sysmon({"events": [first]})
        self.assertEqual(normalized[0]["timestamp"], "2026-11-09T11:00:00+00:00")
        first["System"]["TimeCreated"] = "2026-11-09T20:00:00"
        self.assertEqual(parse_sysmon({"events": [first]})[1][0]["status"], "invalid")
        first["EventData"]["UtcTime"] = "2026-11-09T10:00:00+09:00"
        self.assertEqual(parse_sysmon({"events": [first]})[1][0]["status"], "invalid")
        first["EventData"]["UtcTime"] = "2026-11-09"
        self.assertEqual(parse_sysmon({"events": [first]})[1][0]["status"], "invalid")

    def test_same_source_record_is_rejected_case_insensitively(self):
        first = fixture()["events"][0]
        second = copy.deepcopy(first)
        second["System"].update(Computer="lab-01", EventRecordID="01")
        events, items = parse_sysmon({"events": [first, second]})
        self.assertEqual(len(events), 1)
        self.assertEqual(items[1]["reason"], "duplicate source record")
        second["System"]["EventRecordID"] = None
        third = copy.deepcopy(second)
        events, items = parse_sysmon({"events": [first, second, third]})
        self.assertEqual(len(events), 3)
        self.assertEqual(len({event["event_id"] for event in events}), 3)

    def test_required_fields_ips_ports_and_paths(self):
        base = fixture()["events"][2]
        mutations = (
            ("System", "Computer", ""), ("System", "Channel", "not-sysmon"),
            ("EventData", "Image", "C:\\"),
            ("EventData", "DestinationIp", ""), ("EventData", "SourceIp", "not-an-ip"),
            ("EventData", "DestinationPort", "65536"), ("EventData", "SourcePort", True),
            ("EventData", "ProcessId", "-1"), ("System", "EventRecordID", "-1"),
            ("EventData", "ProcessGuid", "not-a-guid"), ("System", "Computer", "bad host"),
        )
        for section, key, value in mutations:
            with self.subTest(key=key):
                bad = copy.deepcopy(base)
                bad[section][key] = value
                self.assertEqual(parse_sysmon({"events": [bad]})[1][0]["status"], "invalid")
        process = fixture()["events"][0]
        process["EventData"]["CommandLine"] = ""
        process["EventData"]["User"] = ""
        self.assertEqual(parse_sysmon({"events": [process]})[1][0]["status"], "processed")


if __name__ == "__main__":
    unittest.main()
