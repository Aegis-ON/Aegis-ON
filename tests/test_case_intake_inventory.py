import hashlib
import json
from pathlib import Path
import subprocess
import sys
from tempfile import TemporaryDirectory
import unittest


class CaseIntakeInventoryTests(unittest.TestCase):
    def setUp(self) -> None:
        directory = TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        self.original = self.root / "original"
        self.intake = self.root / "intake"
        for filename in ("cases/demo/event.json", "manifest.json"):
            path = self.original / filename
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("fixture", encoding="utf-8")
        for filename in (
            "runtime_cases/demo/log.json", "synthetic_cases/demo/log.json",
            "label_manifest.jsonl", "training_split_manifest.jsonl",
            "labeling_guideline.md", "training_data_contract.json",
        ):
            path = self.intake / filename
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("fixture", encoding="utf-8")

    def run_inventory(self) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, "-m", "aegis_on.case_intake_inventory", "--original",
             str(self.original), "--intake", str(self.intake)],
            capture_output=True, text=True, timeout=10,
        )

    def test_cli_hashes_nested_evidence_and_reports_relative_paths(self) -> None:
        evidence = b"fixture-evidence"
        (self.original / "cases/demo/event.json").write_bytes(evidence)

        result = self.run_inventory()

        self.assertEqual(result.returncode, 0, result.stderr)
        rows = json.loads(result.stdout)["original"]["files"]
        self.assertIn(
            {"path": "cases/demo/event.json", "bytes": len(evidence),
             "sha256": hashlib.sha256(evidence).hexdigest()},
            rows,
        )
        self.assertNotIn(str(self.root), result.stdout)

    def test_cli_fails_when_intake_manifest_is_missing(self) -> None:
        (self.intake / "training_split_manifest.jsonl").unlink()

        result = self.run_inventory()

        self.assertEqual(result.returncode, 1)
        self.assertIn({"path": "training_split_manifest.jsonl", "reason": "required_file_missing"},
                      json.loads(result.stdout)["intake"]["issues"])

    def test_cli_does_not_follow_links_to_evidence_outside_the_package(self) -> None:
        outside = self.root / "outside"
        outside.write_bytes(b"outside")
        try:
            (self.original / "cases/external.json").symlink_to(outside)
        except (NotImplementedError, OSError):
            self.skipTest("creating symbolic links requires platform support")

        result = self.run_inventory()

        self.assertEqual(result.returncode, 1)
        original = json.loads(result.stdout)["original"]
        self.assertIn({"path": "cases/external.json", "reason": "unsupported_entry"}, original["issues"])
        self.assertNotIn(hashlib.sha256(b"outside").hexdigest(), result.stdout)
