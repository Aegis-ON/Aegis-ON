from hashlib import sha256
import json
from pathlib import Path
from shutil import copytree
from tempfile import TemporaryDirectory
import unittest

from aegis_on.case_intake_inventory import PackageIntegrityError
from aegis_on.case_manifest import CaseManifestError, load_cases


PACKAGE = Path(__file__).resolve().parents[1] / "datasets" / "agent_framework_eval_intake_2026-11-21"


class CaseManifestTests(unittest.TestCase):
    def copy_package(self) -> Path:
        directory = TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        return copytree(PACKAGE, Path(directory.name) / "intake")

    def test_published_cases_keep_actual_and_synthetic_admission_separate(self) -> None:
        cases = load_cases(PACKAGE)

        actual = [case for case in cases if not case.label.synthetic]
        synthetic = [case for case in cases if case.label.synthetic]
        self.assertEqual([case.split.split for case in actual], ["not_assigned"] * 5)
        self.assertEqual([case.split.split for case in synthetic], ["synthetic_demo"] * 2)
        incident = next(case for case in synthetic if case.label.label == "confirmed_security_incident")
        self.assertEqual(incident.label.display_label, "simulated_confirmed_security_incident")
        self.assertTrue(incident.label.not_actual_incident)

    def test_modification_to_evidence_fails_checksum(self) -> None:
        root = self.copy_package()
        first = json.loads((root / "label_manifest.jsonl").read_text().splitlines()[0])
        evidence = root / first["evidence_paths"][0]
        evidence.write_bytes(evidence.read_bytes() + b"\n")

        with self.assertRaisesRegex(PackageIntegrityError, "SHA-256 mismatch"):
            load_cases(root)

    def test_rehashed_manifests_still_enforce_case_and_split_contract(self) -> None:
        scenarios = (
            ("duplicate", "duplicate case_id"),
            ("production split", "invalid demo admission or split"),
            ("other case evidence", "outside its own case"),
            ("mismatched group", "identity fields differ"),
        )
        for name, error in scenarios:
            with self.subTest(name=name):
                root = self.copy_package()
                manifest = root / ("label_manifest.jsonl" if name == "other case evidence"
                                   else "training_split_manifest.jsonl")
                rows = [json.loads(line) for line in manifest.read_text().splitlines()]
                match name:
                    case "duplicate":
                        rows.append(rows[0].copy())
                    case "production split":
                        rows[0]["split"] = "test"
                    case "other case evidence":
                        rows[0]["evidence_paths"] = rows[1]["evidence_paths"]
                    case "mismatched group":
                        rows[0]["case_group"] = "other_group"
                manifest.write_text("".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8")
                sums = root / "SHA256SUMS.txt"
                lines = sums.read_text().splitlines()
                digest = sha256(manifest.read_bytes()).hexdigest()
                suffix = f"  ./{manifest.name}"
                sums.write_text("\n".join(digest + suffix if line.endswith(suffix) else line
                                          for line in lines) + "\n", encoding="utf-8")

                with self.assertRaisesRegex(CaseManifestError, error):
                    load_cases(root)
