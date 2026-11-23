import json
from pathlib import Path
import subprocess
import sys
from tempfile import TemporaryDirectory
import unittest

from aegis_on.codebert_data import Case, SPLITS, Split, write_json
from aegis_on.codebert_input import sha256_file


class SplitAuditTests(unittest.TestCase):
    def setUp(self) -> None:
        directory = TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        self.cases: dict[Split, list[Case]] = {
            split: [
                Case(case_id=f"{split}-{label}", label=label, source_ref="fixture", evidence_ref="reviewer",
                     scenario_id=split, run_id=split, command_family=f"{split}-{label}",
                     investigation_id=f"{split}-{label}", command=f"echo {split}-{label}", status="eligible")
                for label in ("benign", "review")
            ]
            for split in SPLITS
        }

    def audit(self) -> subprocess.CompletedProcess[str]:
        hashes = {}
        for split, rows in self.cases.items():
            path = self.root / f"{split}.jsonl"
            path.write_text("".join(row.model_dump_json() + "\n" for row in rows), encoding="utf-8")
            hashes[split] = {"sha256": sha256_file(path)}
        write_json(self.root / "split-audit.json", {"eligible": True, "fixture": True,
                                                  "splits": hashes})
        return subprocess.run(
            [sys.executable, "-m", "aegis_on.codebert_data", "audit", "--splits", str(self.root)],
            capture_output=True, text=True, timeout=10,
        )

    def test_audit_accepts_three_independent_splits(self) -> None:
        result = self.audit()

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout)["test"], {
            "rows": 2,
            "groups": 1,
            "eligible_labels": {"benign": 1, "review": 1},
        })

    def test_audit_rejects_holdout_without_an_eligible_review_case(self) -> None:
        self.cases["test"][1] = self.cases["test"][1].model_copy(update={"status": "missing_command"})

        result = self.audit()

        self.assertEqual(result.returncode, 1)
        self.assertIn("both eligible classes are required in test", result.stderr)

    def test_audit_rejects_group_leakage_into_test_even_with_matching_hashes(self) -> None:
        self.cases["test"][0] = self.cases["test"][0].model_copy(
            update={"command": self.cases["train"][0].command},
        )

        result = self.audit()

        self.assertEqual(result.returncode, 1)
        self.assertIn("overlapping case groups in test, train", result.stderr)

    def test_audit_rejects_duplicate_case_ids_across_otherwise_independent_groups(self) -> None:
        self.cases["validation"][0] = self.cases["validation"][0].model_copy(
            update={"case_id": self.cases["train"][0].case_id},
        )

        result = self.audit()

        self.assertEqual(result.returncode, 1)
        self.assertIn("duplicate case_id", result.stderr)
