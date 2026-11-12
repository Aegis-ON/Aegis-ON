import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from fastapi.testclient import TestClient

from aegis_on import api
from aegis_on.codebert_data import Case, connected_groups, split_cases
from aegis_on.codebert_input import normalize_command
from aegis_on.codebert_shadow import ShadowModel
from aegis_on.history_store import SQLiteHistory
from aegis_on.review_priority import Candidate, RankingPolicy, rank_candidates
from aegis_on.service import DetectionService
from test_sysmon_api import make_event


class CodeBertReviewTests(unittest.TestCase):
    def test_group_split_keeps_transitive_duplicates_together(self):
        cases = [
            Case(case_id=f"{group}-{label}", label=label, source_ref="fixture", evidence_ref="reviewer",
                 scenario_id=f"scenario-{group}", run_id=f"run-{group}",
                 command_family=f"family-{group}-{label}", investigation_id=f"investigation-{group}",
                 command=f"echo {group}-{label}", status="eligible")
            for group in range(8) for label in ("benign", "review")
        ]
        cases[2] = cases[2].model_copy(update={"command": cases[0].command})
        cases[4] = cases[4].model_copy(update={"command_family": cases[3].command_family})
        group = next(rows for rows in connected_groups(cases) if cases[0] in rows)
        self.assertEqual({row.scenario_id for row in group}, {"scenario-0", "scenario-1", "scenario-2"})
        splits = split_cases(cases)
        self.assertTrue(any(set(group_id.case_id for group_id in group) <= {row.case_id for row in rows}
                            for rows in splits.values()))
        for rows in splits.values():
            self.assertEqual({row.label for row in rows}, {"benign", "review"})

    def test_normalization_preserves_switch_and_masks_identifiers(self):
        text = r'cmd.exe /c echo --password="fixture secret" C:\Users\fixture\notes.txt fixture@example.invalid'
        normalized = normalize_command(text)
        self.assertEqual(normalized, r"cmd.exe /c echo --password=[SECRET] C:\Users\[USER]\notes.txt [EMAIL]")

    def test_ai_can_move_general_cards_below_protected_cards(self):
        candidates = [
            Candidate(detection_id=key, score=score, event_ids=(key,), source=source,
                      requires_human_approval=approval)
            for key, score, source, approval in (
                ("a", 72, "rule", False), ("b", 65, "semantic-baseline", False),
                ("c", 60, "semantic-baseline", False), ("d", 25, "semantic-baseline", True),
            )
        ]
        order = rank_candidates(candidates, {"c": 0.95, "b": float("nan")}, RankingPolicy(weight=20))
        self.assertEqual(order, ["a", "d", "c", "b"])

    def test_sysmon_codebert_event_scope_and_durable_links(self):
        class FixtureModel(ShadowModel):
            def predict(self, command: str, identities: tuple[str, ...] = ()):
                return {"status": "ok", "score": 0.9}

        with tempfile.TemporaryDirectory() as directory:
            database = Path(directory) / "history.sqlite3"
            model = FixtureModel(state="ready", graph_sha256="f" * 64, fixture=True)
            with (patch.object(api, "codebert_shadow", model),
                  patch.object(api, "service", DetectionService(SQLiteHistory(database))),
                  patch.dict("os.environ", {"AEGIS_API_TOKEN": "fixture", "AEGIS_ANALYST_NAME": "reviewer"}),
                  TestClient(api.app) as client):
                headers = {"Authorization": "Bearer fixture"}
                process, network = make_event(1, 1), make_event(3, 2)
                network["EventData"]["CommandLine"] = "curl fixture-network-command"
                response = client.post("/api/v1/sysmon/analyze", headers=headers, json={"events": [process, network]})
                self.assertEqual(response.status_code, 200)
                body = response.json()
                shadow = body["review_shadow"]
                self.assertEqual([event["event_id"] for event in shadow["events"]],
                                 [body["source_events"][0]["event_id"]])
                self.assertEqual(shadow["current_order"], [row["detection_id"] for row in body["detections"]])
                with patch.object(api, "service", DetectionService(SQLiteHistory(database))):
                    history = client.get("/api/v1/history", headers=headers).json()
                self.assertEqual(history["analyses"][0]["review_shadow"], shadow)
                self.assertNotIn(b"fixture-network-command", database.read_bytes())
