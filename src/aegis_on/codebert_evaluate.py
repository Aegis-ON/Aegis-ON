from __future__ import annotations

import argparse
from collections import Counter
from dataclasses import dataclass
import json
from pathlib import Path

from sklearn.metrics import average_precision_score
import torch
from transformers import AutoTokenizer, RobertaForSequenceClassification

from .codebert_classifier import LightClassifier
from .codebert_data import Case, DatasetError, read_split, write_json
from .codebert_eval_data import load_candidates, replay_candidates, save_candidates
from .codebert_input import sha256_file, token_ids
from .review_priority import Candidate, RankingPolicy, rank_candidates


@dataclass(frozen=True, slots=True)
class Scores:
    values: dict[str, float]
    statuses: dict[str, str]


@dataclass(frozen=True, slots=True)
class Evaluation:
    cases: list[Case]
    candidates: list[Candidate]

    def top(self, order: list[str]) -> dict:
        labels = {row.case_id: row for row in self.cases}
        cards = {row.detection_id: row for row in self.candidates}
        window = [cards[key] for key in order[:10]]
        selected = {key for card in window for key in card.event_ids}
        return {"slots": len(window), "candidate_ids": order[:10],
                "investigations": sorted({labels[key].investigation_id for key in selected
                                          if labels[key].label == "review"}),
                "unknown_cases": sum(labels[key].label == "unknown" for key in selected),
                "protected_order": [key for key in order if cards[key].protected]}

    def ranked(self, scores: Scores, policy: RankingPolicy) -> dict:
        order = rank_candidates(self.candidates, scores.values, policy)
        return self.top(order)


def load_training(path: Path) -> dict:
    training = json.loads((path / "training.json").read_text(encoding="utf-8"))
    for name, digest in training["artifacts"].items():
        if Path(name).name != name or sha256_file(path / name) != digest:
            raise DatasetError("training artifact checksum mismatch")
    return training


def load_classifier(path: Path):
    tokenizer = AutoTokenizer.from_pretrained(path, local_files_only=True, trust_remote_code=False)
    model = RobertaForSequenceClassification.from_pretrained(
        path, local_files_only=True, use_safetensors=True, attn_implementation="eager",
    ).eval()
    if model.config.id2label != {0: "benign", 1: "review"}:
        raise DatasetError("unexpected classifier labels")
    return tokenizer, model


def score_cases(cases: list[Case], path: Path) -> dict[str, Scores]:
    tokenizer, model = load_classifier(path)
    light = LightClassifier(path / "light.json")
    statuses, light_values, bert_values = {}, {}, {}
    with torch.inference_mode():
        for case in cases:
            status = case.status
            if status == "eligible":
                ids = token_ids(tokenizer, case.command)
                status = "ok" if ids is not None else "too_long"
                if ids is not None:
                    bert_values[case.case_id] = float(model(
                        input_ids=torch.tensor([ids]), attention_mask=torch.ones(1, len(ids), dtype=torch.long),
                    ).logits.softmax(dim=1)[0, 1])
                    light_values[case.case_id] = light.score(case.command)
            statuses[case.case_id] = status
    return {"light": Scores(light_values, statuses), "codebert": Scores(bert_values, statuses)}


def classification(cases: list[Case], scores: Scores, threshold: float) -> dict:
    known = [row for row in cases if row.label != "unknown"]
    positives = {row.case_id for row in known if row.label == "review"}
    scored = [row for row in known if row.case_id in scores.values]
    predicted = {row.case_id for row in scored if scores.values[row.case_id] >= threshold}
    tp, fp, missed = len(positives & predicted), predicted - positives, positives - predicted
    return {"ap": float(average_precision_score(
                [row.label == "review" for row in scored], [scores.values[row.case_id] for row in scored],
            )) if any(row.label == "review" for row in scored) else None,
            "scored_known": len(scored), "known": len(known),
            "unknown": len(cases) - len(known), "scored": len(scores.values),
            "unscored_positives": sorted(positives - scores.values.keys()),
            "false_positives": sorted(fp), "missed": sorted(missed),
            "recall": tp / len(positives) if positives else 0.0,
            "f1": 2 * tp / (2 * tp + len(fp) + len(missed)) if tp else 0.0,
            "statuses": dict(Counter(scores.statuses.values())), "case_status": scores.statuses}


def calibrate(eval_set: Evaluation, scores: Scores) -> RankingPolicy:
    def metric(threshold: float) -> tuple[float, float, float]:
        result = classification(eval_set.cases, scores, threshold)
        return result["f1"], result["recall"], threshold

    threshold = max((0.30, 0.40, 0.50, 0.60, 0.70), key=metric)
    policies = [RankingPolicy(threshold=threshold, weight=weight) for weight in (0, 5, 10, 20)]
    return max(policies, key=lambda policy: len(eval_set.ranked(scores, policy)["investigations"]))


def frozen_policy(path: Path, model: Path, test: Path) -> dict:
    policy = json.loads(path.read_text(encoding="utf-8"))
    if (policy["training_sha256"] != sha256_file(model / "training.json")
            or policy["split_audit_sha256"] != sha256_file(test.parent / "split-audit.json")
            or policy["validation_sha256"] == sha256_file(test)):
        raise DatasetError("policy, checkpoint and holdout do not match")
    return policy


def evaluate(eval_set: Evaluation, scores: dict[str, Scores], policies: dict) -> dict:
    rules = eval_set.top([row.detection_id for row in eval_set.candidates])
    context = eval_set.ranked(Scores({}, {}), RankingPolicy())
    arms = {"existing": rules, "context": context}
    for name, result in scores.items():
        policy = RankingPolicy.model_validate(policies[name])
        arm = eval_set.ranked(result, policy)
        hits = set(arm["investigations"])
        arm["classification"] = classification(eval_set.cases, result, policy.threshold)
        arm["scored_candidates"] = sum(any(key in result.values for key in row.event_ids)
                                       for row in eval_set.candidates)
        arm["gained_vs_context"] = sorted(hits - set(context["investigations"]))
        arm["lost_vs_context"] = sorted(set(context["investigations"]) - hits)
        arms[name] = arm
    code_hits = set(arms["codebert"]["investigations"])
    light_hits = set(arms["light"]["investigations"])
    arms["codebert"]["gained_vs_light"] = sorted(code_hits - light_hits)
    arms["codebert"]["lost_vs_light"] = sorted(light_hits - code_hits)
    linked = {key for row in eval_set.candidates for key in row.event_ids}
    return {"arms": arms, "cases_without_alert": len(eval_set.cases) - len(linked),
            "candidate_count": len(eval_set.candidates),
            "codebert_wins": len(code_hits) > max(len(light_hits), len(context["investigations"]))
            and arms["codebert"]["protected_order"] == rules["protected_order"]}


def main() -> None:
    parser = argparse.ArgumentParser()
    commands = parser.add_subparsers(dest="command", required=True)
    replay = commands.add_parser("candidates")
    for name in ("events", "split-file", "out"):
        replay.add_argument(f"--{name}", type=Path, required=True)
    replay.add_argument("--split", choices=("validation", "test"), required=True)
    for command, split in (("calibrate", "validation"), ("evaluate", "test")):
        subparser = commands.add_parser(command)
        for name in (split, "candidates", "model", "out"):
            subparser.add_argument(f"--{name}", type=Path, required=True)
        if command == "evaluate":
            subparser.add_argument("--policy", type=Path, required=True)
    args = parser.parse_args()
    if args.command == "candidates":
        save_candidates(args.out, replay_candidates(args.events, args.split_file, args.split), args.split_file)
        return
    split = "validation" if args.command == "calibrate" else "test"
    path = getattr(args, split)
    cases, fixture = read_split(path, split)
    training = load_training(args.model)
    audit_hash = sha256_file(path.parent / "split-audit.json")
    if training["fixture"] != fixture or training["split_audit_sha256"] != audit_hash:
        raise DatasetError("model and split audit do not match")
    eval_set = Evaluation(cases, load_candidates(args.candidates, path, cases))
    torch.set_num_threads(2)
    scores = score_cases(cases, args.model)
    if split == "validation":
        report = {"fixture": fixture, "validation_sha256": sha256_file(path),
                  "split_audit_sha256": audit_hash, "candidates_sha256": sha256_file(args.candidates),
                  "training_sha256": sha256_file(args.model / "training.json"),
                  "policies": {name: calibrate(eval_set, value).model_dump() for name, value in scores.items()}}
    else:
        policy = frozen_policy(args.policy, args.model, path)
        if policy["fixture"] != fixture:
            raise DatasetError("policy fixture flag differs from holdout")
        report = {"fixture": fixture, "test_sha256": sha256_file(path),
                  "candidates_sha256": sha256_file(args.candidates), "policy_sha256": sha256_file(args.policy),
                  **evaluate(eval_set, scores, policy["policies"])}
        report["promotion_eligible"] = not fixture and report["codebert_wins"]
    write_json(args.out, report)


if __name__ == "__main__":
    main()
