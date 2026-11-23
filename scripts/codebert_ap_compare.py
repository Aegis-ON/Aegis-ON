from __future__ import annotations

import argparse
from collections import Counter
from dataclasses import dataclass
import json
from pathlib import Path

import numpy as np
from scipy.special import expit
from scipy.stats import rankdata
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import average_precision_score
from sklearn.pipeline import FeatureUnion, make_pipeline
import torch

from aegis_on.codebert_classifier import LightClassifier
from aegis_on.codebert_data import Case, DatasetError, Split, read_split, verify_disjoint_splits, write_json
from aegis_on.codebert_evaluate import load_classifier, load_training
from aegis_on.codebert_input import sha256_file, token_ids

PURE = ("original-codebert", "resume-four", "fresh-six", "extend-four")
LEXICAL = "lexical-model.json"


@dataclass(frozen=True, slots=True)
class RunPaths:
    splits: Path
    baseline: Path
    out: Path


def split(directory: Path, name: Split) -> list[Case]:
    rows, fixture = read_split(directory / f"{name}.jsonl", name)
    if not fixture:
        raise DatasetError("synthetic fixture expected")
    return rows


def read_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def model_digest(directory: Path) -> str:
    for name, expected in read_json(directory / "training.json")["artifacts"].items():
        if Path(name).name != name or sha256_file(directory / name) != expected:
            raise DatasetError(f"artifact digest mismatch for {directory.name}: {name}")
    return sha256_file(directory / "model.safetensors")


def lexical_features() -> FeatureUnion:
    return FeatureUnion([
        ("char", TfidfVectorizer(analyzer="char", ngram_range=(3, 5), sublinear_tf=True)),
        ("tokens", TfidfVectorizer(analyzer="word", ngram_range=(1, 2), sublinear_tf=True,
                                   token_pattern=r"(?u)[/\-]?\w[\w.-]*|[*|]")),
    ], transformer_weights={"char": 1.0, "tokens": 0.5})


def fit_lexical(paths: RunPaths) -> None:
    train = split(paths.splits, "train")
    valid = split(paths.splits, "validation")
    verify_disjoint_splits({"train": train, "validation": valid})
    known = [row for row in train if row.status == "eligible" and row.label != "unknown"]
    artifact = paths.out / LEXICAL
    manifest = paths.out / "lexical.json"
    if len(known) != 204 or artifact.exists() or manifest.exists():
        raise DatasetError("unexpected training input or lexical output already exists")
    features = lexical_features()
    classifier = LogisticRegression(C=4.0, max_iter=2000, random_state=101)
    model = make_pipeline(features, classifier)
    model.fit([row.command for row in known], [int(row.label == "review") for row in known])
    paths.out.mkdir(parents=True, exist_ok=True)
    write_json(artifact, {
        "features": {name: {"vocab": vectorizer.vocabulary_, "idf": vectorizer.idf_.tolist()}
                     for name, vectorizer in features.transformer_list},
        "weights": classifier.coef_[0].tolist(), "bias": float(classifier.intercept_[0]),
    })
    write_json(manifest, {
        "training_known": len(known), "train_sha256": sha256_file(paths.splits / "train.jsonl"),
        "artifact_sha256": sha256_file(artifact),
    })


def neural_scores(rows: list[Case], path: Path) -> np.ndarray:
    tokenizer, model = load_classifier(path)
    encoded = [token_ids(tokenizer, row.command) for row in rows]
    if any(ids is None or row.status != "eligible" for ids, row in zip(encoded, rows, strict=True)):
        raise DatasetError("all candidates need eligible model inputs")
    outputs: list[float] = []
    with torch.inference_mode():
        for start in range(0, len(encoded), 8):
            inputs = tokenizer.pad({"input_ids": encoded[start:start + 8]}, return_tensors="pt")
            outputs.extend(model(**inputs).logits.softmax(dim=1)[:, 1].tolist())
    return np.array(outputs)


def lexical_scores(rows: list[Case], paths: RunPaths) -> np.ndarray:
    flags = read_json(paths.out / "lexical.json")
    artifact = paths.out / LEXICAL
    if flags["artifact_sha256"] != sha256_file(artifact):
        raise DatasetError("lexical model digest mismatch")
    if flags["train_sha256"] != sha256_file(paths.splits / "train.jsonl"):
        raise DatasetError("lexical model was trained on a different split")
    saved = read_json(artifact)
    features = lexical_features()
    for name, vectorizer in features.transformer_list:
        vectorizer.vocabulary = saved["features"][name]["vocab"]
        vectorizer.idf_ = np.array(saved["features"][name]["idf"], dtype=np.float64)
    logits = features.transform([row.command for row in rows]) @ np.array(saved["weights"]) + saved["bias"]
    return expit(logits)


def blend(a: np.ndarray, b: np.ndarray) -> np.ndarray:
    return (rankdata(a) + rankdata(b)) / (2 * len(a))


def metrics(rows: list[Case], scores: np.ndarray) -> dict:
    if len(rows) != 56 or len(scores) != len(rows) or not np.isfinite(scores).all():
        raise DatasetError("all 56 candidate scores must be finite")
    if len({row.case_id for row in rows}) != len(rows):
        raise DatasetError("candidate IDs must be unique")
    keep = [i for i, row in enumerate(rows) if row.label != "unknown"]
    if len(keep) != 42:
        raise DatasetError("unexpected known label count")
    labels = [int(rows[i].label == "review") for i in keep]
    order = sorted(range(len(rows)), key=lambda i: (-scores[i], rows[i].case_id))[:10]
    bins = Counter(rows[i].label for i in order)
    return {"ap": float(average_precision_score(labels, scores[keep])),
            "top10": {key: bins[key] for key in ("review", "benign", "unknown")},
            "top10_ids": [rows[i].case_id for i in order],
            "known_labels": len(keep), "scored": len(rows),
            "score_min": float(scores.min()), "score_max": float(scores.max())}


def select(paths: RunPaths) -> None:
    if (paths.out / "selection.json").exists() or (paths.out / "reference.json").exists():
        raise DatasetError("candidate selection is already frozen")
    train, val = split(paths.splits, "train"), split(paths.splits, "validation")
    verify_disjoint_splits({"train": train, "validation": val})
    base_metadata = load_training(paths.baseline)
    if base_metadata["split_audit_sha256"] != sha256_file(paths.splits / "split-audit.json"):
        raise DatasetError("baseline was trained with a different split")
    directories = {"original-codebert": paths.baseline, **{key: paths.out / key for key in PURE[1:]}}
    expected_splits = {f"{name}_sha256": sha256_file(paths.splits / f"{name}.jsonl")
                       for name in ("train", "validation")}
    expected_splits["split_audit_sha256"] = sha256_file(paths.splits / "split-audit.json")
    for path in directories.values():
        metadata = read_json(path / "training.json")
        if any(metadata[key] != digest for key, digest in expected_splits.items()):
            raise DatasetError("model selection split mismatch")
    digests = {key: model_digest(path) for key, path in directories.items()}
    scores = {key: neural_scores(val, path) for key, path in directories.items()}
    light = LightClassifier(paths.baseline / "light.json")
    scores["original-light"] = np.array([light.score(row.command) for row in val])
    scores["lexical"] = lexical_scores(val, paths)
    pure = max(PURE, key=lambda key: metrics(val, scores[key])["ap"])
    scores["blend"] = blend(scores[pure], scores["lexical"])
    board = {key: metrics(val, value) for key, value in scores.items()}
    best = max(board, key=lambda key: board[key]["ap"])
    selected = pure if board[pure]["ap"] >= 0.8 else best
    write_json(paths.out / "selection.json", {"validation": board, "best_pure": pure, "selected": selected,
                                      "highest_ap": best, "model_sha256": digests,
                                      "training_manifest_sha256": {
                                          key: sha256_file(path / "training.json") for key, path in directories.items()
                                      },
                                      "lexical_sha256": sha256_file(paths.out / LEXICAL),
                                      "validation_sha256": expected_splits["validation_sha256"],
                                      "split_audit_sha256": expected_splits["split_audit_sha256"]})
    print(json.dumps({"selected": selected, "best_pure": pure, "validation": {
        key: {"ap": row["ap"], "top10": row["top10"]} for key, row in board.items()
    }}, indent=2))


def reference(paths: RunPaths) -> None:
    if (paths.out / "reference.json").exists():
        raise DatasetError("the frozen reference check has already run")
    selection = read_json(paths.out / "selection.json")
    if selection["split_audit_sha256"] != sha256_file(paths.splits / "split-audit.json"):
        raise DatasetError("the frozen evaluation split changed")
    directories = {"original-codebert": paths.baseline, **{key: paths.out / key for key in PURE[1:]}}
    if selection["training_manifest_sha256"] != {
        key: sha256_file(path / "training.json") for key, path in directories.items()
    }:
        raise DatasetError("training manifest changed after candidate selection")
    if selection["model_sha256"] != {key: model_digest(path) for key, path in directories.items()}:
        raise DatasetError("model changed after candidate selection")
    if selection["lexical_sha256"] != sha256_file(paths.out / LEXICAL):
        raise DatasetError("lexical weights changed after selection")
    train, val, test = (split(paths.splits, name) for name in ("train", "validation", "test"))
    verify_disjoint_splits({"train": train, "validation": val, "test": test})
    chosen = selection["selected"]
    priors = {"original-codebert": neural_scores(test, paths.baseline)}
    light = LightClassifier(paths.baseline / "light.json")
    priors["original-light"] = np.array([light.score(row.command) for row in test])
    if chosen == "blend":
        pure = selection["best_pure"]
        priors["blend"] = blend(neural_scores(test, directories[pure]), lexical_scores(test, paths))
    elif chosen == "lexical":
        priors["lexical"] = lexical_scores(test, paths)
    elif chosen not in priors:
        priors[chosen] = neural_scores(test, directories[chosen])
    board = {key: metrics(test, value) for key, value in priors.items()}
    write_json(paths.out / "reference.json", {"previously_observed_fixture": True,
                                       "selected_before_scoring_test": chosen,
                                       "test_sha256": sha256_file(paths.splits / "test.jsonl"),
                                       "models": board})
    print(json.dumps({key: {"ap": value["ap"], "top10": value["top10"]}
                      for key, value in board.items()}, indent=2))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Select candidates on validation and run one reference check.")
    parser.add_argument("action", choices=("lexical", "select", "reference"))
    for name in ("splits", "baseline", "out"):
        parser.add_argument(f"--{name}", type=Path, required=True)
    args = parser.parse_args()
    torch.set_num_threads(2)
    actions = {"lexical": fit_lexical, "select": select, "reference": reference}
    actions[args.action](RunPaths(args.splits, args.baseline, args.out))
