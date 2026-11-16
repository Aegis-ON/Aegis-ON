from __future__ import annotations

import argparse
from collections import Counter
from dataclasses import dataclass
from pathlib import Path

import torch
import transformers
from sklearn import __version__ as sklearn_version
from sklearn.metrics import average_precision_score
from transformers import AutoTokenizer, RobertaForSequenceClassification, set_seed

from .codebert_classifier import LightClassifier, fit_rows, train_light
from .codebert_data import DatasetError, connected_groups, read_split, write_json
from .codebert_input import BASE_SHA256, sha256_file


@dataclass(frozen=True, slots=True)
class Stage:
    name: str
    head_lr: float
    encoder_lr: float | None = None


STAGES = (Stage("head", 3e-4), Stage("last_two", 1e-4, 2e-5))


def _batches(rows: list[tuple[str, list[int], int]], tokenizer, *, shuffle: bool):
    order = torch.randperm(len(rows)).tolist() if shuffle else range(len(rows))
    for start in range(0, len(order), 4):
        items = [rows[index] for index in order[start:start + 4]]
        features = tokenizer.pad({"input_ids": [item[1] for item in items]}, return_tensors="pt")
        yield features, torch.tensor([item[2] for item in items], dtype=torch.long)


def _fit_stage(model, tokenizer, rows, validation, stage: Stage, epochs: int) -> tuple[dict, dict]:
    model.requires_grad_(False)
    model.classifier.requires_grad_(True)
    groups = [{"params": model.classifier.parameters(), "lr": stage.head_lr}]
    if stage.encoder_lr is not None:
        layers = model.roberta.encoder.layer[-2:]
        layers.requires_grad_(True)
        groups.append({"params": layers.parameters(), "lr": stage.encoder_lr})
    optimizer = torch.optim.AdamW(groups)
    best_ap, best_epoch, checkpoint = -1.0, 0, {}
    history = []
    for epoch in range(1, epochs + 1):
        model.train()
        for features, labels in _batches(rows, tokenizer, shuffle=True):
            optimizer.zero_grad()
            loss = model(**features, labels=labels).loss
            if not torch.isfinite(loss):
                raise DatasetError("non-finite training loss")
            loss.backward()
            optimizer.step()
        model.eval()
        scores, targets = [], []
        with torch.inference_mode():
            for features, labels in _batches(validation, tokenizer, shuffle=False):
                scores.extend(model(**features).logits.softmax(dim=-1)[:, 1].tolist())
                targets.extend(labels.tolist())
        ap = float(average_precision_score(targets, scores))
        history.append({"epoch": epoch, "validation_ap": ap})
        if ap > best_ap:
            best_ap, best_epoch = ap, epoch
            checkpoint = {name: value.detach().clone() for name, value in model.state_dict().items()}
        if epoch - best_epoch >= 2:
            break
    return checkpoint, {
        "stage": stage.name, "best_ap": best_ap, "best_epoch": best_epoch, "epochs": history,
        "trainable": [name for name, value in model.named_parameters() if value.requires_grad],
    }


def train(args: argparse.Namespace) -> None:
    if args.train.parent.resolve() != args.validation.parent.resolve():
        raise DatasetError("train and validation must come from the same split audit")
    train_cases, fixture = read_split(args.train, "train")
    val_cases, _ = read_split(args.validation, "validation")
    if fixture != args.fixture or (not fixture and args.epochs != 5):
        raise DatasetError("fixture flag must match the input audit; custom epoch counts are fixture-only")
    if not 1 <= args.epochs <= 5:
        raise DatasetError("epochs must be in [1, 5]")
    train_ids = {row.case_id for row in train_cases}
    if any(len({row.case_id in train_ids for row in group}) > 1
           for group in connected_groups(train_cases + val_cases)):
        raise DatasetError("overlapping train and validation groups")
    base_hash = sha256_file(args.base / "model.safetensors")
    if not fixture and base_hash != BASE_SHA256:
        raise DatasetError("CodeBERT base weight checksum mismatch")
    torch.set_num_threads(2)
    set_seed(101)
    tokenizer = AutoTokenizer.from_pretrained(args.base, local_files_only=True, trust_remote_code=False)
    model = RobertaForSequenceClassification.from_pretrained(
        args.base, local_files_only=True, use_safetensors=True, num_labels=2,
        id2label={0: "benign", 1: "review"}, label2id={"benign": 0, "review": 1},
    )
    rows, validation = fit_rows(train_cases, tokenizer), fit_rows(val_cases, tokenizer)
    head, head_report = _fit_stage(model, tokenizer, rows, validation, STAGES[0], args.epochs)
    model.load_state_dict(head)
    tail, tail_report = _fit_stage(model, tokenizer, rows, validation, STAGES[1], args.epochs)
    choose_tail = tail_report["best_ap"] > head_report["best_ap"]
    model.load_state_dict(tail if choose_tail else head)
    args.out.mkdir(parents=True, exist_ok=False)
    model.save_pretrained(args.out, safe_serialization=True)
    tokenizer_paths = tokenizer.save_pretrained(args.out)
    train_light(rows, args.out / "light.json")
    light = LightClassifier(args.out / "light.json")
    light_ap = float(average_precision_score(
        [label for _, _, label in validation], [light.score(command) for command, _, label in validation],
    ))
    artifacts = {"config.json", "model.safetensors", "light.json"}
    artifacts.update(Path(path).name for path in tokenizer_paths if Path(path).is_file())
    write_json(args.out / "training.json", {
        "fixture": fixture, "seed": 101, "selected": STAGES[int(choose_tail)].name,
        "selection": "validation average precision; ties favor head-only and earlier epochs",
        "base_sha256": base_hash,
        "split_audit_sha256": sha256_file(args.train.parent / "split-audit.json"),
        "train_sha256": sha256_file(args.train), "validation_sha256": sha256_file(args.validation),
        "artifacts": {name: sha256_file(args.out / name) for name in sorted(artifacts)},
        "versions": {"torch": str(torch.__version__), "transformers": transformers.__version__,
                     "scikit_learn": sklearn_version},
        "rows": {"train": dict(Counter(row[2] for row in rows)),
                 "validation": dict(Counter(row[2] for row in validation))},
        "light_validation_ap": light_ap,
        "stages": [head_report, tail_report],
    })


def main() -> None:
    parser = argparse.ArgumentParser()
    for name in ("base", "train", "validation", "out"):
        parser.add_argument(f"--{name}", type=Path, required=True)
    parser.add_argument("--fixture", action="store_true")
    parser.add_argument("--epochs", type=int, default=5)
    train(parser.parse_args())


if __name__ == "__main__":
    main()
