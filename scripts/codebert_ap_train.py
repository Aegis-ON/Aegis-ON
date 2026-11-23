from __future__ import annotations

import argparse
from dataclasses import dataclass
from pathlib import Path
from time import perf_counter
from typing import Literal

from sklearn.metrics import average_precision_score
import torch
from transformers import AutoTokenizer, RobertaForSequenceClassification, get_linear_schedule_with_warmup, set_seed

from aegis_on.codebert_classifier import fit_rows
from aegis_on.codebert_data import DatasetError, read_split, verify_disjoint_splits, write_json
from aegis_on.codebert_evaluate import load_training
from aegis_on.codebert_input import BASE_SHA256, sha256_file

BATCH = 8


@dataclass(frozen=True, slots=True)
class Recipe:
    source: Literal["baseline", "base", "resume-four"]
    layers: int
    encoder_lr: float
    head_lr: float
    epochs: int


RECIPES = {
    "resume-four": Recipe("baseline", 4, 3e-5, 3e-4, 6),
    "fresh-six": Recipe("base", 6, 5e-5, 4e-4, 8),
    "extend-four": Recipe("resume-four", 4, 1.8e-5, 1e-4, 8),
}


def batches(rows: list[tuple[str, list[int], int]], tokenizer, shuffle: bool):
    ordering = torch.randperm(len(rows)).tolist() if shuffle else range(len(rows))
    for start in range(0, len(ordering), BATCH):
        batch = [rows[index] for index in ordering[start:start + BATCH]]
        encoded = tokenizer.pad({"input_ids": [row[1] for row in batch]}, return_tensors="pt")
        yield encoded, torch.tensor([row[2] for row in batch], dtype=torch.long)


def train(args: argparse.Namespace) -> None:
    name = args.recipe
    recipe = RECIPES[name]
    output = args.out / name
    data = args.splits
    initial_model = {"baseline": args.baseline, "base": args.base,
                     "resume-four": args.out / "resume-four"}[recipe.source]
    if output.exists() or sha256_file(args.base / "model.safetensors") != BASE_SHA256:
        raise DatasetError("need a fresh output and the pinned CodeBERT weights")
    train_rows, fixture = read_split(data / "train.jsonl", "train")
    val_rows, val_fixture = read_split(data / "validation.jsonl", "validation")
    verify_disjoint_splits({"train": train_rows, "validation": val_rows})
    if not (fixture and val_fixture):
        raise DatasetError("the experiment requires synthetic fixture splits")
    source_sha = sha256_file(initial_model / "model.safetensors")
    if recipe.source != "base":
        previous = load_training(initial_model)
        if (previous["split_audit_sha256"] != sha256_file(data / "split-audit.json")
                or not previous["fixture"] or previous["base_sha256"] != BASE_SHA256):
            raise DatasetError("the warm start uses a different fixture split or base")
    torch.set_num_threads(2)
    set_seed(101)
    tokenizer = AutoTokenizer.from_pretrained(initial_model, local_files_only=True, trust_remote_code=False)
    model = RobertaForSequenceClassification.from_pretrained(
        initial_model, local_files_only=True, use_safetensors=True, attn_implementation="eager",
        num_labels=2, id2label={0: "benign", 1: "review"}, label2id={"benign": 0, "review": 1},
    )
    model.requires_grad_(False)
    encoder = model.roberta.encoder.layer[-recipe.layers:]
    encoder.requires_grad_(True)
    model.classifier.requires_grad_(True)
    train_items, val_items = fit_rows(train_rows, tokenizer), fit_rows(val_rows, tokenizer)
    if (len(train_items), len(val_items)) != (204, 42):
        raise DatasetError("unexpected eligible labelled example counts")
    optimizer = torch.optim.AdamW([
        {"params": encoder.parameters(), "lr": recipe.encoder_lr},
        {"params": model.classifier.parameters(), "lr": recipe.head_lr},
    ], weight_decay=0.01)
    total_steps = ((len(train_items) + BATCH - 1) // BATCH) * recipe.epochs
    scheduler = get_linear_schedule_with_warmup(optimizer, int(total_steps * 0.1), total_steps)
    trainable = {key: value for key, value in model.named_parameters() if value.requires_grad}
    history = []
    best: dict[str, torch.Tensor] = {}
    best_ap, best_epoch = -1.0, 0
    initial = perf_counter()
    for epoch in range(1, recipe.epochs + 1):
        model.train()
        for batch, labels in batches(train_items, tokenizer, shuffle=True):
            optimizer.zero_grad(set_to_none=True)
            loss = model(**batch, labels=labels).loss
            if not torch.isfinite(loss):
                raise DatasetError("non-finite loss")
            loss.backward()
            torch.nn.utils.clip_grad_norm_(trainable.values(), 1.0)
            optimizer.step()
            scheduler.step()
        model.eval()
        scores, targets = [], []
        with torch.inference_mode():
            for batch, labels in batches(val_items, tokenizer, shuffle=False):
                scores.extend(model(**batch).logits.softmax(dim=1)[:, 1].tolist())
                targets.extend(labels.tolist())
        ap = float(average_precision_score(targets, scores))
        history.append({"epoch": epoch, "validation_ap": ap})
        print(f"{name} epoch={epoch} validation_ap={ap:.6f}", flush=True)
        if ap > best_ap:
            best_ap, best_epoch = ap, epoch
            best = {key: value.detach().clone() for key, value in trainable.items()}
        if epoch - best_epoch >= 3:
            break
    with torch.no_grad():
        for key, value in best.items():
            trainable[key].copy_(value)
    output.mkdir(parents=True, exist_ok=False)
    model.save_pretrained(output, safe_serialization=True)
    tokenizer.save_pretrained(output)
    write_json(output / "training.json", {
        "recipe": name, "base_sha256": BASE_SHA256, "initial_sha256": source_sha,
        "train_sha256": sha256_file(data / "train.jsonl"),
        "validation_sha256": sha256_file(data / "validation.jsonl"),
        "split_audit_sha256": sha256_file(data / "split-audit.json"),
        "artifacts": {path.name: sha256_file(path) for path in sorted(output.iterdir()) if path.is_file()},
        "fixture": True, "seed": 101, "train_known": len(train_items), "validation_known": len(val_items),
        "head_lr": recipe.head_lr, "encoder_lr": recipe.encoder_lr, "unfrozen_layers": recipe.layers,
        "best_epoch": best_epoch, "best_validation_ap": best_ap, "epochs": history,
        "batch_size": BATCH, "seconds": perf_counter() - initial,
    })


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Run a predefined synthetic CodeBERT training recipe.")
    parser.add_argument("recipe", choices=tuple(RECIPES))
    for name in ("splits", "base", "baseline", "out"):
        parser.add_argument(f"--{name}", type=Path, required=True)
    train(parser.parse_args())
