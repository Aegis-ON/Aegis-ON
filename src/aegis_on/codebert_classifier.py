from __future__ import annotations

import json
from pathlib import Path

import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression

from .codebert_data import Case, DatasetError, write_json
from .codebert_input import Encoder, token_ids


def fit_rows(rows: list[Case], tokenizer: Encoder) -> list[tuple[str, list[int], int]]:
    eligible = []
    for row in rows:
        if row.status == "eligible" and row.label != "unknown":
            ids = token_ids(tokenizer, row.command)
            if ids is not None:
                eligible.append((row.command, ids, int(row.label == "review")))
    if {row[2] for row in eligible} != {0, 1}:
        raise DatasetError("both known classes must fit the token limit")
    return eligible


def train_light(rows: list[tuple[str, list[int], int]], out: Path) -> None:
    commands, _, labels = zip(*rows, strict=True)
    vectorizer = TfidfVectorizer(analyzer="char", ngram_range=(3, 5))
    classifier = LogisticRegression(C=1, random_state=101, max_iter=1000)
    classifier.fit(vectorizer.fit_transform(commands), labels)
    write_json(out, {"vocabulary": vectorizer.vocabulary_, "idf": vectorizer.idf_.tolist(),
                     "weights": classifier.coef_[0].tolist(), "bias": float(classifier.intercept_[0])})


class LightClassifier:
    def __init__(self, path: Path):
        model = json.loads(path.read_text(encoding="utf-8"))
        self.vectorizer = TfidfVectorizer(analyzer="char", ngram_range=(3, 5), vocabulary=model["vocabulary"])
        self.vectorizer.idf_ = np.array(model["idf"], dtype=np.float64)
        self.weights = np.array(model["weights"], dtype=np.float64)
        self.bias = model["bias"]

    def score(self, command: str) -> float:
        logit = float((self.vectorizer.transform([command]) @ self.weights)[0]) + self.bias
        return float(np.exp(-np.logaddexp(0, -logit)))
