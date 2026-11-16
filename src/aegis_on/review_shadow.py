from __future__ import annotations

from collections.abc import Sequence
from typing import TypedDict

from .codebert_shadow import Prediction, ShadowModel
from .review_priority import Candidate, rank_candidates


class ShadowEvent(TypedDict):
    event_id: str
    command_line: str
    identities: tuple[str, ...]


class EventResult(Prediction):
    event_id: str


class ShadowResult(TypedDict):
    state: str
    manifest_sha256: str | None
    graph_sha256: str | None
    fixture: bool
    current_order: list[str]
    proposed_order: list[str]
    events: list[EventResult]


def review_shadow(
    model: ShadowModel, candidates: Sequence[Candidate], events: Sequence[ShadowEvent],
) -> ShadowResult:
    original = [row.detection_id for row in candidates]
    state = model.state
    results: list[EventResult] = []
    scores: dict[str, float] = {}
    if state == "ready":
        for event in events:
            prediction = model.predict(event["command_line"], event["identities"])
            key = event["event_id"]
            results.append({"event_id": key, **prediction})
            if prediction["status"] == "inference_error":
                state = "inference_error"
            if "score" in prediction:
                scores[key] = prediction["score"]
    proposed = rank_candidates(candidates, scores, model.policy) if state == "ready" and scores else original
    return {"state": state, "manifest_sha256": model.manifest_sha256, "graph_sha256": model.graph_sha256,
            "fixture": model.fixture, "current_order": original, "proposed_order": proposed, "events": results}
