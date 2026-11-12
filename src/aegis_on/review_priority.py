from __future__ import annotations

import math
from collections.abc import Mapping, Sequence

from pydantic import BaseModel, ConfigDict, Field


class Candidate(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    detection_id: str = Field(min_length=1)
    event_ids: tuple[str, ...]
    score: int = Field(ge=0, le=100)
    source: str
    requires_human_approval: bool
    verified_critical_asset: bool = False
    approved_work_match: bool = False

    @property
    def protected(self) -> bool:
        return self.requires_human_approval or (self.source == "rule" and self.score >= 70)


class RankingPolicy(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    threshold: float = Field(default=0.5, ge=0, lt=1)
    weight: int = Field(default=0, ge=0, le=20)


def rank_candidates(
    candidates: Sequence[Candidate], scores: Mapping[str, float], policy: RankingPolicy,
) -> list[str]:
    def priority(candidate: Candidate) -> tuple[int, float]:
        if candidate.protected:
            return (0, 0.0)
        context = 10 * (int(candidate.verified_critical_asset) - int(candidate.approved_work_match))
        base = min(100, max(0, candidate.score + context))
        probability = max(
            (scores[key] for key in candidate.event_ids if key in scores and math.isfinite(scores[key])
             and 0 <= scores[key] <= 1), default=0.0,
        )
        uplift = policy.weight * max(0.0, (probability - policy.threshold) / (1 - policy.threshold))
        return (1, -(base + uplift))

    return [candidate.detection_id for candidate in sorted(candidates, key=priority)]
