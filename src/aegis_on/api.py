from __future__ import annotations

import hmac
import os
from typing import Any

from fastapi import Depends, FastAPI, HTTPException
from fastapi.responses import FileResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, Field

from .service import DetectionService

app = FastAPI(title="Aegis-ON API", version="0.1.0")
service = DetectionService()
bearer = HTTPBearer(auto_error=False)


def authenticated_analyst(
    credentials: HTTPAuthorizationCredentials | None = Depends(bearer),
) -> str:
    token = os.environ.get("AEGIS_API_TOKEN", "")
    analyst = os.environ.get("AEGIS_ANALYST_NAME", "").strip()
    if not token or not analyst:
        raise HTTPException(status_code=503, detail="API authentication is not configured")
    if credentials is None or not hmac.compare_digest(
        credentials.credentials.encode("utf-8"), token.encode("utf-8")
    ):
        raise HTTPException(status_code=401, detail="invalid or missing API token", headers={"WWW-Authenticate": "Bearer"})
    return analyst


class AnalyzeRequest(BaseModel):
    events: list[dict[str, Any]] = Field(min_length=1, max_length=1000)


class ApprovalRequest(BaseModel):
    analyst: str = Field(min_length=2, max_length=100)
    rationale: str = Field(default="", max_length=500)


@app.get("/", include_in_schema=False)
def dashboard() -> FileResponse:
    return FileResponse("static/index.html")


@app.get("/api/v1/health")
def health() -> dict[str, str]:
    return {"status": "ok", "model_state": "semantic-baseline"}


@app.get("/data/demo_events.json", include_in_schema=False)
def demo_events(analyst: str = Depends(authenticated_analyst)) -> FileResponse:
    return FileResponse("data/demo_events.json")


@app.post("/api/v1/analyze")
def analyze(payload: AnalyzeRequest, analyst: str = Depends(authenticated_analyst)) -> dict[str, Any]:
    try:
        detections, event_refs = service.analyze_with_event_refs(payload.events)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    return {"model_state": "semantic-baseline", "detections": detections, "event_refs": event_refs}


@app.get("/api/v1/detections")
def list_detections(analyst: str = Depends(authenticated_analyst)) -> dict[str, Any]:
    return {"detections": service.list_detections()}


@app.post("/api/v1/detections/{detection_id}/approval")
def approve(
    detection_id: str, payload: ApprovalRequest, analyst: str = Depends(authenticated_analyst)
) -> dict[str, Any]:
    if payload.analyst != analyst:
        raise HTTPException(status_code=403, detail="analyst does not match the configured identity")
    try:
        detection = service.approve(detection_id, payload.analyst, payload.rationale)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="detection not found") from exc
    return {"simulation_only": True, "detection": detection}
