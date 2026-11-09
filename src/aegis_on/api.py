from __future__ import annotations

from typing import Any

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from .service import DetectionService

app = FastAPI(title="Aegis-ON API", version="0.1.0")
app.mount("/data", StaticFiles(directory="data"), name="data")
service = DetectionService()


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


@app.post("/api/v1/analyze")
def analyze(payload: AnalyzeRequest) -> dict[str, Any]:
    try:
        detections = service.analyze(payload.events)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    return {"model_state": "semantic-baseline", "detections": detections}


@app.get("/api/v1/detections")
def list_detections() -> dict[str, Any]:
    return {"detections": service.list_detections()}


@app.post("/api/v1/detections/{detection_id}/approval")
def approve(detection_id: str, payload: ApprovalRequest) -> dict[str, Any]:
    try:
        detection = service.approve(detection_id, payload.analyst, payload.rationale)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="detection not found") from exc
    return {"simulation_only": True, "detection": detection}
