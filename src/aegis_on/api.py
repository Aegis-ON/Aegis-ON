from __future__ import annotations

import hmac
import ipaddress
import json
import os
from typing import Any

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import FileResponse, JSONResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, Field

from .service import DetectionService
from .privacy import redact_for_display
from .pii import PIIDetector
from .pii_reporting import InvalidPIIInput, inspect_events
from .sysmon import parse_sysmon

app = FastAPI(title="Aegis-ON API", version="0.1.0")
service = DetectionService()
pii_detector = PIIDetector.from_environment()
bearer = HTTPBearer(auto_error=False)
MAX_SYSMON_BYTES = 2 * 1024 * 1024
DEMO_SCENARIOS = {
    "a": "data/scenario_a.json",
    "b": "data/scenario_b.json",
    "c": "data/scenario_c.json",
}


@app.exception_handler(RequestValidationError)
async def handle_validation_error(request: Request, exc: RequestValidationError):
    # Pydantic errors can contain the original input or attacker-controlled keys.
    return JSONResponse(status_code=422, content={"detail": "invalid request"})


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def _reject_nonfinite(value: str) -> None:
    raise ValueError("non-finite JSON value")


def _display_ip(value: str) -> str:
    """Use the same IP identity for display tokens and Sysmon correlation."""
    if not value:
        return ""
    address = ipaddress.ip_address(value)
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None:
        return str(address.ipv4_mapped)
    return str(address)


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


@app.get("/api/v1/pii/status")
def pii_status(analyst: str = Depends(authenticated_analyst)) -> dict[str, str]:
    return pii_detector.status()


def _pii_inspect(events: list[dict[str, Any]], indices: list[int]):
    try:
        return inspect_events(events, indices, pii_detector)
    except InvalidPIIInput:
        raise HTTPException(status_code=422, detail="invalid event text field") from None
    except RuntimeError:
        raise HTTPException(status_code=503, detail="PII model inference failed") from None
    except ValueError:
        raise HTTPException(status_code=413, detail="PII analysis input exceeds the configured limit") from None


def _link_pii(pii: dict[str, Any], refs: list[dict[str, Any]]) -> None:
    event_ids = {ref["input_index"]: ref["event_id"] for ref in refs}
    for finding in pii["findings"]:
        finding["event_id"] = event_ids.get(finding["input_index"], "")


@app.get("/data/demo_events.json", include_in_schema=False)
def demo_events(analyst: str = Depends(authenticated_analyst)) -> FileResponse:
    return FileResponse("data/demo_events.json")


@app.get("/api/v1/demo/scenarios/{scenario}")
def demo_scenario(scenario: str, analyst: str = Depends(authenticated_analyst)) -> FileResponse:
    path = DEMO_SCENARIOS.get(scenario)
    if path is None:
        raise HTTPException(status_code=404, detail="demo scenario not found")
    return FileResponse(path, media_type="application/json")


@app.post("/api/v1/analyze")
def analyze(payload: AnalyzeRequest, analyst: str = Depends(authenticated_analyst)) -> dict[str, Any]:
    pii, mask = _pii_inspect(payload.events, list(range(len(payload.events))))
    try:
        detections, event_refs = service.analyze_with_event_refs(payload.events, mask=mask)
    except ValueError as exc:
        message = str(exc)
        if not (message.startswith("duplicate event_id") or message.startswith("missing required event fields:")
                or message.startswith("invalid Unicode field:")):
            message = "invalid event"
        raise HTTPException(status_code=422, detail=message) from None
    _link_pii(pii, event_refs)
    return {"model_state": "semantic-baseline", "detections": detections, "event_refs": event_refs, "pii": pii}


@app.post("/api/v1/sysmon/analyze")
async def analyze_sysmon(request: Request, analyst: str = Depends(authenticated_analyst)) -> dict[str, Any]:
    if request.headers.get("content-type", "").split(";", 1)[0].strip().lower() != "application/json":
        raise HTTPException(status_code=415, detail="application/json is required")
    if request.headers.get("content-encoding", "identity").lower() != "identity":
        raise HTTPException(status_code=415, detail="content encoding is not supported")
    content_length = request.headers.get("content-length")
    if content_length is not None:
        if not content_length.isdecimal():
            raise HTTPException(status_code=400, detail="invalid content length")
        if int(content_length) > MAX_SYSMON_BYTES:
            raise HTTPException(status_code=413, detail="Sysmon file exceeds 2 MiB")
    body = bytearray()
    async for chunk in request.stream():
        if len(body) + len(chunk) > MAX_SYSMON_BYTES:
            raise HTTPException(status_code=413, detail="Sysmon file exceeds 2 MiB")
        body.extend(chunk)
    try:
        payload = json.loads(body.decode("utf-8-sig"), object_pairs_hook=_unique_object, parse_constant=_reject_nonfinite)
        raw_events, items = parse_sysmon(payload)
    except (ValueError, UnicodeDecodeError, RecursionError):
        raise HTTPException(status_code=422, detail="invalid Sysmon JSON batch") from None

    processed_indices = [item["input_index"] for item in items if item["status"] == "processed"]
    pii, mask = _pii_inspect(raw_events, processed_indices)
    if raw_events:
        try:
            detections, _ = service.analyze_with_event_refs(raw_events, allow_empty_command_line=True, mask=mask)
        except ValueError:
            raise HTTPException(status_code=422, detail="invalid analyzed events") from None
    else:
        detections = []
    # Return only identifiers and connection details needed to trace detections;
    # paths, commands, user names, and the original raw event are never returned.
    source_events = []
    by_id = {event["event_id"]: event for event in raw_events}
    for item in items:
        if item["status"] != "processed":
            continue
        event = by_id[item["event_id"]]
        metadata = event["source_metadata"]
        source = {
            "input_index": item["input_index"], "event_id": event["event_id"],
            "host": event["host"], "timestamp": event["timestamp"],
            **{key: metadata.get(key) for key in (
                "sysmon_event_id", "record_id", "log_source", "process_guid", "process_id",
                "source_port", "destination_port", "initiated"
            )},
            "source_ip": metadata["source_ip"],
            "destination_ip": metadata["destination_ip"],
        }
        # Numeric identifiers and ports are not separately scanned, but an
        # already-detected value may also appear there. Preserve numbers unless
        # a candidate is actually present; structural event indexes stay numeric.
        def display_source_value(key: str, value: Any) -> Any:
            if isinstance(value, str):
                masked = mask(value)
                # Mask the original form before normalization. Rewriting an IP
                # first can break its full-span match and leak address fragments.
                if key in {'source_ip', 'destination_ip'} and masked == value:
                    return _display_ip(value)
                return masked
            if key in {'record_id', 'process_id', 'source_port', 'destination_port'} and type(value) is int:
                masked = mask(str(value))
                return value if masked == str(value) else masked
            return value
        source_events.append({key: display_source_value(key, value) for key, value in source.items()})
    for item in items:
        if item["status"] == "processed":
            item["event_id"] = mask(item["event_id"])
        elif item["status"] == "unsupported" and type(item.get("sysmon_event_id")) is int:
            original = item["sysmon_event_id"]
            masked = mask(str(original))
            if masked != str(original):
                item["sysmon_event_id"] = masked
    summary = {"total": len(items)}
    for status in ("processed", "invalid", "unsupported"):
        summary[status] = sum(item["status"] == status for item in items)
    source_events = redact_for_display(source_events)
    _link_pii(pii, source_events)
    return {
        "model_state": "semantic-baseline", "summary": summary,
        "items": redact_for_display(items), "source_events": source_events,
        "detections": detections, "pii": pii,
    }


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
        _, mask = _pii_inspect([{"user": payload.analyst, "command_line": payload.rationale}], [0])
        safe_analyst = redact_for_display(mask(payload.analyst))
        rationale = redact_for_display(mask(payload.rationale))
        detection = service.approve(detection_id, safe_analyst, rationale)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="detection not found") from exc
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    return {"simulation_only": True, "detection": detection}
