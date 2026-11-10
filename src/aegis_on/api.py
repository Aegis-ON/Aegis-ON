from __future__ import annotations

import hmac
import hashlib
import copy
import ipaddress
import json
import os
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from uuid import uuid4

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import FileResponse, JSONResponse, RedirectResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, Field, ValidationError

from .service import DetectionService
from .attack_model import AttackModel
from starlette.concurrency import run_in_threadpool
from .privacy import redact_for_display, _token
from .pii import PIIDetector
from .pii_reporting import InvalidPIIInput, inspect_events
from .sysmon import parse_sysmon
from .history_store import SQLiteHistory, HistoryError, BatchConflict
from .endpoint_views import build_endpoint_groups

app = FastAPI(title="Aegis-ON API", version="0.1.0")
service = DetectionService(SQLiteHistory(os.environ.get('AEGIS_HISTORY_DB') or str(Path.home() / '.aegis-on' / 'history.sqlite3')))
pii_detector = PIIDetector.from_environment()
attack_model = AttackModel.from_environment()
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


class CollectorHeartbeat(BaseModel):
    state: str
    error_code: str | None = None


@app.get("/", include_in_schema=False)
def dashboard() -> FileResponse:
    return FileResponse("static/console.html")


@app.get('/console/analysis', include_in_schema=False)
def analysis_console() -> FileResponse:
    return RedirectResponse('/console/events', status_code=307)


@app.get('/console', include_in_schema=False)
@app.get('/console/endpoints', include_in_schema=False)
@app.get('/console/detections', include_in_schema=False)
@app.get('/console/events', include_in_schema=False)
@app.get('/console/history', include_in_schema=False)
def console_page() -> FileResponse:
    return FileResponse('static/console.html')


@app.get('/console/endpoints/{endpoint_id}', include_in_schema=False)
def endpoint_console_page(endpoint_id: str) -> FileResponse:
    return FileResponse('static/console.html')


@app.get("/api/v1/health")
def health() -> dict[str, str]:
    return {"status": "ok", "model_state": "semantic-baseline"}


def _attack_model_status() -> dict[str, Any]:
    return attack_model.status()


@app.get("/api/v1/attack-model/status")
def attack_model_status(analyst: str = Depends(authenticated_analyst)) -> dict[str, Any]:
    return _attack_model_status()


@app.get("/api/v1/pii/status")
def pii_status(analyst: str = Depends(authenticated_analyst)) -> dict[str, str]:
    _, state = _verified_public_hosts()
    return {**pii_detector.status(), 'verified_public_hosts': state}


def _verified_public_hosts() -> tuple[frozenset[str], str]:
    """Read operator-controlled exact host values; invalid settings fail closed."""
    raw = os.environ.get('AEGIS_PII_VERIFIED_PUBLIC_HOSTS', '')
    if not raw:
        return frozenset(), 'disabled'
    try:
        values = json.loads(raw)
        if (not isinstance(values, list) or len(values) > 1000 or
                any(not isinstance(v, str) or not v or len(v) > 512
                    or any(0xD800 <= ord(c) <= 0xDFFF for c in v) for v in values)):
            raise ValueError('invalid configuration')
        return frozenset(values), 'enabled' if values else 'disabled'
    except (ValueError, RecursionError):
        return frozenset(), 'invalid'


def _pii_inspect(events: list[dict[str, Any]], indices: list[int]):
    try:
        verified_hosts, state = _verified_public_hosts()
        pii, mask = inspect_events(events, indices, pii_detector, verified_public_hosts=verified_hosts)
        pii['verified_public_hosts'] = state
        # Never persist or echo the configured bearer token if it occurs in an
        # analyzed field. Preserve the existing host-only display policy.
        token = os.environ.get('AEGIS_API_TOKEN', '')
        secret = re.compile(r'(?i)\b(password|passwd|pwd|secret|api[_-]?key|token)\s*[:=]\s*[^\s,;]+')
        def strip_secrets(value: str) -> str:
            value = value.replace(token, '[REDACTED_SECRET]') if token else value
            return secret.sub(lambda m: m.group(1) + '=[REDACTED_SECRET]', value)
        def safe_mask(value: str) -> str:
            return strip_secrets(mask(strip_secrets(value)))
        def safe_host(value: str) -> str:
            return strip_secrets(getattr(mask, 'host', mask)(strip_secrets(value)))
        safe_mask.host = safe_host
        return pii, safe_mask
    except InvalidPIIInput:
        raise HTTPException(status_code=422, detail="invalid event text field") from None
    except RuntimeError:
        raise HTTPException(status_code=503, detail="PII model inference failed") from None
    except ValueError:
        raise HTTPException(status_code=413, detail="PII analysis input exceeds the configured limit") from None


def _attack_results(events: list[dict[str, Any]], refs: list[dict[str, Any]]) -> dict[str, Any]:
    # Only sanitized refs are returned; model receives command text alone.
    results = []
    for event, ref in zip(events, refs):
        result = attack_model.predict(event.get('command_line', ''))
        results.append({'input_index': ref['input_index'], 'event_id': ref['event_id'], **result})
    state = _attack_model_status()
    if any(r['status'] == 'inference_error' for r in results):
        state = {**state, 'state': 'inference_error', 'reason': 'At least one command analysis failed'}
    return {**state, 'results': results}


def _link_pii(pii: dict[str, Any], refs: list[dict[str, Any]]) -> None:
    event_ids = {ref["input_index"]: ref["event_id"] for ref in refs}
    for finding in pii["findings"]:
        finding["event_id"] = event_ids.get(finding["input_index"], "")


def _history_batch(kind: str, prepared: dict[str, Any], sources: list[dict[str, Any]],
                   summary: dict[str, int], pii: dict[str, Any], model: dict[str, Any]) -> dict[str, Any]:
    # This is a strict allowlist: never retain input records, commands, user
    # fields, PII candidates, bearer tokens, or arbitrary model errors.
    allowed_states = {'ready', 'disabled', 'error', 'inference_error'}
    state = model.get('state') if model.get('state') in allowed_states else 'error'
    weights = model.get('weights_sha256')
    if not isinstance(weights, str) or len(weights) != 64 or any(c not in '0123456789abcdef' for c in weights):
        weights = None
    results = []
    for result in model.get('results', []):
        allowed = {k: result[k] for k in ('input_index', 'event_id') if k in result}
        status = result.get('status')
        allowed['status'] = status if status in {'ok', 'missing_command', 'model_unavailable', 'too_long', 'invalid_input', 'inference_error'} else 'invalid_output'
        if allowed['status'] == 'ok' and result.get('label') in {'review', 'below_threshold'}:
            allowed['label'] = result['label']
            score = result.get('score')
            if type(score) in (float, int) and 0 <= score <= 1:
                allowed['score'] = score
        results.append(allowed)
    return {'analysis_id': str(uuid4()), 'analyzed_at': datetime.now(timezone.utc).isoformat(),
            'input_type': kind, 'status': 'completed', 'summary': summary,
            'event_refs': prepared['refs'], 'source_events': sources,
            'detection_ids': [d['detection_id'] for d in prepared['conservative']],
            'pii_state': pii.get('state', 'error'),
            'model_state': 'semantic-baseline',
            'attack_model': {'state': state, 'weights_sha256': weights, 'results': results}}


def _commit_history(prepared: dict[str, Any], batch: dict[str, Any], collection: dict[str, str] | None = None) -> dict[str, Any] | None:
    # Keep current API response and in-memory display independent from the
    # more conservative durable representation.
    batch = copy.deepcopy(batch)
    if collection is not None and collection.get('received_at'):
        batch['received_at'] = collection['received_at']
    prepared = {**prepared, 'conservative': copy.deepcopy(prepared['conservative'])}
    # Hosts may be personal even when neither detector recognizes them. Never
    # persist the normal host display itself as the conservative value.
    for source in batch['source_events']:
        if source.get('host'):
            source['host'] = _token('HOST', source['host'], 'aegis-on-demo')
    if collection is not None and collection.get('events') is not None:
        # Display values come only from the conservative allowlisted metadata.
        for entry, source in zip(collection['events'], batch['source_events']):
            entry['event_id'] = source['event_id']
            entry['host_display'] = source.get('host') or '[HOST:unknown]'
            # A stable collector-scoped pseudonymous grouping hint, not a
            # proven device identity. Authenticated callers can correlate it.
            source['endpoint_group'] = entry['host_key']
    # User-supplied legacy JSON event IDs can contain arbitrary text. Persist
    # a stable display pseudonym while retaining cross-reference consistency.
    ids = {}
    if batch['input_type'] == 'json':
        ids = {r['event_id']: _token('EVENT', r['event_id'], 'aegis-on-demo') for r in batch['event_refs']}
        for ref in batch['event_refs']:
            ref['event_id'] = ids[ref['event_id']]
        for result in batch['attack_model']['results']:
            if result.get('event_id') in ids:
                result['event_id'] = ids[result['event_id']]
    # Rule evidence from legacy JSON may include command fragments or process
    # paths; retain the rule title, not the matched raw fragment.
    for detection in prepared['conservative']:
        if detection.get('host'):
            detection['host'] = _token('HOST', detection['host'], 'aegis-on-demo')
        detection['event_ids'] = [ids.get(event_id, event_id) for event_id in detection['event_ids']]
        override = prepared['overrides'].get(detection['detection_id'])
        if override:
            # The alternate can only be shown while the operator's exact host
            # remains approved. It may itself be sensitive; access is restricted.
            detection['_host_override_hash'] = override[0].hex()
            detection['_host_override_display'] = redact_for_display(override[1])
        evidence = detection.get('evidence', [])
        detection['evidence'] = [f"matched rule: {detection['title']}" if e.startswith('matched pattern:')
                                 else e for e in evidence if not e.startswith('process:')]
    try:
        return service.commit_analysis(prepared, batch, collection) if collection is not None else service.commit_analysis(prepared, batch)
    except BatchConflict:
        raise HTTPException(status_code=409, detail='batch key or source event identity conflicts with stored input') from None
    except HistoryError:
        raise HTTPException(status_code=503, detail='history storage unavailable') from None


@app.get("/data/demo_events.json", include_in_schema=False)
def demo_events(analyst: str = Depends(authenticated_analyst)) -> FileResponse:
    return FileResponse("data/demo_events.json")


@app.get("/api/v1/demo/scenarios/{scenario}")
def demo_scenario(scenario: str, analyst: str = Depends(authenticated_analyst)) -> FileResponse:
    path = DEMO_SCENARIOS.get(scenario)
    if path is None:
        raise HTTPException(status_code=404, detail="demo scenario not found")
    return FileResponse(path, media_type="application/json")


def _analyze_json(payload: AnalyzeRequest, collection: dict[str, str] | None = None) -> dict[str, Any]:
    pii, mask = _pii_inspect(payload.events, list(range(len(payload.events))))
    try:
        prepared = service.prepare_analysis(payload.events, mask=mask)
        detections, event_refs = prepared['display'], prepared['refs']
    except ValueError as exc:
        message = str(exc)
        if not (message.startswith("duplicate event_id") or message.startswith("missing required event fields:")
                or message.startswith("invalid Unicode field:")):
            message = "invalid event"
        raise HTTPException(status_code=422, detail=message) from None
    _link_pii(pii, event_refs)
    model = _attack_results(payload.events, event_refs)
    batch = _history_batch('json', prepared, [], {'total': len(payload.events), 'processed': len(payload.events), 'invalid': 0, 'unsupported': 0}, pii, model)
    saved = _commit_history(prepared, batch, collection)
    if collection is not None:
        return saved
    return {"model_state": "semantic-baseline", "detections": detections, "event_refs": event_refs, "pii": pii, "attack_model": model, 'analysis_id': batch['analysis_id']}


@app.post("/api/v1/analyze")
def analyze(payload: AnalyzeRequest, analyst: str = Depends(authenticated_analyst)) -> dict[str, Any]:
    return _analyze_json(payload)


async def _bounded_json_body(request: Request) -> bytes:
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
    return bytes(body)


async def _analyze_sysmon(body: bytes, collection: dict[str, str] | None = None) -> dict[str, Any]:
    try:
        payload = json.loads(body.decode("utf-8-sig"), object_pairs_hook=_unique_object, parse_constant=_reject_nonfinite)
        raw_events, items = parse_sysmon(payload)
    except (ValueError, UnicodeDecodeError, RecursionError):
        raise HTTPException(status_code=422, detail="invalid Sysmon JSON batch") from None

    processed_indices = [item["input_index"] for item in items if item["status"] == "processed"]
    if collection is not None and len(processed_indices) != len(items):
        # Collectors can only advance a cursor after the whole batch commits.
        # Invalid/unsupported entries require explicit collector-side handling.
        raise HTTPException(status_code=422, detail='collector batch contains invalid or unsupported events')
    pii, mask = _pii_inspect(raw_events, processed_indices)
    try:
        prepared = service.prepare_analysis(raw_events, allow_empty_command_line=True, mask=mask)
        for ref, input_index in zip(prepared['refs'], processed_indices):
            ref['input_index'] = input_index
        detections = prepared['display']
    except ValueError:
        raise HTTPException(status_code=422, detail="invalid analyzed events") from None
    # Return only identifiers and connection details needed to trace detections;
    # paths, commands, user names, and the original raw event are never returned.
    source_events = []
    history_sources = []
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
        def display_source_value(key: str, value: Any, conservative: bool = False) -> Any:
            if isinstance(value, str):
                masked = mask.host(value) if key == 'host' and not conservative else mask(value)
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
        history_sources.append({key: display_source_value(key, value, True) for key, value in source.items()})
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
    history_sources = redact_for_display(history_sources)
    _link_pii(pii, source_events)
    model = await run_in_threadpool(_attack_results, raw_events, source_events)
    # Sysmon event IDs were generated by the parser; these are the same IDs
    # used in the conservative detection/event references.
    batch = _history_batch('sysmon', prepared, history_sources, summary, pii, model)
    if collection is not None:
        entries = []
        for event, input_index in zip(raw_events, processed_indices):
            meta = event['source_metadata']
            record_id = meta['record_id']
            if record_id is None:
                raise HTTPException(status_code=422, detail='collector events require EventRecordID')
            def digest(value):
                return hashlib.sha256(json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(',', ':')).encode()).hexdigest()
            host_key = digest([collection['collector_id'], event['host'].casefold()])
            identity = digest([collection['collector_id'], event['host'].casefold(), meta['log_source'].casefold(), record_id])
            # Bind the identity to the full source object, including fields
            # that are not currently mapped by the normalizer. Never store it.
            content = payload['events'][input_index]
            destination = _display_ip(meta['destination_ip']) if meta['destination_ip'] else None
            entries.append({'event_key': identity, 'fingerprint':'full-v1:' + digest(content), 'host_key':host_key,
                            'occurred':event['timestamp'], 'destination_key':digest(destination) if destination else None,
                            'outbound':meta['sysmon_event_id'] == 3 and meta['initiated'] is True,
                            'event_id':event['event_id'], 'host_display':''})
        collection = {**collection, 'events':entries}
    saved = _commit_history(prepared, batch, collection)
    if collection is not None:
        return saved
    return {
        "model_state": "semantic-baseline", "summary": summary,
        "items": redact_for_display(items), "source_events": source_events,
        "detections": detections, "pii": pii, "attack_model": model, 'analysis_id': batch['analysis_id'],
    }


@app.post("/api/v1/sysmon/analyze")
async def analyze_sysmon(request: Request, analyst: str = Depends(authenticated_analyst)) -> dict[str, Any]:
    return await _analyze_sysmon(await _bounded_json_body(request))


def _collector_name(value: str | None) -> str:
    # Treat identifiers as opaque non-secret labels, never hostnames or logs.
    # Avoid persisting the configured bearer token if mistakenly supplied.
    token = os.environ.get('AEGIS_API_TOKEN', '')
    if (not value or not re.fullmatch(r'[A-Za-z0-9_-]{1,64}', value)
            or (token and token in value)):
        raise HTTPException(status_code=422, detail='invalid collector identifier or idempotency key')
    return value


def _collector_store() -> SQLiteHistory:
    if not isinstance(service.history, SQLiteHistory):
        raise HTTPException(status_code=503, detail='persistent history is required for collection')
    return service.history


@app.post('/api/v1/ingest/{kind}')
async def ingest_batch(kind: str, request: Request, analyst: str = Depends(authenticated_analyst)) -> dict[str, Any]:
    if kind not in ('json', 'sysmon'):
        raise HTTPException(status_code=404, detail='unsupported ingestion type')
    collector_id = _collector_name(request.headers.get('x-collector-id'))
    batch_id = _collector_name(request.headers.get('idempotency-key'))
    received_at = datetime.now(timezone.utc).isoformat()
    body = await _bounded_json_body(request)
    collection = {'collector_id': collector_id, 'batch_id': batch_id,
                  'input_type': kind, 'digest': hashlib.sha256(body).hexdigest(), 'received_at': received_at}
    store = _collector_store()
    try:
        previous = await run_in_threadpool(store.lookup_collected, collection)
        if previous is not None:
            return previous
        if kind == 'sysmon':
            return await _analyze_sysmon(body, collection)
        try:
            payload = json.loads(body.decode('utf-8-sig'), object_pairs_hook=_unique_object,
                                 parse_constant=_reject_nonfinite)
            if not isinstance(payload, dict):
                raise ValueError('invalid payload')
            valid = AnalyzeRequest(**payload)
        except (ValueError, UnicodeDecodeError, RecursionError, ValidationError):
            raise HTTPException(status_code=422, detail='invalid collector JSON batch') from None
        return await run_in_threadpool(_analyze_json, valid, collection)
    except BatchConflict:
        raise HTTPException(status_code=409, detail='batch key or source event identity conflicts with stored input') from None
    except HistoryError:
        raise HTTPException(status_code=503, detail='history storage unavailable') from None


@app.post('/api/v1/collectors/{collector_id}/heartbeat')
def collector_heartbeat(collector_id: str, payload: CollectorHeartbeat,
                        analyst: str = Depends(authenticated_analyst)) -> dict[str, Any]:
    collector_id = _collector_name(collector_id)
    codes = {'read_error', 'export_error', 'send_error', 'invalid_input', 'other'}
    if payload.state not in {'running','stopped','error'} or (
            payload.state == 'error' and payload.error_code not in codes) or (
            payload.state != 'error' and payload.error_code is not None):
        raise HTTPException(status_code=422, detail='invalid collector heartbeat')
    try:
        _collector_store().heartbeat(collector_id, payload.state, payload.error_code)
    except HistoryError:
        raise HTTPException(status_code=503, detail='history storage unavailable') from None
    return {'recorded': True}


@app.get('/api/v1/collectors')
def collectors(analyst: str = Depends(authenticated_analyst)) -> dict[str, Any]:
    try:
        records = _collector_store().list_collectors()
    except HistoryError:
        raise HTTPException(status_code=503, detail='history storage unavailable') from None
    return {'collectors': records,
            'note': 'Reported state and timestamps are not a live connectivity guarantee.'}


@app.get("/api/v1/detections")
def list_detections(analyst: str = Depends(authenticated_analyst)) -> dict[str, Any]:
    hosts, _ = _verified_public_hosts()
    try:
        return {"detections": service.list_detections(hosts)}
    except HistoryError:
        raise HTTPException(status_code=503, detail='history storage unavailable') from None


@app.get('/api/v1/history')
def list_history(analyst: str = Depends(authenticated_analyst)) -> dict[str, Any]:
    try:
        hosts, _ = _verified_public_hosts()
        analyses, detections = service.list_snapshot(hosts)
        return {'analyses': analyses, 'detections': detections}
    except HistoryError:
        raise HTTPException(status_code=503, detail='history storage unavailable') from None


def _endpoint_snapshot() -> list[dict[str, Any]]:
    try:
        # Deliberately use the conservative stored host representation, even
        # if an operator has configured an optional display exception.
        analyses, detections = service.list_snapshot()
        return build_endpoint_groups(analyses, detections)
    except HistoryError:
        raise HTTPException(status_code=503, detail='history storage unavailable') from None


@app.get('/api/v1/endpoints')
def list_endpoints(analyst: str = Depends(authenticated_analyst)) -> dict[str, Any]:
    groups = _endpoint_snapshot()
    return {'endpoints': [{k: v for k, v in g.items() if k not in ('events', 'detections')} for g in groups],
            'limitations': [
                'collector-scoped host-name groups can span analyses, but do not prove physical device identity; legacy events remain analysis-scoped',
                'pseudonyms can collide or vary; no connection or online status is collected',
                'legacy JSON events without linked detections have unknown hosts',
            ]}


@app.get('/api/v1/endpoints/{endpoint_id}')
def get_endpoint(endpoint_id: str, analyst: str = Depends(authenticated_analyst)) -> dict[str, Any]:
    if not re.fullmatch(r'[0-9a-f]{64}', endpoint_id):
        raise HTTPException(status_code=404, detail='endpoint observation not found')
    for group in _endpoint_snapshot():
        if group['endpoint_id'] == endpoint_id:
            return {'endpoint': {k: v for k, v in group.items() if k not in ('events', 'detections')},
                    'events': group['events'], 'detections': group['detections']}
    raise HTTPException(status_code=404, detail='endpoint observation not found')


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
        hosts, _ = _verified_public_hosts()
        detection = service.approve(detection_id, safe_analyst, rationale, hosts)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="detection not found") from exc
    except HistoryError:
        raise HTTPException(status_code=503, detail='history storage unavailable') from None
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    return {"simulation_only": True, "detection": detection}
