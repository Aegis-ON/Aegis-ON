# Project Memory

## Hot Memory

- [decision][refs:1][last_referenced:2026-11-09][last_verified:2026-11-09] The MVP uses a configured bearer token tied to one configured analyst identity; it is not multi-user authentication. Sensitive API endpoints and the demo event file require the token. Evidence: src/aegis_on/api.py and tests/test_api_regressions.py.
- [decision][refs:1][last_referenced:2026-11-09][last_verified:2026-11-09] Analysis returns event_refs mapping each input index to its displayed event ID, without persisting the source events. Callers must retain source events and responses for later traceability. Evidence: src/aegis_on/service.py and README.md.
- [decision][refs:1][last_referenced:2026-11-09][last_verified:2026-11-09] Sysmon ingestion accepts the documented PowerShell JSON export, isolates invalid records, assigns per-request event IDs, and returns only redacted source identifiers rather than original command lines. Evidence: src/aegis_on/sysmon.py, src/aegis_on/api.py and tests/test_sysmon_api.py.
- [constraint][refs:1][last_referenced:2026-11-09][last_verified:2026-11-09] Multiple-destination fan-out is a heuristic, not proof of scanning; it is batch-local and uses non-overlapping ten-minute windows. Sysmon fan-out includes only Event 3 records with explicit Initiated=true; unknown direction is not inferred. Evidence: src/aegis_on/engine.py, src/aegis_on/sysmon.py and tests/test_review_backend.py.
- [decision][refs:1][last_referenced:2026-11-09][last_verified:2026-11-09] The three presentation scenarios use synthetic logs through the authenticated production analysis pipeline, not real network activity. Dashboard approval changes simulation state only; severity labels are score-based heuristics. Evidence: data/scenario_*.json, static/index.html and tests/test_demo_scenarios.py.
- [decision][refs:1][last_referenced:2026-11-09][last_verified:2026-11-09] Repeated approval requests return the first simulation result without changing its reason; locking and state are limited to one server process. Evidence: src/aegis_on/service.py and tests/test_approval_idempotency.py.

## Warm Memory

- [decision][refs:1][last_referenced:2026-11-09][last_verified:2026-11-09] The presentation dashboard defaults to a low-glare dark palette at the user's request; retain readable text, focus indicators, and status badges. Evidence: static/index.html.
- [decision][refs:1][last_referenced:2026-11-10][last_verified:2026-11-10] Evaluate synthetic command triage per event and outbound fan-out conditions per batch separately; fan-out condition truth is not attack truth. Keep truth annotations independent of predictions, exclude invalid/unknown cases appropriately, and do not treat this dataset as a PII or real-world performance benchmark. Evidence: evaluation/synthetic_v1.json, src/aegis_on/evaluation.py and docs/detection_evaluation.md.
- [decision][refs:1][last_referenced:2026-11-10][last_verified:2026-11-10] PII NER is optional and local-only, separate from the keyword threat baseline and its evaluation; regex-only operation and model failure must be explicit, and undetected PII can remain visible. Real ONNX inference and tokenizer-file integrity were not verified in the implementation environment. Evidence: src/aegis_on/pii.py, docs/pii_model.md and docs/pii_evaluation.md.

## Cold Memory

## Archived Decisions
