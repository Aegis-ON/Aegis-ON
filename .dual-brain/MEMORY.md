# Project Memory

## Hot Memory

- [decision][refs:1][last_referenced:2026-11-09][last_verified:2026-11-09] The MVP uses a configured bearer token tied to one configured analyst identity; it is not multi-user authentication. Sensitive API endpoints and the demo event file require the token. Evidence: src/aegis_on/api.py and tests/test_api_regressions.py.
- [decision][refs:1][last_referenced:2026-11-09][last_verified:2026-11-09] Analysis returns event_refs mapping each input index to its displayed event ID, without persisting the source events. Callers must retain source events and responses for later traceability. Evidence: src/aegis_on/service.py and README.md.
- [decision][refs:1][last_referenced:2026-11-09][last_verified:2026-11-09] Sysmon ingestion accepts the documented PowerShell JSON export, isolates invalid records, assigns per-request event IDs, and returns only redacted source identifiers rather than original command lines. Evidence: src/aegis_on/sysmon.py, src/aegis_on/api.py and tests/test_sysmon_api.py.
- [constraint][refs:1][last_referenced:2026-11-09][last_verified:2026-11-09] Multiple-destination fan-out is a heuristic, not proof of scanning; it is batch-local and uses non-overlapping ten-minute windows. Sysmon fan-out includes only Event 3 records with explicit Initiated=true; unknown direction is not inferred. Evidence: src/aegis_on/engine.py, src/aegis_on/sysmon.py and tests/test_review_backend.py.
- [decision][refs:1][last_referenced:2026-11-09][last_verified:2026-11-09] The three presentation scenarios use synthetic logs through the authenticated production analysis pipeline, not real network activity. Dashboard approval changes simulation state only; severity labels are score-based heuristics. Evidence: data/scenario_*.json, static/index.html and tests/test_demo_scenarios.py.

## Warm Memory

## Cold Memory

## Archived Decisions
