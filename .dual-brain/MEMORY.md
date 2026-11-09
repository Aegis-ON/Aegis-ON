# Project Memory

## Hot Memory

- [decision][refs:1][last_referenced:2026-11-09][last_verified:2026-11-09] The MVP uses a configured bearer token tied to one configured analyst identity; it is not multi-user authentication. Sensitive API endpoints and the demo event file require the token. Evidence: src/aegis_on/api.py and tests/test_api_regressions.py.
- [decision][refs:1][last_referenced:2026-11-09][last_verified:2026-11-09] Analysis returns event_refs mapping each input index to its displayed event ID, without persisting the source events. Callers must retain source events and responses for later traceability. Evidence: src/aegis_on/service.py and README.md.

## Warm Memory

## Cold Memory

## Archived Decisions
