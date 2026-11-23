---
case_id: CASE-HEXSTRIKE-GATE-20261122-01
case_kind: synthetic_schema_fixture_not_observed
learning_case_eligibility: parser_and_correlation_testing_only
framework_runtime_observed: false
synthetic: true
provenance: GHSA-crrg-2r24-3g67 security gate with no verified fixed version
---

# HexStrike gate synthetic fixture memo

This directory is a static schema fixture, not a runtime case. It represents no observed framework runtime, execution, network activity, process, MCP call, or web request.

The fixture preserves the blocked gate: no verified fixed version exists for GHSA-crrg-2r24-3g67. The `Execute Endpoint` label appears only in the synthetic `policy_gate_denied_before_execution` event and does not represent an actual request.

## Fixed aliases

- Host: `LAB-HOST-01`
- Framework: `FRAMEWORK-HEXSTRIKE-01`
- Network: `DOCKER-INT-NET-01`
- Container: `CONTAINER-ID-01`

## Permitted use

Use this fixture only to test parsers, event correlation, and dashboards. It is not evidence of HexStrike behavior and is ineligible for framework learning, behavior evaluation, or attack labeling.

The boundary record is a declared safety-policy shape for validation only: internal-only network, no host port, no Docker socket, read-only root filesystem, all capabilities dropped, no-new-privileges, and bounded PID and memory settings. It is not an observed container configuration.
