---
case_id: CASE-SYNTHETIC-CONFIRMED-INCIDENT-20261122-01
synthetic: true
framework_runtime_observed: false
ground_truth_source: synthetic_exercise_scenario
final_label: confirmed_security_incident
display_label: simulated_confirmed_security_incident
eligible_for_training: synthetic_only
eligible_for_production_validation: false
review_status: synthetic_scenario_approved
not_actual_incident: true
---

# Synthetic confirmed-incident demonstration memo

This directory is a static monitoring demonstration fixture. It is not an observation of an actual incident, framework runtime, process execution, network connection, authentication attempt, or web request.

The label `confirmed_security_incident` is retained only as a correlation and alert-priority exercise label. The required display label is `simulated_confirmed_security_incident` to prevent presentation as a real compromise.

## Stable aliases

- Host: `LAB-HOST-01`
- User: `USER-ALIAS-01`
- Process: `PROCESS-ALIAS-01`
- Source: `SOURCE-ALIAS-01`
- Service: `SERVICE-WEB-01`
- Request ID: `REQ-SYN-INC-01`

## Permitted use and limits

Use this fixture only for Aegis-ON monitoring-screen, event-correlation, and alert-priority demonstrations. It is ineligible for production validation, incident statistics, production detection-performance claims, and actual training ground truth.

The Sysmon, web-authentication, and correlation records are non-executed metadata. They contain no execution detail, real-world identifier, sensitive value, or reproduction material.
