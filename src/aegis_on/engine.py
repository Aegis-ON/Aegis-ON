from __future__ import annotations

import re
from collections import defaultdict
from datetime import timedelta

from .models import Detection, DetectionSource, SecurityEvent


class RuleDetector:
    """Small explainable ruleset. Production rules should be managed as Sigma files."""

    RULES = (
        (
            "T1485",
            "Potential data destruction command",
            88,
            re.compile(
                r"\b(?:rm\s+(?:(?:--[a-z-]+(?:=[^\s;&|]+)?|-[a-z]+)\s+)*"
                r"(?:--recursive|-[a-z]*r[a-z]*)(?=\s|$|[;&|])"
                r"|del\s+(?:/[a-z]+\s+)*"
                r"/[a-z]*[sq][a-z]*(?=\s|$|[/;&|])"
                r"|format\s+|mkfs\b)",
                re.I,
            ),
        ),
        (
            "T1489",
            "Potential service stop command",
            68,
            re.compile(r"\b(?:stop-service|systemctl\s+stop|sc\s+stop)\b", re.I),
        ),
        (
            "T1105",
            "Potential ingress tool transfer",
            58,
            re.compile(r"\b(?:curl|wget|invoke-webrequest|certutil)\b", re.I),
        ),
    )

    def detect(self, event: SecurityEvent) -> list[Detection]:
        findings: list[Detection] = []
        for technique, title, score, pattern in self.RULES:
            match = pattern.search(event.command_line)
            if not match:
                continue
            findings.append(
                Detection(
                    technique=technique,
                    title=title,
                    score=score,
                    source=DetectionSource.RULE,
                    evidence=(
                        [f"matched rule: {title} ({technique})"]
                        if event.source_metadata.get("sysmon_event_id") in (1, 3)
                        else [f"matched pattern: {match.group(0)}", f"process: {event.process}"]
                    ),
                    event_ids=[event.event_id],
                    host=event.host,
                    requires_human_approval=technique == "T1485",
                )
            )
        return findings


class SemanticRiskAdapter:
    """Explicit temporary baseline until a validated multi-label Transformer replaces it."""

    FEATURES = {
        "T1059": ("Command and Scripting Interpreter", 42, ("powershell", "cmd.exe", "bash -c", "sh -c")),
        "T1485": ("Potential destructive intent", 55, ("delete", "remove", "wipe", "erase")),
        "T1105": ("Potential remote retrieval", 38, ("download", "http://", "https://", "transfer")),
    }

    def classify(self, event: SecurityEvent) -> list[Detection]:
        # A network connection without a command line must not invent command intent.
        if not event.command_line:
            return []
        corpus = " ".join((event.process, event.parent_process, event.command_line)).lower()
        findings: list[Detection] = []
        for technique, (title, base_score, signals) in self.FEATURES.items():
            hits = [signal for signal in signals if signal in corpus]
            if not hits:
                continue
            score = min(80, base_score + 8 * (len(hits) - 1))
            if technique == "T1485" and not any(
                term in corpus for term in ("delete", "remove", "wipe", "erase")
            ):
                continue
            findings.append(
                Detection(
                    technique=technique,
                    title=title,
                    score=score,
                    source=DetectionSource.SEMANTIC_BASELINE,
                    evidence=[f"semantic signals: {', '.join(hits)}", "model state: baseline"],
                    event_ids=[event.event_id],
                    host=event.host,
                    requires_human_approval=score >= 70,
                )
            )
        return findings


class CorrelationEngine:
    def detect_scan_fanout(self, events: list[SecurityEvent]) -> list[Detection]:
        """Flag a host contacting at least three unique destinations in ten minutes."""

        grouped: dict[tuple[bool, str], list[SecurityEvent]] = defaultdict(list)
        for event in sorted(events, key=lambda item: item.timestamp):
            if event.destination:
                is_sysmon = event.source_metadata.get("sysmon_event_id") in (1, 3)
                grouped[(is_sysmon, event.host.casefold() if is_sysmon else event.host)].append(event)

        findings: list[Detection] = []
        for host_events in grouped.values():
            host = host_events[0].host
            anchor_index = 0
            while anchor_index < len(host_events):
                anchor = host_events[anchor_index]
                window = [item for item in host_events[anchor_index:]
                          if item.timestamp - anchor.timestamp <= timedelta(minutes=10)]
                destinations = {item.destination for item in window if item.destination}
                if len(destinations) < 3:
                    anchor_index += 1
                    continue
                findings.append(
                    Detection(
                        technique="T1595",
                        title="Potential multiple-destination connections",
                        score=min(85, 48 + 8 * len(destinations)),
                        source=DetectionSource.CORRELATION,
                        evidence=[
                            f"{len(destinations)} unique destinations in ten minutes",
                            f"observed period: {window[0].timestamp.isoformat()} to {window[-1].timestamp.isoformat()}",
                            f"related connection events: {len(window)}",
                            "condition: same host, at least 3 unique destinations within 10 minutes",
                            "multiple connections are not proof of scanning or attack",
                        ],
                        event_ids=[item.event_id for item in window],
                        host=host,
                        requires_human_approval=False,
                    )
                )
                # Emit one alert per non-overlapping ten-minute window.
                anchor_index += len(window)
        return findings


class DetectionPipeline:
    def __init__(self) -> None:
        self.rules = RuleDetector()
        self.semantic = SemanticRiskAdapter()
        self.correlation = CorrelationEngine()

    def analyze(self, events: list[SecurityEvent]) -> list[Detection]:
        detections: list[Detection] = []
        for event in events:
            detections.extend(self.rules.detect(event))
            detections.extend(self.semantic.classify(event))
        detections.extend(self.correlation.detect_scan_fanout(events))
        return sorted(detections, key=lambda item: item.score, reverse=True)
