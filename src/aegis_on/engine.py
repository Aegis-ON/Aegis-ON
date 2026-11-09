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
            re.compile(r"\b(?:rm\s+-[^\n]*r|del\s+/[^\n]*[sq]|format\s+|mkfs\b)", re.I),
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
                    evidence=[f"matched pattern: {match.group(0)}", f"process: {event.process}"],
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

        grouped: dict[str, list[SecurityEvent]] = defaultdict(list)
        for event in sorted(events, key=lambda item: item.timestamp):
            grouped[event.host].append(event)

        findings: list[Detection] = []
        for host, host_events in grouped.items():
            for anchor_index, anchor in enumerate(host_events):
                window_end = anchor.timestamp + timedelta(minutes=10)
                window = [item for item in host_events[anchor_index:] if item.timestamp <= window_end]
                destinations = {item.destination for item in window if item.destination}
                if len(destinations) < 3:
                    continue
                findings.append(
                    Detection(
                        technique="T1595",
                        title="Potential active scanning fan-out",
                        score=min(85, 48 + 8 * len(destinations)),
                        source=DetectionSource.CORRELATION,
                        evidence=[f"{len(destinations)} unique destinations in ten minutes", f"host: {host}"],
                        event_ids=[item.event_id for item in window],
                        host=host,
                        requires_human_approval=False,
                    )
                )
                break
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
