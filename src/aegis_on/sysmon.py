"""Normalize the documented, bounded Sysmon JSON export format.

Event 1 requires Computer and Image. Event 3 requires Computer, Image, and
DestinationIp. User and CommandLine are optional for both. Both need
the Sysmon provider/channel and a valid UTC timestamp. No input values are
included in per-item error messages.
"""

from __future__ import annotations

from datetime import datetime, timezone
import ipaddress
import ntpath
import re
from typing import Any
from uuid import UUID, uuid4

PROVIDER = "microsoft-windows-sysmon"
CHANNEL = "microsoft-windows-sysmon/operational"
MAX_EVENTS = 1000


def _string(value: Any, *, required: bool = False, field: str = "field") -> str:
    if value is None:
        value = ""
    if not isinstance(value, str):
        raise ValueError(f"invalid text field: {field}")
    if any(0xD800 <= ord(char) <= 0xDFFF for char in value):
        raise ValueError(f"invalid Unicode field: {field}")
    if required and not value.strip():
        raise ValueError(f"missing required field: {field}")
    return value


def _integer(value: Any, *, minimum: int = 0, maximum: int | None = None, field: str = "field") -> int | None:
    if value is None or value == "":
        return None
    if isinstance(value, bool) or not isinstance(value, (str, int)):
        raise ValueError(f"invalid numeric field: {field}")
    if isinstance(value, str) and (not value.isascii() or not value.isdecimal()):
        raise ValueError(f"invalid numeric field: {field}")
    result = int(value)
    if result < minimum or (maximum is not None and result > maximum):
        raise ValueError(f"invalid numeric field: {field}")
    return result


def _ip(value: Any, *, required: bool = False, field: str = "IP") -> str:
    value = _string(value, required=required, field=field)
    if value:
        try:
            ipaddress.ip_address(value)
        except ValueError as exc:
            raise ValueError(f"invalid IP address: {field}") from exc
    return value


def _initiated(value: Any) -> bool | None:
    if value is None:
        return None
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        text = _string(value, field="Initiated").strip().casefold()
        if not text:
            return None
        if text in ("true", "false"):
            return text == "true"
    raise ValueError("invalid Initiated field")


def _timestamp(sysmon_time: Any, system_time: Any) -> str:
    value = _string(sysmon_time)
    sysmon_utc = bool(value)
    if not value:
        value = _string(system_time, required=True, field="UtcTime or TimeCreated")
    if not re.fullmatch(r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})?", value):
        raise ValueError("invalid timestamp")
    try:
        timestamp = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError("invalid timestamp") from exc
    if timestamp.tzinfo is None:
        if not sysmon_utc:
            raise ValueError("timestamp requires timezone")
        timestamp = timestamp.replace(tzinfo=timezone.utc)
    elif sysmon_utc and timestamp.utcoffset() != timezone.utc.utcoffset(timestamp):
        raise ValueError("UtcTime must use UTC")
    try:
        return timestamp.astimezone(timezone.utc).isoformat()
    except OverflowError as exc:
        raise ValueError("timestamp out of range") from exc


def parse_sysmon(payload: Any) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Return normalized events and one result per input, preserving input order.

    The outer object must contain an ``events`` array of at most 1000
    elements. Bad or unsupported records are reported individually. Duplicate
    source record keys are rejected within this batch; missing record IDs get
    new event IDs and cannot be deduplicated across imports.
    """
    if not isinstance(payload, dict) or not isinstance(payload.get("events"), list):
        raise ValueError("expected an object with an events array")
    records = payload["events"]
    if len(records) > MAX_EVENTS:
        raise ValueError("events must contain at most 1000 records")

    events: list[dict[str, Any]] = []
    items: list[dict[str, Any]] = []
    seen: set[tuple[str, str, int]] = set()
    for index, record in enumerate(records):
        item: dict[str, Any] = {"input_index": index}
        try:
            if not isinstance(record, dict):
                raise ValueError("record must be an object")
            system = record.get("System")
            data = record.get("EventData")
            if not isinstance(system, dict) or not isinstance(data, dict):
                raise ValueError("System and EventData must be objects")
            provider = _string(system.get("Provider"), required=True, field="Provider").strip()
            event_type = _integer(system.get("EventID"), field="EventID")
            if event_type is None:
                raise ValueError("missing event type")
            if provider.casefold() != PROVIDER or event_type not in (1, 3):
                item.update(status="unsupported", sysmon_event_id=event_type,
                            reason="unsupported provider or event type")
                items.append(item)
                continue
            channel = _string(system.get("Channel"), required=True, field="Channel").strip()
            if channel.casefold() != CHANNEL:
                raise ValueError("invalid Sysmon channel")
            host = _string(system.get("Computer"), required=True, field="Computer").strip()
            if any(character.isspace() or ord(character) < 32 for character in host):
                raise ValueError("invalid computer name")
            user = _string(data.get("User"), field="User")
            image = _string(data.get("Image"), required=True, field="Image")
            command = _string(data.get("CommandLine"), field="CommandLine")
            parent_image = _string(data.get("ParentImage"))
            process_name = ntpath.basename(image)
            parent_name = ntpath.basename(parent_image)
            if not process_name.strip() or (parent_image and not parent_name.strip()):
                raise ValueError("invalid process path")
            parent_command = _string(data.get("ParentCommandLine"))
            guid = _string(data.get("ProcessGuid"))
            if guid:
                try:
                    UUID(guid)
                except (ValueError, AttributeError) as exc:
                    raise ValueError("invalid process GUID") from exc
            process_id = _integer(data.get("ProcessId"), maximum=4294967295, field="ProcessId")
            record_id = _integer(system.get("EventRecordID"), minimum=1, field="EventRecordID")
            source_ip = _ip(data.get("SourceIp"), field="SourceIp")
            destination_ip = _ip(data.get("DestinationIp"), required=event_type == 3, field="DestinationIp")
            source_port = _integer(data.get("SourcePort"), maximum=65535, field="SourcePort")
            destination_port = _integer(data.get("DestinationPort"), maximum=65535, field="DestinationPort")
            initiated = _initiated(data.get("Initiated")) if event_type == 3 else None
            timestamp = _timestamp(data.get("UtcTime"), system.get("TimeCreated"))
            key = (host.casefold(), channel.casefold(), record_id) if record_id is not None else None
            if key is not None and key in seen:
                raise ValueError("duplicate source record")
            event_id = str(uuid4())
            metadata = {
                "sysmon_event_id": event_type, "record_id": record_id,
                "log_source": channel, "process_guid": guid, "process_id": process_id,
                "source_ip": source_ip, "source_port": source_port,
                "destination_ip": destination_ip, "destination_port": destination_port,
                "initiated": initiated,
            }
            events.append({
                "timestamp": timestamp, "host": host, "user": user,
                "process": process_name, "process_path": image, "command_line": command,
                "parent_process": parent_name, "parent_process_path": parent_image,
                "parent_command_line": parent_command,
                "source_ip": source_ip, "source_port": source_port,
                "destination": destination_ip, "destination_port": destination_port,
                "event_id": event_id, "source_metadata": metadata,
            })
            if key is not None:
                seen.add(key)
            item.update(status="processed", event_id=event_id)
        except ValueError as exc:
            item.update(status="invalid", reason=str(exc))
        items.append(item)
    return events, items
