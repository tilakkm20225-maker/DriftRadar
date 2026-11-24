
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone


DEFAULT_CORRELATION_WINDOW_MINUTES = 15


def _get_event_timestamp(event):
    timestamp = event.get("parsed_timestamp") or event.get("timestamp")

    if isinstance(timestamp, str):
        timestamp = datetime.fromisoformat(
            timestamp.replace("Z", "+00:00")
        )

    if not isinstance(timestamp, datetime):
        raise ValueError("Each event must contain a valid timestamp.")

    if timestamp.tzinfo is None or timestamp.utcoffset() is None:
        raise ValueError("Event timestamps must include a timezone.")

    return timestamp.astimezone(timezone.utc)


def correlate_events(
    events,
    window_minutes=DEFAULT_CORRELATION_WINDOW_MINUTES
):
    if not isinstance(events, list):
        raise ValueError("Events must be provided as a list.")

    if (
        not isinstance(window_minutes, int)
        or isinstance(window_minutes, bool)
        or window_minutes <= 0
    ):
        raise ValueError("Correlation window must be a positive integer.")

    source_events = defaultdict(list)

    for event in events:
        if not isinstance(event, dict):
            raise ValueError("Every event must be a dictionary.")

        source_ip = event.get("source_ip")

        if not isinstance(source_ip, str) or not source_ip.strip():
            continue

        source_events[source_ip.strip()].append({
            "event_type": str(event.get("event_type", "unknown")),
            "severity": str(event.get("severity", "UNKNOWN")).upper(),
            "timestamp": _get_event_timestamp(event)
        })

    correlation_groups = []
    window = timedelta(minutes=window_minutes)

    for source_ip, records in source_events.items():
        records.sort(key=lambda item: item["timestamp"])
        current_group = []

        for record in records:
            if not current_group:
                current_group.append(record)
                continue

            if record["timestamp"] - current_group[0]["timestamp"] <= window:
                current_group.append(record)
            else:
                if len(current_group) >= 2:
                    correlation_groups.append(
                        _build_correlation_group(source_ip, current_group)
                    )

                current_group = [record]

        if len(current_group) >= 2:
            correlation_groups.append(
                _build_correlation_group(source_ip, current_group)
            )

    correlation_groups.sort(key=lambda group: group["start_time"])

    return {
        "window_minutes": window_minutes,
        "groups_detected": len(correlation_groups),
        "correlation_groups": correlation_groups
    }


def _build_correlation_group(source_ip, records):
    event_types = sorted({
        record["event_type"] for record in records
    })

    severity_counts = Counter(
        record["severity"] for record in records
    )

    timeline = [
        {
            "event_type": record["event_type"],
            "severity": record["severity"],
            "timestamp": record["timestamp"].isoformat()
        }
        for record in records
    ]

    if len(event_types) > 1:
        reason = (
            "Multiple event types from the same source "
            "occurred within the configured time window."
        )
        activity_type = "MULTI_EVENT_ACTIVITY"
    else:
        reason = (
            "Repeated events from the same source "
            "occurred within the configured time window."
        )
        activity_type = "REPEATED_EVENT_ACTIVITY"

    return {
        "source_ip": source_ip,
        "event_count": len(records),
        "event_types": event_types,
        "distinct_event_types": len(event_types),
        "severity_distribution": dict(severity_counts),
        "activity_type": activity_type,
        "start_time": records[0]["timestamp"].isoformat(),
        "end_time": records[-1]["timestamp"].isoformat(),
        "correlation_reason": reason,
        "timeline": timeline
    }
