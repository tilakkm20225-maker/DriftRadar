
from datetime import datetime, timedelta, timezone
from collections import defaultdict


DEFAULT_ATTACK_WINDOW_MINUTES = 30


def _parse_timestamp(event):
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


def _classify_event(event_type):
    event_type = event_type.lower().replace("-", "_").replace(" ", "_")

    if any(term in event_type for term in (
        "port_scan", "port_scanning", "network_scan", "reconnaissance"
    )):
        return "RECONNAISSANCE"

    if any(term in event_type for term in (
        "failed_login", "login_failure", "authentication_failure",
        "auth_failure", "brute_force"
    )):
        return "AUTHENTICATION_FAILURE"

    if any(term in event_type for term in (
        "successful_login", "login_success", "successful_authentication",
        "auth_success"
    )):
        return "SUCCESSFUL_AUTHENTICATION"

    if any(term in event_type for term in (
        "malware", "suspicious_process", "privilege_escalation",
        "command_execution", "process_injection", "data_exfiltration"
    )):
        return "POST_AUTHENTICATION_ACTIVITY"

    return None


def detect_attack_chains(
    events,
    window_minutes=DEFAULT_ATTACK_WINDOW_MINUTES
):
    if not isinstance(events, list):
        raise ValueError("Events must be provided as a list.")

    if (
        not isinstance(window_minutes, int)
        or isinstance(window_minutes, bool)
        or window_minutes <= 0
    ):
        raise ValueError("Attack window must be a positive integer.")

    source_events = defaultdict(list)

    for event in events:
        if not isinstance(event, dict):
            raise ValueError("Every event must be a dictionary.")

        source_ip = event.get("source_ip")
        event_type = event.get("event_type")

        if not isinstance(source_ip, str) or not source_ip.strip():
            continue

        if not isinstance(event_type, str):
            continue

        stage = _classify_event(event_type)

        if stage is None:
            continue

        source_events[source_ip.strip()].append({
            "event_type": event_type,
            "stage": stage,
            "severity": str(event.get("severity", "UNKNOWN")).upper(),
            "timestamp": _parse_timestamp(event)
        })

    attack_chains = []
    window = timedelta(minutes=window_minutes)

    for source_ip, records in source_events.items():
        records.sort(key=lambda item: item["timestamp"])

        current_group = []

        for record in records:
            if not current_group:
                current_group = [record]
                continue

            if record["timestamp"] - current_group[0]["timestamp"] <= window:
                current_group.append(record)
            else:
                chain = _build_attack_chain(source_ip, current_group)

                if chain:
                    attack_chains.append(chain)

                current_group = [record]

        if current_group:
            chain = _build_attack_chain(source_ip, current_group)

            if chain:
                attack_chains.append(chain)

    attack_chains.sort(key=lambda item: item["start_time"])

    return {
        "window_minutes": window_minutes,
        "chains_detected": len(attack_chains),
        "attack_chains": attack_chains
    }


def _build_attack_chain(source_ip, records):
    stages = list(dict.fromkeys(
        record["stage"] for record in records
    ))

    if len(stages) < 2:
        return None

    stage_order = [
        "RECONNAISSANCE",
        "AUTHENTICATION_FAILURE",
        "SUCCESSFUL_AUTHENTICATION",
        "POST_AUTHENTICATION_ACTIVITY"
    ]

    ordered_stages = [
        stage for stage in stage_order if stage in stages
    ]

    timeline = [
        {
            "event_type": record["event_type"],
            "stage": record["stage"],
            "severity": record["severity"],
            "timestamp": record["timestamp"].isoformat()
        }
        for record in records
    ]

    return {
        "source_ip": source_ip,
        "stages_detected": ordered_stages,
        "stage_count": len(ordered_stages),
        "event_count": len(records),
        "start_time": records[0]["timestamp"].isoformat(),
        "end_time": records[-1]["timestamp"].isoformat(),
        "timeline": timeline,
        "interpretation": (
            "Multiple attack-related stages were observed from "
            "the same source within the configured time window. "
            "This is a suspicious sequence requiring investigation, "
            "not proof of a successful compromise."
        )
    }
