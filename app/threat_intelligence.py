
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone


SUPPORTED_SEVERITIES = {"LOW", "MEDIUM", "HIGH", "CRITICAL"}


def validate_events(events):
    """Validate a batch of cybersecurity events."""

    if not isinstance(events, list) or not events:
        raise ValueError("Events must be a non-empty list.")

    validated = []

    for index, event in enumerate(events):
        if not isinstance(event, dict):
            raise ValueError(f"Event {index} must be an object.")

        event_type = event.get("event_type")
        severity = event.get("severity")
        timestamp = event.get("timestamp")

        if not isinstance(event_type, str) or not event_type.strip():
            raise ValueError(f"Event {index} has an invalid event_type.")

        if not isinstance(severity, str):
            raise ValueError(f"Event {index} has an invalid severity.")

        severity = severity.upper().strip()

        if severity not in SUPPORTED_SEVERITIES:
            raise ValueError(f"Event {index} has an unsupported severity.")

        if not isinstance(timestamp, str):
            raise ValueError(f"Event {index} requires an ISO timestamp.")

        try:
            parsed_timestamp = datetime.fromisoformat(
                timestamp.replace("Z", "+00:00")
            )
        except ValueError as exc:
            raise ValueError(
                f"Event {index} has an invalid timestamp."
            ) from exc

        if parsed_timestamp.tzinfo is None:
            raise ValueError(
                f"Event {index} timestamp must include a timezone."
            )

        validated.append({
            **event,
            "event_type": event_type.strip().lower(),
            "severity": severity,
            "parsed_timestamp": parsed_timestamp.astimezone(timezone.utc)
        })

    return validated

AUTH_FAILURE_TYPES = {
    "authentication_failure",
    "failed_login",
    "brute_force"
}

AUTH_BURST_WINDOW_MINUTES = 5
AUTH_BURST_THRESHOLD = 5


def detect_authentication_bursts(records):
    """
    Detect repeated authentication failures from the same source
    within a five-minute sliding time window.
    """

    source_events = defaultdict(list)

    for event in records:
        if event["event_type"] not in AUTH_FAILURE_TYPES:
            continue

        source_ip = event.get("source_ip")

        if isinstance(source_ip, str) and source_ip.strip():
            source_events[source_ip.strip()].append(
                event["parsed_timestamp"]
            )

    bursts = []

    window = timedelta(minutes=AUTH_BURST_WINDOW_MINUTES)

    for source_ip, timestamps in source_events.items():
        timestamps.sort()

        left = 0
        maximum_count = 0
        best_start = None
        best_end = None

        for right, current_time in enumerate(timestamps):
            while current_time - timestamps[left] > window:
                left += 1

            count = right - left + 1

            if count > maximum_count:
                maximum_count = count
                best_start = timestamps[left]
                best_end = current_time

        if maximum_count >= AUTH_BURST_THRESHOLD:
            bursts.append({
                "source_ip": source_ip,
                "event_count": maximum_count,
                "window_minutes": AUTH_BURST_WINDOW_MINUTES,
                "start_time": best_start.isoformat(),
                "end_time": best_end.isoformat()
            })

    return bursts

TREND_WINDOW_MINUTES = 60
TREND_INCREASE_THRESHOLD = 50
TREND_MINIMUM_EVENTS = 5


def analyze_authentication_trend(records):
    """Compare authentication failures across consecutive time windows."""

    timestamps = [
        event["parsed_timestamp"]
        for event in records
        if event["event_type"] in AUTH_FAILURE_TYPES
    ]

    if not timestamps:
        return {
            "previous_window_count": 0,
            "current_window_count": 0,
            "percentage_change": None,
            "trend_detected": False,
            "status": "no_authentication_activity"
        }

    latest_time = max(timestamps)

    current_start = latest_time - timedelta(minutes=TREND_WINDOW_MINUTES)
    previous_start = latest_time - timedelta(minutes=2 * TREND_WINDOW_MINUTES)

    previous_count = sum(
        1 for timestamp in timestamps
        if previous_start < timestamp <= current_start
    )

    current_count = sum(
        1 for timestamp in timestamps
        if current_start < timestamp <= latest_time
    )

    percentage_change = None

    if previous_count > 0:
        percentage_change = round(
            ((current_count - previous_count) / previous_count) * 100,
            2
        )

    if previous_count == 0 and current_count >= TREND_MINIMUM_EVENTS:
        trend_detected = True
        status = "new_activity"
    elif (
        previous_count > 0
        and current_count >= TREND_MINIMUM_EVENTS
        and percentage_change >= TREND_INCREASE_THRESHOLD
    ):
        trend_detected = True
        status = "increasing"
    else:
        trend_detected = False
        status = "stable_or_insufficient_activity"

    return {
        "window_minutes": TREND_WINDOW_MINUTES,
        "previous_window_count": previous_count,
        "current_window_count": current_count,
        "percentage_change": percentage_change,
        "trend_detected": trend_detected,
        "status": status
    }

def calculate_threat_confidence(pattern):
    """Calculate an explainable heuristic confidence score."""

    score = 20
    factors = []

    severity = pattern.get("severity", "LOW")
    count = pattern.get("observed_count", 0)
    pattern_name = pattern.get("pattern", "")

    severity_points = {
        "LOW": 5,
        "MEDIUM": 15,
        "HIGH": 25,
        "CRITICAL": 30
    }

    points = severity_points.get(severity, 0)
    score += points
    factors.append(f"Severity contribution: +{points}")

    if count >= 10:
        score += 25
        factors.append("High event frequency: +25")
    elif count >= 5:
        score += 15
        factors.append("Repeated event frequency: +15")

    if pattern_name == "authentication_failure_burst":
        score += 15
        factors.append("Temporal burst detected: +15")

    if pattern_name == "increasing_authentication_failures":
        score += 15
        factors.append("Increasing threat trend: +15")

    score = min(score, 95)

    if score >= 80:
        level = "VERY_HIGH"
    elif score >= 60:
        level = "HIGH"
    elif score >= 40:
        level = "MODERATE"
    else:
        level = "LOW"

    return {
        "confidence_score": score,
        "confidence_level": level,
        "confidence_factors": factors
    }



def analyze_threat_patterns(events):
    """
    Identify observable changes and recurring threat patterns.

    This engine generates indicators for investigation.
    It does not independently confirm that an attack occurred.
    """

    records = validate_events(events)

    event_counts = Counter()
    severity_counts = Counter()
    source_activity = defaultdict(Counter)
    source_ports = defaultdict(set)

    for event in records:
        event_counts[event["event_type"]] += 1
        severity_counts[event["severity"]] += 1

        source_ip = event.get("source_ip")

        if isinstance(source_ip, str) and source_ip.strip():
            source_ip = source_ip.strip()
            source_activity[source_ip][event["event_type"]] += 1

            port = event.get("destination_port")

            if isinstance(port, int) and not isinstance(port, bool):
                if 1 <= port <= 65535:
                    source_ports[source_ip].add(port)

    patterns = []
    recommendations = []

        # Temporal trend analysis
    authentication_trend = analyze_authentication_trend(records)

    if authentication_trend["trend_detected"]:
        patterns.append({
            "pattern": "increasing_authentication_failures",
            "severity": "HIGH",
            "observed_count": authentication_trend["current_window_count"],
            "evidence": (
                f"Authentication failures increased from "
                f"{authentication_trend['previous_window_count']} to "
                f"{authentication_trend['current_window_count']} "
                f"across consecutive one-hour windows."
            )
        })

        recommendations.append({
            "priority": "HIGH",
            "action": "Investigate the increase in authentication failures.",
            "reason": (
                "Recent authentication activity is elevated compared "
                "with the previous time window."
            ),
            "suggested_response": [
                "Review recent authentication logs.",
                "Identify affected accounts and source addresses.",
                "Check for suspicious successful logins."
            ]
        })

        # Temporal analysis: authentication failure bursts
    authentication_bursts = detect_authentication_bursts(records)

    for burst in authentication_bursts:
        patterns.append({
            "pattern": "authentication_failure_burst",
            "source_ip": burst["source_ip"],
            "observed_count": burst["event_count"],
            "severity": "HIGH",
            "evidence": (
                f"{burst['event_count']} authentication failures from "
                f"{burst['source_ip']} occurred within "
                f"{burst['window_minutes']} minutes."
            ),
            "start_time": burst["start_time"],
            "end_time": burst["end_time"]
        })

        recommendations.append({
            "priority": "HIGH",
            "action": (
                f"Investigate authentication burst from "
                f"{burst['source_ip']}."
            ),
            "reason": (
                "Multiple authentication failures occurred within "
                "a short time window."
            ),
            "suggested_response": [
                "Review the source IP and targeted accounts.",
                "Check for successful logins after the failures.",
                "Investigate whether the activity was authorized."
            ]
        })

    # Pattern 1: Repeated authentication failures
    auth_failures = sum(
        count for event_type, count in event_counts.items()
        if event_type in {
            "authentication_failure",
            "failed_login",
            "brute_force"
        }
    )

    if auth_failures >= 5:
        patterns.append({
            "pattern": "repeated_authentication_failures",
            "observed_count": auth_failures,
            "severity": "HIGH",
            "evidence": (
                f"{auth_failures} authentication failure events "
                "were observed in this batch."
            )
        })

        recommendations.append({
            "priority": "HIGH",
            "action": "Investigate authentication failure sources.",
            "reason": "Repeated authentication failures may indicate "
                      "credential attacks.",
            "suggested_response": [
                "Review affected accounts and source addresses.",
                "Check whether successful logins followed failures.",
                "Consider rate limiting and account protection."
            ]
        })

    # Pattern 2: Multiple destination ports from one source
    for source_ip, ports in source_ports.items():
        if len(ports) >= 5:
            patterns.append({
                "pattern": "multi_port_scanning_indicator",
                "source_ip": source_ip,
                "observed_count": len(ports),
                "severity": "MEDIUM",
                "evidence": (
                    f"Source {source_ip} contacted "
                    f"{len(ports)} distinct destination ports."
                )
            })

            recommendations.append({
                "priority": "MEDIUM",
                "action": f"Investigate network activity from {source_ip}.",
                "reason": "Activity across multiple destination ports "
                          "can be consistent with scanning.",
                "suggested_response": [
                    "Review connection timestamps and destination hosts.",
                    "Correlate with firewall and IDS logs.",
                    "Check whether the activity was authorized."
                ]
            })

    # Pattern 3: High and critical severity concentration
    high_severity = (
        severity_counts["HIGH"] + severity_counts["CRITICAL"]
    )

    if high_severity > 0:
        patterns.append({
            "pattern": "high_severity_activity",
            "observed_count": high_severity,
            "severity": "HIGH",
            "evidence": (
                f"{high_severity} high or critical severity events "
                "were observed."
            )
        })

        recommendations.append({
            "priority": "HIGH",
            "action": "Prioritize investigation of high-severity events.",
            "reason": "High-severity activity requires timely review.",
            "suggested_response": [
                "Inspect event details and affected assets.",
                "Correlate related events across data sources.",
                "Escalate confirmed incidents through the SOC process."
            ]
        })

    # Calculate confidence for every detected pattern
    for pattern in patterns:
        confidence = calculate_threat_confidence(pattern)
        pattern.update(confidence)

    return {
        "total_events": len(records),
        "event_distribution": dict(event_counts),
        "severity_distribution": dict(severity_counts),
        "unique_sources": len(source_activity),
        "patterns_detected": len(patterns),
        "patterns": patterns,
        "recommendations": recommendations,

        # NEW: Temporal analysis results
        "temporal_analysis": {
            "window_minutes": AUTH_BURST_WINDOW_MINUTES,
            "burst_threshold": AUTH_BURST_THRESHOLD,
            "authentication_bursts": authentication_bursts,
            "bursts_detected": len(authentication_bursts)
            },
        "trend_analysis": authentication_trend,

        "interpretation": (
            "Observable threat-related patterns were identified. "
            "These are investigation indicators, not proof of an attack."
            if patterns else
            "No configured threat patterns were identified in this batch. "
            "This does not guarantee that the environment is threat-free."
        )
    }

