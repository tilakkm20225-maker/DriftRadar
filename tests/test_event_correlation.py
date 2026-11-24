
from datetime import datetime, timedelta, timezone

from app.event_correlation import correlate_events


def make_event(event_type, source_ip, minute, severity="MEDIUM"):
    timestamp = (
        datetime(2026, 11, 23, 10, 0, tzinfo=timezone.utc)
        + timedelta(minutes=minute)
    )

    return {
        "event_type": event_type,
        "severity": severity,
        "source_ip": source_ip,
        "timestamp": timestamp.isoformat()
    }


def test_correlates_events_from_same_source():
    events = [
        make_event("port_scan", "192.168.1.50", 0),
        make_event("failed_login", "192.168.1.50", 5),
    ]

    result = correlate_events(events)

    assert result["groups_detected"] == 1
    assert result["correlation_groups"][0]["event_count"] == 2


def test_does_not_correlate_different_sources():
    events = [
        make_event("port_scan", "192.168.1.50", 0),
        make_event("failed_login", "192.168.1.60", 5),
    ]

    result = correlate_events(events)

    assert result["groups_detected"] == 0


def test_does_not_correlate_events_outside_window():
    events = [
        make_event("port_scan", "192.168.1.50", 0),
        make_event("failed_login", "192.168.1.50", 20),
    ]

    result = correlate_events(events)

    assert result["groups_detected"] == 0


def test_ignores_events_without_source_ip():
    events = [
        make_event("port_scan", "192.168.1.50", 0),
        {
            "event_type": "failed_login",
            "severity": "HIGH",
            "timestamp": "2026-11-23T10:05:00+00:00"
        }
    ]

    result = correlate_events(events)

    assert result["groups_detected"] == 0


def test_correlation_timeline_is_chronological():
    events = [
        make_event("successful_login", "192.168.1.50", 10),
        make_event("failed_login", "192.168.1.50", 2),
        make_event("port_scan", "192.168.1.50", 5),
    ]

    result = correlate_events(events)

    group = result["correlation_groups"][0]

    timestamps = [
        event["timestamp"]
        for event in group["timeline"]
    ]

    assert timestamps == sorted(timestamps)
    assert group["event_count"] == 3


def test_identifies_multiple_event_types():
    events = [
        make_event("port_scan", "192.168.1.50", 0),
        make_event("failed_login", "192.168.1.50", 3),
        make_event("successful_login", "192.168.1.50", 6),
    ]

    result = correlate_events(events)

    group = result["correlation_groups"][0]

    assert group["distinct_event_types"] == 3
    assert group["activity_type"] == "MULTI_EVENT_ACTIVITY"
