import pytest
from datetime import datetime, timedelta, timezone

from app.threat_intelligence import (
    analyze_threat_patterns,
    validate_events
)


def make_event(
    event_type="normal_traffic",
    severity="LOW",
    source_ip="192.168.1.10",
    timestamp="2026-11-23T10:00:00+05:30",
    destination_port=443
):
    return {
        "event_type": event_type,
        "severity": severity,
        "source_ip": source_ip,
        "timestamp": timestamp,
        "destination_port": destination_port
    }


def test_repeated_authentication_failures():
    events = [
        make_event("failed_login", "HIGH")
        for _ in range(6)
    ]

    result = analyze_threat_patterns(events)

    assert result["total_events"] == 6
    assert any(
        p["pattern"] == "repeated_authentication_failures"
        for p in result["patterns"]
    )


def test_multi_port_scanning_indicator():
    events = [
        make_event(
            "network_connection",
            source_ip="10.0.0.5",
            destination_port=port
        )
        for port in [21, 22, 23, 80, 443]
    ]

    result = analyze_threat_patterns(events)

    assert any(
        p["pattern"] == "multi_port_scanning_indicator"
        for p in result["patterns"]
    )


def test_high_severity_activity():
    events = [
        make_event("malware_indicator", "CRITICAL")
    ]

    result = analyze_threat_patterns(events)

    assert any(
        p["pattern"] == "high_severity_activity"
        for p in result["patterns"]
    )


def test_normal_events_produce_no_patterns():
    events = [make_event() for _ in range(3)]

    result = analyze_threat_patterns(events)

    assert result["patterns_detected"] == 0
    assert result["recommendations"] == []


def test_empty_event_list_is_rejected():
    with pytest.raises(ValueError):
        analyze_threat_patterns([])


def test_invalid_severity_is_rejected():
    events = [make_event(severity="UNKNOWN")]

    with pytest.raises(ValueError):
        validate_events(events)


def test_timezone_is_required():
    events = [
        make_event(timestamp="2026-11-23T10:00:00")
    ]

    with pytest.raises(ValueError):
        validate_events(events)


def test_missing_event_type_is_rejected():
    event = make_event()
    event["event_type"] = ""

    with pytest.raises(ValueError):
        validate_events([event])




def make_auth_events(count, minutes_apart=1, source="192.168.1.10"):
    from datetime import datetime, timedelta, timezone

    start = datetime(2026, 11, 23, 10, 0, tzinfo=timezone.utc)

    return [
        {
            "event_type": "failed_login",
            "severity": "HIGH",
            "source_ip": source,
            "timestamp": (
                start + timedelta(minutes=i * minutes_apart)
            ).isoformat()
        }
        for i in range(count)
    ]


def test_authentication_burst_detected():
    result = analyze_threat_patterns(make_auth_events(5))

    assert result["temporal_analysis"]["bursts_detected"] == 1


def test_spread_out_failures_do_not_trigger_burst():
    result = analyze_threat_patterns(
        make_auth_events(5, minutes_apart=15)
    )

    assert result["temporal_analysis"]["bursts_detected"] == 0


def test_different_sources_do_not_combine():
    events = []
    for i in range(5):
        events.extend(make_auth_events(1, source=f"192.168.1.{i + 1}"))

    result = analyze_threat_patterns(events)

    assert result["temporal_analysis"]["bursts_detected"] == 0


def test_out_of_order_events_detect_burst():
    events = make_auth_events(5)
    events.reverse()

    result = analyze_threat_patterns(events)

    assert result["temporal_analysis"]["bursts_detected"] == 1


def test_authentication_trend_detects_increase():
    events = []

    # Previous hour: 3 authentication failures
    for minute in [20, 30, 40]:
        events.append(make_event(
            event_type="failed_login",
            severity="HIGH",
            timestamp=(
                datetime(2026, 11, 23, 10, 0, tzinfo=timezone.utc)
                + timedelta(minutes=minute)
            ).isoformat()
        ))

    # Current hour: 5 authentication failures
    for minute in [70, 80, 90, 100, 110]:
        events.append(make_event(
            event_type="failed_login",
            severity="HIGH",
            timestamp=(
                datetime(2026, 11, 23, 10, 0, tzinfo=timezone.utc)
                + timedelta(minutes=minute)
            ).isoformat()
        ))

    result = analyze_threat_patterns(events)

    assert result["trend_analysis"]["trend_detected"] is True
    assert result["trend_analysis"]["percentage_change"] == 66.67


def test_no_authentication_activity_has_no_trend():
    result = analyze_threat_patterns([make_event()])

    assert result["trend_analysis"]["trend_detected"] is False


def test_zero_previous_activity_reports_new_activity():
    events = make_auth_events(5)

    result = analyze_threat_patterns(events)

    trend = result["trend_analysis"]

    assert trend["trend_detected"] is True
    assert trend["status"] == "new_activity"
    assert trend["percentage_change"] is None


def test_authentication_decrease_does_not_trigger_trend():
    events = []

    # Previous window: 8 authentication failures
    for minute in [-85, -80, -75, -70, -65, -60, -55, -50]:
        events.append(make_event(
            event_type="failed_login",
            severity="HIGH",
            timestamp=(
                datetime(2026, 11, 23, 10, 0, tzinfo=timezone.utc)
                + timedelta(minutes=minute)
            ).isoformat()
        ))

    # Current window: only 1 authentication failure
    events.append(make_event(
        event_type="failed_login",
        severity="HIGH",
        timestamp="2026-11-23T10:30:00+00:00"
    ))

    result = analyze_threat_patterns(events)

    assert result["trend_analysis"]["trend_detected"] is False
    assert result["trend_analysis"]["previous_window_count"] == 8
    assert result["trend_analysis"]["current_window_count"] == 1



def test_confidence_score_is_within_valid_range():
    result = analyze_threat_patterns(make_auth_events(6))

    for pattern in result["patterns"]:
        assert 0 <= pattern["confidence_score"] <= 100


def test_authentication_burst_has_confidence_boost():
    result = analyze_threat_patterns(make_auth_events(5))

    burst = next(
        p for p in result["patterns"]
        if p["pattern"] == "authentication_failure_burst"
    )

    assert burst["confidence_score"] == 75
    assert burst["confidence_level"] == "HIGH"


def test_confidence_contains_explanation():
    result = analyze_threat_patterns(make_auth_events(6))

    for pattern in result["patterns"]:
        assert len(pattern["confidence_factors"]) > 0


def test_increasing_trend_receives_confidence_boost():
    events = []

    for minute in [20, 30, 40, 70, 80, 90, 100, 110]:
        events.append(
            make_event(
                event_type="failed_login",
                severity="HIGH",
                timestamp=(
                    datetime(2026, 11, 23, 10, 0, tzinfo=timezone.utc)
                    + timedelta(minutes=minute)
                ).isoformat()
            )
        )

    result = analyze_threat_patterns(events)

    trend = next(
        p for p in result["patterns"]
        if p["pattern"] == "increasing_authentication_failures"
    )

    assert trend["confidence_score"] == 75
