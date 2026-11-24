
from app.attack_chain import detect_attack_chains


def make_event(event_type, minute, source_ip="192.168.1.10"):
    return {
        "source_ip": source_ip,
        "event_type": event_type,
        "severity": "HIGH",
        "timestamp": f"2026-11-24T10:{minute:02d}:00+00:00"
    }


def test_detects_multi_stage_attack_chain():
    events = [
        make_event("port_scan", 0),
        make_event("failed_login", 5),
        make_event("successful_login", 10),
        make_event("malware_detected", 15)
    ]

    result = detect_attack_chains(events)

    assert result["chains_detected"] == 1
    chain = result["attack_chains"][0]
    assert chain["stage_count"] == 4


def test_does_not_correlate_different_sources():
    events = [
        make_event("port_scan", 0, "192.168.1.10"),
        make_event("failed_login", 5, "192.168.1.20")
    ]

    result = detect_attack_chains(events)

    assert result["chains_detected"] == 0


def test_ignores_single_stage_activity():
    events = [
        make_event("failed_login", 0),
        make_event("failed_login", 5)
    ]

    result = detect_attack_chains(events)

    assert result["chains_detected"] == 0


def test_ignores_events_outside_time_window():
    events = [
        make_event("port_scan", 0),
        make_event("successful_login", 40)
    ]

    result = detect_attack_chains(events)

    assert result["chains_detected"] == 0


def test_preserves_chronological_timeline():
    events = [
        make_event("successful_login", 10),
        make_event("port_scan", 0),
        make_event("failed_login", 5)
    ]

    result = detect_attack_chains(events)

    timeline = result["attack_chains"][0]["timeline"]

    assert timeline[0]["stage"] == "RECONNAISSANCE"
    assert timeline[1]["stage"] == "AUTHENTICATION_FAILURE"
    assert timeline[2]["stage"] == "SUCCESSFUL_AUTHENTICATION"


def test_rejects_invalid_window():
    events = [
        make_event("port_scan", 0),
        make_event("failed_login", 5)
    ]

    try:
        detect_attack_chains(events, window_minutes=0)
        assert False, "Expected ValueError"
    except ValueError:
        pass
