import numpy as np
from app.drift import calculate_psi, analyze_feature

def test_psi_non_negative():
    rng = np.random.default_rng(10)
    assert calculate_psi(rng.normal(size=500), rng.normal(size=500)) >= 0

def test_shifted_distribution_is_flagged():
    rng = np.random.default_rng(11)
    reference = rng.normal(0, 1, 500)
    current = rng.normal(2, 1, 500)
    result = analyze_feature("packet_count", reference, current)
    assert result["drift_detected"]
    assert result["psi"] > 0.2

def test_constant_reference_detects_change():
    result = calculate_psi(np.full(100, 10.0), np.full(100, 20.0))
    assert result > 0.2
