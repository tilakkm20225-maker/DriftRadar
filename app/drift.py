import numpy as np
from scipy.stats import ks_2samp
from app.config import PSI_THRESHOLD, KS_ALPHA

def calculate_psi(reference, current) -> float:
    reference = np.asarray(reference, dtype=float)
    current = np.asarray(current, dtype=float)
    if reference.size < 2 or current.size < 2:
        raise ValueError("PSI requires at least two values in each sample.")
    if not np.isfinite(reference).all() or not np.isfinite(current).all():
        raise ValueError("PSI inputs must contain only finite values.")

    # Reference quantiles define stable comparison buckets. Duplicate edges are removed.
    if np.ptp(reference) == 0:
        center = float(reference[0])
        margin = max(abs(center) * 0.01, 0.5)
        edges = np.array([-np.inf, center - margin, center + margin, np.inf])
    else:
        edges = np.unique(np.quantile(reference, np.linspace(0, 1, 11)))
        if len(edges) < 2:
            edges = np.array([reference.min() - 1, reference.max() + 1])
        else:
            edges[0], edges[-1] = -np.inf, np.inf

    ref_counts, _ = np.histogram(reference, bins=edges)
    cur_counts, _ = np.histogram(current, bins=edges)
    epsilon = 1e-6
    bins = len(ref_counts)
    ref_pct = (ref_counts + epsilon) / (len(reference) + epsilon * bins)
    cur_pct = (cur_counts + epsilon) / (len(current) + epsilon * bins)
    return float(np.sum((cur_pct - ref_pct) * np.log(cur_pct / ref_pct)))

def analyze_feature(name: str, reference, current) -> dict:
    reference = np.asarray(reference, dtype=float)
    current = np.asarray(current, dtype=float)
    psi = calculate_psi(reference, current)
    ks = ks_2samp(reference, current, alternative="two-sided", method="auto")
    # PSI captures magnitude by bucket; KS p-value is a statistical signal.
    drift = psi >= PSI_THRESHOLD or float(ks.pvalue) < KS_ALPHA
    return {
        "feature": name,
        "psi": round(psi, 6),
        "ks_statistic": round(float(ks.statistic), 6),
        "ks_p_value": round(float(ks.pvalue), 10),
        "drift_detected": bool(drift),
        "reference_samples": int(reference.size),
        "current_samples": int(current.size),
    }
