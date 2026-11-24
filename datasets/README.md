# DriftRadar synthetic datasets

All three CSV files are generated synthetic examples, not real network captures.
They contain no personal or production data. Each file has 2,000 rows and six
numeric network-flow features.

- `baseline_network_traffic.csv`: reference distribution.
- `current_stable_traffic.csv`: similar distribution, for a stability check.
- `current_shifted_traffic.csv`: intentionally changed distributions, for drift testing.

Use the baseline CSV in the Register a baseline form, then compare either current
CSV in the Analyze current traffic form. The shifted data is not labelled as
malicious: statistical drift alone does not establish an attack.
