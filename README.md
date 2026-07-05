Project 5 — Watchman (Normal Tier)
This project builds a baseline from baseline_flows.csv and detects anomalies in window_flows.csv.

## Files

**baseline_reader.py** builds per‑host baseline (p95, normal ports, normal destinations)

**flow_detector.py** detects exfiltration, port scans, and beaconing

**REPORT.docx** plain‑English explanation of findings

Run
Code
python3 code/baseline_reader.py

python3 code/flow_detector.py

**Findings**

Exfiltration: 10.20.4.45

Port Scan: 10.20.4.77

Beaconing: 10.20.4.62
