import pandas as pd
from baseline_reader import baseline

# Load window flows
window = pd.read_csv("code/window_flows.csv")

# Filter invalid rows
window = window[window["src_ip"].str.contains(r"^\d+\.\d+\.\d+\.\d+$", na=False)]

print("=== WINDOW FLOWS LOADED ===")
print(window.head())

# === EXFILTRATION DETECTION ===

exfil_alerts = []

for index, row in window.iterrows():
    src = row["src_ip"]
    bytes_out = row["bytes_out"]

    if src not in baseline:
        continue

    p95 = baseline[src]["p95"]

    # Exfil rule: bytes_out > 2 * baseline p95
    if bytes_out > (2 * p95):
        exfil_alerts.append({
            "src_ip": src,
            "anomaly": "exfil",
            "bytes_out": bytes_out,
            "baseline_p95": p95,
            "reason": f"bytes_out {bytes_out} > 2 * p95 {p95}"
        })

print("\n=== EXFILTRATION ALERTS ===")
for alert in exfil_alerts:
    print(alert)

# === PORT SCAN DETECTION ===

port_scan_alerts = []

for src, group in window.groupby("src_ip"):
    if src not in baseline:
        continue

    baseline_dests = baseline[src]["destinations"]
    baseline_ports = baseline[src]["ports"]

    window_dests = set(group["dst_ip"])
    window_ports = set(group["dst_port"])

    new_dests = window_dests - baseline_dests
    new_ports = window_ports - baseline_ports

    # Normal Tier rule: many new destinations or ports
    if len(new_dests) >= 5 or len(new_ports) >= 5:
        port_scan_alerts.append({
            "src_ip": src,
            "anomaly": "port_scan",
            "new_destinations": new_dests,
            "new_ports": new_ports,
            "reason": f"{len(new_dests)} new destinations, {len(new_ports)} new ports vs baseline"
        })

print("\n=== PORT SCAN ALERTS ===")
for alert in port_scan_alerts:
    print(alert)
# === BEACONING DETECTION ===

import numpy as np

beacon_alerts = []

# Group by src, dst, port
for (src, dst, port), group in window.groupby(["src_ip", "dst_ip", "dst_port"]):
    if src not in baseline:
        continue

    # Convert timestamps to datetime
    group = group.sort_values("ts")
    times = pd.to_datetime(group["ts"])

    if len(times) < 3:
        continue  # need at least 3 points to detect regularity

    # Compute time differences between consecutive flows
    deltas = (times.diff().dt.total_seconds()).dropna()

    # If the time intervals are very similar → beaconing
    if deltas.std() < 5:  # very low variation in timing
        beacon_alerts.append({
            "src_ip": src,
            "dst_ip": dst,
            "dst_port": port,
            "anomaly": "beaconing",
            "count": len(group),
            "interval_mean": deltas.mean(),
            "interval_std": deltas.std(),
            "reason": f"Regular intervals: mean {deltas.mean():.2f}s, std {deltas.std():.2f}s"
        })

print("\n=== BEACONING ALERTS ===")
for alert in beacon_alerts:
    print(alert)


findings = exfil_alerts + port_scan_alerts + beacon_alerts

print("\n=== ALL FINDINGS ===")
for f in findings:
    print(f)

