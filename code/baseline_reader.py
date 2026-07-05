import pandas as pd

# Load the CSV
df = pd.read_csv("code/baseline_flows.csv")

#keep only rows where src_ip is a valid IPv4 address
df = df[df["src_ip"].str.contains(r"^\d+\.\d+\.\d+\.\d+$", na=False)]

# Group by host
grouped = df.groupby("src_ip")

baseline = {}

for host, group in grouped:
    baseline[host] = {
        "mean": group["bytes_out"].mean(),
        "p95": group["bytes_out"].quantile(0.95),
        "destinations": set(group["dst_ip"]),
        "ports": set(group["dst_port"])
    }

print("\n=== BASELINE ===")
for host, info in baseline.items():
    print(host, info)
