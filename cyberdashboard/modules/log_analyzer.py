import matplotlib.pyplot as plt
import os
import re
from collections import defaultdict
from datetime import datetime

def analyze_logs(log_file):

    failed_attempts = defaultdict(int)
    all_requests = defaultdict(int)
    successful_logins = []

    trusted_ips = ["192.168.1.10"]

    with open(log_file, "r", errors="ignore") as file:
        for line in file:

            # -------------------------
            # Extract IP
            # -------------------------
            ip_match = re.search(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", line)
            if not ip_match:
                continue
            ip = ip_match.group()

            # -------------------------
            # Extract Time
            # -------------------------
            log_time = None

            # Format: [12/Mar/2025:10:12:01]
            time_match = re.search(r"\[(.*?)\]", line)
            if time_match:
                try:
                    log_time = datetime.strptime(
                        time_match.group(1),
                        "%d/%b/%Y:%H:%M:%S"
                    )
                except:
                    pass

            # Backup format: Mar 12 10:12:01
            if not log_time:
                alt_time = re.search(r"\w+\s+\d+\s+\d+:\d+:\d+", line)
                if alt_time:
                    try:
                        log_time = datetime.strptime(
                            alt_time.group(),
                            "%b %d %H:%M:%S"
                        )
                    except:
                        pass

            if not log_time:
                continue

            # -------------------------
            # Count requests
            # -------------------------
            all_requests[ip] += 1

            if "FAILED" in line.upper() or "401" in line:
                failed_attempts[ip] += 1

            if "SUCCESS" in line.upper() or "200" in line:
                successful_logins.append({
                    "ip": ip,
                    "time": log_time
                })

    # -------------------------
    # Detection Logic
    # -------------------------

    brute_force = []
    suspicious_ips = []
    unauthorized_logins = []

    # 🚨 Brute Force Detection
    for ip, count in failed_attempts.items():
        if count >= 3:
            brute_force.append({
                "ip": ip,
                "attempts": count
            })

    # ⚠️ Suspicious IP Detection
    for ip, count in all_requests.items():
        if count > 5:
            suspicious_ips.append({
                "ip": ip,
                "requests": count
            })

    # 🔐 Unauthorized Login Detection
    seen = set()

    for entry in successful_logins:
        ip = entry["ip"]
        time = entry["time"]

        if (ip, time) in seen:
            continue
        seen.add((ip, time))

        if time.hour < 6 or time.hour > 22:
            unauthorized_logins.append({
                "type": "Odd Time Login",
                "ip": ip,
                "time": str(time)
            })

        elif ip not in trusted_ips:
            unauthorized_logins.append({
                "type": "Unknown IP",
                "ip": ip,
                "time": str(time)
            })

    # -------------------------
    # Generate Graph
    # -------------------------
    chart_path = generate_ip_chart(all_requests)

    return {
        "brute_force": brute_force,
        "suspicious_ips": suspicious_ips,
        "unauthorized": unauthorized_logins,
        "chart": chart_path
    }


# -------------------------
# Graph Function
# -------------------------
def generate_ip_chart(ip_data):

    chart_dir = os.path.join("static", "charts")
    os.makedirs(chart_dir, exist_ok=True)

    ips = list(ip_data.keys())
    counts = list(ip_data.values())

    plt.figure(figsize=(8, 4))
    plt.bar(ips, counts, color="skyblue")

    plt.xlabel("IP Address")
    plt.ylabel("Requests")
    plt.title("IP Activity Analysis")

    plt.xticks(rotation=45)

    chart_path = os.path.join(chart_dir, "ip_chart.png")

    plt.tight_layout()
    plt.savefig(chart_path)
    plt.close()

    return chart_path