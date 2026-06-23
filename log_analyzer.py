import sys
import json
import re
from collections import defaultdict
from datetime import datetime


def parse_log_line(line):
    """
    Parse Linux authentication logs (SSH / auth logs).
    Extract username and IP address.
    """

    line = line.strip()
    if not line:
        return None

    patterns = [
        r"Failed password for invalid user (?P<user>\S+) from (?P<ip>\d+\.\d+\.\d+\.\d+)",
        r"Failed password for user (?P<user>\S+) from (?P<ip>\d+\.\d+\.\d+\.\d+)",
        r"Failed password for (?P<user>\S+) from (?P<ip>\d+\.\d+\.\d+\.\d+)",
        r"authentication failure.*user[=\s](?P<user>\S+)",
    ]

    for pattern in patterns:
        match = re.search(pattern, line)
        if match:
            data = match.groupdict()

            return {
                "user": data.get("user", "unknown"),
                "ip": data.get("ip", "N/A"),
                "status": "failed",
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "raw_log": line[:200]
            }

    return None


def generate_alert(count, ip_count):
    """Determine severity level."""

    if count >= 20 or ip_count >= 5:
        return "CRITICAL"
    elif count >= 10 or ip_count >= 3:
        return "HIGH"
    elif count >= 5:
        return "MEDIUM"
    return "LOW"


def save_json_report(report, filename="log_analysis_report.json"):
    """Export results to JSON file."""

    try:
        with open(filename, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=4)

        print(f"\n✅ JSON report saved: {filename}")

    except Exception as e:
        print(f"❌ Failed to save JSON report: {e}")


def analyze_log_file(log_file_path, threshold=5):

    user_attempts = defaultdict(int)
    ip_attempts = defaultdict(int)
    user_ip_map = defaultdict(set)

    print("\n📊 Security Log Analyzer")
    print("=" * 60)

    try:
        with open(log_file_path, "r", encoding="utf-8", errors="ignore") as f:

            for line in f:
                result = parse_log_line(line)

                if not result:
                    continue

                user = result["user"]
                ip = result["ip"]

                user_attempts[user] += 1

                if ip != "N/A":
                    ip_attempts[ip] += 1
                    user_ip_map[user].add(ip)

    except FileNotFoundError:
        print(f"❌ File not found: {log_file_path}")
        return

    report = {
        "analysis_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "log_file": log_file_path,
        "total_failed_attempts": sum(user_attempts.values()),
        "unique_users": len(user_attempts),
        "unique_ips": len(ip_attempts),
        "alerts": [],
        "top_users": [],
        "top_ips": []
    }

    alerts = []

    print("\n🚨 Alerts")
    print("-" * 60)

    for user, count in sorted(user_attempts.items(), key=lambda x: x[1], reverse=True):

        ip_count = len(user_ip_map[user])
        severity = generate_alert(count, ip_count)

        report["top_users"].append({
            "user": user,
            "failed_attempts": count,
            "unique_ips": ip_count,
            "severity": severity
        })

        if count >= threshold:
            alert = (
                f"{severity} ALERT → user={user} "
                f"attempts={count} ips={ip_count}"
            )

            print(alert)
            alerts.append(alert)

    report["alerts"] = alerts

    print("\n🌐 Top Attacking IPs")
    print("-" * 60)

    for ip, count in sorted(ip_attempts.items(), key=lambda x: x[1], reverse=True)[:10]:

        report["top_ips"].append({
            "ip": ip,
            "attempts": count
        })

        print(f"{ip:<18} → {count}")

    save_json_report(report)

    print(f"\n✅ Analysis completed ({len(alerts)} alerts generated)")


if __name__ == "__main__":

    if len(sys.argv) != 2:
        print("Usage:")
        print("  python log_analyzer_v1.py <logfile>")
        print("\nExample:")
        print("  python log_analyzer_v1.py real_auth.log")
        sys.exit(1)

    log_file = sys.argv[1]
    analyze_log_file(log_file)
