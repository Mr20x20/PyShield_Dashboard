import sys
import os
import time
import json
from collections import defaultdict
from datetime import datetime

print("[+] Step 1: Core Python modules loaded.")

try:
    from scapy.all import sniff
    from scapy.layers.inet import IP, TCP
    print("[+] Step 2: Scapy networking modules loaded successfully.")
except Exception as import_err:
    print(f"❌ CRITICAL: Scapy import failed: {import_err}")
    if sys.stdin.isatty():
        input("Press Enter to exit...")
    sys.exit(1)

OUTPUT_FILE = "port_scan_report.json"

# Sliding window trackers using tuples (timestamp, port)
# Structure: { src_ip: [(timestamp_1, port_1), (timestamp_2, port_2)] }
port_scan_tracker = defaultdict(list)
syn_flood_tracker = defaultdict(list)

# -----------------------------------------------------------------------
# Security Policy Dimensions
# -----------------------------------------------------------------------
# TIME_WINDOW: sliding window (seconds) used by BOTH detectors below.
TIME_WINDOW = 10

# UNIQUE_PORTS_THRESHOLD: number of distinct ports a single source IP can
# probe within TIME_WINDOW before it's flagged as reconnaissance.
# NOTE: 3 is intentionally sensitive for demo/testing purposes. On a real
# LAN, normal traffic (browsers, background services) can legitimately
# touch 3+ ports on the same host within 10s. Consider raising to 5-8
# to reduce false positives in a non-demo environment.
UNIQUE_PORTS_THRESHOLD = 3

# SYN_FLOOD_THRESHOLD: pure SYN packets from one source within TIME_WINDOW
# before it's flagged as a flood/DoS attempt.
# NOTE: this is tuned to catch noisy local testing, not a real-world DDoS
# (genuine SYN floods are typically orders of magnitude higher volume).
SYN_FLOOD_THRESHOLD = 40

# MAX_LOG_RETENTION: max number of alerts kept in OUTPUT_FILE before the
# oldest entries are dropped (simple ring-buffer behavior).
# NOTE: save_alert_to_json() rewrites the entire file on every alert, so
# read+write cost grows as this number grows. Fine at this scale; if you
# ever need higher throughput, switch to an append-only JSON Lines format
# instead of a single JSON array.
MAX_LOG_RETENTION = 500


def save_alert_to_json(alert_type, src_ip, message):
    """Appends a security alert into the JSON report file (ring buffer)."""

    new_alert = {
        "source": "packet_sniffer",
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "alert_type": alert_type,
        "attacker_ip": src_ip,
        "message": message,
        "status": "ALERT",
    }

    alerts_list = []
    if os.path.exists(OUTPUT_FILE):
        try:
            with open(OUTPUT_FILE, "r", encoding="utf-8") as f:
                alerts_list = json.load(f)
                if not isinstance(alerts_list, list):
                    alerts_list = []
        except Exception as file_read_err:
            print(f"[!] SIEM Database Read Error: {file_read_err}")
            alerts_list = []

    alerts_list.append(new_alert)

    if len(alerts_list) > MAX_LOG_RETENTION:
        alerts_list.pop(0)

    try:
        with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
            json.dump(alerts_list, f, indent=4)
    except Exception as file_write_err:
        print(f"[-] SIEM Database Write Exception: {file_write_err}")


def check_smart_port_scan(src_ip, dport):
    """
    Time-Sliding Heuristic Port Scan Engine.
    Tracks distinct ports targeted by a source IP within a moving
    time-window to flag reconnaissance while avoiding false positives
    from a single repeated connection.
    """

    current_time = time.time()

    # 1. Purge entries older than the sliding window
    port_scan_tracker[src_ip] = [
        (t, p) for (t, p) in port_scan_tracker[src_ip]
        if current_time - t <= TIME_WINDOW
    ]

    # 2. Log current port activity with its discrete timestamp
    port_scan_tracker[src_ip].append((current_time, dport))

    # 3. Compute distinct ports targeted strictly within the valid timeframe
    unique_ports = {port for (t, port) in port_scan_tracker[src_ip]}

    if len(unique_ports) > UNIQUE_PORTS_THRESHOLD:
        port_scan_tracker[src_ip] = []  # reset tracker state post-detection
        return True
    return False


def check_syn_flood_dos(src_ip):
    """Tracks the rate of incoming pure SYN packets from a single source."""

    current_time = time.time()
    syn_flood_tracker[src_ip] = [
        t for t in syn_flood_tracker[src_ip]
        if current_time - t <= TIME_WINDOW
    ]
    syn_flood_tracker[src_ip].append(current_time)

    if len(syn_flood_tracker[src_ip]) > SYN_FLOOD_THRESHOLD:
        syn_flood_tracker[src_ip] = []
        return True
    return False


def packet_callback(packet):
    """Reactive packet analyzer using precise layer-4 bitmask matching."""
    try:
        if packet.haslayer(IP) and packet.haslayer(TCP):
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst  # ADDED: Extract destination IP
            dport = packet[TCP].dport

            # 0x02 isolates pure SYN packets (SYN=1, ACK=0, FIN=0, etc.)
            if packet[TCP].flags == 0x02:

                # 1. Smart Port Scan Validation (time-bounded distinct ports)
                if check_smart_port_scan(src_ip, dport):
                    msg = (
                        f"Reconnaissance threat from {src_ip} -> {dst_ip}. "
                        f"Targeted > {UNIQUE_PORTS_THRESHOLD} distinct "
                        f"ports within {TIME_WINDOW}s."
                    )
                    print(f"🚨 [SCAN ALERT] {msg}")
                    save_alert_to_json("PORT_SCAN", src_ip, msg)

                # 2. Targeted SYN Flood DoS Validation
                if check_syn_flood_dos(src_ip):
                    msg = (
                        f"SYN Flood DoS attack from {src_ip} -> {dst_ip} "
                        f"(> {SYN_FLOOD_THRESHOLD} SYNs within "
                        f"{TIME_WINDOW}s)"
                    )
                    print(f"🚨 [DOS ALERT] {msg}")
                    save_alert_to_json("DOS_ATTACK", src_ip, msg)

    except Exception as packet_err:
        print(f"[!] Packet Analysis Exception: {packet_err}", file=sys.stderr)


def main():
    print("[+] Step 3: Entering main execution block...")

    try:
        if os.path.exists(OUTPUT_FILE):
            os.remove(OUTPUT_FILE)
            print("[+] Step 4: Stale report database cleared.")
    except Exception as e:
        print(f"[!] Step 4 Exception (File Locked): {e}")

    print("[+] Step 5: Initializing Enterprise-Grade IDS Sniffer Core...")
    print(
        f"[*] Configuration: Scan Trigger = {UNIQUE_PORTS_THRESHOLD} "
        f"unique ports / DoS Trigger = {SYN_FLOOD_THRESHOLD} SYNs."
    )

    try:
        # Bind to the default network interface. (Previously this tried
        # "Npcap Loopback Adapter" first — removed: confirmed via testing
        # that self-targeted loopback traffic doesn't reliably traverse
        # that adapter on this setup, and the bare except around it was
        # silently swallowing real errors too. Default interface is what
        # actually captures live LAN traffic.)
        sniff(prn=packet_callback, store=False, filter="tcp")

        print("[+] Step 6: Sniffer engine closed gracefully.")
    except KeyboardInterrupt:
        print("\n[-] Sniffer execution halted by user request.")
    except Exception as runtime_error:
        print(f"\n❌ FATAL KERNEL ERROR DURING SNIFF: {runtime_error}")


if __name__ == "__main__":
    try:
        main()
    except Exception as global_fatal:
        print(f"❌ EMERGENCY CRASH: {global_fatal}")

    print("\n" + "=" * 60)
    # Only block on input if running in an actual interactive terminal —
    # avoids hanging forever if this is ever run non-interactively
    # (e.g. a scheduled task or invoked from another script).
    if sys.stdin.isatty():
        input("Execution Terminated. Press Enter to close this terminal...")
