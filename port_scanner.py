import socket
import sys
import threading
from queue import Queue, Empty
import time
import json 

def scan_port(ip, port):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(1)
            result = sock.connect_ex((ip, port))
            return result == 0
    except Exception:
        return False


def worker(ip, port_queue, open_ports):
    while True:
        try:
            port = port_queue.get_nowait()
        except Empty:
            break

        if scan_port(ip, port):
            open_ports.append(port)

        port_queue.task_done()


def main():
    if len(sys.argv) != 4:
        print(
            "Usage: python port_scanner.py <IP> <START_PORT> <END_PORT>"
        )
        sys.exit(1)

    ip = sys.argv[1]
    start_port = int(sys.argv[2])
    end_port = int(sys.argv[3])

    print(
        f"Scanning {ip} from {start_port} to {end_port}"
    )

    start_time = time.time()

    port_queue = Queue()
    open_ports = []

    for port in range(start_port, end_port + 1):
        port_queue.put(port)

    num_threads = 100

    threads = []

    for _ in range(num_threads):
        thread = threading.Thread(
            target=worker,
            args=(ip, port_queue, open_ports)
        )

        thread.start()
        threads.append(thread)

    for thread in threads:
        thread.join()

    open_ports.sort()

    duration = time.time() - start_time

    scan_report = {
        "source": "port_scanner",
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "target_ip": ip,
        "scan_duration_sec": round(duration, 2),
        "open_ports": open_ports,
        "ports_count": len(open_ports)
    }

    with open("port_scan_report.json", "w", encoding="utf-8") as f:
        json.dump(scan_report, f, indent=4)

    print(f"\n✅ Scan report saved to port_scan_report.json")

    print("\nOpen Ports:")

    for port in open_ports:
        print(f"{port}/tcp OPEN")

    print(
        f"\nFound {len(open_ports)} open ports"
    )

    print(
        f"Scan completed in {duration:.2f} seconds"
    )


if __name__ == "__main__":
    main()
