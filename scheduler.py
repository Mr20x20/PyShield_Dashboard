"""
scheduler.py — PyShield Dashboard
Runs each sensor on its own background thread with its own interval.
Also exposes run_sensor(name) for manual on-demand triggers from app.py.

Sensor strategy:
  port_scanner   : calls inner scan logic directly, target=127.0.0.1, ports 1-1024
  log_analyzer   : calls analyze_log_file() with real_auth.log
  secure_monitor : single-pass directory scan (avoids its infinite loop)
  sniffer        : NOT scheduled — runs standalone as admin, we only read its JSON
"""

import logging
import threading
import time
from pathlib import Path

logger = logging.getLogger("pyshield.scheduler")

# ── Config ────────────────────────────────────────────────────────────────────
PROJECT_ROOT = Path(__file__).parent.resolve()

SENSOR_CONFIG = {
    "port_scanner": {
        "interval": 180,           # every 3 minutes
        "target_ip": "127.0.0.1",
        "start_port": 1,
        "end_port": 1024,
    },
    "log_analyzer": {
        "interval": 60,            # every 60 seconds
        "log_file": str(PROJECT_ROOT / "real_auth.log"),
    },
    "secure_monitor": {
        "interval": 90,            # every 90 seconds
        "monitor_dir": str(PROJECT_ROOT / "monitored"),
    },
}

# Tracks last run time and status for each sensor
_sensor_status = {
    "port_scanner":   {"last_run": None, "last_result": "never run", "running": False},
    "log_analyzer":   {"last_run": None, "last_result": "never run", "running": False},
    "secure_monitor": {"last_run": None, "last_result": "never run", "running": False},
}

_status_lock = threading.Lock()


# ── Public API ────────────────────────────────────────────────────────────────
def start_all() -> None:
    """Start all sensor scheduler threads. Called once from app.py on startup."""
    _ensure_monitored_dir()

    for name, cfg in SENSOR_CONFIG.items():
        t = threading.Thread(
            target=_sensor_loop,
            args=(name, cfg),
            daemon=True,
            name=f"scheduler-{name}",
        )
        t.start()
        logger.info("Scheduler started: %s (interval=%ds)", name, cfg["interval"])


def run_sensor(name: str) -> dict:
    """
    Manually trigger a single sensor immediately.
    Returns {"ok": bool, "message": str}
    Called by /api/run/<sensor> in app.py.
    """
    if name not in SENSOR_CONFIG:
        return {"ok": False, "message": f"Unknown sensor: {name}"}

    with _status_lock:
        if _sensor_status[name]["running"]:
            return {"ok": False, "message": f"{name} is already running"}

    # Run in a thread so the HTTP request returns immediately
    t = threading.Thread(
        target=_run_once,
        args=(name, SENSOR_CONFIG[name]),
        daemon=True,
        name=f"manual-{name}",
    )
    t.start()
    return {"ok": True, "message": f"{name} triggered"}


def get_status() -> dict:
    """Return current status of all sensors. Used by /api/sensor-status."""
    with _status_lock:
        return {k: dict(v) for k, v in _sensor_status.items()}


# ── Sensor loops ──────────────────────────────────────────────────────────────
def _sensor_loop(name: str, cfg: dict) -> None:
    """Infinite loop for a single sensor — runs, sleeps, repeats."""
    while True:
        _run_once(name, cfg)
        time.sleep(cfg["interval"])


def _run_once(name: str, cfg: dict) -> None:
    """Execute one sensor cycle with status tracking."""
    with _status_lock:
        _sensor_status[name]["running"] = True

    try:
        if name == "port_scanner":
            _run_port_scanner(cfg)
        elif name == "log_analyzer":
            _run_log_analyzer(cfg)
        elif name == "secure_monitor":
            _run_secure_monitor(cfg)

        _set_status(name, "ok")

    except Exception as exc:
        logger.exception("Sensor %s failed: %s", name, exc)
        _set_status(name, f"error: {exc}")

    finally:
        with _status_lock:
            _sensor_status[name]["running"] = False


# ── Sensor implementations ────────────────────────────────────────────────────
def _run_port_scanner(cfg: dict) -> None:
    """
    Calls port_scanner inner logic directly — bypasses sys.argv dependency.
    Scans localhost ports 1-1024 using 100 threads.
    """
    import time as _time
    import json
    from queue import Queue, Empty
    import threading as _threading
    import socket

    ip         = cfg["target_ip"]
    start_port = cfg["start_port"]
    end_port   = cfg["end_port"]

    logger.info("Port scanner: scanning %s ports %d-%d", ip, start_port, end_port)

    def scan_port(port):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(1)
                return s.connect_ex((ip, port)) == 0
        except Exception:
            return False

    def worker(port_queue, open_ports):
        while True:
            try:
                port = port_queue.get_nowait()
            except Empty:
                break
            if scan_port(port):
                open_ports.append(port)
            port_queue.task_done()

    port_queue = Queue()
    open_ports = []
    for p in range(start_port, end_port + 1):
        port_queue.put(p)

    start_time = _time.time()
    threads = []
    for _ in range(100):
        t = _threading.Thread(target=worker, args=(port_queue, open_ports))
        t.start()
        threads.append(t)
    for t in threads:
        t.join()

    open_ports.sort()
    duration = round(_time.time() - start_time, 2)

    report = {
        "source": "port_scanner",
        "timestamp": _time.strftime("%Y-%m-%d %H:%M:%S"),
        "target_ip": ip,
        "scan_duration_sec": duration,
        "open_ports": open_ports,
        "ports_count": len(open_ports),
    }

    out = PROJECT_ROOT / "port_scan_report.json"
    with open(out, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=4)

    logger.info("Port scanner done: %d open ports in %.2fs", len(open_ports), duration)


def _run_log_analyzer(cfg: dict) -> None:
    """Calls log_analyzer.analyze_log_file() directly."""
    import sys as _sys
    log_file = cfg["log_file"]

    if not Path(log_file).exists():
        logger.warning("Log analyzer: file not found: %s", log_file)
        return

    # Suppress the print() output from log_analyzer during scheduled runs
    import io
    from contextlib import redirect_stdout

    # log_analyzer.py uses sys.path-relative import so ensure root is on path
    import sys
    if str(PROJECT_ROOT) not in sys.path:
        sys.path.insert(0, str(PROJECT_ROOT))

    from log_analyzer import analyze_log_file

    logger.info("Log analyzer: scanning %s", log_file)
    with redirect_stdout(io.StringIO()):
        analyze_log_file(log_file)
    logger.info("Log analyzer: done")


def _run_secure_monitor(cfg: dict) -> None:
    """
    Single-pass FIM scan — replicates monitor_directory() logic
    WITHOUT the infinite while loop.
    Writes fim_report.json exactly like the original.
    """
    import hashlib
    import glob
    import json
    from datetime import datetime
    from cryptography.hazmat.primitives import serialization, hashes
    from cryptography.hazmat.primitives.asymmetric import padding as _padding

    dir_path   = cfg["monitor_dir"]
    public_key_file  = str(PROJECT_ROOT / "public_key.pem")
    fim_output = str(PROJECT_ROOT / "fim_report.json")

    timestamp_start = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    if not Path(dir_path).exists():
        logger.warning("FIM: monitored dir does not exist: %s — creating it", dir_path)
        Path(dir_path).mkdir(parents=True, exist_ok=True)

    if not Path(public_key_file).exists():
        logger.warning("FIM: public_key.pem not found — skipping scan")
        return

    with open(public_key_file, "rb") as f:
        public_key = serialization.load_pem_public_key(f.read())

    def file_hash(path):
        h = hashlib.sha256()
        with open(path, "rb") as f:
            while chunk := f.read(4096):
                h.update(chunk)
        return h.digest()

    all_files = [
        fp for fp in glob.glob(str(Path(dir_path) / "*"))
        if not fp.endswith(".sig") and not fp.endswith(".pem")
    ]

    modified_files     = []
    missing_signatures = []

    for file_path in all_files:
        sig_file = file_path + ".sig"
        if not Path(sig_file).exists():
            missing_signatures.append(file_path)
            continue
        current_hash = file_hash(file_path)
        with open(sig_file, "rb") as f:
            signature = f.read()
        try:
            public_key.verify(
                signature,
                current_hash,
                _padding.PSS(
                    mgf=_padding.MGF1(hashes.SHA256()),
                    salt_length=_padding.PSS.MAX_LENGTH,
                ),
                hashes.SHA256(),
            )
        except Exception:
            modified_files.append(file_path)

    if modified_files or missing_signatures:
        report = {
            "source": "file_integrity_monitor",
            "monitor_type": "continuous",
            "scan_window": {
                "start": timestamp_start,
                "end": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            },
            "status": "ALERT",
            "details": {
                "modified_files": modified_files,
                "new_untracked_files": missing_signatures,
            },
        }
        logger.warning("FIM ALERT: %d modified, %d untracked",
                       len(modified_files), len(missing_signatures))
    else:
        report = {
            "source": "file_integrity_monitor",
            "monitor_type": "continuous",
            "scan_window": {
                "start": timestamp_start,
                "end": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            },
            "status": "SUCCESS",
            "details": {"message": "All files intact."},
        }
        logger.info("FIM: all files intact")

    with open(fim_output, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=4)


# ── Helpers ───────────────────────────────────────────────────────────────────
def _set_status(name: str, result: str) -> None:
    from datetime import datetime
    with _status_lock:
        _sensor_status[name]["last_run"]    = datetime.utcnow().isoformat(timespec="seconds")
        _sensor_status[name]["last_result"] = result


def _ensure_monitored_dir() -> None:
    monitored = PROJECT_ROOT / "monitored"
    if not monitored.exists():
        monitored.mkdir()
        logger.info("Created monitored\\ directory at %s", monitored)
