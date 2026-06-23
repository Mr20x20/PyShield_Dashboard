"""
app.py — PyShield Dashboard
Flask + Flask-SocketIO server.
"""

import argparse
import logging
import threading
import time
from datetime import datetime

from flask import Flask, jsonify, render_template
from flask_socketio import SocketIO

import Database as db
import scheduler

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("pyshield.app")

app = Flask(__name__)
app.config["SECRET_KEY"] = "pyshield-dev-secret"
socketio = SocketIO(app, async_mode="threading", cors_allowed_origins="*")

try:
    import ingestion
    _ingestion_available = True
except ImportError:
    logger.warning("ingestion.py not found — background polling disabled")
    _ingestion_available = False

POLL_INTERVAL = 30


# ── SIEM polling thread ───────────────────────────────────────────────────────
def _polling_loop() -> None:
    logger.info("Polling thread started (interval=%ds)", POLL_INTERVAL)
    while True:
        try:
            _run_cycle()
        except Exception as exc:
            logger.exception("Cycle failed: %s", exc)
        time.sleep(POLL_INTERVAL)


def _run_cycle() -> None:
    if _ingestion_available:
        siem_data = ingestion.collect()
    else:
        siem_data = _fallback_read_siem()

    if siem_data is None:
        return

    snapshot_id = db.insert_snapshot(siem_data)
    logger.info("Snapshot #%d | score=%s | level=%s",
                snapshot_id,
                siem_data.get("total_risk_score"),
                siem_data.get("risk_level"))

    payload = _build_push_payload(siem_data)
    socketio.emit("siem_update", payload)


def _fallback_read_siem() -> dict | None:
    import json
    from pathlib import Path
    for path in [Path("sensors/siem/siem_final_report.json"), Path("siem_final_report.json")]:
        if path.exists():
            with open(path) as f:
                return json.load(f)
    return None


def _build_push_payload(siem_data: dict) -> dict:
    return {
        "timestamp":        siem_data.get("timestamp", datetime.utcnow().isoformat()),
        "total_risk_score": siem_data.get("total_risk_score", 0),
        "risk_level":       siem_data.get("risk_level", "UNKNOWN"),
        "triggered_events": siem_data.get("triggered_events", []),
        "summary":          siem_data.get("summary", []),
        "event_counts":     db.get_event_type_counts(limit_snapshots=20),
    }


# ── Routes ────────────────────────────────────────────────────────────────────
@app.route("/")
def index():
    return render_template("dashboard.html")


@app.route("/api/history")
def api_history():
    return jsonify(db.get_risk_history(limit=60))


@app.route("/api/latest")
def api_latest():
    latest = db.get_latest_snapshot()
    if latest is None:
        return jsonify({"message": "No data yet"}), 204
    return jsonify(latest)


@app.route("/api/event-counts")
def api_event_counts():
    return jsonify(db.get_event_type_counts())


@app.route("/api/sensor-status")
def api_sensor_status():
    """Returns last run time and result for each sensor."""
    return jsonify(scheduler.get_status())


@app.route("/api/run/<sensor>", methods=["POST"])
def api_run_sensor(sensor):
    """
    Manually trigger a sensor scan immediately.
    After the sensor writes its JSON, the next SIEM polling cycle
    (within 30s) will pick it up — or the client can call /api/run/siem
    to force an immediate SIEM re-evaluation.
    """
    allowed = {"port_scanner", "log_analyzer", "secure_monitor", "siem"}

    if sensor not in allowed:
        return jsonify({"ok": False, "message": f"Unknown sensor: {sensor}"}), 400

    if sensor == "siem":
        # Force an immediate SIEM collection + push
        def _immediate_siem():
            time.sleep(0.5)   # let sensors finish writing if triggered together
            _run_cycle()
        threading.Thread(target=_immediate_siem, daemon=True).start()
        return jsonify({"ok": True, "message": "SIEM re-evaluation triggered"})

    result = scheduler.run_sensor(sensor)
    status_code = 200 if result["ok"] else 409
    return jsonify(result), status_code


# ── SocketIO events ───────────────────────────────────────────────────────────
@socketio.on("connect")
def on_connect():
    logger.info("Client connected")


@socketio.on("disconnect")
def on_disconnect():
    logger.info("Client disconnected")


@socketio.on("request_update")
def on_request_update():
    latest = db.get_latest_snapshot()
    if latest:
        socketio.emit("siem_update", latest)


# ── Entrypoint ────────────────────────────────────────────────────────────────
def main() -> None:
    parser = argparse.ArgumentParser(description="PyShield Dashboard")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=5000)
    parser.add_argument("--debug", action="store_true")
    args = parser.parse_args()

    db.init_db()

    # Start SIEM polling thread
    threading.Thread(target=_polling_loop, daemon=True, name="poller").start()

    # Start all sensor scheduler threads
    scheduler.start_all()

    logger.info("Starting PyShield Dashboard on http://%s:%d", args.host, args.port)
    socketio.run(
        app,
        host=args.host,
        port=args.port,
        debug=args.debug,
        use_reloader=False,
        log_output=False,
    )


if __name__ == "__main__":
    main()
