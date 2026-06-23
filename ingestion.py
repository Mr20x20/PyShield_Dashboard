"""
ingestion.py — PyShield Dashboard
Sensor orchestration layer.

Called by app.py's background thread every 30 seconds.
Public API: collect() -> dict | None

Sensor strategy:
  - mini_siem_v2.analyze_security_state()  : direct import (safe, no privileges)
  - sniffer_report.json                    : read from file (sniffer runs separately
                                             as admin in its own terminal)

Why not import the sniffer directly?
  pyshield_sniffer_v4.py uses Scapy raw sockets which require admin/root.
  Running the entire Flask app as admin just for the sniffer is a security
  anti-pattern. The sniffer writes sniffer_report.json independently;
  mini_siem_v2.analyze_security_state() already reads that file as part of
  its own logic — so ingestion only needs to call one function.
"""

import logging
import sys
from pathlib import Path

logger = logging.getLogger("pyshield.ingestion")

# ── Make sure project root is on sys.path ─────────────────────────────────────
_PROJECT_ROOT = Path(__file__).parent.resolve()
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

# ── Import SIEM module ────────────────────────────────────────────────────────
try:
    from mini_siem2 import analyze_security_state
    logger.info("mini_siem_v2 loaded successfully")
except ImportError as e:
    analyze_security_state = None
    logger.error("Could not import mini_siem_v2: %s", e)


# ── Public API ────────────────────────────────────────────────────────────────
def collect() -> dict | None:
    """
    Run one full SIEM collection cycle.

    Returns:
        dict  — siem report (same schema as siem_final_report.json)
        None  — if collection failed entirely
    """
    if analyze_security_state is None:
        logger.error("analyze_security_state not available — skipping cycle")
        return None

    try:
        report = analyze_security_state()
        _log_cycle_summary(report)
        return report
    except Exception as exc:
        logger.exception("analyze_security_state raised an exception: %s", exc)
        return None


# ── Internals ─────────────────────────────────────────────────────────────────
def _log_cycle_summary(report: dict) -> None:
    """Emit a one-liner so the terminal gives live feedback."""
    score = report.get("total_risk_score", "?")
    level = report.get("risk_level", "?")
    events = report.get("triggered_events", [])
    logger.info(
        "Ingestion cycle done | score=%s | level=%s | events=%s",
        score,
        level,
        events if events else "none",
    )
