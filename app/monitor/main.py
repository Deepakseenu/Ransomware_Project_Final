# app/monitor/main.py
"""
Standalone runner for the modular monitor package.
Clean, safe, and fully functional version.
"""

import os
import time
import threading
from pathlib import Path
from typing import Dict
import json

from app.monitor.alerts import trigger_alert

from .lifecycle import start, shutdown
from .logger import logger
from .event_emit import safe_emit
from .utils import safe_copy
from app.prevention.sandbox_engine import SandboxSimulation

# ----------------------------------------------------
# Load alert config safely
# ----------------------------------------------------
config_path = Path(__file__).resolve().parents[1] / "config" / "alert_config.json"
try:
    alert_config = json.load(open(config_path))
except Exception:
    alert_config = {}

# -------------------------------
# Prevention package imports
# -------------------------------
try:
    from app.prevention.quarantine import backup_and_quarantine
    from app.prevention.file_guard import FileGuard
    from app.prevention.process_guard import ProcessGuard
    from app.prevention.net_guard import NetGuard
except Exception:
    backup_and_quarantine = None
    FileGuard = None
    ProcessGuard = None
    NetGuard = None

# -------------------------------
# Analysis directory
# -------------------------------
HP_ANALYSIS = str(
    Path.home() /
    "Ransomware_Project_Final" /
    "honeypot_data" /
    "honeypot_analysis"
)
os.makedirs(HP_ANALYSIS, exist_ok=True)

# ----------------------------------------------------
# Build Helper Layer
# ----------------------------------------------------
def build_helpers():
    helpers = {}

    if backup_and_quarantine:
        helpers["backup_and_quarantine"] = backup_and_quarantine
    else:
        helpers["backup_and_quarantine"] = lambda p, r: {
            "backup": None,
            "quarantine": None,
            "reason": "prevention_not_loaded"
        }

    helpers["emit_event"] = lambda ev: safe_emit("prevention_event", ev)
    helpers["handle_suspicious"] = handle_suspicious_local

    return helpers


def handle_suspicious_local(path, reason, analysis):
    """Used only if prevention package fails."""
    ev = {
        "type": "suspicious_local",
        "path": path,
        "reason": reason,
        "analysis": analysis
    }
    safe_emit("new_event", ev)
    logger.warning("Suspicious (fallback): %s", ev)

# ----------------------------------------------------
# Sandbox (YARA + ML)
# ----------------------------------------------------
_SANDBOX = SandboxSimulation(
    yara_enabled=True,
    ml_enabled=True,
    entropy_threshold=float(os.getenv("HIGH_ENTROPY_THRESHOLD", "7.5"))
)

def sandbox_analysis(path: str) -> dict:
    try:
        result = _SANDBOX.analyze(path)
        return {
            "suspicious": result["suspicious"],
            "reasons": result["reasons"],
            "score": result["score"],
            "yara_matches": result["yara_matches"],
            "ml_prediction": result["ml_prediction"],
            "ml_probability": result["ml_probability"],
            "meta": result["meta"],
        }
    except Exception as e:
        logger.error("Sandbox analysis failed: %s", e)
        return {"suspicious": False, "reasons": ["analysis_failed"], "score": 0.0}

# ----------------------------------------------------
# Suspicious Handler
# ----------------------------------------------------
def handle_suspicious(path: str, reason: str, analysis=None, helpers=None):
    if helpers is None:
        helpers = {}

    if analysis is None:
        analysis = sandbox_analysis(path)

    event = {
        "timestamp": time.time(),
        "reason": reason,
        "path": path,
        "analysis": analysis
    }

    if analysis.get("suspicious"):
        logger.warning("Suspicious file detected → %s", path)

        if "backup_and_quarantine" in helpers:
            qmeta = helpers["backup_and_quarantine"](path, reason)
            event["quarantine"] = qmeta

        safe_emit("new_event", {"type": "suspicious", **event})
        return event

    try:
        cp = safe_copy(path, HP_ANALYSIS)
        event["copy"] = cp
    except Exception:
        pass

    safe_emit("new_event", {"type": "benign", "path": path, "analysis": analysis})
    return event

# ----------------------------------------------------
# Start Prevention Subsystems
# ----------------------------------------------------
def create_monitor():
    helpers = build_helpers()

    fg = pg = ng = None

    if FileGuard:
        try:
            watch_dirs = [
                "/var/www/html/college_clone",
                "/home/deepak/Desktop",
                "/home/deepak/Documents",
                "/home/deepak/Downloads",
                "/home/deepak/Pictures",
                str(Path.home() / "Ransomware_Project_Final" / "honeypot_data" / "decoys")
            ]
            fg = FileGuard(watch_dirs=watch_dirs, helpers=helpers)
            fg.start()
            logger.info("FileGuard started")
        except Exception as e:
            logger.error("FileGuard failed: %s", e)

    if ProcessGuard:
        try:
            pg = ProcessGuard(helpers=helpers, terminate_on_detect=False)
            pg.start()
            logger.info("ProcessGuard started")
        except Exception as e:
            logger.error("ProcessGuard failed: %s", e)

    if NetGuard:
        try:
            ng = NetGuard(helpers=helpers)
            ng.start()
            logger.info("NetGuard started")
        except Exception as e:
            logger.error("NetGuard failed: %s", e)

    return helpers, (fg, pg, ng)

# ----------------------------------------------------
# Main Runner
# ----------------------------------------------------
def main():
    helpers, subsystems = create_monitor()

    start(helpers)
    logger.info("Monitor running. Press Ctrl-C to stop.")

    try:
        while True:
            time.sleep(1)

    except KeyboardInterrupt:
        logger.warning("Ctrl-C / Signal 2 → Fast shutdown triggered")

    finally:
        logger.info("Stopping subsystems...")

        shutdown()
        fg, pg, ng = subsystems

        if fg:
            try:
                fg.stop()
                if fg._thread:
                    fg._thread.join(timeout=2)
            except Exception:
                pass

        if pg:
            try:
                pg.stop()
                if hasattr(pg, "_thread"):
                    pg._thread.join(timeout=2)
            except Exception:
                pass

        if ng:
            try:
                ng.stop()
                if hasattr(ng, "_thread"):
                    ng._thread.join(timeout=2)
            except Exception:
                pass

        logger.info("All subsystems shut down cleanly. Exiting.")
        os._exit(0)


if __name__ == "__main__":
    main()
