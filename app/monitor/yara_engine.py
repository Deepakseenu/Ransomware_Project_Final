# app/monitor/yara_engine.py
"""
Centralized YARA loader & scanner.
Safe no-op if yara library missing.
"""

import os
from pathlib import Path
import json

# Single correct logger
from .logger import logger

# Alert system
from app.monitor.alerts import trigger_alert

# Config path for alerts
_cfg_path = Path(__file__).resolve().parents[2] / "config" / "alert_config.json"
try:
    with open(_cfg_path, "r") as f:
        ALERT_CONFIG = json.load(f)
except Exception:
    ALERT_CONFIG = {}

# Config import for YARA rules
from .config import YARA_RULE_PATH


# ----------------------------------------------------
# Load YARA if available
# ----------------------------------------------------
yara = None
YARA_AVAILABLE = False
yara_rules = None

try:
    import yara as _y
    yara = _y
    YARA_AVAILABLE = True
except Exception:
    logger.warning("YARA module not installed — YARA scanning disabled.")
    YARA_AVAILABLE = False


# ----------------------------------------------------
# Compile YARA rules
# ----------------------------------------------------
def load_rules(path: str = None):
    """Compile YARA rules into memory."""
    global yara_rules

    if not YARA_AVAILABLE:
        logger.info("YARA not available in environment.")
        return None

    p = path or YARA_RULE_PATH
    try:
        if p and os.path.exists(p):
            yara_rules = yara.compile(p)
            logger.info(f"YARA rules loaded from: {p}")
        else:
            logger.warning(f"YARA rule file missing at: {p}")
            yara_rules = None
    except Exception as e:
        logger.error(f"YARA compile failed: {e}")
        yara_rules = None

    return yara_rules


# ----------------------------------------------------
# Scan a single file
# ----------------------------------------------------
def scan_file(path: str):
    """
    Scan only the first 64KB of the file for YARA matches.
    If ransomware rules match → fire HIGH alert automatically.
    Returns: list of matched rule names.
    """
    if yara_rules is None:
        return []

    try:
        with open(path, "rb") as f:
            data = f.read(1024 * 64)

        matches = yara_rules.match(data=data)

        # On match → log + alert
        if matches:
            for m in matches:
                rule_name = m.rule
                msg = f"YARA: ransomware signature hit ({rule_name}) on {path}"

                logger.warning(msg)
                trigger_alert(msg, ALERT_CONFIG, level="HIGH")

        return [m.rule for m in matches] if matches else []

    except Exception as e:
        logger.debug(f"YARA scan error on {path}: {e}")
        return []


# ----------------------------------------------------
# Wrapper: safe YARA scan for sandbox
# ----------------------------------------------------
def yara_scan_file(path: str) -> dict:
    """
    Safer API for external modules.
    Returns:
        { "matches": [...], "errors": None }  OR
        { "matches": [], "errors": "message" }
    """
    try:
        result = scan_file(path)
        return {"matches": result, "errors": None}
    except Exception as e:
        return {"matches": [], "errors": str(e)}
