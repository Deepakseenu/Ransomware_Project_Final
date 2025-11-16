# app/monitor/yara_engine.py
"""
Centralized YARA loader & scanner. Safe no-op if yara library missing.
"""
import os
from .config import YARA_RULE_PATH
from .logger import logger

yara = None
YARA_AVAILABLE = False
yara_rules = None

try:
    import yara
    yara = yara
    YARA_AVAILABLE = True
except Exception:
    YARA_AVAILABLE = False

def load_rules(path: str = None):
    global yara_rules
    if not YARA_AVAILABLE:
        logger.info("YARA not available in environment.")
        return None
    p = path or YARA_RULE_PATH
    try:
        if p and os.path.exists(p):
            yara_rules = yara.compile(p)
            logger.info("YARA rules loaded from %s", p)
        else:
            logger.info("YARA rule file not found at %s", p)
    except Exception as e:
        logger.warning("YARA compile failed: %s", e)
        yara_rules = None
    return yara_rules

def scan_file(path: str):
    if yara_rules is None:
        return []
    try:
        # scan initial chunk to reduce time; full scan could be used
        with open(path, "rb") as f:
            data = f.read(1024 * 64)
        matches = yara_rules.match(data=data)
        return [m.rule for m in matches] if matches else []
    except Exception as e:
        logger.debug("yara scan error %s: %s", path, e)
        return []
# ----------------------------------------------------------------------
# Unified YARA wrapper for other modules (monitor + prevention)
# ----------------------------------------------------------------------

def yara_scan_file(path: str) -> dict:
    """
    Simple wrapper so other modules (like sandbox_engine) can call YARA safely.
    Returns:
        {"matches": [...], "errors": "..."} 
    """
    try:
        result = scan_file(path)   # calls your existing scan_file()
        return {"matches": result, "errors": None}
    except Exception as e:
        return {"matches": [], "errors": str(e)}
