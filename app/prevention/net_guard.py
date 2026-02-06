# app/prevention/net_guard.py
import json
import subprocess
from pathlib import Path
from datetime import datetime
from .logger import logger
from .config import DASHBOARD_URL, BLOCKED_FILE, AUTOBLOCK_ENABLED, IPTABLES_CMD
from ..monitor.event_emit import safe_emit
from app.monitor.alerts import trigger_alert
from pathlib import Path as _P

# Load alert config
_cfg_path = _P(__file__).resolve().parents[2] / "config" / "alert_config.json"
try:
    with open(_cfg_path, "r") as _f:
        ALERT_CONFIG = json.load(_f)
except Exception:
    ALERT_CONFIG = {}

# ----------------------------
# Persistence helpers
# ----------------------------
def load_blocked():
    try:
        p = Path(BLOCKED_FILE)
        if p.exists():
            return json.loads(p.read_text())
    except Exception:
        logger.debug("Failed to load blocked file")
    return {}

def save_blocked(data):
    try:
        Path(BLOCKED_FILE).write_text(json.dumps(data, indent=2))
    except Exception:
        logger.exception("Failed to save blocked file")

# ----------------------------
# CompletedProcess-like Dummy for failures
# ----------------------------
class _DummyCP:
    def __init__(self, returncode=1, stderr=b""):
        self.returncode = returncode
        self.stderr = stderr

# ----------------------------
# Core blocking helpers
# ----------------------------
def _run_iptables_check(ip):
    """Return True if rule exists (returncode 0)."""
    try:
        check = subprocess.run(
            [IPTABLES_CMD, "-C", "INPUT", "-s", ip, "-j", "DROP"],
            capture_output=True
        )
        return check.returncode == 0
    except Exception as e:
        logger.exception("iptables check failed for %s", ip)
        return False

def _run_iptables_add(ip):
    try:
        add = subprocess.run(
            [IPTABLES_CMD, "-A", "INPUT", "-s", ip, "-j", "DROP"],
            capture_output=True
        )
        return add
    except Exception as e:
        logger.exception("iptables add failed for %s: %s", ip, e)
        return _DummyCP(returncode=1, stderr=str(e).encode())

def _run_iptables_delete(ip):
    try:
        delete = subprocess.run(
            [IPTABLES_CMD, "-D", "INPUT", "-s", ip, "-j", "DROP"],
            capture_output=True
        )
        return delete
    except Exception as e:
        logger.exception("iptables delete failed for %s: %s", ip, e)
        return _DummyCP(returncode=1, stderr=str(e).encode())

# ----------------------------
# Public helpers used by API
# ----------------------------
def block_ip(ip: str) -> dict:
    """
    Try to block an IP using dashboard forward (if configured) or local iptables.
    Returns a dict describing the action taken.
    """
    ip = str(ip).strip()
    if not ip:
        return {"error": "empty_ip"}

    # First try dashboard forwarding (best-effort)
    if DASHBOARD_URL:
        try:
            import requests
            url = DASHBOARD_URL.rstrip("/") + "/api/block_ip"
            r = requests.post(url, json={"ip": ip}, timeout=4)
            result = r.json() if r is not None else {}
            safe_emit("net_guard", {"action": "dashboard_block_forwarded", "detail": {"ip": ip, "result": result}})
            msg = f"NetGuard: Dashboard requested block for {ip}"
            logger.info(msg)
            trigger_alert(msg, ALERT_CONFIG, level="HIGH")
            return {"dashboard": result}
        except Exception as e:
            logger.debug("Dashboard block forward failed, falling back to local: %s", e)
            safe_emit("net_guard", {"action": "dashboard_block_failed", "detail": {"ip": ip, "error": str(e)}})
            # continue to local block

    # Local iptables fallback
    try:
        if _run_iptables_check(ip):
            safe_emit("net_guard", {"action": "already_blocked", "detail": {"ip": ip}})
            return {"local": "already_blocked"}

        add = _run_iptables_add(ip)
        if add is None:
            # defensive: should not happen because add returns _DummyCP on exception
            safe_emit("net_guard", {"action": "local_block_error", "detail": {"ip": ip, "error": "iptables_unavailable"}})
            return {"error": "iptables_unavailable"}

        if add.returncode == 0:
            # persist
            data = load_blocked()
            data[ip] = {"blocked": True, "time": datetime.utcnow().isoformat()}
            save_blocked(data)

            safe_emit("net_guard", {"action": "local_blocked", "detail": {"ip": ip, "time": data[ip]["time"]}})
            msg = f"NetGuard: Locally blocked IP {ip}"
            logger.warning(msg)
            trigger_alert(msg, ALERT_CONFIG, level="HIGH")
            return {"local_blocked": ip}

        # failure
        try:
            error_msg = add.stderr.decode()
        except Exception:
            error_msg = "iptables_add_failed"
        safe_emit("net_guard", {"action": "local_block_error", "detail": {"ip": ip, "error": error_msg}})
        msg = f"NetGuard: iptables failed to block {ip}: {error_msg}"
        logger.error(msg)
        trigger_alert(msg, ALERT_CONFIG, level="HIGH")
        return {"error": error_msg}

    except Exception as e:
        logger.exception("Unexpected error in block_ip for %s: %s", ip, e)
        safe_emit("net_guard", {"action": "local_block_error", "detail": {"ip": ip, "error": str(e)}})
        return {"error": str(e)}

def unblock_ip(ip: str) -> dict:
    """
    Remove a local iptables rule for the IP and update the blocked file.
    Returns dict describing result.
    """
    ip = str(ip).strip()
    if not ip:
        return {"error": "empty_ip"}

    try:
        delete = _run_iptables_delete(ip)
        # defensive check (delete should never be None)
        if delete is None:
            safe_emit("net_guard", {"action": "local_unblock_error", "detail": {"ip": ip, "error": "iptables_unavailable"}})
            return {"error": "iptables_unavailable"}

        if delete.returncode == 0:
            # update blocked persistence
            data = load_blocked()
            if ip in data:
                removed = data.pop(ip, None)
                save_blocked(data)
            safe_emit("net_guard", {"action": "local_unblocked", "detail": {"ip": ip}})
            msg = f"NetGuard: Locally unblocked IP {ip}"
            logger.warning(msg)
            trigger_alert(msg, ALERT_CONFIG, level="HIGH")
            return {"unblocked": ip}
        else:
            # Not blocked or failed: provide stderr
            try:
                error_msg = delete.stderr.decode()
            except Exception:
                error_msg = "iptables_delete_failed"
            safe_emit("net_guard", {"action": "local_unblock_error", "detail": {"ip": ip, "error": error_msg}})
            msg = f"NetGuard: failed to unblock {ip}: {error_msg}"
            logger.error(msg)
            trigger_alert(msg, ALERT_CONFIG, level="HIGH")
            return {"error": error_msg}
    except Exception as e:
        logger.exception("Unexpected error in unblock_ip for %s: %s", ip, e)
        safe_emit("net_guard", {"action": "local_unblock_error", "detail": {"ip": ip, "error": str(e)}})
        return {"error": str(e)}

def list_blocked() -> dict:
    """Return the contents of the blocked store."""
    return load_blocked()

# ----------------------------
# NetGuard class (light wrapper kept for backward compatibility)
# ----------------------------
class NetGuard:
    def __init__(self, helpers=None):
        self.helpers = helpers or {}

    def start(self):
        logger.info("NetGuard ready (autoblock=%s)", AUTOBLOCK_ENABLED)
        safe_emit("net_guard", {"action": "started", "detail": {"autoblock": AUTOBLOCK_ENABLED}})

    def ensure_block(self, ip):
        return block_ip(ip)

    def unblock(self, ip):
        return unblock_ip(ip)
