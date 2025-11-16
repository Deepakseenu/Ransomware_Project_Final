# app/prevention/net_guard.py

import json
import subprocess
import requests
from pathlib import Path
from datetime import datetime
from .logger import logger
from .config import DASHBOARD_URL, BLOCKED_FILE, AUTOBLOCK_ENABLED, IPTABLES_CMD
from ..monitor.event_emit import safe_emit   # NEW unified event emission


def load_blocked():
    if Path(BLOCKED_FILE).exists():
        try:
            return json.loads(Path(BLOCKED_FILE).read_text())
        except:
            return {}
    return {}


def save_blocked(data):
    try:
        Path(BLOCKED_FILE).write_text(json.dumps(data, indent=2))
    except:
        pass


class NetGuard:
    def __init__(self, helpers=None):
        self.helpers = helpers or {}

    # ---------------------------------------------------------
    # Start
    # ---------------------------------------------------------
    def start(self):
        logger.info("NetGuard ready (autoblock=%s)", AUTOBLOCK_ENABLED)

        safe_emit("net_guard", {
            "action": "started",
            "detail": {
                "autoblock": AUTOBLOCK_ENABLED
            }
        })

    # ---------------------------------------------------------
    # Block IP function
    # ---------------------------------------------------------
    def ensure_block(self, ip):
        """Attempt dashboard -> fallback to iptables."""
        result = None

        # ──────────────────────────────────────────────────────
        # 1. Try forwarding block request to Dashboard API
        # ──────────────────────────────────────────────────────
        try:
            url = DASHBOARD_URL.rstrip("/") + "/api/block_ip"

            r = requests.post(url, json={"ip": ip}, timeout=4)
            result = r.json()

            safe_emit("net_guard", {
                "action": "dashboard_block_forwarded",
                "detail": {"ip": ip, "result": result}
            })

            return {"dashboard": result}

        except Exception as e:
            safe_emit("net_guard", {
                "action": "dashboard_block_failed",
                "detail": {
                    "ip": ip,
                    "error": str(e)
                }
            })

        # ──────────────────────────────────────────────────────
        # 2. LOCAL iptables fallback
        # ──────────────────────────────────────────────────────
        try:
            # Check existing block
            check = subprocess.run(
                [IPTABLES_CMD, "-C", "INPUT", "-s", ip, "-j", "DROP"],
                capture_output=True
            )

            if check.returncode == 0:
                safe_emit("net_guard", {
                    "action": "already_blocked",
                    "detail": {"ip": ip}
                })
                return {"local": "already_blocked"}

            # Add iptables rule
            add = subprocess.run(
                [IPTABLES_CMD, "-A", "INPUT", "-s", ip, "-j", "DROP"],
                capture_output=True
            )

            if add.returncode == 0:
                # persist
                data = load_blocked()
                data[ip] = {
                    "blocked": True,
                    "time": datetime.utcnow().isoformat()
                }
                save_blocked(data)

                safe_emit("net_guard", {
                    "action": "local_blocked",
                    "detail": {
                        "ip": ip,
                        "time": data[ip]["time"]
                    }
                })

                return {"local_blocked": ip}

            # failure to add
            error_msg = add.stderr.decode()

            safe_emit("net_guard", {
                "action": "local_block_error",
                "detail": {
                    "ip": ip,
                    "error": error_msg
                }
            })

            return {"error": error_msg}

        except Exception as e:
            safe_emit("net_guard", {
                "action": "iptables_exception",
                "detail": {
                    "ip": ip,
                    "error": str(e)
                }
            })
            return {"error": str(e)}
