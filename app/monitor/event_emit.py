# app/monitor/event_emit.py
"""
Event emitter that forwards monitor events to the FastAPI dashboard backend.
No socket.io — now uses HTTP POST to /api/push_event.
Also writes events to local logs for backup & forensic purposes.
"""

import requests
import threading
from typing import Dict
from .logger import logger
from .config import LOG_PATH

# dashboard API endpoint
DASHBOARD_PUSH_URL = "http://127.0.0.1:8000/api/push_event"


def safe_emit(event_type: str, payload: Dict):
    """
    Send event to dashboard backend + write to local logs.
    event_type: "file", "process", "net", etc.
    payload: { action, detail, path, ... }
    """

    # 1) POST to FastAPI dashboard
    try:
        requests.post(
            DASHBOARD_PUSH_URL,
            json={"type": event_type, **payload},
            timeout=0.2
        )
    except Exception as e:
        logger.debug(f"[safe_emit] Failed to push event HTTP: {e}")

    # 2) Local structured log
    try:
        from .utils import write_event_struct
        write_event_struct(LOG_PATH, {"type": event_type, **payload})
    except Exception as e:
        logger.debug(f"[safe_emit] Failed to write local log: {e}")


def start_background_connector():
    """
    Kept for compatibility — not needed anymore.
    Just returns a dummy thread.
    """
    def _noop():
        return

    t = threading.Thread(target=_noop, daemon=True)
    t.start()
    return t
