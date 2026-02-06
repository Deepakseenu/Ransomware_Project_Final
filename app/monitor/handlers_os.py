# app/monitor/handlers_os.py

from watchdog.events import FileSystemEventHandler
import os
from typing import Optional
from .utils import safe_copy
from .sandbox_heuristics import analyze_file
from .event_emit import safe_emit
from app.monitor.logger import logger
from .config import BACKUP_DIR

# --- ALERT CONFIG ---
from pathlib import Path
import json
from app.monitor.alerts import trigger_alert

_cfg_path = Path(__file__).resolve().parents[2] / "config" / "alert_config.json"
try:
    with open(_cfg_path, "r") as _f:
        ALERT_CONFIG = json.load(_f)
except Exception:
    ALERT_CONFIG = {}
# ------------------------------------------------

helpers = {}

def set_helpers(h):
    global helpers
    helpers = h or {}

class OSHandler(FileSystemEventHandler):

    def _emit_file_event(self, action: str, path: str, extra: dict = None):
        """Helper to send consistent file events to dashboard."""
        payload = {"action": action, "detail": {"path": path}}
        if extra:
            payload["detail"].update(extra)
        safe_emit("file", payload)

    def on_created(self, event):
        if event.is_directory:
            return

        path = os.path.abspath(event.src_path)
        logger.info("OS created: %s", path)

        self._emit_file_event("created", path)

        # Heuristic analysis
        try:
            analysis = analyze_file(path)
            self._emit_file_event("analysis", path, {"analysis": analysis})
        except Exception as e:
            logger.debug("analysis on_created failed: %s", e)
            return

        if analysis.get("suspicious"):
            handler = helpers.get("handle_suspicious")
            if handler:
                try:
                    handler(path, "file_created_suspicious", analysis)
                except Exception:
                    logger.debug("helpers.handle_suspicious failed")

    def on_modified(self, event):
        if event.is_directory:
            return

        path = os.path.abspath(event.src_path)
        logger.info("OS modified: %s", path)

        self._emit_file_event("modified", path)

        # Auto-backup for important file types
        _, ext = os.path.splitext(path)
        if ext.lower() in [".jpg", ".png", ".pdf", ".docx", ".doc"]:
            try:
                backup_path = safe_copy(path, BACKUP_DIR)
                if backup_path:
                    self._emit_file_event("backup", path, {"backup": backup_path})
            except Exception as e:
                logger.debug("backup failed: %s", e)

        # Heuristic analysis
        try:
            analysis = analyze_file(path)
            self._emit_file_event("analysis", path, {"analysis": analysis})
        except Exception as e:
            logger.debug("analysis on_modified failed: %s", e)
            return

        if analysis.get("suspicious"):
            handler = helpers.get("handle_suspicious")
            if handler:
                try:
                    handler(path, "file_modified_suspicious", analysis)
                except Exception:
                    logger.debug("helpers.handle_suspicious failed")

    # ---------------------------------------------
    # (Optional) Future: Rapid change detection
    # This is where the alert should be triggered
    # ---------------------------------------------
    def trigger_rapid_change_alert(self, watched_dir, change_count, interval):
        msg = (
            f"Rapid file modification detected in {watched_dir} "
            f"(count={change_count} in {interval}s)"
        )
        logger.warning(msg)
        trigger_alert(msg, ALERT_CONFIG, level="HIGH")
