# app/monitor/handlers_os.py

from watchdog.events import FileSystemEventHandler
import os
from typing import Optional
from .utils import safe_copy
from .sandbox_heuristics import analyze_file
from .event_emit import safe_emit
from .logger import logger
from .config import BACKUP_DIR

helpers = {}

def set_helpers(h):
    global helpers
    helpers = h or {}

class OSHandler(FileSystemEventHandler):

    def _emit_file_event(self, action: str, path: str, extra: dict = None):
        """
        Helper to send consistent file events to dashboard.
        """
        payload = {"action": action, "detail": {"path": path}}
        if extra:
            payload["detail"].update(extra)
        safe_emit("file", payload)

    def on_created(self, event):
        if event.is_directory:
            return

        path = os.path.abspath(event.src_path)
        logger.info("OS created: %s", path)

        # Emit simple event
        self._emit_file_event("created", path)

        # Run heuristics
        try:
            analysis = analyze_file(path)
            self._emit_file_event("analysis", path, {"analysis": analysis})
        except Exception as e:
            logger.debug("analysis on_created failed: %s", e)
            return

        # If suspicious, escalate
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

        # Emit simple event
        self._emit_file_event("modified", path)

        # Auto-backup certain extensions
        _, ext = os.path.splitext(path)
        if ext.lower() in [".jpg", ".png", ".pdf", ".docx", ".doc"]:
            try:
                backup_path = safe_copy(path, BACKUP_DIR)
                if backup_path:
                    self._emit_file_event("backup", path, {"backup": backup_path})
            except Exception as e:
                logger.debug("backup failed: %s", e)

        # Run heuristics
        try:
            analysis = analyze_file(path)
            self._emit_file_event("analysis", path, {"analysis": analysis})
        except Exception as e:
            logger.debug("analysis on_modified failed: %s", e)
            return

        # Suspicious detection
        if analysis.get("suspicious"):
            handler = helpers.get("handle_suspicious")
            if handler:
                try:
                    handler(path, "file_modified_suspicious", analysis)
                except Exception:
                    logger.debug("helpers.handle_suspicious failed")
