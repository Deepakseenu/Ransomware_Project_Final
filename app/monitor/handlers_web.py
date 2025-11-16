# app/monitor/handlers_web.py

from watchdog.events import FileSystemEventHandler
import os
from typing import Optional
from .utils import safe_copy
from .sandbox_heuristics import analyze_file
from .event_emit import safe_emit
from .logger import logger
from .config import HONEYPOT_ANALYSIS_DIR

# helpers expected in handlers (injected by lifecycle)
helpers = {}

def set_helpers(h):
    global helpers
    helpers = h or {}

class WebHandler(FileSystemEventHandler):

    def _emit_web_event(self, action: str, path: str, extra: dict = None):
        """
        Helper to send consistent web events to dashboard.
        """
        payload = {"action": action, "detail": {"path": path}}
        if extra:
            payload["detail"].update(extra)
        safe_emit("web", payload)

    def on_created(self, event):
        if event.is_directory:
            return

        path = os.path.abspath(event.src_path)
        logger.info("Web created: %s", path)

        # Emit simple event
        self._emit_web_event("created", path)

        # Sandbox analysis
        try:
            analysis = analyze_file(path)
            self._emit_web_event("analysis", path, {"analysis": analysis})
        except Exception as e:
            logger.debug("web analysis failed: %s", e)
            return

        # Suspicious handling
        if analysis.get("suspicious"):
            handler = helpers.get("handle_suspicious")

            if handler:
                try:
                    handler(path, "web_created_suspicious", analysis)
                except Exception:
                    logger.debug("helpers.handle_suspicious failed")
            else:
                # fallback copy for deep inspection
                try:
                    copied = safe_copy(path, HONEYPOT_ANALYSIS_DIR)
                    if copied:
                        self._emit_web_event("copied_for_analysis", path, {"copy": copied})
                except Exception:
                    logger.debug("web copy failed")
        else:
            # Normal files also get copied to analysis pool
            try:
                copied = safe_copy(path, HONEYPOT_ANALYSIS_DIR)
                if copied:
                    self._emit_web_event("copied_for_analysis", path, {"copy": copied})
            except Exception:
                logger.debug("web copy failed")

    def on_modified(self, event):
        if event.is_directory:
            return

        path = os.path.abspath(event.src_path)
        logger.info("Web modified: %s", path)

        # Emit event
        self._emit_web_event("modified", path)

        # Sandbox analysis
        try:
            analysis = analyze_file(path)
            self._emit_web_event("analysis", path, {"analysis": analysis})
        except Exception as e:
            logger.debug("web modify analysis failed: %s", e)
            return

        # Suspicious detection
        if analysis.get("suspicious"):
            handler = helpers.get("handle_suspicious")
            if handler:
                try:
                    handler(path, "web_modified_suspicious", analysis)
                except Exception:
                    logger.debug("helpers.handle_suspicious failed")
