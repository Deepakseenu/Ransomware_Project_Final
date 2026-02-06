"""
FileGuard – Integrity Monitor
Monitors watched directories and detects ransomware-like changes.
"""

import os
import time
import json
import threading
from pathlib import Path

from .logger import logger
from .utils import sha256
from .quarantine import backup_and_quarantine, create_decoy_at_path
from app.monitor.main import _SANDBOX
from app.monitor.event_emit import safe_emit

from watchdog.events import FileSystemEventHandler

# --- ALERT CONFIG ---
from pathlib import Path as P
import json
from app.monitor.alerts import trigger_alert

_cfg_path = P(__file__).resolve().parents[2] / "config" / "alert_config.json"
try:
    with open(_cfg_path, "r") as _f:
        ALERT_CONFIG = json.load(_f)
except Exception:
    ALERT_CONFIG = {}
# ------------------------------------------------

from .config import (
    BASELINE_PATH,
    INTEGRITY_INTERVAL,
    MASS_CHANGE_THRESHOLD,
    EXCLUDE_DIRS,
)


class FileGuard:
    """
    FileGuard monitors directories & triggers quarantine when
    sandbox analysis marks file as suspicious.
    """

    IGNORED_DIRS = {
        "/honeypot_data/logs",
        "/honeypot_data/quarantine",
        "/honeypot_data/backup",
        "/honeypot_data/decoys",

        "/home/deepak/.config",
        "/home/deepak/.local",
        "/home/deepak/.cache",
        "/home/deepak/.mozilla",
        "/home/deepak/.thunderbird",

        "/home/deepak/Ransomware_Project_Final/app",
        "/home/deepak/Ransomware_Project_Final/logs",
        "/home/deepak/Ransomware_Project_Final/models",
        "/home/deepak/Ransomware_Project_Final/.venv_app",
    }

    IGNORED_FILES = {BASELINE_PATH}

    # -------------------------------------------------------------
    # Init
    # -------------------------------------------------------------
    def __init__(self, watch_dirs, helpers=None):
        self.watch_dirs = watch_dirs
        self.helpers = helpers or {}
        self._baseline = {}
        self._stop = threading.Event()
        self._thread = None

        # watchdog compatibility placeholders
        self.observer = None
        self.watchdog_observer = None
        self.observers = None

        Path(BASELINE_PATH).parent.mkdir(parents=True, exist_ok=True)

        self._load_or_create_baseline()

        # Use global Sandbox
        self.sandbox = _SANDBOX

    # -------------------------------------------------------------
    # Utility
    # -------------------------------------------------------------
    def _normalize(self, p: str) -> str:
        return os.path.abspath(os.path.realpath(p))

    def _is_excluded(self, path: str) -> bool:
        p = self._normalize(path)
        return any(p.startswith(ex) for ex in EXCLUDE_DIRS)

    def _should_ignore(self, path: str) -> bool:
        p = self._normalize(path)

        if p in self.IGNORED_FILES:
            return True

        for d in self.IGNORED_DIRS:
            if p.startswith(self._normalize(d)):
                return True

        if self._is_excluded(p):
            return True

        if os.path.basename(p) in {"lock", ".lock"}:
            return True

        return False

    # -------------------------------------------------------------
    # Baseline
    # -------------------------------------------------------------
    def _load_or_create_baseline(self):
        if os.path.exists(BASELINE_PATH):
            try:
                with open(BASELINE_PATH, "r") as f:
                    self._baseline = json.load(f).get("files", {})
            except Exception:
                self._baseline = {}

        if not self._baseline:
            logger.info("Building new baseline...")

            for d in self.watch_dirs:
                d = self._normalize(d)
                if not os.path.exists(d):
                    continue

                for root, _, files in os.walk(d):
                    if self._should_ignore(root):
                        continue

                    for fn in files:
                        fp = os.path.join(root, fn)
                        if self._should_ignore(fp):
                            continue
                        self._baseline[self._normalize(fp)] = sha256(fp)

            self._save()

    def _save(self):
        try:
            with open(BASELINE_PATH, "w") as f:
                json.dump({"files": self._baseline}, f, indent=2)
        except Exception as e:
            logger.error(f"Baseline save error: {e}")

    # -------------------------------------------------------------
    # Start / Stop
    # -------------------------------------------------------------
    def start(self):
        if self._thread and self._thread.is_alive():
            return
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()
        logger.info("FileGuard started.")

    def stop(self):
        logger.info("FileGuard stop requested.")
        self._stop.set()

        for attr in ("observer", "watchdog_observer", "observers"):
            obs = getattr(self, attr, None)
            if not obs:
                continue

            if isinstance(obs, (list, tuple)):
                for o in obs:
                    try: o.stop()
                    except: pass
                    try: o.join(timeout=1)
                    except: pass
            else:
                try: obs.stop()
                except: pass
                try: obs.join(timeout=2)
                except: pass

        if self._thread and self._thread.is_alive():
            try:
                self._thread.join(timeout=2)
            except:
                pass

        logger.info("FileGuard stopped.")

    # -------------------------------------------------------------
    # File Change Handler
    # -------------------------------------------------------------
    def _handle_change(self, path, old_hash, new_hash):
        logger.warning(f"[FILEGUARD] Change detected: {path}")

        safe_emit("file_guard", {
            "action": "changed",
            "detail": {"path": path, "old_hash": old_hash, "new_hash": new_hash}
        })

        # --- Honeypot / Decoy Tampering Alert ---
        if "decoys" in path:
            msg = f"Honeypot hit: decoy file modified: {path}"
            logger.critical(msg)
            trigger_alert(msg, ALERT_CONFIG, level="HIGH")

        # ---------------------------------------------------------
        # Run sandbox BEFORE deciding
        # ---------------------------------------------------------
        try:
            analysis = self.sandbox.analyze(path)
        except Exception as e:
            logger.error(f"Sandbox error for {path}: {e}")
            analysis = {"suspicious": False, "error": True}

        if not analysis.get("suspicious"):
            logger.info(f"[FILEGUARD] Benign change ignored: {path}")

            safe_emit("file_guard", {
                "action": "benign",
                "detail": {"path": path, "analysis": analysis}
            })

            try:
                if os.path.exists(path):
                    self._baseline[path] = sha256(path)
                else:
                    self._baseline.pop(path, None)
                self._save()
            except:
                pass

            return

        # ---------------------------------------------------------
        # Suspicious → QUARANTINE
        # ---------------------------------------------------------
        logger.warning(f"[FILEGUARD] Suspicious file - quarantining: {path}")

        safe_emit("file_guard", {
            "action": "suspicious",
            "detail": {"path": path, "analysis": analysis}
        })

        meta = backup_and_quarantine(path, "file_guard_detected")

        safe_emit("file_guard", {
            "action": "quarantined",
            "detail": {"path": path, "meta": meta}
        })

        try:
            create_decoy_at_path(path)
        except Exception as e:
            logger.warning(f"Decoy creation failed: {e}")

        try:
            if os.path.exists(path):
                self._baseline[path] = sha256(path)
            else:
                self._baseline.pop(path, None)
            self._save()
        except:
            pass

    # -------------------------------------------------------------
    # Loop
    # -------------------------------------------------------------
    def _loop(self):
        while not self._stop.is_set():
            changes = []

            for path, old_hash in list(self._baseline.items()):
                if self._should_ignore(path):
                    continue

                if os.path.exists(path):
                    new_hash = sha256(path)
                    if new_hash and new_hash != old_hash:
                        changes.append((path, old_hash, new_hash))
                else:
                    changes.append((path, old_hash, None))
                    self._baseline.pop(path, None)

            # MASS change alert
            if len(changes) >= MASS_CHANGE_THRESHOLD:
                msg = f"[FileGuard] MASS CHANGE DETECTED ({len(changes)} files)"
                logger.critical(msg)
                trigger_alert(msg, ALERT_CONFIG, level="HIGH")

                safe_emit("file_guard", {
                    "action": "mass_change",
                    "detail": {"count": len(changes)}
                })

            for p, old_h, new_h in changes:
                self._handle_change(p, old_h, new_h)

            time.sleep(INTEGRITY_INTERVAL)
