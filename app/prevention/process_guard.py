# app/prevention/process_guard.py

import psutil
import threading
import time
from .logger import logger
from .config import CPU_SPIKE_THRESHOLD, MEM_SPIKE_THRESHOLD
from ..monitor.event_emit import safe_emit   # NEW
# (relative import depending on your structure, this is correct)

SUSPICIOUS_NAMES = {
    "nmap", "metasploit", "msfconsole", "sqlmap",
    "hydra", "john", "msf", "nc", "netcat"
}


class ProcessGuard:
    def __init__(self, helpers=None, terminate_on_detect=False):
        self.helpers = helpers or {}
        self.terminate_on_detect = terminate_on_detect
        self._stop = threading.Event()
        self._thread = None

    # ---------------------------------------------------------
    # Lifecycle
    # ---------------------------------------------------------

    def start(self):
        if self._thread:
            return
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()
        logger.info("ProcessGuard started.")

        safe_emit("process_guard", {
            "action": "started",
            "detail": {"terminate_on_detect": self.terminate_on_detect}
        })

    def stop(self):
        self._stop.set()
        safe_emit("process_guard", {
            "action": "stopped",
            "detail": {}
        })

    # ---------------------------------------------------------
    # Suspicion Logic
    # ---------------------------------------------------------

    def _is_suspicious(self, proc: psutil.Process):
        try:
            name = proc.name().lower()

            # 1. Suspicious executable name
            if any(s in name for s in SUSPICIOUS_NAMES):
                return True

            # 2. CPU spike
            if proc.cpu_percent(interval=0.1) > CPU_SPIKE_THRESHOLD:
                return True

            # 3. Memory spike
            if proc.memory_percent() > MEM_SPIKE_THRESHOLD:
                return True

        except Exception:
            return False

        return False

    # ---------------------------------------------------------
    # Action Handler
    # ---------------------------------------------------------

    def _take_action(self, proc: psutil.Process):
        info = {
            "pid": proc.pid,
            "name": None,
            "cmd": []
        }

        try:
            info["name"] = proc.name()
            info["cmd"] = proc.cmdline()
        except Exception:
            pass

        # -----------------------------------------------------
        # Suspend OR Terminate
        # -----------------------------------------------------

        if self.terminate_on_detect:
            try:
                proc.terminate()
                time.sleep(1)
                if proc.is_running():
                    proc.kill()
                info["action"] = "terminated"
            except Exception:
                info["action"] = "terminate_failed"
        else:
            try:
                proc.suspend()
                info["action"] = "suspended"
            except Exception:
                info["action"] = "suspend_failed"

        # -----------------------------------------------------
        # Emit sanitized, unified event to dashboard
        # -----------------------------------------------------

        safe_emit("process_guard", {
            "action": info["action"],
            "detail": info
        })

        # still support legacy helper events
        if "emit_event" in self.helpers:
            try:
                self.helpers["emit_event"]({
                    "type": "process_guard",
                    "detail": info
                })
            except Exception:
                logger.debug("helpers.emit_event failed")

    # ---------------------------------------------------------
    # Main Loop
    # ---------------------------------------------------------

    def _loop(self):
        while not self._stop.is_set():
            for proc in psutil.process_iter():
                try:
                    if self._is_suspicious(proc):
                        safe_emit("process_guard", {
                            "action": "suspicious_detected",
                            "detail": {
                                "pid": proc.pid,
                                "name": proc.name() if proc else "unknown"
                            }
                        })
                        self._take_action(proc)

                except Exception:
                    pass

            time.sleep(3)
