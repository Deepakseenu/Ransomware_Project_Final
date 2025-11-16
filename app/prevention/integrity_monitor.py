# app/prevention/integrity_monitor.py

"""
High-level orchestrator for:
- FileGuard
- ProcessGuard
- NetGuard
- Sandbox engine
"""

from ..monitor.event_emit import safe_emit


class IntegrityMonitor:
    def __init__(self, file_guard, process_guard, net_guard, sandbox):
        self.file_guard = file_guard
        self.process_guard = process_guard
        self.net_guard = net_guard
        self.sandbox = sandbox

    def start(self):
        safe_emit("integrity_monitor", {
            "action": "starting",
            "detail": {}
        })

        if self.file_guard:
            self.file_guard.start()

        if self.process_guard:
            self.process_guard.start()

        if self.net_guard:
            self.net_guard.start()

        safe_emit("integrity_monitor", {
            "action": "started",
            "detail": {}
        })

    def stop(self):
        safe_emit("integrity_monitor", {
            "action": "stopping",
            "detail": {}
        })

        try:
            if self.file_guard:
                self.file_guard.stop()
        except:
            pass

        try:
            if self.process_guard:
                self.process_guard.stop()
        except:
            pass

        safe_emit("integrity_monitor", {
            "action": "stopped",
            "detail": {}
        })
