"""
TEST SCRIPT — FULL SYSTEM EVENT SIMULATION
------------------------------------------
This creates fake OS, WEB, FILEGUARD, PROCESS, and SANDBOX events
so you can see updates inside the dashboard without triggering
real attacks or modifying real files.
"""

import time
from pathlib import Path

# MONITOR LIFECYCLE
from app.monitor.lifecycle import start as monitor_start, shutdown as monitor_shutdown

# PREVENTION MODULES
from app.prevention.file_guard import FileGuard
from app.prevention.process_guard import ProcessGuard
from app.prevention.net_guard import NetGuard
from app.prevention.sandbox_engine import SandboxSimulation

# EVENT EMITTER
from app.monitor.event_emit import safe_emit

# CONFIG PATHS
from app.monitor.config import HONEYPOT_ANALYSIS_DIR


def simulate_events():
    print("\n--- STARTING TEST EVENT SIMULATION ---\n")

    # 1. OS EVENTS
    safe_emit("os", {
        "action": "created",
        "detail": {"path": "/tmp/test_created.txt"}
    })

    safe_emit("os", {
        "action": "modified",
        "detail": {"path": "/tmp/test_modified.txt"}
    })

    # 2. WEB EVENTS
    safe_emit("web", {
        "action": "created",
        "detail": {"path": "/var/www/html/fake_upload.txt"}
    })

    # 3. PROCESS GUARD EVENTS
    safe_emit("process_guard", {
        "action": "suspicious_detected",
        "detail": {"pid": 999, "name": "sqlmap_fake"}
    })

    # 4. NET GUARD EVENT
    safe_emit("net_guard", {
        "action": "local_blocked",
        "detail": {"ip": "192.168.100.55"}
    })

    # 5. FILEGUARD SIMULATED QUARANTINE EVENT
    safe_emit("file_guard", {
        "action": "quarantined",
        "detail": {
            "path": "/home/deepak/Desktop/fake_ransom.bin",
            "meta": {"sha256": "deadbeef123"},
        }
    })

    # 6. SANDBOX SIMULATION
    sandbox = SandboxSimulation()
    res = sandbox.analyze(__file__)   # analyze this test script itself
    safe_emit("sandbox", {
        "action": "analyzed",
        "detail": res
    })

    print("\n--- TEST EVENT SIMULATION COMPLETE ---\n")


def main():
    print("\n========================================")
    print("  TESTING FULL MONITOR + PREVENTION STACK")
    print("========================================\n")

    # Dummy watchers/helpers for lifecycle
    helpers = {}

    # Start monitor lifecycle (starts watchers, background thread)
    print("[+] Starting monitor lifecycle...")
    monitor_start(helpers)

    # Start prevention modules individually
    print("[+] Starting prevention modules...")
    fguard = FileGuard(["/home/deepak/Desktop"])
    pguard = ProcessGuard(terminate_on_detect=False)
    nguard = NetGuard()
    sandbox = SandboxSimulation()

    fguard.start()
    pguard.start()
    nguard.start()

    time.sleep(1)

    # Simulate events
    simulate_events()

    # Keep running for dashboard to show events
    print("[+] Letting event stream run for 10 seconds...")
    time.sleep(10)

    print("[+] Shutting down monitor...")
    monitor_shutdown()
    print("[✓] Done.")


if __name__ == "__main__":
    main()
