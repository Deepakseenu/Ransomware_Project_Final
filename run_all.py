#!/usr/bin/env python3
"""
run_all.py - Unified runner for the Ransomware_Project_Final backend.

Behavior:
 - Prefer in-process start (import modules) for tighter integration.
 - Fallback to subprocess start (python3 app/app.py, python3 app/monitor/main.py, ...)
 - Start order:
     1) Dashboard (Flask + Socket.IO)
     2) ML loader (optional)
     3) Monitor (connects to dashboard)
     4) Prevention subsystems (FileGuard / ProcessGuard / NetGuard)
 - Keeps simple health-monitoring loop and restarts child subprocesses if they crash.
 - Graceful shutdown on SIGINT/SIGTERM.

Notes:
 - This script intentionally keeps orchestration logic generic so it works
   with both the importable modules or the standalone scripts you already have.
 - Logs are written to ./honeypot_data/logs/run_all.log by default.
"""

from __future__ import annotations
import os
import sys
import time
import signal
import logging
import threading
import subprocess
from typing import Optional, Dict, Any, List

ROOT = os.path.abspath(os.path.dirname(__file__))
os.chdir(ROOT)

# ---------------------------------------------------------
# Configuration (tweak if needed)
# ---------------------------------------------------------
DASHBOARD_CMD = [sys.executable, "app/app.py"]
MONITOR_CMD = [sys.executable, "app/monitor/main.py"]
PREVENTION_CMD = [sys.executable, "app/prevention/run_prevention.py"]  # optional fallback script
RUN_LOG_DIR = os.path.join(ROOT, "honeypot_data", "logs")
RUN_LOG = os.path.join(RUN_LOG_DIR, "run_all.log")

START_TIMEOUT = 12.0   # seconds wait for services to become usable
RESTART_DELAY = 3.0    # wait before restarting a crashed child
HEALTH_CHECK_INTERVAL = 5.0

# ensure log dir
os.makedirs(RUN_LOG_DIR, exist_ok=True)

# ---------------------------------------------------------
# Logging
# ---------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler(RUN_LOG),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger("run_all")

# ---------------------------------------------------------
# Process holder
# ---------------------------------------------------------
children: Dict[str, Dict[str, Any]] = {}

_shutdown = False
_shutdown_lock = threading.Lock()

def on_terminate(signum, frame):
    logger.info("Signal %s received, shutting down...", signum)
    with _shutdown_lock:
        global _shutdown
        _shutdown = True
    stop_all_children()

signal.signal(signal.SIGINT, on_terminate)
signal.signal(signal.SIGTERM, on_terminate)

# ---------------------------------------------------------
# Utility: start subprocess and capture logs
# ---------------------------------------------------------
def start_subprocess(name: str, cmd: List[str], cwd: Optional[str] = None, env: Optional[Dict[str,str]] = None) -> subprocess.Popen:
    """
    Start a subprocess and keep its stdout/stderr redirected to files under honeypot_data/logs.
    """
    logfile = os.path.join(RUN_LOG_DIR, f"{name}.log")
    logger.info("Starting subprocess %s: %s  (log: %s)", name, " ".join(cmd), logfile)
    lf = open(logfile, "a", buffering=1)
    proc = subprocess.Popen(cmd, cwd=cwd or ROOT, env=(env or os.environ.copy()), stdout=lf, stderr=subprocess.STDOUT)
    children[name] = {"type": "proc", "proc": proc, "logfile": logfile, "handle": lf, "cmd": cmd}
    return proc

def stop_subprocess(name: str):
    info = children.get(name)
    if not info:
        return
    if info.get("type") == "proc":
        proc: subprocess.Popen = info["proc"]
        logger.info("Stopping subprocess %s (pid=%s)...", name, getattr(proc, "pid", None))
        try:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                logger.warning("Process %s did not terminate, killing...", name)
                proc.kill()
        except Exception as e:
            logger.debug("Error stopping %s: %s", name, e)
        try:
            handle = info.get("handle")
            if handle:
                handle.close()
        except Exception:
            pass
    children.pop(name, None)

# ---------------------------------------------------------
# Utility: start thread wrapper for import-run functions
# ---------------------------------------------------------
def start_threaded(name: str, target, args=()):
    """
    Start a Python thread wrapper that runs `target(*args)`. On exception, logs and marks child entry.
    """
    def runner():
        logger.info("Thread %s starting (in-process)", name)
        try:
            target(*args)
            logger.info("Thread %s finished normally", name)
        except Exception:
            logger.exception("Thread %s crashed", name)
        # mark finished
        children.pop(name, None)

    th = threading.Thread(target=runner, daemon=True)
    children[name] = {"type": "thread", "thread": th}
    th.start()
    return th

# ---------------------------------------------------------
# Try to import and run in-process where possible
# ---------------------------------------------------------
def try_import_dashboard() -> bool:
    """
    Try to import app.app (our flask/socketio module) and run socketio.run in a thread.
    Returns True on success (in-process run started), False on any import error.
    """
    try:
        # Import the module; it should expose `socketio` and `app` objects
        import importlib
        mod = importlib.import_module("app.app")
        sock = getattr(mod, "socketio", None)
        flask_app = getattr(mod, "app", None)
        if sock is None or flask_app is None:
            logger.warning("app.app module didn't expose app/socketio variables.")
            return False

        def _run_socketio():
            # run in the same process (non-debug)
            sock.run(flask_app, host=os.environ.get("DASHBOARD_HOST", "0.0.0.0"),
                     port=int(os.environ.get("DASHBOARD_PORT", "5000")), debug=False)

        start_threaded("dashboard", _run_socketio)
        logger.info("Dashboard started in-process.")
        return True
    except Exception as e:
        logger.warning("In-process dashboard import failed: %s", e)
        return False

def try_import_monitor() -> bool:
    """
    Try to import monitor.main.main() and run in thread.
    Expects app/monitor/main.py to expose a main() function.
    """
    try:
        import importlib
        mod = importlib.import_module("app.monitor.main")
        if hasattr(mod, "main") and callable(getattr(mod, "main")):
            start_threaded("monitor", getattr(mod, "main"))
            logger.info("Monitor started in-process.")
            return True
        else:
            logger.warning("app.monitor.main has no callable main().")
            return False
    except Exception as e:
        logger.warning("In-process monitor import failed: %s", e)
        return False

def try_import_prevention() -> bool:
    """
    Try to import prevention runner or start FileGuard/ProcessGuard in-process if exposed.
    Expected patterns:
      - app.prevention.run_all() OR
      - app.prevention.integrate(...) wrappers
    """
    try:
        import importlib
        mod = importlib.import_module("app.prevention")
        # two possibilities: a run_all function or individual classes
        if hasattr(mod, "run_all") and callable(getattr(mod, "run_all")):
            start_threaded("prevention", getattr(mod, "run_all"))
            logger.info("Prevention run_all started in-process.")
            return True
        # fallback: if module exports an 'init' or 'start' function
        for candidate in ("start_all", "init", "start"):
            if hasattr(mod, candidate) and callable(getattr(mod, candidate)):
                start_threaded("prevention", getattr(mod, candidate))
                logger.info("Prevention %s started in-process.", candidate)
                return True
        # else try to import file_guard.ProcessGuard and start typical guards if available
        try:
            fg_mod = importlib.import_module("app.prevention.file_guard")
            pg_mod = importlib.import_module("app.prevention.process_guard")
            ng_mod = importlib.import_module("app.prevention.net_guard")
            # rough best-effort wiring: create and start if classes exist
            def start_guards():
                try:
                    helpers = {}
                    fileguard = None
                    if hasattr(fg_mod, "FileGuard"):
                        fileguard = fg_mod.FileGuard(watch_dirs=[os.path.expanduser("~")], helpers=helpers)
                        fileguard.start()
                    if hasattr(pg_mod, "ProcessGuard"):
                        procguard = pg_mod.ProcessGuard(helpers=helpers, terminate_on_detect=False, whitelist_basenames=["sshd","systemd"])
                        procguard.start()
                    if hasattr(ng_mod, "NetGuard"):
                        netguard = ng_mod.NetGuard(helpers=helpers)
                        netguard.start()
                    # simple loop to keep thread alive
                    while True:
                        time.sleep(1)
                except Exception:
                    logger.exception("in-process prevention guards crashed")
            start_threaded("prevention", start_guards)
            logger.info("Prevention guards started in-process.")
            return True
        except Exception as e:
            logger.debug("prevention guards import fallback failed: %s", e)
            return False
    except Exception as e:
        logger.warning("In-process prevention import failed: %s", e)
        return False

def try_import_ml_loader() -> bool:
    """
    Try to import ml model loader to pre-warm models (non-blocking)
    Expected location: app.ml.model_predict or app.models.loader
    """
    try:
        import importlib
        # try model_predict
        try:
            mp = importlib.import_module("app.ml.model_predict")
            if hasattr(mp, "warmup") and callable(getattr(mp, "warmup")):
                start_threaded("ml_loader", getattr(mp, "warmup"))
                logger.info("ML warmup started (app.ml.model_predict.warmup).")
                return True
        except Exception:
            pass
        # try models.loader
        try:
            mlmod = importlib.import_module("app.models.loader")
            if hasattr(mlmod, "load_model"):
                def load_once():
                    try:
                        mlmod.load_model()
                        logger.info("ML model loaded via app.models.loader.load_model()")
                    except Exception:
                        logger.exception("ml loader crashed")
                start_threaded("ml_loader", load_once)
                return True
        except Exception:
            pass
        logger.info("No ML loader found for in-process warmup.")
        return False
    except Exception as e:
        logger.debug("ml import attempt failed: %s", e)
        return False

# ---------------------------------------------------------
# Start orchestration
# ---------------------------------------------------------
def start_everything():
    logger.info("Unified runner starting...")

    # 1) Dashboard (preferred in-process)
    dashboard_started = try_import_dashboard()
    if not dashboard_started:
        # fallback: start as subprocess
        start_subprocess("dashboard", DASHBOARD_CMD)
        # give it time to boot
        time.sleep(START_TIMEOUT)

    # 2) ML loader (optional)
    ml_started = try_import_ml_loader()
    if not ml_started:
        logger.info("No in-process ML loader; skipping ML warmup subprocess (if you want one, add app/ml/model_predict.warmup)")

    # 3) Monitor
    monitor_started = try_import_monitor()
    if not monitor_started:
        # fallback to subprocess monitor command
        start_subprocess("monitor", MONITOR_CMD)
        time.sleep(2.0)

    # 4) Prevention
    prevention_started = try_import_prevention()
    if not prevention_started:
        # try to start a fallback script if present
        if os.path.exists(os.path.join(ROOT, "app", "prevention", "run_prevention.py")):
            start_subprocess("prevention", PREVENTION_CMD)
        else:
            logger.info("No prevention runner found; ensure app/prevention exposes run_all or provide run_prevention.py fallback.")

    logger.info("Startup sequence complete. Entering supervision loop.")

    # supervsion loop for subprocess children: restart on crash
    while True:
        with _shutdown_lock:
            if _shutdown:
                logger.info("Shutdown flag set; exiting supervision loop.")
                break
        # scan subprocess children and restart if necessary
        for name, info in list(children.items()):
            if info.get("type") == "proc":
                proc: subprocess.Popen = info.get("proc")
                if proc and proc.poll() is not None:
                    returncode = proc.returncode
                    logger.warning("Child process %s exited with code %s. Restarting after delay...", name, returncode)
                    # close logfile handle
                    try:
                        handle = info.get("handle")
                        if handle:
                            handle.close()
                    except Exception:
                        pass
                    children.pop(name, None)
                    # restart
                    time.sleep(RESTART_DELAY)
                    # re-create
                    cmd = info.get("cmd")
                    if cmd:
                        start_subprocess(name, cmd)
        time.sleep(HEALTH_CHECK_INTERVAL)

def stop_all_children():
    logger.info("Stopping all children...")
    # stop subprocesses first
    for name in list(children.keys()):
        try:
            stop_subprocess(name)
        except Exception:
            # for thread entries we simply ignore (threads are daemonic)
            children.pop(name, None)
    logger.info("All children stop requested.")

# ---------------------------------------------------------
# Entrypoint
# ---------------------------------------------------------
if __name__ == "__main__":
    try:
        start_everything()
    except Exception:
        logger.exception("run_all main crashed")
    finally:
        stop_all_children()
        logger.info("run_all exited.")
