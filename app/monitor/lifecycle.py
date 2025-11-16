# app/monitor/lifecycle.py
import threading
import signal
from typing import Dict

from .watchers import start_watchers, stop_watchers
from .logger import logger

_shutdown_event = threading.Event()
_running = False


def _signal_handler(signum, frame):
    logger.info("Ctrl-C / Signal %s → Fast shutdown triggered", signum)
    shutdown()


def start(helpers: Dict = None):
    """
    Start the monitor lifecycle: watchers + signal handlers.
    This function no longer starts any socket.io connector (we use HTTP push).
    """
    global _running
    if _running:
        return

    logger.info("Starting watchers...")
    start_watchers(helpers)

    # set signals
    try:
        signal.signal(signal.SIGINT, _signal_handler)
        signal.signal(signal.SIGTERM, _signal_handler)
    except Exception:
        # some environments (e.g. uvicorn subprocesses) may restrict signal setting
        logger.debug("signal handler registration failed or not permitted in this environment")

    _running = True
    logger.info("Monitor lifecycle started")


def shutdown():
    """
    Gracefully stop watchers and mark monitor as stopped.
    """
    global _running

    if not _running:
        return

    logger.info("Stopping lifecycle...")

    try:
        stop_watchers()
    except Exception as e:
        logger.error("Error stopping watchers: %s", e)

    _shutdown_event.set()
    _running = False


def wait_loop():
    while not _shutdown_event.wait(0.3):
        pass


def is_running() -> bool:
    """
    Helper to query whether the lifecycle reports as running.
    Useful for APIs that attempt to control the monitor when co-located.
    """
    return _running
