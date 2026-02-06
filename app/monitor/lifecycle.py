# app/monitor/lifecycle.py
import threading
import signal
import importlib
from typing import Dict, Tuple, Optional

from .watchers import start_watchers, stop_watchers
from .logger import logger

# module state
_shutdown_event = threading.Event()
_running = False

# store optional helpers and subsystems started via lifecycle
_helpers: Optional[Dict] = None
_subsystems: Tuple[Optional[object], Optional[object], Optional[object]] = (None, None, None)


def _signal_handler(signum, frame):
    logger.info("Ctrl-C / Signal %s → Fast shutdown triggered", signum)
    shutdown()


def start(helpers: Dict = None):
    """
    Start the monitor lifecycle.

    - If `helpers` is provided (as main.py does), this will use the provided helpers
      and start the watchers only. main.py is responsible for creating the prevention
      subsystems (FileGuard, ProcessGuard, NetGuard) in that workflow.

    - If `helpers` is None (e.g. when started from the dashboard API), this function
      will dynamically import `app.monitor.main.create_monitor()` and call it, which
      constructs and starts the full set of prevention subsystems (same behavior as
      running `python3 -m app.monitor.main`). Those subsystems are stored in module
      state so `shutdown()` can stop them later.
    """
    global _running, _helpers, _subsystems

    if _running:
        logger.debug("lifecycle.start() called but monitor already running")
        return

    # If helpers not provided, we are likely called from the dashboard API.
    if helpers is None:
        try:
            logger.debug("lifecycle.start: no helpers provided — importing create_monitor from app.monitor.main")
            main_mod = importlib.import_module("app.monitor.main")
            create_monitor = getattr(main_mod, "create_monitor", None)
            if not create_monitor:
                logger.error("create_monitor() not found in app.monitor.main; watchers only will be started")
                helpers = {}
            else:
                logger.info("Creating prevention subsystems via app.monitor.main.create_monitor()")
                helpers, subsystems = create_monitor()
                _helpers = helpers
                _subsystems = subsystems
        except Exception as e:
            logger.exception("Failed to import/create prevention subsystems: %s", e)
            helpers = {}
    else:
        # main.py already created the subsystems and passed a helpers dict.
        _helpers = helpers

    logger.info("Starting watchers...")
    try:
        start_watchers(_helpers)
    except Exception as e:
        logger.exception("Failed to start watchers: %s", e)

    # install signal handlers where possible (may fail under some hosts)
    try:
        signal.signal(signal.SIGINT, _signal_handler)
        signal.signal(signal.SIGTERM, _signal_handler)
    except Exception:
        logger.debug("signal handler registration failed or not permitted in this environment")

    _running = True
    logger.info("Monitor lifecycle started")


def shutdown():
    """
    Gracefully stop watchers and any prevention subsystems started by this module.
    main.py will also call subsystem stop itself on exit, but when the dashboard
    started subsystems via lifecycle.start() we must stop them here too.
    """
    global _running, _helpers, _subsystems

    if not _running:
        logger.debug("lifecycle.shutdown() called but monitor not running")
        return

    logger.info("Stopping lifecycle...")

    # First stop watchers
    try:
        stop_watchers()
    except Exception as e:
        logger.exception("Error stopping watchers: %s", e)

    # Then stop prevention subsystems if lifecycle created/owns them
    try:
        fg, pg, ng = _subsystems
        if fg:
            try:
                fg.stop()
            except Exception:
                logger.exception("Error stopping FileGuard")
        if pg:
            try:
                pg.stop()
            except Exception:
                logger.exception("Error stopping ProcessGuard")
        if ng:
            try:
                ng.stop()
            except Exception:
                logger.exception("Error stopping NetGuard")
    except Exception:
        logger.exception("Error while stopping subsystems")

    # clear stored helpers/subsystems state
    _subsystems = (None, None, None)
    _helpers = None

    _shutdown_event.set()
    _running = False
    logger.info("Monitor lifecycle stopped")


def wait_loop():
    while not _shutdown_event.wait(0.3):
        pass


def is_running() -> bool:
    """
    Return whether lifecycle reports as running.
    """
    return _running
