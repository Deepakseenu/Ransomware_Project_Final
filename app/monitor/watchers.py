# app/monitor/watchers.py

from watchdog.observers import Observer
from .handlers_web import WebHandler, set_helpers as set_web_helpers
from .handlers_os import OSHandler, set_helpers as set_os_helpers
from .logger import logger
from .config import WATCH_DIR, MONITORED_FOLDERS
import os

# Always a list (never None)
_observers = []

# Prevent double-start
_watchers_started = False


def start_watchers(helpers=None):
    """
    Start filesystem watchers for web and OS directories.
    Safe to call multiple times (will ignore duplicate start).
    """
    global _watchers_started

    if _watchers_started:  
        logger.debug("Watchers already running — skipping start.")
        return

    set_web_helpers(helpers)
    set_os_helpers(helpers)

    # -------------------------------
    # 1. Web Watcher
    # -------------------------------
    try:
        web_obs = Observer()
        web_obs.schedule(WebHandler(), str(WATCH_DIR), recursive=True)
        web_obs.start()
        _observers.append(web_obs)
        logger.info("Watching web dir: %s", WATCH_DIR)
    except Exception as e:
        logger.error("Failed to start web watcher: %s", e)

    # -------------------------------
    # 2. OS Watcher
    # -------------------------------
    try:
        os_obs = Observer()
        os_handler = OSHandler()

        for folder in MONITORED_FOLDERS:
            try:
                if os.path.exists(folder):
                    os_obs.schedule(os_handler, folder, recursive=True)
                    logger.info("Watching OS folder: %s", folder)
                else:
                    logger.debug("OS folder not present: %s", folder)
            except Exception as e:
                logger.error("Failed to schedule %s: %s", folder, e)

        os_obs.start()
        _observers.append(os_obs)

    except Exception as e:
        logger.error("Failed to start OS observer: %s", e)

    _watchers_started = True


def stop_watchers():
    """
    Stop all active observers safely. 
    Safe to call multiple times.
    """
    global _watchers_started

    if not _watchers_started:
        return  # Already stopped, avoid errors

    for obs in list(_observers):
        try:
            obs.stop()
            obs.join(timeout=2)
        except Exception:
            pass

    _observers.clear()
    _watchers_started = False
