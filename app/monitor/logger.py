# app/monitor/logger.py
import logging
import os
from .config import LOG_PATH
from pathlib import Path

def setup_logger(name: str = "monitor"):
    logger = logging.getLogger(name)
    if logger.handlers:
        return logger  # already configured

    logger.setLevel(logging.INFO)
    # ensure directory
    try:
        Path(LOG_PATH).parent.mkdir(parents=True, exist_ok=True)
        fh = logging.FileHandler(LOG_PATH, mode="a", encoding="utf-8")
        fh.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s"))
        logger.addHandler(fh)
    except Exception:
        # fallback to console
        logger.addHandler(logging.StreamHandler())

    # also log to stdout
    logger.addHandler(logging.StreamHandler())
    return logger

logger = setup_logger()
