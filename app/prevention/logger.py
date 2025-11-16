# app/prevention/logger.py

import logging
from pathlib import Path
from .config import LOG_PATH

def setup_logger(name="prevention"):
    logger = logging.getLogger(name)
    if logger.handlers:
        return logger

    Path(LOG_PATH).parent.mkdir(parents=True, exist_ok=True)
    logger.setLevel(logging.INFO)

    handler = logging.FileHandler(LOG_PATH, mode="a", encoding="utf-8")
    handler.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s"))
    logger.addHandler(handler)

    logger.addHandler(logging.StreamHandler())
    return logger

logger = setup_logger()
