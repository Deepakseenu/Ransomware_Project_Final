# app/monitor/utils.py
import os
import hashlib
import time
import json
from datetime import datetime, timezone
from typing import Tuple
from .config import BACKUP_DIR, HONEYPOT_ANALYSIS_DIR
from .logger import logger
from pathlib import Path
import shutil

def now_iso():
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()

def compute_hashes(path: str) -> Tuple[str, str]:
    try:
        md5 = hashlib.md5()
        sha256 = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                md5.update(chunk); sha256.update(chunk)
        return md5.hexdigest(), sha256.hexdigest()
    except Exception as e:
        logger.debug("compute_hashes error for %s: %s", path, e)
        return "", ""

def safe_copy(src: str, dest_dir: str) -> str:
    try:
        Path(dest_dir).mkdir(parents=True, exist_ok=True)
        basename = os.path.basename(src)
        dest = os.path.join(dest_dir, f"{int(time.time())}_{basename}")
        shutil.copy2(src, dest)
        return dest
    except Exception as e:
        logger.debug("safe_copy failed: %s", e)
        return ""

def write_event_struct(log_path: str, obj: dict):
    try:
        obj.setdefault("timestamp", now_iso())
        Path(log_path).parent.mkdir(parents=True, exist_ok=True)
        with open(log_path, "a", encoding="utf-8") as lf:
            lf.write(json.dumps(obj, default=str) + "\n")
    except Exception as e:
        logger.debug("Failed to write structured event: %s", e)
