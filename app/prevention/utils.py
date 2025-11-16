# app/prevention/utils.py

import os
import shutil
import hashlib
import math
from pathlib import Path
from datetime import datetime, timezone
from .logger import logger

def now_iso():
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()

def sha256(path):
    try:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()
    except:
        return ""

def safe_copy(src, dst_dir):
    try:
        Path(dst_dir).mkdir(parents=True, exist_ok=True)
        dst = Path(dst_dir) / f"{int(datetime.now().timestamp())}_{Path(src).name}"
        shutil.copy2(src, dst)
        return str(dst)
    except Exception as e:
        logger.error("safe_copy failed: %s", e)
        return ""

def compute_entropy(path: str, sample_bytes: int = 4096) -> float:
    try:
        with open(path, "rb") as f:
            data = f.read(sample_bytes)
        if not data:
            return 0.0
        freq = {}
        for b in data:
            freq[b] = freq.get(b, 0) + 1
        ent = 0.0
        ln = len(data)
        for count in freq.values():
            p = count / ln
            ent -= p * math.log2(p)
        return round(ent, 4)
    except Exception:
        return 0.0

def safe_read_chunk(path: str, max_bytes: int = 8192, decode: bool = True):
    try:
        with open(path, "rb") as f:
            data = f.read(max_bytes)
        if decode:
            try:
                return data.decode("utf-8", errors="ignore")
            except Exception:
                return ""
        return data
    except Exception:
        return ""
