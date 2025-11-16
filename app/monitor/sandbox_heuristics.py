# app/monitor/sandbox_heuristics.py
import math
import os
from .config import HIGH_ENTROPY_THRESHOLD, RANSOM_PATTERNS, SUSPICIOUS_EXTS
from .yara_engine import scan_file
from .logger import logger

def shannon_entropy(data: bytes) -> float:
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
    return ent

def analyze_file(path: str, small_file_min: int = 16) -> dict:
    r = {"suspicious": False, "reasons": [], "score": 0.0}
    try:
        if not os.path.exists(path):
            r["reasons"].append("not_found")
            return r
        base = os.path.basename(path).upper()
        for p in RANSOM_PATTERNS:
            if p in base:
                r["reasons"].append("ransom_name"); r["score"] += 5.0
        _, ext = os.path.splitext(path)
        if ext.lower() in SUSPICIOUS_EXTS:
            r["reasons"].append("suspicious_ext"); r["score"] += 5.0

        # YARA matches (if loaded)
        try:
            matches = scan_file(path)
            if matches:
                r["reasons"].append(f"yara:{','.join(matches)}"); r["score"] += 6.0
        except Exception:
            pass

        try:
            size = os.path.getsize(path)
            if size >= small_file_min:
                with open(path, "rb") as f:
                    chunk = f.read(4096)
                ent = shannon_entropy(chunk)
                r["reasons"].append(f"entropy={ent:.2f}")
                if ent > HIGH_ENTROPY_THRESHOLD:
                    r["score"] += 4.0
            else:
                r["reasons"].append("tiny_file")
        except Exception:
            r["reasons"].append("entropy_err")

        if r["score"] >= 6.0:
            r["suspicious"] = True

    except Exception as e:
        logger.debug("sandbox analysis failed: %s", e)
        r["reasons"].append("analysis_failed")
    return r
