# ml/feature_extractor.py

import os
import math
from pathlib import Path

SUSPICIOUS_EXT = {".enc", ".locked", ".encrypted", ".crypt"}

def file_entropy(path):
    try:
        with open(path, "rb") as f:
            data = f.read(8192)
        if not data:
            return 0.0

        freq = {b: data.count(b) for b in set(data)}
        total = len(data)
        return -sum((c / total) * math.log2(c / total) for c in freq.values())
    except:
        return 0.0

def extract_features(filename, label=None):
    """
    Extract ML-ready features from a file path or name.
    Safe: does not require reading the entire file.
    """
    p = Path(filename)
    ext = p.suffix.lower()

    return {
        "filename": p.name,
        "ext": ext,
        "entropy": file_entropy(filename) if os.path.exists(filename) else 0.0,
        "size": os.path.getsize(filename) if os.path.exists(filename) else 0,
        "is_suspicious_ext": int(ext in SUSPICIOUS_EXT),
        "label": label
    }
