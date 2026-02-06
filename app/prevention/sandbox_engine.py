"""
SAFE Dynamic Sandbox Simulation Engine
--------------------------------------
This sandbox NEVER executes files. It simulates behavior using:
- static metadata (entropy, hashes, size, extension)
- YARA scanning
- ML prediction (optional)
- heuristic syscall simulation

This file is SAFE — no real execution occurs.
"""

import os
import hashlib
from pathlib import Path

# ML loader (may return None if model not trained yet)
from app.models.loader import load_model_and_encoder

# YARA wrapper from monitor module
try:
    from app.monitor.yara_engine import yara_scan_file
except Exception:
    yara_scan_file = None  # graceful fallback

# local helpers
from .utils import compute_entropy, safe_read_chunk

# emit events to dashboard
from ..monitor.event_emit import safe_emit


# ----------------------------------------------------------------------
# Load ML model once (if available)
# ----------------------------------------------------------------------
MODEL, ENCODER = None, None
try:
    MODEL, ENCODER = load_model_and_encoder()
except Exception:
    MODEL, ENCODER = None, None


# ======================================================================
# MAIN SANDBOX SIMULATION CLASS
# ======================================================================

class SandboxSimulation:
    def __init__(self, yara_enabled=True, ml_enabled=True, entropy_threshold=7.5):
        self.use_yara = yara_enabled and callable(yara_scan_file)
        self.use_ml = ml_enabled and (MODEL is not None and ENCODER is not None)
        self.entropy_threshold = float(entropy_threshold)

    # ------------------------------------------------------------
    # Metadata + Hashes
    # ------------------------------------------------------------
    def _hashes(self, path, nbytes=65536):
        md5 = hashlib.md5()
        sha256 = hashlib.sha256()
        try:
            with open(path, "rb") as f:
                data = f.read(nbytes)
                md5.update(data)
                sha256.update(data)
            return md5.hexdigest(), sha256.hexdigest()
        except Exception:
            return "", ""

    def extract_metadata(self, path):
        ext = Path(path).suffix.lower()
        try:
            size = os.path.getsize(path)
        except Exception:
            size = 0

        md5, sha256 = self._hashes(path)
        entropy = compute_entropy(path, sample_bytes=8192)

        return {
            "extension": ext,
            "size": size,
            "entropy": entropy,
            "md5": md5,
            "sha256": sha256,
        }

    # ------------------------------------------------------------
    # YARA scanning
    # ------------------------------------------------------------
    def yara_matches(self, path):
        if not self.use_yara:
            return []

        try:
            matches = yara_scan_file(path)
            return matches or []
        except Exception:
            return []

    # ------------------------------------------------------------
    # ML Prediction
    # ------------------------------------------------------------
    def ml_predict(self, meta):
        if not self.use_ml:
            return None, 0.0

        try:
            # Encode extension
            ext = meta.get("extension", "")
            try:
                ext_enc = ENCODER.transform([ext])[0]
            except Exception:
                # fallback if extension not in encoder
                try:
                    ext_enc = ENCODER.transform([ENCODER.classes_[0]])[0]
                except Exception:
                    ext_enc = 0

            size = meta.get("size", 0)
            num_mod = 1   # static placeholder, safe

            X = [[ext_enc, size, num_mod]]

            pred = MODEL.predict(X)[0]
            prob = float(MODEL.predict_proba(X)[0].max())

            return pred, prob
        except Exception:
            return None, 0.0

    # ------------------------------------------------------------
    # Syscall heuristic simulation
    # ------------------------------------------------------------
    def simulated_syscall_score(self, meta):
        score = 0
        reasons = []

        ent = meta.get("entropy", 0.0)
        if ent >= self.entropy_threshold:
            score += 3
            reasons.append("high_entropy_sim")

        size = meta.get("size", 0)
        if size and size % 4096 == 0:
            score += 1
            reasons.append("aligned_io_sim")

        return score, reasons

    # ------------------------------------------------------------
    # Main analysis
    # ------------------------------------------------------------
    def analyze(self, path) -> dict:
        res = {
            "path": path,
            "suspicious": False,
            "score": 0.0,
            "meta": {},
            "yara_matches": [],
            "ml_prediction": None,
            "ml_probability": 0.0,
            "reasons": [],
        }

        # file missing?
        if not os.path.exists(path):
            res["reasons"].append("missing")
            # emit event for missing file analysis
            try:
                safe_emit("sandbox", {"action": "analyzed", "detail": res})
            except Exception:
                pass
            return res

        # metadata
        meta = self.extract_metadata(path)
        res["meta"] = meta

        # --------------------------------------------------
        # Heuristic scoring
        # --------------------------------------------------

        # ransomware extensions
        if meta["extension"] in {".enc", ".locked", ".crypt", ".encrypted"}:
            res["score"] += 5
            res["reasons"].append("suspicious_extension")

        # ransomware filename patterns
        base_name = Path(path).name.upper()
        for tag in ("README_DECRYPT", "README-FILES", "HOW_TO_DECRYPT", "HOW_TO_RESTORE"):
            if tag in base_name:
                res["score"] += 6
                res["reasons"].append("ransomnote_filename")

        # entropy
        ent = meta["entropy"]
        res["reasons"].append(f"entropy={ent:.2f}")
        if ent >= self.entropy_threshold:
            res["score"] += 4
            res["reasons"].append("high_entropy")

        # --------------------------------------------------
        # YARA
        # --------------------------------------------------
        ymatches = self.yara_matches(path)
        if ymatches:
            res["yara_matches"] = ymatches
            res["score"] += 8
            res["reasons"].append("yara_hit")

        # --------------------------------------------------
        # ML Prediction
        # --------------------------------------------------
        pred, prob = self.ml_predict(meta)
        res["ml_prediction"] = pred
        res["ml_probability"] = prob

        if pred == "ransomware" and prob >= 0.75:
            res["score"] += 10
            res["reasons"].append("ml_high_confidence")

        # --------------------------------------------------
        # simulated syscall heuristics
        # --------------------------------------------------
        sc_score, sc_reasons = self.simulated_syscall_score(meta)
        res["score"] += sc_score
        res["reasons"].extend(sc_reasons)

        # --------------------------------------------------
        # final suspicion classification
        # --------------------------------------------------
        THRESHOLD = float(os.environ.get("SANDBOX_SUSPICION_THRESHOLD", "10.0"))
        res["suspicious"] = (res["score"] >= THRESHOLD)

        # emit final analysis result to dashboard (non-blocking)
        try:
            safe_emit("sandbox", {"action": "analyzed", "detail": res})
        except Exception:
            pass

        return res

    # ------------------------------------------------------------
    # Backwards-compatible run() alias
    # ------------------------------------------------------------
    def run(self, path: str) -> dict:
        """
        Backward-compatible method name used by older modules (e.g. FileGuard).
        Delegates to analyze().
        """
        return self.analyze(path)


# ======================================================================
# BACKWARD COMPATIBILITY WRAPPER
# This ensures imports like: from app.prevention.sandbox_engine import SandboxAnalyzer
# ======================================================================

class SandboxAnalyzer:
    """
    Backward-compatible wrapper for SandboxSimulation.
    Allows older code to call: SandboxAnalyzer().analyze(path)
    """
    def __init__(self):
        self.sim = SandboxSimulation()

    def analyze(self, path: str) -> dict:
        return self.sim.analyze(path)


# ----------------------------------------------------------------------
# Module-level convenience function for older imports that used analyze_file()
# ----------------------------------------------------------------------
def analyze_file(path: str) -> dict:
    """
    Convenience function kept for backward compatibility.
    Older code could import: from app.prevention.sandbox_engine import analyze_file
    """
    sim = SandboxSimulation()
    return sim.analyze(path)
