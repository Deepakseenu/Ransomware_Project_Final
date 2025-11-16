# app/models/loader.py

import os
import joblib

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
MODEL_DIR = os.path.join(BASE_DIR, "models")

MODEL_PATH = os.path.join(MODEL_DIR, "ransomware_model.pkl")
ENCODER_PATH = os.path.join(MODEL_DIR, "filetype_encoder.pkl")


def load_model():
    """Load the ML model from disk."""
    if not os.path.exists(MODEL_PATH):
        raise FileNotFoundError(f"ML model file missing: {MODEL_PATH}")
    return joblib.load(MODEL_PATH)


def load_encoder():
    """Load the filetype encoder."""
    if not os.path.exists(ENCODER_PATH):
        raise FileNotFoundError(f"Encoder file missing: {ENCODER_PATH}")
    return joblib.load(ENCODER_PATH)


def load_model_and_encoder():
    """Convenience helper returning (model, encoder)."""
    return load_model(), load_encoder()
