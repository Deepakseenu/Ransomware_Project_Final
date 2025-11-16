# ml/model_predict.py
import os
import joblib
from pathlib import Path
from feature_extractor import extract_features

PROJECT_ROOT = Path(__file__).resolve().parents[1]
MODEL_PATH = PROJECT_ROOT / "app" / "models" / "ransomware_model.pkl"
ENCODER_PATH = PROJECT_ROOT / "app" / "models" / "filetype_encoder.pkl"

clf = None
ext_encoder = None

if MODEL_PATH.exists():
    clf = joblib.load(MODEL_PATH)
    ext_encoder = joblib.load(ENCODER_PATH)

def predict_ransomware(path):
    if not clf:
        return {"ml_available": False}

    feat = extract_features(path)
    ext_enc = ext_encoder.transform([feat["ext"]])[0]

    X = [[
        ext_enc,
        feat["entropy"],
        feat["size"],
        feat["is_suspicious_ext"],
    ]]

    pred = clf.predict(X)[0]
    prob = clf.predict_proba(X)[0].max()

    return {
        "prediction": pred,
        "confidence": round(prob, 3),
        "features": feat,
        "ml_available": True,
    }
