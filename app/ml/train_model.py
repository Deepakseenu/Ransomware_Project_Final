# ml/train_model.py

import os
import joblib
import pandas as pd
from pathlib import Path
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import LabelEncoder

PROJECT_ROOT = Path(__file__).resolve().parents[1]

TRAIN_DATA = PROJECT_ROOT / "training_data" / "training_data.csv"
MODEL_DIR = PROJECT_ROOT / "app" / "models"
MODEL_PATH = MODEL_DIR / "ransomware_model.pkl"
ENCODER_PATH = MODEL_DIR / "filetype_encoder.pkl"

os.makedirs(MODEL_DIR, exist_ok=True)

df = pd.read_csv(TRAIN_DATA)

# Encode extension
ext_encoder = LabelEncoder()
df["ext_enc"] = ext_encoder.fit_transform(df["ext"])

X = df[["ext_enc", "entropy", "size", "is_suspicious_ext"]]
y = df["label"]

clf = RandomForestClassifier(
    n_estimators=200,
    random_state=42,
    class_weight="balanced"
)
clf.fit(X, y)

joblib.dump(clf, MODEL_PATH)
joblib.dump(ext_encoder, ENCODER_PATH)

print(f"[OK] Model saved to {MODEL_PATH}")
print(f"[OK] Encoder saved to {ENCODER_PATH}")
