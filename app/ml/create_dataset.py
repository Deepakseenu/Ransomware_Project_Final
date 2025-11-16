# ml/create_dataset.py
import os
import pandas as pd
from pathlib import Path
from feature_extractor import extract_features

PROJECT_ROOT = Path(__file__).resolve().parents[1]
TRAINING_DATA = PROJECT_ROOT / "training_data" / "training_data.csv"

os.makedirs(TRAINING_DATA.parent, exist_ok=True)

# Example dataset (replace with real samples later)
seed_rows = [
    extract_features("sample1.txt", label="benign"),
    extract_features("invoice.docx", label="benign"),
    extract_features("encryptor.exe", label="ransomware"),
    extract_features("paynote.locked", label="ransomware"),
]

df = pd.DataFrame(seed_rows)
df.to_csv(TRAINING_DATA, index=False)

print(f"[OK] Training dataset created at {TRAINING_DATA}")
