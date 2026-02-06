import time
import os

TEST_DIR = "test_files"
ENCRYPTED_DIR = "encrypted_sim"

os.makedirs(ENCRYPTED_DIR, exist_ok=True)

print("[SIM] Starting fake ransomware simulation...")
time.sleep(1)

for root, dirs, files in os.walk(TEST_DIR):
    for f in files:
        old_path = os.path.join(root, f)
        new_path = os.path.join(ENCRYPTED_DIR, f + ".encrypted_sim")
        print(f"[SIM] Pretending to encrypt: {old_path}")
        with open(old_path, "rb") as infile:
            data = infile.read()

        # Just copy the file, DO NOT encrypt
        with open(new_path, "wb") as outfile:
            outfile.write(data)

print("[SIM] Simulation completed. No real encryption done.")
