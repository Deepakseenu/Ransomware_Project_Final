import os
import time

TARGET = "/home/deepak/Desktop/test_files"

print("[SIM] Starting mass modification test...")

for root, dirs, files in os.walk(TARGET):
    for f in files:
        path = os.path.join(root, f)
        print("[SIM] touching:", path)
        with open(path, "a") as fp:
            fp.write("\nSIMULATED CHANGE\n")
        time.sleep(0.1)

print("[SIM] Done. This should trigger detection.")
