# ransomware-like behavior
import base64

FILE = "test_files/report.pdf"

with open(FILE, "rb") as f:
    data = base64.b64encode(f.read())

with open(FILE, "wb") as f:
    f.write(data)
