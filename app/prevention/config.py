import os
from pathlib import Path

# Base directory for honeypot/prevention storage
BASE_DIR = os.getenv("HP_BASE_DIR", str(Path.home() / "Ransomware_Project_Final" / "honeypot_data"))

# Directories to completely exclude from FileGuard scanning
EXCLUDE_DIRS = [
    "/home/deepak/.cache",
    "/home/deepak/.mozilla",
    "/home/deepak/.local/share/Trash",
    "/home/deepak/.config",
    "/home/deepak/.local",
]

# Core directories
BACKUP_DIR = os.getenv("HP_BACKUP_DIR", str(Path(BASE_DIR) / "backup"))
QUARANTINE_DIR = os.getenv("HP_QUARANTINE_DIR", str(Path(BASE_DIR) / "quarantine"))
DECOY_DIR = os.getenv("HP_DECOY_DIR", str(Path(BASE_DIR) / "decoys"))
LOG_PATH = os.getenv("HP_PREVENTION_LOG", str(Path(BASE_DIR) / "logs" / "prevention.log"))

# FileGuard configuration
INTEGRITY_INTERVAL = int(os.getenv("HP_INTEGRITY_INTERVAL", "20"))
MASS_CHANGE_THRESHOLD = int(os.getenv("HP_MASS_CHANGE_THRESHOLD", "8"))
BASELINE_PATH = os.getenv("HP_BASELINE", str(Path(BASE_DIR) / "baseline_checksums.json"))

# ProcessGuard thresholds
CPU_SPIKE_THRESHOLD = float(os.getenv("HP_CPU_SPIKE", "80.0"))
MEM_SPIKE_THRESHOLD = float(os.getenv("HP_MEM_SPIKE", "80.0"))

# NetGuard settings
DASHBOARD_URL = os.getenv("HP_DASHBOARD_URL", "http://127.0.0.1:5000")
BLOCKED_FILE = os.getenv("HP_BLOCKED_FILE", str(Path(BASE_DIR) / "blocked.json"))
AUTOBLOCK_ENABLED = os.getenv("HP_AUTOBLOCK", "false").lower() in ("true", "1", "yes")
IPTABLES_CMD = os.getenv("HP_IPTABLES_CMD", "/usr/sbin/iptables")

# Sandbox Analyzer
YARA_RULE_PATH = os.getenv(
    "HP_YARA_RULE_PATH",
    str(Path(__file__).resolve().parent.parent / "yara" / "yara_ransom.yar")
)
ENTROPY_THRESHOLD = float(os.getenv("HP_ENTROPY_THRESHOLD", "7.5"))
