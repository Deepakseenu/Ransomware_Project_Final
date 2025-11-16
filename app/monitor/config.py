# app/monitor/config.py
from pathlib import Path
import os

# Base dirs
DEFAULT_OPT = "/opt/honeypot_tools"
FALLBACK_HOME = str(Path.home() / "Ransomware_Project_Final" / "honeypot_data")
BASE_DIR = DEFAULT_OPT if os.access(DEFAULT_OPT, os.W_OK) else FALLBACK_HOME

# Derived paths (can be overridden via env)
LOG_PATH = os.getenv("HP_LOG_PATH", str(Path(BASE_DIR) / "logs" / "events.log"))
BACKUP_DIR = os.getenv("HP_BACKUP_DIR", str(Path(BASE_DIR) / "backup"))
QUARANTINE_DIR = os.getenv("HP_QUARANTINE_DIR", str(Path(BASE_DIR) / "quarantine"))
HONEYPOT_ANALYSIS_DIR = os.getenv("HP_HONEYPOT_ANALYSIS_DIR", str(Path(BASE_DIR) / "honeypot_analysis"))
DECOY_DIR = os.getenv("HP_DECOY_DIR", str(Path(BASE_DIR) / "decoys"))

# Watch configuration
WATCH_DIR = Path(os.getenv("HP_WATCH_DIR", "/var/www/html/college_clone"))
USER_HOME = os.getenv("HP_USER_HOME", str(Path.home()))
MONITORED_FOLDERS = [str(Path(USER_HOME) / d) for d in ["Desktop", "Downloads", "Documents", "Pictures"]]

# Heuristics
WINDOW_SECONDS = int(os.getenv("HP_WINDOW_SECONDS", "6"))
MOD_THRESHOLD = int(os.getenv("HP_MOD_THRESHOLD", "30"))
CREATE_THRESHOLD = int(os.getenv("HP_CREATE_THRESHOLD", "20"))
HIGH_ENTROPY_THRESHOLD = float(os.getenv("HP_HIGH_ENTROPY_THRESHOLD", "7.5"))
YARA_RULE_PATH = os.getenv("HP_YARA_RULE_PATH", str(Path(__file__).resolve().parent.parent / "yara" / "yara_ransom.yar"))

# Access logs to search for correlated IPs
ACCESS_LOG_PATHS = [
    "/var/log/apache2/access.log",
    "/var/log/nginx/access.log",
    "/var/log/httpd/access_log",
]

# Notifications & blocking (use env)
EMAIL_HOST = os.getenv("HP_EMAIL_HOST", "smtp.gmail.com")
EMAIL_PORT = int(os.getenv("HP_EMAIL_PORT", "587"))
EMAIL_USER = os.getenv("HP_EMAIL_USER", "")
EMAIL_PASS = os.getenv("HP_EMAIL_PASS", "")   # IMPORTANT: supply via env
EMAIL_TO = os.getenv("HP_EMAIL_TO", EMAIL_USER or "")
BLOCK_IPS = os.getenv("HP_BLOCK_IPS", "false").lower() in ("1", "true", "yes")
IPINFO_TOKEN = os.getenv("HP_IPINFO_TOKEN", "")

# Dashboard socket
DASHBOARD_URL = os.getenv("HP_DASHBOARD_URL", "http://127.0.0.1:5000")

# Suspicious markers
SUSPICIOUS_EXTS = {'.locked', '.encrypted', '.crypt', '.enc', '.encrypt', '.lock'}
RANSOM_PATTERNS = ['README_DECRYPT', 'HOW_TO_DECRYPT', 'README_DECRYPTION', 'HOW_TO_RECOVER', 'README-FILES']

# Persistence
BLOCKED_PATH = str(Path(BASE_DIR) / "blocked.json")
