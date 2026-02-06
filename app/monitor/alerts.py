# app/monitor/alerts.py
import json
import smtplib
from pathlib import Path
from email.mime.text import MIMEText
from datetime import datetime

ALERT_LOG = Path("logs/alerts.log")
ALERT_LOG.parent.mkdir(exist_ok=True)

def log_alert(message: str, level="HIGH"):
    """Write alert to a dedicated alert log."""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open(ALERT_LOG, "a") as f:
        f.write(f"{timestamp} [{level}] {message}\n")


def console_alert(message: str):
    print(f"\n⚠️ ALERT: {message}\n")


def email_alert(message: str, cfg: dict, level="HIGH"):
    """Send an email alert using SMTP."""
    try:
        msg = MIMEText(message)
        msg["Subject"] = f"[{level}] Ransomware Alert Triggered"
        msg["From"] = cfg["from"]
        msg["To"] = cfg["to"]

        with smtplib.SMTP(cfg["server"], cfg["port"]) as server:
            if cfg.get("tls"):
                server.starttls()

            if cfg.get("username"):
                server.login(cfg["username"], cfg["password"])

            server.send_message(msg)

    except Exception as e:
        log_alert(f"Email alert failed: {e}", level="ERROR")


def trigger_alert(message: str, config=None, level="HIGH"):
    """
    Central alert dispatcher.
    Called by ANY suspicious event in monitoring/prevention.
    """
    console_alert(message)
    log_alert(message, level=level)

    if isinstance(config, dict) and config.get("email_enabled"):
        email_alert(message, config["email"], level=level)
