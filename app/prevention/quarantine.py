# app/prevention/quarantine.py

import os
import shutil
from pathlib import Path
from .utils import now_iso, sha256, safe_copy
from .logger import logger
from .config import BACKUP_DIR, QUARANTINE_DIR, DECOY_DIR
from ..monitor.event_emit import safe_emit   # NEW unified events


def create_decoy_at_path(path, reason="decoy"):
    try:
        Path(path).parent.mkdir(parents=True, exist_ok=True)

        with open(path, "w") as f:
            f.write("Decoy placeholder - ransomware isolation.\n")

        os.chmod(path, 0o444)

        safe_emit("quarantine", {
            "action": "decoy_created",
            "detail": {
                "path": path,
                "reason": reason
            }
        })

        return path

    except Exception as e:
        logger.error("decoy creation failed: %s", e)

        safe_emit("quarantine", {
            "action": "decoy_error",
            "detail": {
                "path": path,
                "error": str(e)
            }
        })

        return ""


def backup_and_quarantine(path, reason):
    meta = {
        "path": path,
        "reason": reason,
        "timestamp": now_iso()
    }

    # File missing
    if not os.path.exists(path):
        meta["error"] = "file_missing"

        safe_emit("quarantine", {
            "action": "file_missing",
            "detail": meta
        })

        return meta

    try:
        Path(BACKUP_DIR).mkdir(parents=True, exist_ok=True)
        Path(QUARANTINE_DIR).mkdir(parents=True, exist_ok=True)

        # ----------------------------------------------------
        # Backup original
        # ----------------------------------------------------
        backup_file = safe_copy(path, BACKUP_DIR)
        meta["backup_file"] = backup_file
        meta["sha256"] = sha256(path)

        safe_emit("quarantine", {
            "action": "backup_created",
            "detail": {
                "path": path,
                "backup_file": backup_file,
                "sha256": meta["sha256"]
            }
        })

        # ----------------------------------------------------
        # Put file in quarantine
        # ----------------------------------------------------
        quarantine_copy = safe_copy(path, QUARANTINE_DIR)
        meta["quarantine"] = quarantine_copy

        safe_emit("quarantine", {
            "action": "quarantined_copy",
            "detail": {
                "path": path,
                "quarantine_file": quarantine_copy
            }
        })

        # ----------------------------------------------------
        # Remove original file
        # ----------------------------------------------------
        try:
            os.remove(path)
        except Exception:
            pass

        # Replace with decoy
        create_decoy_at_path(path, reason=reason)
        meta["status"] = "quarantined"

        safe_emit("quarantine", {
            "action": "completed",
            "detail": meta
        })

    except Exception as e:
        meta["error"] = str(e)

        safe_emit("quarantine", {
            "action": "error",
            "detail": {
                "path": path,
                "error": str(e)
            }
        })

    return meta
