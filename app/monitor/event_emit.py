# app/monitor/event_emit.py
"""
Event emitter for monitor -> FastAPI dashboard.

Features:
- normalize_event / emit_normalized / emit_event (NON-DESTRUCTIVE; preserves raw)
- safe_emit() with retries, short timeout, and local JSONL queue fallback
- atomic append to local queue
- flush_local_queue() helper to replay queued events
- backward-compatible API: safe_emit(event_type, payload)
"""

import os
import json
import uuid
import time
import threading
import errno
import logging
from typing import Dict, Any, Optional
from pathlib import Path
from datetime import datetime

import requests

# Use single logger (module-level)
from .logger import logger

# For structured log file (existing project util)
from .config import LOG_PATH

# Alerting
from app.monitor.alerts import trigger_alert

# ----------------------------
# Config
# ----------------------------
DASHBOARD_PUSH_URL = os.environ.get("DASHBOARD_PUSH_URL", "http://127.0.0.1:8000/api/push_event")
POST_TIMEOUT = float(os.environ.get("DASHBOARD_POST_TIMEOUT", "0.25"))
POST_RETRIES = int(os.environ.get("DASHBOARD_POST_RETRIES", "2"))
_QUEUE_FILE = Path(__file__).resolve().parents[2] / "honeypot_events_queue.jsonl"
# Ensure directory exists
try:
    _QUEUE_FILE.parent.mkdir(parents=True, exist_ok=True)
except Exception:
    pass

# ----------------------------
# Helpers
# ----------------------------
def _now_iso() -> str:
    return datetime.utcnow().isoformat() + "Z"

def _atomic_append_jsonl(path: Path, obj: Dict[str, Any]):
    """
    Append JSON line atomically using open(..., 'a') with os.O_APPEND behaviour.
    This is safe for concurrent appenders on POSIX.
    """
    line = json.dumps({"ts_written": time.time(), "event": obj}, separators=(",", ":")) + "\n"
    try:
        # Use low-level os.open to ensure O_APPEND semantics
        import os as _os
        fd = _os.open(str(path), _os.O_CREAT | _os.O_APPEND | _os.O_WRONLY, 0o644)
        try:
            _os.write(fd, line.encode("utf-8"))
        finally:
            _os.close(fd)
    except Exception as e:
        logger.debug(f"[event_emit] failed atomic append to {path}: {e}")
        # fallback naive append
        try:
            with path.open("a", encoding="utf-8") as fh:
                fh.write(line)
        except Exception as ex:
            logger.debug(f"[event_emit] fallback append failed: {ex}")

# ----------------------------
# Local queue: append & flush
# ----------------------------
def _append_to_local_queue(event: Dict[str, Any]):
    try:
        _atomic_append_jsonl(_QUEUE_FILE, event)
        logger.debug(f"[event_emit] queued event locally: {_QUEUE_FILE}")
    except Exception as e:
        logger.debug(f"[event_emit] append_to_local_queue failed: {e}")

def flush_local_queue(max_items: int = 500) -> int:
    """
    Try to resend queued events. Returns number of events successfully sent.
    Keeps any remaining failed lines in the queue file.
    """
    if not _QUEUE_FILE.exists():
        logger.debug("[event_emit] no local queue to flush")
        return 0

    tmp = _QUEUE_FILE.with_suffix(".tmp")
    sent = 0
    try:
        with _QUEUE_FILE.open("r", encoding="utf-8") as src, tmp.open("w", encoding="utf-8") as dst:
            for line in src:
                if sent >= max_items:
                    dst.write(line)
                    continue
                try:
                    rec = json.loads(line)
                    evt = rec.get("event", rec)
                except Exception:
                    dst.write(line)
                    continue

                # attempt POST
                success = False
                try:
                    r = requests.post(DASHBOARD_PUSH_URL, json=evt, timeout=POST_TIMEOUT)
                    if 200 <= r.status_code < 300:
                        success = True
                except Exception as e:
                    logger.debug(f"[event_emit] flush post failed: {e}")

                if not success:
                    dst.write(line)
                else:
                    sent += 1
                    logger.debug(f"[event_emit] flushed queued event (count={sent})")
        tmp.replace(_QUEUE_FILE)
    except Exception as e:
        logger.debug(f"[event_emit] flush_local_queue exception: {e}")
        try:
            if tmp.exists():
                tmp.unlink()
        except Exception:
            pass
        return sent

    return sent

# ----------------------------
# safe_emit: send to dashboard + local log (robust)
# ----------------------------
def safe_emit(event_type: str, payload: Dict[str, Any]) -> Dict[str, Any]:
    """
    Unified emitter. Returns the final event object (with ts).
    Adds retries, short timeout and local queue fallback on failure.
    """
    event_obj = {"type": event_type, **(payload or {})}
    if "ts" not in event_obj:
        event_obj["ts"] = time.time()

    # Attempt transport with retries
    last_exc = None
    try:
        for attempt in range(1, POST_RETRIES + 1):
            try:
                resp = requests.post(DASHBOARD_PUSH_URL, json=event_obj, timeout=POST_TIMEOUT)
                # treat non-2xx as failure
                if 200 <= resp.status_code < 300:
                    break
                else:
                    last_exc = Exception(f"HTTP {resp.status_code}")
            except Exception as e:
                last_exc = e
            # small backoff (non-blocking)
            time.sleep(min(0.02 * attempt, 0.2))
        else:
            # all retries exhausted
            _append_to_local_queue(event_obj)
            logger.warning(f"[safe_emit] dashboard POST failed after {POST_RETRIES} attempts — event queued locally. Last error: {last_exc}")
    except Exception as e:
        logger.debug(f"[safe_emit] unexpected error during post: {e}")
        _append_to_local_queue(event_obj)

    # Always write structured log for forensics (existing behavior)
    try:
        from .utils import write_event_struct
        write_event_struct(LOG_PATH, event_obj)
    except Exception as e:
        logger.debug(f"[safe_emit] write_event_struct failed: {e}")

    return event_obj

# ----------------------------
# start_background_connector (compat)
# ----------------------------
def start_background_connector():
    t = threading.Thread(target=lambda: None, daemon=True)
    t.start()
    return t

# ----------------------------
# High severity helper
# ----------------------------
def emit_high_severity_ransom(details: Dict[str, Any]):
    event = {"type": "ransomware_alert", "action": "detected", "detail": details, "ts": time.time()}
    safe_emit("ransom", event)
    try:
        trigger_alert(f"[RANSOM] Ransomware detected → {details}", {}, level="HIGH")
    except Exception:
        logger.debug("[emit_high_severity_ransom] trigger_alert failed")
    return event

# ----------------------------
# Normalization utilities
# ----------------------------
def normalize_event(raw: Dict[str, Any]) -> Dict[str, Any]:
    fd = raw.get("fd") if isinstance(raw.get("fd"), dict) else {}
    proc = raw.get("process") or raw.get("proc") or raw.get("proc_name") or raw.get("procname")
    pid = raw.get("pid") or raw.get("process_id") or raw.get("proc_pid")
    src_ip = raw.get("src_ip") or fd.get("sip") or raw.get("ip") or raw.get("ip_src")
    dst_ip = raw.get("dst_ip") or fd.get("dip") or raw.get("ip_dst")
    src = raw.get("source") or raw.get("engine") or raw.get("type") or raw.get("source_engine") or "unknown"
    severity = raw.get("severity") or raw.get("level") or raw.get("severity_level") or "INFO"
    category = raw.get("category") or raw.get("event_type") or raw.get("alert_type") or "unknown"

    norm: Dict[str, Any] = {
        "schema_version": "v2",
        "id": raw.get("id") or str(uuid.uuid4()),
        "timestamp": raw.get("timestamp") or _now_iso(),
        "source": src,
        "category": category,
        "severity": severity,
        "message": raw.get("message") or raw.get("msg") or raw.get("detail") or "",
        "file": raw.get("file") or raw.get("filename") or raw.get("path") or raw.get("file_path"),
        "process": proc,
        "pid": pid,
        "ip_src": src_ip,
        "ip_dst": dst_ip,
        "rule": {
            "engine": raw.get("engine") or src,
            "rule_id": raw.get("rule_id") or raw.get("rule") or raw.get("sig_id") or raw.get("rule_name"),
            "raw": raw
        },
        "score": raw.get("score") or None,
        "tags": raw.get("tags") or [],
        "extra": raw.get("extra") or {}
    }
    return norm

def emit_normalized(raw_event: Dict[str, Any], dry_run: bool = False) -> Dict[str, Any]:
    norm = normalize_event(raw_event)
    # numeric severity map
    if isinstance(norm.get("severity"), int):
        sev_map = {0: "INFO", 1: "WARNING", 2: "ERROR", 3: "CRITICAL", 4: "EMERGENCY"}
        norm["severity"] = sev_map.get(norm["severity"], "INFO")
    if dry_run:
        logger.info("[emit_normalized - dry_run] " + json.dumps(norm))
        return norm
    try:
        safe_emit("normalized_event", norm)
    except Exception as e:
        logger.debug(f"[emit_normalized] safe_emit failed: {e}")
        _append_to_local_queue(norm)
    return norm

def emit_event(raw_event: Dict[str, Any], dry_run: bool = False) -> Dict[str, Any]:
    normalize_globally = os.environ.get("NORMALIZE_EVENTS", "false").lower() in ("1", "true", "yes")
    if normalize_globally:
        return emit_normalized(raw_event, dry_run=dry_run)
    else:
        inferred_type = raw_event.get("type") or raw_event.get("event") or raw_event.get("source") or "event"
        payload = raw_event.copy()
        return safe_emit(inferred_type, payload)
