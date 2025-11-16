#!/usr/bin/env python3
"""
app.py - Dashboard backend (Hybrid: balanced)
- Flask + Flask-SocketIO server
- Tailer that reads structured events from events.log
- Real-time Socket.IO broadcast of events
- Events history sampler for charts
- Endpoints:
    /api/events                 - latest events (JSON)
    /api/events_history         - time-series samples
    /api/backups                - list backup files
    /api/quarantine_list        - list quarantined files
    /api/blocked_ips            - blocked IPs list
    /api/block_ip               - POST {ip,reason}
    /api/unblock_ip             - POST {ip}
    /api/map_data               - blocked IPs (geo) for map visualization
    /api/system_health          - cpu/memory/uptime
    /api/process_list           - process list
    /api/kill_process           - POST {pid,signal}
    /api/network_stats          - network IO counters
    /api/stats_summary          - small aggregated stats
    /api/live_status            - small live payload for dashboard cards
    /api/top_ips                - aggregated top IPs (blocked + optional logs)
    /api/predict                - optional ML prediction for a file path
- Resilient: safe JSON parsing, fallbacks for iptables, geolookup best-effort.
"""

from __future__ import annotations
import argparse
import json
import logging
import os
import shutil
import threading
import time
import subprocess
import signal
from collections import deque, Counter
from datetime import datetime, timezone
from typing import Optional, Dict, Any, List

# Third-party imports
from flask import Flask, request, render_template
from flask import jsonify as _jsonify  # small helper
from flask_socketio import SocketIO, emit
import psutil
import requests

# Try to import ML predict helper if available
ML_PREDICT_AVAILABLE = False
try:
    # prefer the app-level ml module (app/ml/model_predict.py)
    from ml.model_predict import predict_ransomware  # type: ignore
    ML_PREDICT_AVAILABLE = True
except Exception:
    try:
        # or fallback to app.models.loader usage (will require model loader)
        from models.loader import load_model, load_encoder  # type: ignore
        ML_PREDICT_AVAILABLE = True
    except Exception:
        ML_PREDICT_AVAILABLE = False

# ---------------------------
# Base directories (hybrid)
# ---------------------------
DEFAULT_OPT = "/opt/honeypot_tools"
# Use same fallback home as your structure
FALLBACK_HOME = os.path.expanduser("~/Ransomware_Project_Final/honeypot_data")
BASE_DIR = DEFAULT_OPT if os.access(DEFAULT_OPT, os.W_OK) else FALLBACK_HOME

LOG_DIR = os.path.join(BASE_DIR, "logs")
QUARANTINE_DIR = os.path.join(BASE_DIR, "quarantine")
BACKUP_DIR = os.path.join(BASE_DIR, "backup")
HONEYPOT_ANALYSIS_DIR = os.path.join(BASE_DIR, "honeypot_analysis")
BLOCKED_FILE = os.path.join(BASE_DIR, "blocked.json")
LOG_FILE_DEFAULT = os.path.join(LOG_DIR, "events.log")

# ensure dirs
for d in [LOG_DIR, QUARANTINE_DIR, BACKUP_DIR, HONEYPOT_ANALYSIS_DIR, os.path.dirname(BLOCKED_FILE)]:
    try:
        os.makedirs(d, exist_ok=True)
    except Exception:
        pass

# ---------------------------
# Logging config
# ---------------------------
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("dashboard")

# ---------------------------
# Flask + SocketIO init
# ---------------------------
app = Flask(__name__, template_folder="templates", static_folder="static")
app.config["SECRET_KEY"] = os.environ.get("FLASK_SECRET", "change-me")
socketio = SocketIO(
    app,
    cors_allowed_origins="*",
    async_mode="threading",    # <---- required fix
    logger=False,
    engineio_logger=False
)


# ---------------------------
# Globals
# ---------------------------
MAX_RECENT = int(os.environ.get("MAX_RECENT_EVENTS", "2000"))
TAIL_POLL = float(os.environ.get("TAIL_POLL", "1.0"))
recent_events: deque = deque(maxlen=MAX_RECENT)
recent_lock = threading.Lock()
tailer_thread = None

SAMPLE_INTERVAL = float(os.environ.get("SAMPLE_INTERVAL", "5.0"))
HISTORY_MAX = int(os.environ.get("HISTORY_MAX", "200"))
events_history: deque = deque(maxlen=HISTORY_MAX)
events_history_lock = threading.Lock()

# iptables command (may differ per system)
IPTABLES_CMD = os.environ.get("IPTABLES_CMD", "/usr/sbin/iptables")

# small whitelist for kill safety - comma separated process basenames allowed
KILL_PROCESS_ALLOWED = os.environ.get("KILL_PROCESS_ALLOWED", "").split(",") if os.environ.get("KILL_PROCESS_ALLOWED") else []

# ---------------------------
# Utilities
# ---------------------------
def now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()

def safe_json_response(data: Any, status: int = 200):
    try:
        return app.response_class(response=json.dumps(data, indent=2, default=str), status=status, mimetype="application/json")
    except Exception:
        return _jsonify({"error": "serialization_error"}), 500

def safe_parse_json_line(line: str) -> dict:
    try:
        return json.loads(line)
    except Exception:
        return {"raw": line.strip(), "ts": now_iso()}

def load_blocked() -> Dict[str, dict]:
    try:
        if os.path.exists(BLOCKED_FILE):
            with open(BLOCKED_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
                if isinstance(data, dict):
                    return data
                if isinstance(data, list):
                    return {x.get("ip"): x for x in data if isinstance(x, dict) and "ip" in x}
    except Exception as e:
        logger.warning("load_blocked failed: %s", e)
    return {}

def save_blocked(data: Dict[str, dict]) -> bool:
    try:
        with open(BLOCKED_FILE, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, default=str)
        return True
    except Exception as e:
        logger.warning("save_blocked failed: %s", e)
        return False

# ---------------------------
# Tailer - reads events.log and broadcasts
# ---------------------------
class JSONTailer(threading.Thread):
    def __init__(self, path: str, poll: float = 1.0):
        super().__init__(daemon=True)
        self.path = path
        self.poll = poll
        self._stop = threading.Event()
        self.pos = 0

    def run(self):
        logger.info("Tailer starting for %s", self.path)
        # start at end
        try:
            if os.path.exists(self.path):
                with open(self.path, "r", errors="replace") as fh:
                    fh.seek(0, os.SEEK_END)
                    self.pos = fh.tell()
        except Exception as e:
            logger.debug("Tailer init error: %s", e)

        while not self._stop.is_set():
            try:
                if not os.path.exists(self.path):
                    time.sleep(self.poll)
                    continue
                with open(self.path, "r", errors="replace") as fh:
                    fh.seek(self.pos)
                    for line in fh:
                        self.pos = fh.tell()
                        ev = safe_parse_json_line(line)
                        with recent_lock:
                            recent_events.append(ev)
                        # update events history sample
                        with events_history_lock:
                            if events_history:
                                events_history[-1]["count"] += 1
                            else:
                                events_history.append({"ts": now_iso(), "count": 1})
                        # emit to clients
                        try:
                            socketio.emit("new_event", ev, namespace="/")
                        except Exception:
                            logger.debug("socket emit failed")
            except Exception as e:
                logger.debug("tailer loop error: %s", e)
            time.sleep(self.poll)

    def stop(self):
        self._stop.set()

def start_tailer(log_path: str):
    global tailer_thread
    if tailer_thread and tailer_thread.is_alive():
        return
    tailer_thread = JSONTailer(log_path, poll=TAIL_POLL)
    tailer_thread.start()

# ---------------------------
# Events sampler thread - produces time buckets
# ---------------------------
class EventsSampler(threading.Thread):
    def __init__(self, interval: float = SAMPLE_INTERVAL):
        super().__init__(daemon=True)
        self.interval = interval
        self._stop = threading.Event()

    def run(self):
        logger.info("EventsSampler started (interval=%s)", self.interval)
        while not self._stop.is_set():
            with events_history_lock:
                events_history.append({"ts": now_iso(), "count": 0})
            time.sleep(self.interval)

    def stop(self):
        self._stop.set()

events_sampler = EventsSampler(SAMPLE_INTERVAL)

# ---------------------------
# Helper: preload last N events into recent_events
# ---------------------------
def preload_events(log_path: str, limit: int = 500):
    try:
        if os.path.exists(log_path):
            with open(log_path, "r", errors="replace") as fh:
                lines = fh.read().splitlines()[-limit:]
            for ln in lines:
                ev = safe_parse_json_line(ln)
                with recent_lock:
                    recent_events.append(ev)
    except Exception as e:
        logger.warning("preload_events failed: %s", e)

# ---------------------------
# API endpoints
# ---------------------------
@app.route("/")
def index():
    # basic template - frontend should be in templates/dashboard.html
    try:
        return render_template("dashboard.html")
    except Exception:
        return "<h3>Honeypot Dashboard</h3><p>Frontend missing.</p>"

@app.route("/api/events")
def api_events():
    with recent_lock:
        # newest-first
        data = list(reversed(list(recent_events)))[:1000]
    return safe_json_response(data)

@app.route("/api/events_history")
def api_events_history():
    with events_history_lock:
        hist = list(events_history)
    return safe_json_response(hist)

@app.route("/api/backups")
def api_backups():
    files: List[str] = []
    for root, _, fnames in os.walk(BACKUP_DIR):
        for f in fnames:
            files.append(os.path.join(root, f))
    files.sort(key=lambda p: os.path.getmtime(p) if os.path.exists(p) else 0, reverse=True)
    return safe_json_response(files)

@app.route("/api/quarantine_list")
def api_quarantine_list():
    files: List[str] = []
    for root, _, fnames in os.walk(QUARANTINE_DIR):
        for f in fnames:
            files.append(os.path.join(root, f))
    files.sort(key=lambda p: os.path.getmtime(p) if os.path.exists(p) else 0, reverse=True)
    return safe_json_response(files)

# compatibility aliases
@app.route("/api/list_backup")
def api_list_backup():
    return api_backups()

@app.route("/api/list_quarantine")
def api_list_quarantine():
    return api_quarantine_list()

@app.route("/api/blocked_ips")
def api_blocked_ips():
    blocked = load_blocked()
    entries = list(blocked.values())
    entries.sort(key=lambda x: x.get("last_blocked", ""), reverse=True)
    return safe_json_response(entries)

@app.route("/api/block_ip", methods=["POST"])
def api_block_ip():
    try:
        body = request.get_json(force=True, silent=True) or {}
        ip = body.get("ip")
        reason = body.get("reason", "manual")
        if not ip:
            return safe_json_response({"error": "missing ip"}, 400)

        blocked = load_blocked()
        entry = blocked.get(ip, {})
        entry.update({
            "ip": ip,
            "reason": reason,
            "last_blocked": now_iso(),
            "first_blocked": entry.get("first_blocked") or now_iso()
        })

        # try geo lookup best-effort
        try:
            r = requests.get(f"https://ipinfo.io/{ip}/json", timeout=3)
            if r.status_code == 200:
                entry["geo"] = r.json()
        except Exception:
            pass

        blocked[ip] = entry
        save_blocked(blocked)

        # try to apply iptables (best-effort)
        try:
            if shutil.which(IPTABLES_CMD):
                subprocess.run([IPTABLES_CMD, "-A", "INPUT", "-s", ip, "-j", "DROP"], capture_output=True, check=False)
        except Exception:
            pass

        ev = {"type": "block_ip", "ip": ip, "reason": reason, "ts": now_iso()}
        with recent_lock:
            recent_events.append(ev)
        try:
            socketio.emit("new_event", ev, namespace="/")
        except Exception:
            pass
        return safe_json_response({"status": "blocked", "ip": ip})
    except Exception as e:
        logger.exception("api_block_ip")
        return safe_json_response({"error": str(e)}, 500)

@app.route("/api/unblock_ip", methods=["POST"])
def api_unblock_ip():
    try:
        body = request.get_json(force=True, silent=True) or {}
        ip = body.get("ip")
        if not ip:
            return safe_json_response({"error": "missing ip"}, 400)
        blocked = load_blocked()
        if ip in blocked:
            blocked.pop(ip, None)
            save_blocked(blocked)
            # remove iptables DROP (best-effort)
            try:
                if shutil.which(IPTABLES_CMD):
                    subprocess.run([IPTABLES_CMD, "-D", "INPUT", "-s", ip, "-j", "DROP"], capture_output=True, check=False)
            except Exception:
                pass
            ev = {"type": "unblock_ip", "ip": ip, "ts": now_iso()}
            with recent_lock:
                recent_events.append(ev)
            try:
                socketio.emit("new_event", ev, namespace="/")
            except Exception:
                pass
            return safe_json_response({"status": "unblocked", "ip": ip})
        return safe_json_response({"error": "ip_not_found"}, 404)
    except Exception as e:
        logger.exception("api_unblock_ip")
        return safe_json_response({"error": str(e)}, 500)

@app.route("/api/map_data")
def api_map_data():
    try:
        blocked = load_blocked()
        out = []
        for ip, info in blocked.items():
            geo = info.get("geo") or {}
            lat = lon = None
            if isinstance(geo, dict):
                if "loc" in geo:
                    try:
                        lat, lon = geo["loc"].split(",")
                    except Exception:
                        pass
                # fallback keys
                lat = lat or geo.get("latitude")
                lon = lon or geo.get("longitude")
            out.append({
                "ip": ip,
                "last_blocked": info.get("last_blocked"),
                "city": geo.get("city") if isinstance(geo, dict) else None,
                "region": geo.get("region") if isinstance(geo, dict) else None,
                "country": geo.get("country") if isinstance(geo, dict) else None,
                "lat": lat,
                "lon": lon
            })
        return safe_json_response(out)
    except Exception as e:
        logger.exception("api_map_data")
        return safe_json_response({"error": str(e)}, 500)

# ---------------------------
# System & Process APIs
# ---------------------------
@app.route("/api/system_health")
def api_system_health():
    try:
        cpu = psutil.cpu_percent(interval=0.1)
        mem = psutil.virtual_memory().percent
        uptime = time.time() - psutil.boot_time()
        return safe_json_response({"cpu": cpu, "memory": mem, "uptime": round(uptime, 1)})
    except Exception as e:
        return safe_json_response({"error": str(e)}, 500)

@app.route("/api/process_list")
def api_process_list():
    try:
        procs = []
        for p in psutil.process_iter(attrs=["pid", "name", "username"]):
            info = p.info
            try:
                info["cpu_percent"] = p.cpu_percent(interval=None)
            except Exception:
                info["cpu_percent"] = 0.0
            try:
                info["memory_percent"] = p.memory_percent()
            except Exception:
                info["memory_percent"] = 0.0
            procs.append(info)
        procs.sort(key=lambda x: x.get("cpu_percent", 0.0), reverse=True)
        return safe_json_response(procs[:200])
    except Exception as e:
        return safe_json_response({"error": str(e)}, 500)

@app.route("/api/kill_process", methods=["POST"])
def api_kill_process():
    """
    POST JSON: {"pid": 1234, "signal": "TERM" }  signal optional (TERM or KILL)
    Safety: requires PROC whitelist OR KILL_PROCESS_ALLOWED configured.
    """
    try:
        body = request.get_json(force=True, silent=True) or {}
        pid = int(body.get("pid") or 0)
        sig = body.get("signal", "TERM").upper()
        if pid <= 0:
            return safe_json_response({"error": "invalid pid"}, 400)
        try:
            proc_name = psutil.Process(pid).name()
        except Exception:
            return safe_json_response({"error": "process_not_found"}, 404)

        allowed = False
        if KILL_PROCESS_ALLOWED and proc_name in KILL_PROCESS_ALLOWED:
            allowed = True
        # If no whitelist configured, basic safety checks
        if not KILL_PROCESS_ALLOWED:
            if pid in (0, 1) or proc_name.lower() in ("systemd", "kthreadd", "kworker"):
                return safe_json_response({"error": "forbidden"}, 403)
            allowed = True

        if not allowed:
            return safe_json_response({"error": "not_allowed"}, 403)

        signum = signal.SIGTERM if sig == "TERM" else signal.SIGKILL
        os.kill(pid, signum)
        ev = {"type": "process_kill", "pid": pid, "proc_name": proc_name, "signal": sig, "ts": now_iso()}
        with recent_lock:
            recent_events.append(ev)
        try:
            socketio.emit("new_event", ev, namespace="/")
        except Exception:
            pass
        return safe_json_response({"status": "killed", "pid": pid, "proc_name": proc_name})
    except Exception as e:
        logger.exception("api_kill_process")
        return safe_json_response({"error": str(e)}, 500)

@app.route("/api/network_stats")
def api_network_stats():
    try:
        stats = psutil.net_io_counters(pernic=False)
        return safe_json_response({
            "bytes_sent": stats.bytes_sent,
            "bytes_recv": stats.bytes_recv,
            "packets_sent": stats.packets_sent,
            "packets_recv": stats.packets_recv
        })
    except Exception as e:
        return safe_json_response({"error": str(e)}, 500)

@app.route("/api/stats_summary")
def api_stats_summary():
    try:
        blocked = load_blocked()
        q_files = sum(len(fnames) for _, _, fnames in os.walk(QUARANTINE_DIR))
        b_files = sum(len(fnames) for _, _, fnames in os.walk(BACKUP_DIR))
        with recent_lock:
            total_events = len(recent_events)
            latest = list(reversed(list(recent_events)))[:20]
        ip_counts = []
        try:
            ips = list(load_blocked().keys())
            ip_counts = [{"ip": ip, **load_blocked().get(ip, {})} for ip in ips]
        except Exception:
            ip_counts = []
        return safe_json_response({
            "total_events": total_events,
            "recent_events_sample": latest,
            "blocked_ips": len(blocked),
            "top_ips": ip_counts[:10],
            "quarantine_count": q_files,
            "backup_count": b_files
        })
    except Exception as e:
        return safe_json_response({"error": str(e)}, 500)

@app.route("/api/live_status")
def api_live_status():
    try:
        blocked = load_blocked()
        cpu = psutil.cpu_percent(interval=0.05)
        mem = psutil.virtual_memory().percent
        uptime = time.time() - psutil.boot_time()
        with recent_lock:
            recent = len(recent_events)
        with events_history_lock:
            hist = list(events_history)[-12:]
        return safe_json_response({
            "cpu": cpu,
            "memory": mem,
            "blocked_ips": len(blocked),
            "recent_events": recent,
            "uptime": round(uptime, 1),
            "events_history_sample": hist
        })
    except Exception as e:
        return safe_json_response({"error": str(e)}, 500)

@app.route("/api/top_ips")
def api_top_ips():
    try:
        blocked = load_blocked()
        counts = Counter()
        for ip, info in blocked.items():
            counts[ip] += 1
        scan_logs = request.args.get("scan_logs", "false").lower() in ("1", "true", "yes")
        if scan_logs:
            paths = ["/var/log/apache2/access.log", "/var/log/nginx/access.log", "/var/log/httpd/access_log"]
            for p in paths:
                try:
                    if os.path.exists(p):
                        with open(p, "r", errors="ignore") as f:
                            for ln in f:
                                parts = ln.split()
                                if parts:
                                    counts[parts[0]] += 1
                except Exception:
                    continue
        top = [{"ip": ip, "count": cnt, "meta": blocked.get(ip)} for ip, cnt in counts.most_common(25)]
        return safe_json_response(top)
    except Exception as e:
        logger.exception("api_top_ips")
        return safe_json_response({"error": str(e)}, 500)

# ---------------------------
# ML Predict endpoint (optional)
# ---------------------------
@app.route("/api/predict", methods=["POST"])
def api_predict():
    """
    POST JSON: {"path": "/full/path/to/file"} or {"name": "filename"}.
    If ML is not available, returns ml_available: False.
    """
    try:
        body = request.get_json(force=True, silent=True) or {}
        path = body.get("path") or body.get("name")
        if not path:
            return safe_json_response({"error": "missing path"}, 400)
        if not ML_PREDICT_AVAILABLE:
            return safe_json_response({"ml_available": False, "error": "ml_not_loaded"}, 200)
        try:
            # prefer the ml.model_predict.predict_ransomware if available
            if "predict_ransomware" in globals():
                result = globals()["predict_ransomware"](path)  # type: ignore
                return safe_json_response(result)
            # fallback: try to use models.loader to load & run a simple predict (if implemented)
            model = None
            encoder = None
            try:
                model = load_model()  # type: ignore
                encoder = load_encoder()  # type: ignore
            except Exception:
                model = None
            if model is None:
                return safe_json_response({"ml_available": False, "error": "model_not_loaded"}, 200)
            # Simple feature: extension + size + 0 entropy (monitor should provide better features)
            ext = os.path.splitext(path)[1] if isinstance(path, str) else ""
            size = os.path.getsize(path) if os.path.exists(path) else 0
            try:
                ext_enc = encoder.transform([ext])[0]
            except Exception:
                ext_enc = 0
            X = [[ext_enc, 0.0, size, 1 if ext in (".enc", ".locked", ".crypt") else 0]]
            pred = model.predict(X)[0]
            probs = None
            try:
                probs = model.predict_proba(X)[0].max()
            except Exception:
                probs = None
            return safe_json_response({"prediction": pred, "confidence": probs, "ml_available": True})
        except Exception as e:
            logger.exception("predict failed")
            return safe_json_response({"error": str(e)}, 500)
    except Exception as e:
        logger.exception("api_predict")
        return safe_json_response({"error": str(e)}, 500)

# ---------------------------
# SocketIO handlers
# ---------------------------
@socketio.on("connect")
def on_connect():
    logger.info("Socket client connected")
    with recent_lock:
        # send a short burst of recent events
        for e in list(recent_events)[-100:]:
            try:
                emit("new_event", e)
            except Exception:
                pass

@socketio.on("new_event")
def on_new_event(data):
    try:
        # allow clients to post events (persisted by monitor usually)
        with recent_lock:
            recent_events.append(data)
        try:
            socketio.emit("new_event", data, broadcast=True)
        except Exception:
            pass
    except Exception:
        logger.exception("on_new_event")

# ---------------------------
# Runner
# ---------------------------
def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", default=5000, type=int)
    parser.add_argument("--log", default=LOG_FILE_DEFAULT, help="path to events.log (tailer)")
    parser.add_argument("--no-tailer", action="store_true", help="do not start the log tailer")
    args = parser.parse_args()

    log_path = args.log

    # preload last events
    preload_events(log_path, limit=500)

    # start tailer and sampler unless disabled
    if not args.no_tailer:
        start_tailer(log_path)
        try:
            events_sampler.start()
        except RuntimeError:
            pass

    logger.info("Dashboard running on %s:%s (log=%s)", args.host, args.port, log_path)
    # choose the best async mode available (socketio picks)
    socketio.run(app, host=args.host, port=args.port, debug=False)

if __name__ == "__main__":
    # default startup when double-clicked
    start_tailer(LOG_FILE_DEFAULT)
    try:
        events_sampler.start()
    except Exception:
        pass
    socketio.run(app, host="0.0.0.0", port=5000, debug=True)
