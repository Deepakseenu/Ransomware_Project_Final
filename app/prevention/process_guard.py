# app/prevention/process_guard.py
"""
Robust ProcessGuard with safer defaults:
 - default = DRY-RUN (no suspend/terminate) unless HP_PROC_FORCE_ACTION=1
 - skip acting on processes owned by same user as monitor (configurable)
 - improved logging + clearer safe_emit messages
 - preserves existing configuration constants and behavior if explicitly enabled
"""

import os
import time
import threading
from collections import deque, defaultdict
from typing import Deque, Dict, Tuple, Optional
import psutil
import getpass
from app.prevention.logger import logger

# Avoid circular import of logger above (some projects also import logger locally)
try:
    from .logger import logger as _local_logger
    if _local_logger:
        logger = _local_logger
except Exception:
    pass

from ..monitor.event_emit import safe_emit

# --- ALERT CONFIG ---
from pathlib import Path
import json
from app.monitor.alerts import trigger_alert

_cfg_path = Path(__file__).resolve().parents[2] / "config" / "alert_config.json"
try:
    with open(_cfg_path, "r") as _f:
        ALERT_CONFIG = json.load(_f)
except Exception:
    ALERT_CONFIG = {}

# ---------------------------------------------------------
# Import config (fallback defaults)
try:
    from .config import (
        PROC_SUSTAINED_SAMPLES,
        PROC_COOLDOWN,
        PROC_SAMPLE_INTERVAL,
        PROC_TERMINATE,
        PROC_WHITELIST,
    )
except Exception:
    PROC_SUSTAINED_SAMPLES = 3
    PROC_COOLDOWN = 60
    PROC_SAMPLE_INTERVAL = 1.0
    PROC_TERMINATE = False
    PROC_WHITELIST = ""

# Environment toggles (safe defaults)
# If HP_PROC_FORCE_ACTION == "1" then allow suspend/terminate according to PROC_TERMINATE
HP_PROC_FORCE_ACTION = os.getenv("HP_PROC_FORCE_ACTION", "0") == "1"
# Dry-run mode: do not perform suspend/terminate; emit "would_*" actions instead.
HP_PROC_DRY_RUN = os.getenv("HP_PROC_DRY_RUN", "1").strip().lower() not in ("0", "false", "no")
# Option: skip acting on processes owned by the same user running the monitor.
HP_PROC_SKIP_OWN = os.getenv("HP_PROC_SKIP_OWN", "1").strip().lower() not in ("0", "false", "no")

CPU_SPIKE_THRESHOLD = float(os.getenv("HP_CPU_SPIKE", "80.0"))
MEM_SPIKE_THRESHOLD = float(os.getenv("HP_MEM_SPIKE", "80.0"))

SUSTAINED_SAMPLES = int(PROC_SUSTAINED_SAMPLES or 3)
COOLDOWN_SECONDS = float(PROC_COOLDOWN or 60.0)
SAMPLE_INTERVAL = float(PROC_SAMPLE_INTERVAL or 1.0)
TERMINATE_ON_DETECT_DEFAULT = bool(PROC_TERMINATE)

# ---------------------------------------------------------
# WHITELIST
_DEFAULT_WHITELIST = {
    "systemd", "kworker", "ksoftirqd", "rcu_sched", "rcu_bh",
    "dbus-daemon", "gnome-shell", "xorg", "xwayland",
    "pulseaudio", "pipewire", "timedated", "systemd-timesyncd",
    "rsyslogd", "cron", "agetty", "at-spi-bus-launcher",
    "zsh", "bash",
    "uvicorn", "gunicorn", "werkzeug",
    "python3", "python"
    # note: firefox intentionally not blacklisted here; user-level processes are protected
}

DEFAULT_WHITELIST = {w.lower() for w in _DEFAULT_WHITELIST}

if PROC_WHITELIST:
    for name in str(PROC_WHITELIST).split(","):
        n = name.strip().lower()
        if n:
            DEFAULT_WHITELIST.add(n)

env_whitelist = os.getenv("HP_PROC_WHITELIST", "")
if env_whitelist:
    for name in env_whitelist.split(","):
        n = name.strip().lower()
        if n:
            DEFAULT_WHITELIST.add(n)

# ensure current process (monitor) is whitelisted
try:
    current_proc = psutil.Process(os.getpid()).name().lower()
    DEFAULT_WHITELIST.add(current_proc)
except Exception:
    current_proc = None

SUSPICIOUS_NAMES = {
    "nmap", "metasploit", "msfconsole", "sqlmap",
    "hydra", "john", "msf", "nc", "netcat",
    "exploit", "metasploit-framework",
}

SampleWindow = Dict[int, Deque[Tuple[float, float]]]

# user running monitor (for owner-safety)
try:
    MONITOR_USER = getpass.getuser()
except Exception:
    MONITOR_USER = None

# ---------------------------------------------------------
# MAIN CLASS
# ---------------------------------------------------------
class ProcessGuard:
    def __init__(self, helpers: Optional[dict] = None, terminate_on_detect: Optional[bool] = None):
        self.helpers = helpers or {}
        # allow explicit override
        self.terminate_on_detect = (
            terminate_on_detect if terminate_on_detect is not None else TERMINATE_ON_DETECT_DEFAULT
        )
        # if HP_PROC_FORCE_ACTION True then allow actions regardless of dry-run
        if HP_PROC_FORCE_ACTION:
            self.effective_terminate = True
        else:
            self.effective_terminate = self.terminate_on_detect

        # if dry-run is enabled, we will not suspend/kill; only simulate
        self.dry_run = HP_PROC_DRY_RUN

        self._stop = threading.Event()
        self._thread = None

        self._samples = defaultdict(lambda: deque(maxlen=SUSTAINED_SAMPLES))
        self._cooldowns = {}
        self._names = {}
        self._recent_suspicious = {}

        logger.info("ProcessGuard initialized: dry_run=%s, skip_own=%s, terminate_on_detect=%s (effective=%s)",
                    self.dry_run, HP_PROC_SKIP_OWN, self.terminate_on_detect, self.effective_terminate)

    # ---------------------------------------------------------
    def start(self):
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._loop, daemon=True, name="ProcessGuardThread")
        self._thread.start()
        logger.info("ProcessGuard started. terminate_on_detect=%s, dry_run=%s", self.terminate_on_detect, self.dry_run)
        safe_emit("process_guard", {"action": "started", "detail": {"terminate_on_detect": self.terminate_on_detect, "dry_run": self.dry_run}})

    # ---------------------------------------------------------
    def stop(self, timeout=2.0):
        self._stop.set()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout)
        logger.info("ProcessGuard stopped.")
        safe_emit("process_guard", {"action": "stopped", "detail": {}})

    # ---------------------------------------------------------
    def _is_whitelisted(self, name: str) -> bool:
        """Whitelist check — match exact or prefix; avoid substring matches that are too permissive."""
        if not name:
            return False
        n = name.lower()
        # exact or prefix matching is intentional (avoid 'x in y' false positives)
        for w in DEFAULT_WHITELIST:
            if n == w or n.startswith(w):
                return True
        return False

    def _looks_suspicious_name(self, name: str) -> bool:
        if not name:
            return False
        n = name.lower()
        return any(s in n for s in SUSPICIOUS_NAMES)

    # ---------------------------------------------------------
    def _sustained_spike(self, pid: int) -> bool:
        window = self._samples.get(pid)
        if not window or len(window) < SUSTAINED_SAMPLES:
            return False
        return all((cpu > CPU_SPIKE_THRESHOLD or mem > MEM_SPIKE_THRESHOLD) for cpu, mem in window)

    def _in_cooldown(self, pid: int) -> bool:
        t = self._cooldowns.get(pid)
        return t and (time.time() - t) < COOLDOWN_SECONDS

    # ---------------------------------------------------------
    def _take_action(self, proc: psutil.Process):
        pid = proc.pid
        info = {"pid": pid, "name": None, "cmd": [], "action": "none"}

        try:
            info["name"] = proc.name()
            try:
                info["cmd"] = proc.cmdline()
            except Exception:
                info["cmd"] = []
        except Exception:
            pass

        # skip acting on processes owned by monitor user (configurable)
        try:
            if HP_PROC_SKIP_OWN:
                try:
                    owner = proc.username()
                    if MONITOR_USER and owner == MONITOR_USER:
                        info["action"] = "skipped_same_user"
                        safe_emit("process_guard", {"action": info["action"], "detail": info})
                        logger.info("ProcessGuard skipping action on PID %s (owned by monitor user %s)", pid, MONITOR_USER)
                        # set cooldown so we don't repeatedly report
                        self._cooldowns[pid] = time.time()
                        return
                except Exception:
                    # if owner lookup fails, continue to default behavior
                    pass
        except Exception:
            pass

        # If dry-run: don't actually suspend/terminate; just emit what would have been done
        if self.dry_run and not HP_PROC_FORCE_ACTION:
            # describe would-be action
            if self.effective_terminate:
                info["action"] = "would_terminate"
            else:
                info["action"] = "would_suspend"
            safe_emit("process_guard", {"action": info["action"], "detail": info})
            logger.warning("ProcessGuard DRY-RUN: %s (PID=%s, cmd=%s)", info["action"], pid, info.get("cmd"))
            # still set cooldown
            self._cooldowns[pid] = time.time()
            # create alert but mark it as informational in dry run
            trigger_alert(f"ProcessGuard (dry-run): {info['action']} PID {pid}, name={info.get('name')}", ALERT_CONFIG, level="MEDIUM")
            return

        # Real action: either terminate (preferred) or suspend
        try:
            if self.effective_terminate:
                try:
                    proc.terminate()
                except psutil.NoSuchProcess:
                    info["action"] = "already_exited"
                except Exception:
                    info["action"] = "terminate_failed"
                else:
                    time.sleep(0.4)
                    if proc.is_running():
                        try:
                            proc.kill()
                            info["action"] = "terminated"
                        except Exception:
                            info["action"] = "kill_failed"
                    else:
                        info["action"] = "terminated"
            else:
                try:
                    proc.suspend()
                    info["action"] = "suspended"
                except psutil.NoSuchProcess:
                    info["action"] = "already_exited"
                except Exception:
                    info["action"] = "suspend_failed"
        finally:
            self._cooldowns[pid] = time.time()
            safe_emit("process_guard", {"action": info["action"], "detail": info})
            alert_msg = f"ProcessGuard: Action={info['action']} — PID {pid}, name={info.get('name')}"
            trigger_alert(alert_msg, ALERT_CONFIG, level="HIGH")
            logger.warning("ProcessGuard action result: %s", info)

    # ---------------------------------------------------------
    def _loop(self):
        while not self._stop.is_set():
            seen = set()
            try:
                for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
                    pid = proc.info.get('pid')
                    name = (proc.info.get('name') or "").lower().strip()
                    seen.add(pid)
                    self._names[pid] = name

                    if not name:
                        continue

                    # Skip whitelisted names early
                    if self._is_whitelisted(name):
                        continue

                    # CPU / MEM sampling
                    try:
                        # use non-blocking cpu_percent measurement
                        cpu = proc.cpu_percent(interval=None)
                    except Exception:
                        cpu = 0.0

                    try:
                        mem = proc.memory_percent()
                    except Exception:
                        mem = 0.0

                    self._samples[pid].append((cpu, mem))

                    # Suspicious name detection
                    if self._looks_suspicious_name(name) and not self._in_cooldown(pid):
                        safe_emit("process_guard", {
                            "action": "suspicious_name",
                            "detail": {"pid": pid, "name": name}
                        })
                        trigger_alert(
                            f"ProcessGuard: Suspicious process name detected — {name} (PID {pid})",
                            ALERT_CONFIG,
                            level="HIGH"
                        )
                        # set cooldown so we don't spam identical alerts
                        self._cooldowns[pid] = time.time()

                    # Sustained CPU/MEM spike
                    if self._sustained_spike(pid) and not self._in_cooldown(pid):
                        safe_emit("process_guard", {
                            "action": "sustained_spike",
                            "detail": {"pid": pid, "name": name,
                                       "cpu_window": list(self._samples[pid])}
                        })

                        trigger_alert(
                            f"ProcessGuard: High CPU/MEM spike — PID {pid}, name={name}",
                            ALERT_CONFIG,
                            level="HIGH"
                        )

                        # take action (respect dry-run / owner-safety)
                        try:
                            self._take_action(psutil.Process(pid))
                        except psutil.NoSuchProcess:
                            # process ended between detection and action - ignore
                            self._cooldowns[pid] = time.time()
                        except Exception as e:
                            logger.exception("ProcessGuard _take_action failed for PID %s: %s", pid, e)

                # Cleanup dead PIDs
                for old in list(self._samples.keys()):
                    if old not in seen:
                        self._samples.pop(old, None)
                        self._names.pop(old, None)
                        self._cooldowns.pop(old, None)
                        self._recent_suspicious.pop(old, None)

            except Exception:
                logger.exception("ProcessGuard main loop error")

            time.sleep(SAMPLE_INTERVAL)
