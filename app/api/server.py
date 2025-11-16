from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Request
from fastapi.responses import HTMLResponse, FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
import asyncio
import uvicorn
import time
import psutil
from typing import List, Dict
from fastapi import HTTPException

app = FastAPI()

# Allow local dev origins
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# serve a `static/` folder (dashboard will be there)
app.mount("/static", StaticFiles(directory="./static"), name="static")

# --- In-memory stores (simple, persistent only while process runs) ---
recent_events: List[Dict] = []        # newest first
blocked_ips: Dict[str, Dict] = {}     # ip -> {ip, reason, last_blocked, added_at}
quarantine: List[str] = []
backups: List[str] = []

# WebSocket manager
class ConnectionManager:
    def __init__(self):
        self.active: List[WebSocket] = []
        self.lock = asyncio.Lock()

    async def connect(self, ws: WebSocket):
        await ws.accept()
        async with self.lock:
            self.active.append(ws)

    async def disconnect(self, ws: WebSocket):
        async with self.lock:
            if ws in self.active:
                self.active.remove(ws)

    async def broadcast(self, message: Dict):
        # send message to all websocket clients concurrently
        async with self.lock:
            remove = []
            for ws in list(self.active):
                try:
                    await ws.send_json(message)
                except Exception:
                    remove.append(ws)
            for r in remove:
                if r in self.active:
                    self.active.remove(r)

manager = ConnectionManager()

# An asyncio queue for internal event ingestion
_event_queue: asyncio.Queue = asyncio.Queue()

async def _broadcaster_loop():
    """Background task: pull from queue and broadcast to connected websockets."""
    while True:
        data = await _event_queue.get()
        # store in recent_events (cap 500)
        recent_events.insert(0, data)
        if len(recent_events) > 500:
            recent_events.pop()
        # also broadcast
        await manager.broadcast({"type": "new_event", "data": data})

@app.on_event("startup")
async def startup_event():
    # start broadcaster background task
    asyncio.create_task(_broadcaster_loop())

# Helper to push an event into the pipeline
async def push_event(event: Dict):
    # Add timestamp if missing
    if "ts" not in event:
        event["ts"] = time.time()
    await _event_queue.put(event)

# -------------------- API endpoints --------------------

@app.post("/api/push_event")
async def api_push_event(req: Request):
    obj = await req.json()
    await push_event(obj)
    return JSONResponse({"ok": True})

@app.get("/api/events")
async def api_get_events(limit: int = 100):
    return JSONResponse(recent_events[:limit])

@app.get("/api/live_status")
async def api_live_status():
    cpu = psutil.cpu_percent(interval=0.1)
    mem = psutil.virtual_memory().percent
    net = psutil.net_io_counters()
    return JSONResponse({
        "cpu": cpu,
        "memory": mem,
        "bytes_sent": net.bytes_sent,
        "bytes_recv": net.bytes_recv,
        "recent_events": len(recent_events),
        "blocked_ips": len(blocked_ips),
    })

@app.get("/api/blocked_ips")
async def api_blocked_ips():
    # return as list
    return JSONResponse(list(blocked_ips.values()))

@app.post("/api/block_ip")
async def api_block_ip(req: Request):
    body = await req.json()
    ip = body.get("ip")
    reason = body.get("reason", "manual")
    if not ip:
        return JSONResponse({"ok": False, "error": "missing ip"}, status_code=400)
    blocked_ips[ip] = {"ip": ip, "reason": reason, "last_blocked": time.ctime(), "added_at": time.time()}
    # TODO: here you could call `iptables` or `nft` command to actually block — omitted for safety
    await push_event({"type": "net", "action": "block", "detail": {"ip": ip, "reason": reason}})
    return JSONResponse({"ok": True, "ip": ip})

@app.post("/api/unblock_ip")
async def api_unblock_ip(req: Request):
    body = await req.json()
    ip = body.get("ip")
    if not ip or ip not in blocked_ips:
        return JSONResponse({"ok": False, "error": "unknown ip"}, status_code=400)
    blocked_ips.pop(ip, None)
    # TODO: remove from firewall
    await push_event({"type": "net", "action": "unblock", "detail": {"ip": ip}})
    return JSONResponse({"ok": True, "ip": ip})

@app.get("/api/list_quarantine")
async def api_list_quarantine():
    return JSONResponse(quarantine)

@app.get("/api/list_backup")
async def api_list_backup():
    return JSONResponse(backups)

@app.get("/api/process_list")
async def api_process_list():
    procs = []
    for p in psutil.process_iter(['pid', 'name']):
        try:
            info = p.as_dict(attrs=['pid', 'name'])
            info['cpu_percent'] = p.cpu_percent(interval=0.0)
            info['memory_percent'] = p.memory_percent()
            procs.append(info)
        except Exception:
            pass

    procs = sorted(procs, key=lambda x: x.get('cpu_percent', 0), reverse=True)[:200]
    return JSONResponse(procs)

@app.get("/dashboard")
async def dashboard_html():
    return FileResponse("./static/dashboard.html")

# WebSocket endpoint for live events
@app.websocket("/ws/events")
async def ws_events(websocket: WebSocket):
    await manager.connect(websocket)
    try:
        while True:
            # keep connection open; client may send pings
            msg = await websocket.receive_text()
            # we do not require any specific client messages; if client sends 'ping' respond
            if msg.strip().lower() == 'ping':
                await websocket.send_text('pong')
    except WebSocketDisconnect:
        await manager.disconnect(websocket)
    except Exception:
        await manager.disconnect(websocket)


# ---------------- Monitor control endpoints ----------------

@app.post("/api/monitor/start")
async def api_monitor_start():
    """
    Try to start the monitor lifecycle in-process.
    NOTE: This only works if monitor package is importable and starting it in the same process is desired.
    If your monitor runs as a separate process (python -m app.monitor.main), call that externally instead.
    """
    try:
        import importlib
        lifecycle = importlib.import_module("app.monitor.lifecycle")
    except Exception as e:
        return JSONResponse({"ok": False, "error": "monitor module not importable in this process", "detail": str(e)})

    try:
        # call start() (synchronous)
        lifecycle.start()
        running = getattr(lifecycle, "is_running", lambda: True)()
        return JSONResponse({"ok": True, "started": True, "running": running})
    except Exception as e:
        return JSONResponse({"ok": False, "error": str(e)})

@app.post("/api/monitor/stop")
async def api_monitor_stop():
    """
    Try to stop the monitor lifecycle in-process.
    If monitor is a separate process, this will not stop that external process.
    """
    try:
        import importlib
        lifecycle = importlib.import_module("app.monitor.lifecycle")
    except Exception as e:
        return JSONResponse({"ok": False, "error": "monitor module not importable in this process", "detail": str(e)})

    try:
        lifecycle.shutdown()
        running = getattr(lifecycle, "is_running", lambda: False)()
        return JSONResponse({"ok": True, "stopped": True, "running": running})
    except Exception as e:
        return JSONResponse({"ok": False, "error": str(e)})

@app.get("/api/monitor/status")
async def api_monitor_status():
    """
    Query monitor status (in-process).
    Returns a clear message if monitor lifecycle is not importable in this FastAPI process.
    """
    try:
        import importlib
        lifecycle = importlib.import_module("app.monitor.lifecycle")
    except Exception as e:
        return JSONResponse({"ok": False, "importable": False, "error": "monitor module not importable", "detail": str(e)})

    try:
        running = getattr(lifecycle, "is_running", lambda: False)()
        return JSONResponse({"ok": True, "importable": True, "running": bool(running)})
    except Exception as e:
        return JSONResponse({"ok": False, "error": str(e)})

if __name__ == '__main__':
    uvicorn.run('app.api.server:app', host='0.0.0.0', port=8000, reload=True)
