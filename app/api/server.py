# app/api/server.py
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Request, HTTPException
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
import asyncio
import uvicorn
import time
import psutil
from typing import List, Dict, Any

# REAL firewall engine
from app.prevention import net_guard

# FastAPI routers
from app.api import block_api
from app.api import map_api


# ------------------- APP -------------------
app = FastAPI()

# CORS allow all (dashboard loads local JS files)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Serve modular dashboard
app.mount("/static", StaticFiles(directory="static"), name="static")

# Include API routes
app.include_router(block_api.router, prefix="/api")
app.include_router(map_api.router, prefix="/api")


# ------------------- LIVE EVENT SYSTEM -------------------

recent_events: List[Dict] = []
_event_queue: asyncio.Queue = asyncio.Queue()


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
        async with self.lock:
            dead = []
            for ws in list(self.active):
                try:
                    await ws.send_json(message)
                except:
                    dead.append(ws)
            for ws in dead:
                if ws in self.active:
                    self.active.remove(ws)


manager = ConnectionManager()


async def _broadcaster_loop():
    """Push queued events to all WebSocket dashboards with smooth CPU usage."""
    while True:
        event = await _event_queue.get()

        # small sleep prevents server freeze when many events arrive quickly
        await asyncio.sleep(0.01)

        recent_events.insert(0, event)
        if len(recent_events) > 500:
            recent_events.pop()

        try:
            await manager.broadcast({"type": "new_event", "data": event})
        except:
            pass


async def push_event(event: Dict):
    """External modules call this - safe and lightweight."""
    if "ts" not in event:
        event["ts"] = time.time()
    await _event_queue.put(event)


@app.on_event("startup")
async def on_start():
    asyncio.create_task(_broadcaster_loop())


# ---------------------------------------------------------
# API ENDPOINTS
# ---------------------------------------------------------

@app.get("/api/events")
async def api_events(limit: int = 200):
    return JSONResponse(recent_events[:limit])


@app.post("/api/test_event")
async def api_test_event(req: Request):
    body = await req.json()
    ev = {
        "type": body.get("type", "manual_test"),
        "detail": body.get("detail", {}),
        "source": "http_test"
    }
    await push_event(ev)
    return JSONResponse({"ok": True, "queued": ev})


@app.get("/api/live_status")
async def api_live_status():
    cpu = psutil.cpu_percent(interval=0.1)
    mem = psutil.virtual_memory().percent
    net = psutil.net_io_counters()
    blocked = net_guard.list_blocked() or []
    return {
        "cpu": cpu,
        "memory": mem,
        "bytes_sent": net.bytes_sent,
        "bytes_recv": net.bytes_recv,
        "recent_events": len(recent_events),
        "blocked_ips": len(blocked),
    }


def normalize_netguard(raw: Any):
    out = []
    if isinstance(raw, list):
        for ip in raw:
            if isinstance(ip, str):
                out.append({"ip": ip, "reason": "firewall", "time": int(time.time())})
            elif isinstance(ip, dict) and ip.get("ip"):
                out.append(ip)
    elif isinstance(raw, dict):
        for ip, meta in raw.items():
            obj = {"ip": ip}
            if isinstance(meta, dict):
                obj.update(meta)
            out.append(obj)
    return out


@app.get("/api/blocked_ips")
async def api_blocked_ips():
    raw = net_guard.list_blocked()
    return JSONResponse(normalize_netguard(raw))


@app.get("/api/process_list")
async def api_process_list():
    out = []
    for p in psutil.process_iter(['pid', 'name']):
        try:
            info = p.as_dict(attrs=['pid', 'name'])
            info["cpu_percent"] = p.cpu_percent(interval=0.0)
            info["memory_percent"] = p.memory_percent()
            out.append(info)
        except:
            pass

    out = sorted(out, key=lambda x: x.get("cpu_percent", 0), reverse=True)[:200]
    return JSONResponse(out)


# ------------------- DASHBOARD -------------------
@app.get("/dashboard")
async def dashboard_page():
    return FileResponse("static/dashboard/index.html")



# ------------------- WEBSOCKET -------------------
@app.websocket("/ws/events")
async def ws_events(websocket: WebSocket):
    await manager.connect(websocket)
    try:
        while True:
            msg = await websocket.receive_text()
            if msg.lower().strip() == "ping":
                await websocket.send_text("pong")
    except WebSocketDisconnect:
        await manager.disconnect(websocket)
    except:
        await manager.disconnect(websocket)


# ------------------- MONITOR CONTROL -------------------

@app.post("/api/monitor/start")
async def api_monitor_start():
    try:
        import importlib
        lifecycle = importlib.import_module("app.monitor.lifecycle")
        lifecycle.start()
        running = getattr(lifecycle, "is_running", lambda: True)()
        return {"ok": True, "started": True, "running": running}
    except Exception as e:
        return {"ok": False, "error": str(e)}


@app.post("/api/monitor/stop")
async def api_monitor_stop():
    try:
        import importlib
        lifecycle = importlib.import_module("app.monitor.lifecycle")
        lifecycle.shutdown()
        running = getattr(lifecycle, "is_running", lambda: False)()
        return {"ok": True, "stopped": True, "running": running}
    except Exception as e:
        return {"ok": False, "error": str(e)}


@app.get("/api/monitor/status")
async def api_monitor_status():
    try:
        import importlib
        lifecycle = importlib.import_module("app.monitor.lifecycle")
        running = getattr(lifecycle, "is_running", lambda: False)()
        return {"ok": True, "importable": True, "running": bool(running)}
    except Exception as e:
        return {"ok": False, "importable": False, "error": str(e)}


from fastapi import Body

@app.post("/api/push_event")
async def api_push_event(payload: dict = Body(...)):
    event = {}
    event["type"] = (
        payload.get("type")
        or payload.get("event_type")
        or payload.get("evt")
        or payload.get("category")
        or "monitor_event"
    )

    event["action"] = (
        payload.get("action")
        or payload.get("op")
        or payload.get("verb")
        or None
    )

    detail = payload.get("detail") or payload.get("payload") or payload.get("data") or {}

    if isinstance(detail, dict) and detail == {}:
        detail = {
            k: v for k, v in payload.items()
            if k not in ("type", "event_type", "action", "op", "verb", "ts", "payload", "detail", "data")
        }

    event["detail"] = detail

    ts = payload.get("ts") or payload.get("time")
    if ts:
        try:
            tsf = float(ts)
            if tsf > 1e12:   # ms conversion
                tsf /= 1000.0
            event["ts"] = tsf
        except:
            event["ts"] = time.time()
    else:
        event["ts"] = time.time()

    await push_event(event)
    return JSONResponse({"ok": True, "queued": event})


# ------------------- RUN -------------------
if __name__ == "__main__":
    uvicorn.run("app.api.server:app", host="0.0.0.0", port=8000)
