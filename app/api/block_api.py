# app/api/block_api.py
from fastapi import APIRouter, Request, HTTPException
from fastapi.responses import JSONResponse
from pathlib import Path
import json
import time
from typing import Any, Dict, List, Union

router = APIRouter()
ROOT = Path(__file__).resolve().parents[2]
BLOCK_FILE = ROOT / "honeypot_data" / "blocked.json"

# ensure directory exists
BLOCK_FILE.parent.mkdir(parents=True, exist_ok=True)


# ----------------------
# Storage helpers
# ----------------------
def _read_block_file() -> Any:
    """Read raw JSON from BLOCK_FILE. Returns parsed object or an empty list."""
    if not BLOCK_FILE.exists():
        return []
    try:
        raw = json.loads(BLOCK_FILE.read_text())
        return raw
    except Exception:
        # Corrupt file -> return empty list for safety
        return []


def _write_block_file(obj: Any) -> None:
    """Write object to BLOCK_FILE (JSON)."""
    try:
        BLOCK_FILE.write_text(json.dumps(obj, indent=2))
    except Exception:
        # Best-effort; ignore errors here (server will log elsewhere)
        pass


def normalize_blocks(raw: Any) -> List[Dict]:
    """
    Normalize a raw blocked-store value into a list of canonical objects:
      {"ip": "...", "reason": "...", "time": 1234567890, ...}
    Acceptable input forms:
      - list of dicts [{ "ip": "...", ...}, ...]
      - list of strings ["1.2.3.4", ...]
      - dict mapping ip -> meta { "1.2.3.4": { "blocked": true, "time": ... }, ... }
    """
    out: List[Dict] = []
    if isinstance(raw, list):
        for item in raw:
            if isinstance(item, str):
                out.append({"ip": item, "reason": "manual", "time": int(time.time())})
            elif isinstance(item, dict) and item.get("ip"):
                # ensure time exists
                entry = dict(item)
                if "time" not in entry:
                    entry.setdefault("time", int(time.time()))
                out.append(entry)
    elif isinstance(raw, dict):
        for ip, meta in raw.items():
            obj = {"ip": ip}
            if isinstance(meta, dict):
                obj.update(meta)
            # ensure time exists
            if "time" not in obj:
                obj.setdefault("time", int(time.time()))
            out.append(obj)
    return out


def _canonical_store_from_list(lst: List[Dict]) -> Dict[str, Dict]:
    """
    Convert a list of canonical dict entries to mapping ip -> meta for stable storage.
    Example:
      [ {"ip":"1.2.3.4", "reason":"manual", "time":123}, ... ]
    -> { "1.2.3.4": {"reason":"manual","time":123}, ... }
    """
    out: Dict[str, Dict] = {}
    for item in lst:
        ip = item.get("ip")
        if not ip:
            continue
        meta = dict(item)
        meta.pop("ip", None)
        out[ip] = meta
    return out


def _load_persisted_blocks() -> Any:
    """
    Attempt to load the canonical store using app.prevention.net_guard if available,
    otherwise fall back to reading BLOCK_FILE directly.
    """
    try:
        # prefer net_guard.list_blocked if available
        import importlib
        ng = importlib.import_module("app.prevention.net_guard")
        if hasattr(ng, "list_blocked"):
            return ng.list_blocked()
    except Exception:
        pass
    return _read_block_file()


def _save_persisted_blocks(obj: Any) -> None:
    """
    Attempt to save using net_guard.save_blocked if available, otherwise write the file.
    """
    try:
        import importlib
        ng = importlib.import_module("app.prevention.net_guard")
        if hasattr(ng, "save_blocked"):
            try:
                ng.save_blocked(obj)
                return
            except Exception:
                # fallback to file write
                pass
    except Exception:
        pass
    _write_block_file(obj)


# ----------------------
# Optional migration helper
# ----------------------
def migrate_block_store():
    """
    Convert existing storage (list/dict) into a canonical dict mapping ip->meta.
    Writes the canonical representation back via _save_persisted_blocks.
    """
    raw = _load_persisted_blocks()
    normalized = normalize_blocks(raw)
    canonical = _canonical_store_from_list(normalized)
    _save_persisted_blocks(canonical)
    return canonical


# ----------------------
# API Endpoints
# ----------------------

@router.get("/blocked_ips")
async def api_get_blocked():
    """
    Return blocked IPs in normalized list form for the frontend.
    """
    raw = _load_persisted_blocks()
    normalized = normalize_blocks(raw)
    return JSONResponse(normalized)


@router.post("/block_ip")
async def api_block_ip(req: Request):
    """
    Block an IP (best-effort):
      - Persist the block in the canonical blocked store
      - Try to call app.prevention.net_guard.block_ip(ip) if available
      - Emit a push_event to the server event queue if possible
    """
    body = await req.json()
    ip = (body.get("ip") or body.get("address") or "").strip()
    if not ip:
        raise HTTPException(status_code=400, detail="missing ip")

    # Load existing store (canonicalize to list of dicts)
    raw = _load_persisted_blocks()
    normalized = normalize_blocks(raw)

    # avoid duplicate
    if not any(d.get("ip") == ip for d in normalized):
        entry = {"ip": ip, "reason": "manual", "time": int(time.time())}
        normalized.append(entry)

        # persist as canonical mapping (ip -> meta) for stable storage
        canonical = _canonical_store_from_list(normalized)
        _save_persisted_blocks(canonical)

    # Attempt to apply the block via NetGuard (best-effort)
    block_result = None
    try:
        import importlib
        ng = importlib.import_module("app.prevention.net_guard")
        if hasattr(ng, "block_ip"):
            try:
                block_result = ng.block_ip(ip)
            except Exception as e:
                block_result = {"error": str(e)}
    except Exception:
        # net guard not available; ignore (we already persisted)
        block_result = {"error": "net_guard_unavailable"}

    # Try to emit event via server push_event if available (best-effort)
    try:
        from app.api.server import push_event  # import late to avoid cycles
        await push_event({"type": "net", "action": "block", "detail": {"ip": ip, "result": block_result}})
    except Exception:
        pass

    return JSONResponse({"status": "blocked", "ip": ip, "result": block_result})


@router.post("/unblock_ip")
async def api_unblock_ip(req: Request):
    """
    Unblock an IP (best-effort):
      - Try to remove the iptables rule via NetGuard if available
      - Update persisted blocked store in a tolerant way
      - Emit a push_event if available
    """
    body = await req.json()
    ip = (body.get("ip") or body.get("address") or "").strip()
    if not ip:
        raise HTTPException(status_code=400, detail="missing ip")

    # 1) Try to remove rule via NetGuard
    unblock_result = None
    try:
        import importlib
        ng = importlib.import_module("app.prevention.net_guard")
        if hasattr(ng, "unblock"):
            try:
                unblock_result = ng.unblock(ip)
            except Exception as e:
                unblock_result = {"error": str(e)}
    except Exception:
        unblock_result = {"error": "net_guard_unavailable"}

    # 2) Tolerantly update persisted store
    try:
        raw = _load_persisted_blocks()
        normalized = normalize_blocks(raw)

        # Build a new list excluding the ip
        new_list = []
        removed = False
        for entry in normalized:
            try:
                if entry.get("ip") != ip:
                    new_list.append(entry)
                else:
                    removed = True
            except Exception:
                # keep unknown entries
                new_list.append(entry)

        if removed:
            # persist canonical mapping
            canonical = _canonical_store_from_list(new_list)
            _save_persisted_blocks(canonical)

        # Emit event regardless of whether it was found in store (use unblock_result for detail)
        try:
            from app.api.server import push_event
            await push_event({"type": "net", "action": "unblock", "detail": {"ip": ip, "result": unblock_result}})
        except Exception:
            pass

        if removed:
            return JSONResponse({"status": "unblocked", "ip": ip, "result": unblock_result})
        else:
            # Not found in persisted store — still return result of unblock attempt
            return JSONResponse({"status": "not_found_in_store", "ip": ip, "result": unblock_result})
    except Exception as e:
        # Fallback: return unblock result but do not raise 500
        return JSONResponse({"status": "unblock_attempted", "ip": ip, "result": unblock_result, "error": str(e)})


# End of file
