# app/api/map_api.py
from fastapi import APIRouter
from fastapi.responses import JSONResponse
from app.prevention import net_guard
import httpx
import time

router = APIRouter()

# Simple in-memory GeoIP cache (ip -> geo)
_geo_cache = {}
_CACHE_TTL = 3600  # 1 hour


async def geo_lookup(ip: str):
    """Lookup IP using ipapi.co with caching."""
    now = time.time()
    if ip in _geo_cache:
        cached = _geo_cache[ip]
        if now - cached["ts"] < _CACHE_TTL:
            return cached["geo"]

    # Query IPAPI
    url = f"https://ipapi.co/{ip}/json/"

    try:
        async with httpx.AsyncClient(timeout=4.0) as client:
            r = await client.get(url)
            j = r.json()
            if j.get("latitude") and j.get("longitude"):
                geo = {
                    "lat": j["latitude"],
                    "lon": j["longitude"],
                    "city": j.get("city"),
                    "country": j.get("country_name"),
                    "asn": j.get("asn"),
                    "org": j.get("org"),
                }
                _geo_cache[ip] = {"geo": geo, "ts": now}
                return geo
    except Exception:
        return None

    return None


@router.get("/map_data")
async def api_map_data():
    """Returns GeoJSON points for all blocked IPs."""

    blocked = net_guard.list_blocked() or []

    # Normalize (same logic as server.py)
    ips = []
    if isinstance(blocked, list):
        for i in blocked:
            if isinstance(i, str):
                ips.append(i)
            elif isinstance(i, dict) and i.get("ip"):
                ips.append(i["ip"])
    elif isinstance(blocked, dict):
        ips.extend(list(blocked.keys()))

    features = []

    for ip in ips:
        geo = await geo_lookup(ip)
        if not geo:
            continue

        features.append({
            "type": "Feature",
            "geometry": {
                "type": "Point",
                "coordinates": [geo["lon"], geo["lat"]]
            },
            "properties": {
                "ip": ip,
                "city": geo.get("city"),
                "country": geo.get("country"),
                "asn": geo.get("asn"),
                "org": geo.get("org"),
                "severity": "high",
                "source": "blocked_ip"
            }
        })

    return JSONResponse({
        "type": "FeatureCollection",
        "features": features
    })
