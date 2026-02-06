import { apiGet, apiPost } from "../api.js";

let map, markersLayer;
const geocache = {}; // ip -> {lat, lon, ...}
let isInitialized = false;

// lightweight rate-limited geoip lookup using ipapi.co
async function geoip(ip){
  if(geocache[ip]) return geocache[ip];
  try {
    const r = await fetch(`https://ipapi.co/${ip}/json/`);
    const j = await r.json();
    if(j && j.latitude && j.longitude){
      geocache[ip] = {lat: j.latitude, lon: j.longitude, city:j.city, country:j.country_name, org:j.org, asn:j.asn};
      return geocache[ip];
    }
  } catch(e){ console.warn('geoip error', e); }
  return null;
}

export function initMapTab(container){
  container.innerHTML = `
    <div class="card md:col-span-2">
      <h2 class="text-xl mb-2">Threat Map</h2>
      <div id="ipMap" style="height:520px;"></div>
    </div>
    <div class="card">
      <h3 class="mb-2">Map Controls</h3>
      <label class="muted">Auto-refresh</label><div><input id="mapAuto" type="checkbox" checked /> Refresh every 30s</div>
      <button id="mapRefresh" class="btn-primary mt-3 w-full">Refresh</button>
    </div>
  `;

  // init Leaflet map (dark tiles)
  if(!isInitialized){
    map = L.map('ipMap', {zoomControl:true}).setView([20,0],2);
    L.tileLayer('https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png', {
      attribution: '&copy; OpenStreetMap & CartoDB', maxZoom:19
    }).addTo(map);
    markersLayer = L.markerClusterGroup({spiderfyOnMaxZoom:true, chunkedLoading:true});
    map.addLayer(markersLayer);
    isInitialized = true;
  }
  document.getElementById('mapRefresh').addEventListener('click', updateMap);
  setInterval(()=>{ const el = document.getElementById('mapAuto'); if(el && el.checked && document.getElementById('ipMap')) updateMap(); }, 30000);

  // initial load
  updateMap();
}

export async function updateMap(){
  if(!isInitialized) return;
  try {
    markersLayer.clearLayers();
    const data = await apiGet('/api/blocked_ips');
    let list = [];
    if(Array.isArray(data)) list = data;
    else if(typeof data === 'object') list = Object.entries(data).map(([ip,d])=>({ip, ...d}));
    const ips = Array.from(new Set(list.map(x=>x.ip)));
    // fetch geo for each ip sequential-ish (slower but safe w/ rate limit)
    for(const ip of ips){
      const g = await geoip(ip);
      if(!g) continue;
      const m = L.marker([g.lat, g.lon]);
      const info = `<div style="min-width:200px"><b>${ip}</b><br>${g.city||''}, ${g.country||''}<br><small>${g.org||g.asn||''}</small><br>
                    <div style="margin-top:8px"><button onclick="window.__dashboard_unblock('${ip}')" class="px-2 py-1 rounded bg-yellow-500">Unblock</button>
                    <button onclick="window.__dashboard_openIntel('${ip}')" class="px-2 py-1 rounded bg-blue-500">Intel</button></div></div>`;
      m.bindPopup(info);
      markersLayer.addLayer(m);
    }
    if(markersLayer && markersLayer.getLayers().length) map.fitBounds(markersLayer.getBounds(), {maxZoom:4, padding:[50,50]});
  } catch(e){ console.warn('updateMap failed', e); }
}

// helpers available globally for popups (wired by main)
window.__dashboard_unblock = async function(ip){
  if(!confirm('Unblock '+ip+'?')) return;
  try { await apiPost('/api/unblock_ip', {ip}); await updateMap(); } catch(e){ alert('Unblock failed'); }
};
window.__dashboard_openIntel = function(ip){
  // main will implement tab switch + set intel input
  if(window.__open_threat_intel_tab) window.__open_threat_intel_tab(ip);
};
