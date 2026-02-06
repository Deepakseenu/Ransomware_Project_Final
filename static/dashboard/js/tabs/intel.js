// Threat Intel tab: simple GeoIP + RDNS + optional AbuseIPDB client-side call
import { apiGet } from "../api.js";

let intelInput, intelOut, abuseKeyInput;

export function initIntelTab(container){
  container.innerHTML = `
    <div class="card">
      <h2 class="text-xl mb-3">IP Lookup & Threat Intel</h2>
      <input id="intelIp" placeholder="Enter IP (e.g. 1.2.3.4)" class="w-full p-2 rounded bg-white/5 mb-2" />
      <div class="flex gap-2 mb-2">
        <button id="doLookup" class="btn-primary flex-1">Lookup GeoIP</button>
        <button id="doRDNS" class="px-3 py-2 rounded bg-indigo-600">Reverse DNS</button>
      </div>
      <div class="muted text-sm mb-2">Optional AbuseIPDB key (client-side)</div>
      <input id="abuseKey" class="w-full p-2 rounded bg-white/5 mb-2" placeholder="Paste AbuseIPDB key (optional)"/>
      <div id="intelResult" class="text-sm"></div>
    </div>
  `;
  intelInput = document.getElementById('intelIp');
  intelOut = document.getElementById('intelResult');
  abuseKeyInput = document.getElementById('abuseKey');

  document.getElementById('doLookup').addEventListener('click', doLookup);
  document.getElementById('doRDNS').addEventListener('click', doRDNS);
}

async function doLookup(){
  const ip = intelInput.value.trim();
  if(!ip) return alert('Enter IP');
  intelOut.textContent = 'Loading...';
  try {
    const r = await fetch(`https://ipapi.co/${ip}/json/`);
    const j = await r.json();
    intelOut.innerHTML = `<div><b>${ip}</b> — ${j.city||''}, ${j.region||''}, ${j.country_name||''}</div>
      <div class="muted text-sm">ASN: ${j.asn||j.org||''} • ${j.org||''}</div>
      <pre class="mt-2 text-xs">${JSON.stringify(j,null,2)}</pre>`;
    // optional AbuseIPDB
    const key = abuseKeyInput.value.trim();
    if(key){
      try {
        const res = await fetch(`https://api.abuseipdb.com/api/v2/check?ipAddress=${ip}`, {
          headers: { 'Key': key, 'Accept': 'application/json' }
        });
        const d = await res.json();
        intelOut.innerHTML += `<div class="mt-2">AbuseIPDB: <pre class="text-xs">${JSON.stringify(d.data||d,null,2)}</pre></div>`;
      } catch(e){ intelOut.innerHTML += `<div class="mt-2 muted">AbuseIPDB lookup failed</div>`; }
    }
  } catch(e){ intelOut.textContent = 'Lookup failed'; console.warn(e); }
}

async function doRDNS(){
  const ip = intelInput.value.trim();
  if(!ip) return alert('Enter IP');
  intelOut.textContent = 'RDNS...';
  try {
    const res = await fetch(`https://cloudflare-dns.com/dns-query?name=${ip}.in-addr.arpa&type=PTR`, {headers:{accept:'application/dns-json'}});
    const j = await res.json();
    intelOut.innerHTML = `<pre class="text-xs">${JSON.stringify(j,null,2)}</pre>`;
  } catch(e){ intelOut.textContent = 'RDNS failed'; console.warn(e); }
}

// allow external open
window.__open_threat_intel_tab = function(ip){
  const tab = document.querySelector('[data-tab="threat_intel"]');
  if(tab) tab.click();
  setTimeout(()=>{ document.getElementById('intelIp').value = ip; document.getElementById('doLookup').click(); }, 120);
};
