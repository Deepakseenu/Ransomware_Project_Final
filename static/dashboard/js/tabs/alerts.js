// Ransomware Alerts tab: derived from events. Main will call handleEvent for each event.
import { tsFormat } from "../utils.js";

let outEl;
let recentAlerts = [];

export function initAlertsTab(container){
  container.innerHTML = `<div class="card"><h2 class="text-xl mb-3">Ransomware Alerts</h2><div id="ransomAlertsList" class="space-y-3"></div></div>`;
  outEl = document.getElementById('ransomAlertsList');
  render();
}

function isSuspicious(ev){
  const t = (ev.type||'').toLowerCase();
  const a = (ev.action||'').toLowerCase();
  const d = JSON.stringify(ev.detail||{}).toLowerCase();
  return t.includes('ransom') || a.includes('ransom') || d.includes('yara') || d.includes('entropy') || d.includes('quarantine') || d.includes('honeypot');
}

export function handleEvent(ev){
  if(isSuspicious(ev)){
    recentAlerts.unshift(ev);
    if(recentAlerts.length > 200) recentAlerts.pop();
    render();
  }
}

function render(){
  if(!outEl) return;
  outEl.innerHTML = '';
  if(recentAlerts.length === 0){ outEl.innerHTML = '<div class="muted">No recent ransomware alerts.</div>'; return; }
  recentAlerts.slice(0,100).forEach(ev=>{
    const ts = tsFormat(ev.ts || Date.now());
    const el = document.createElement('div');
    el.className = 'p-3 rounded bg-white/3';
    el.innerHTML = `<div class="font-semibold">${ts} — <span class="chip">${ev.type||'event'}</span></div>
                    <div class="muted text-sm mt-1">${ev.action || ''} • ${JSON.stringify(ev.detail||{})}</div>`;
    outEl.appendChild(el);
  });
}
