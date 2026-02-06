import { apiGet, apiPost } from "../api.js";
import { createEl } from "../utils.js";

let containerEl;

export function initBlockedTab(container){
  container.innerHTML = `<div class="card"><h2 class="text-xl mb-3">Blocked IPs</h2><div id="blockedList" class="space-y-2"></div></div>`;
  containerEl = document.getElementById('blockedList');
  loadBlocked();
}

export async function loadBlocked(){
  if(!containerEl) return;
  containerEl.innerHTML = 'Loading...';
  try {
    const data = await apiGet('/api/blocked_ips');
    let list = [];
    if(Array.isArray(data)) list = data;
    else if(typeof data === 'object') list = Object.entries(data).map(([ip,d])=>({ip, ...d}));
    containerEl.innerHTML = '';
    list.forEach(entry=>{
      const row = createEl('div', '', 'p-2 rounded bg-white/3 flex items-center justify-between');
      row.innerHTML = `<div><div class="font-semibold">${entry.ip}</div><div class="muted text-sm">${entry.reason || ''} • ${entry.last_blocked || entry.time || ''}</div></div>
                       <div class="flex gap-2">
                         <button class="btn-primary btn-unblock" data-ip="${entry.ip}">Unblock</button>
                       </div>`;
      containerEl.appendChild(row);
    });
    containerEl.querySelectorAll('.btn-unblock').forEach(b=>{
      b.addEventListener('click', async (ev)=>{
        const ip = ev.currentTarget.dataset.ip;
        if(!confirm('Unblock '+ip+'?')) return;
        try {
          await apiPost('/api/unblock_ip', {ip});
          await loadBlocked();
        } catch(e){ alert('Unblock failed: '+e); }
      });
    });
  } catch(e){ containerEl.innerHTML = 'Failed to load blocked list'; console.warn(e); }
}
