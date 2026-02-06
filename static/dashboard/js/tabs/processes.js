import { apiGet } from "../api.js";

let tableEl;

export function initProcessesTab(container){
  container.innerHTML = `<div class="card"><h2 class="text-xl mb-3">Top Processes</h2>
    <table class="w-full text-left"><thead class="muted text-sm"><tr><th>PID</th><th>Name</th><th>CPU%</th><th>MEM%</th></tr></thead><tbody id="processTable"></tbody></table></div>`;
  tableEl = document.getElementById('processTable');
  loadProcesses();
  setInterval(loadProcesses, 3000);
}

async function loadProcesses(){
  try {
    const arr = await apiGet('/api/process_list');
    tableEl.innerHTML = '';
    arr.forEach(p=>{
      const tr = document.createElement('tr');
      tr.innerHTML = `<td class="py-1">${p.pid}</td><td class="py-1">${p.name}</td><td class="py-1">${(p.cpu_percent||0).toFixed(1)}</td><td class="py-1">${(p.memory_percent||0).toFixed(1)}</td>`;
      tableEl.appendChild(tr);
    });
  } catch(e){ console.warn('processes load failed', e); tableEl.innerHTML = '<tr><td colspan="4">failed to load</td></tr>'; }
}
