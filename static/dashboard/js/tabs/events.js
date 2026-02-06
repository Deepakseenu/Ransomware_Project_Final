// static/dashboard/js/tabs/events.js
import { $, tsFormat } from "../utils.js";
import { apiGet } from "../api.js";

/*
  Exports:
    - initEventsTab(container)
    - handleEvent(ev)
    - getRecentEvents()
*/

let recentEvents = [];
let containerEl = null;
let tableBody = null;
let lastPrintedHash = null;

const MAX_ROWS = 1000;     // memory buffer
const VISIBLE_ROWS = 500;  // DOM rows

// ----------------------------
// Helpers
// ----------------------------
function severityOf(ev){
  try {
    const t = (ev.type || "").toLowerCase();
    const a = (ev.action || "").toLowerCase();
    const d = ev.detail || {};
    if (t.includes("ransom") || a.includes("ransom") || d?.analysis?.suspicious) return "high";
    if (t.includes("process") || t.includes("guard") || a.includes("suspicious") || a.includes("spike")) return "medium";
    if (t.includes("net") || d?.ip) return "medium";
  } catch {}
  return "low";
}

function badgeForSeverity(s){
  if(s==="high") return '<span class="ev-badge ev-high">HIGH</span>';
  if(s==="medium") return '<span class="ev-badge ev-medium">MED</span>';
  return '<span class="ev-badge ev-low">LOW</span>';
}

function prettyDetails(ev){
  try { return ev.detail ? JSON.stringify(ev.detail, null, 2) : "{}"; }
  catch { return "{}"; }
}

function escapeHtml(s){
  return String(s).replace(/[&<>"']/g,
    m => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":"&#39;"}[m]));
}

// ----------------------------
// Create a table row
// ----------------------------
function createRow(ev){
  const ts = (ev.ts && ev.ts < 1e12) ? ev.ts * 1000 : (ev.ts || Date.now());
  const timestr = tsFormat(ts);

  const type = escapeHtml((ev.type || "EVENT").toUpperCase());
  const action = escapeHtml(ev.action || "");
  const sev = severityOf(ev);
  const sevBadge = badgeForSeverity(sev);

  let shortInfo = "";
  if(ev.detail){
    if(ev.detail.path) shortInfo = ev.detail.path;
    else if(ev.detail.pid) shortInfo = "PID:" + ev.detail.pid;
    else if(ev.detail.ip) shortInfo = ev.detail.ip;
    else if(ev.detail.name) shortInfo = ev.detail.name;
  }
  shortInfo = escapeHtml(shortInfo || "");

  const detailsPretty = escapeHtml(prettyDetails(ev));

  const tr = document.createElement("tr");
  tr.className = "ev-row";

  tr.innerHTML = `
    <td class="ev-time">${timestr}</td>
    <td class="ev-type">${type}</td>
    <td class="ev-action">${action}</td>
    <td class="ev-info">${shortInfo}</td>
    <td class="ev-sev">${sevBadge}</td>
    <td class="ev-more"><button class="btn-small btn-inspect">View</button></td>
    <td class="ev-hidden" style="display:none">${detailsPretty}</td>
  `;

  const btn = tr.querySelector(".btn-inspect");
  if (btn)
    btn.addEventListener("click", (e) => {
      e.stopPropagation();
      showDetailsModal(type, timestr, detailsPretty);
    });

  return tr;
}

// ----------------------------
// Modal
// ----------------------------
function showDetailsModal(type, time, details){
  const modal = document.getElementById("evModal");
  if (!modal) return;
  document.getElementById("evModalTitle").textContent = `${type} • ${time}`;
  document.getElementById("evModalBody").textContent = details;
  modal.style.display = "flex";
}

// ----------------------------
// DOM builder + control wiring
// ----------------------------
function ensureTableExists(container){
  // create DOM (idempotent)
  container.innerHTML = `
    <div class="events-controls">
      <div class="left">
        <div class="filter-group">
          <label>Filter:</label>
          <button class="filter-btn active" data-filter="">All</button>
          <button class="filter-btn" data-filter="file">File</button>
          <button class="filter-btn" data-filter="process">Process</button>
          <button class="filter-btn" data-filter="net">Network</button>
          <button class="filter-btn" data-filter="ransom">Ransomware</button>
        </div>
      </div>
      <div class="right">
        <input id="eventSearch" placeholder="Search…" />
        <button id="clearEvents" class="btn-small">Clear</button>
      </div>
    </div>

    <div class="events-wrap">
      <table class="events-table">
        <thead>
          <tr>
            <th>Time</th><th>Type</th><th>Action</th>
            <th>Info</th><th>Severity</th><th></th>
          </tr>
        </thead>
        <tbody id="eventsTableBody"></tbody>
      </table>
    </div>

    <div id="evModal" class="ev-modal" style="display:none">
      <div class="ev-modal-content">
        <div class="ev-modal-header">
          <div id="evModalTitle"></div>
          <button id="evModalClose" class="btn-small">Close</button>
        </div>
        <pre id="evModalBody" class="ev-json"></pre>
      </div>
    </div>
  `;

  // assign tableBody to a fresh DOM lookup
  tableBody = document.getElementById("eventsTableBody");

  // wire controls (safe)
  document.querySelectorAll(".filter-btn").forEach(btn => {
    btn.addEventListener("click", () => {
      document.querySelectorAll(".filter-btn").forEach(x => x.classList.remove("active"));
      btn.classList.add("active");
      renderTableFromMemory();
    });
  });

  const searchEl = document.getElementById("eventSearch");
  if (searchEl) searchEl.addEventListener("input", renderTableFromMemory);

  const clearBtn = document.getElementById("clearEvents");
  if (clearBtn) clearBtn.addEventListener("click", () => { recentEvents = []; renderTableFromMemory(); });

  const closeBtn = document.getElementById("evModalClose");
  if (closeBtn) closeBtn.addEventListener("click", () => { document.getElementById("evModal").style.display = "none"; });

  const modal = document.getElementById("evModal");
  if (modal) modal.addEventListener("click", (e) => { if (e.target === modal) modal.style.display = "none"; });
}

// ----------------------------
// Filtering
// ----------------------------
function rowMatchesFilter(ev, filter){
  if(!filter) return true;
  const t = (ev.type || "").toLowerCase();
  if(filter==="file" && t.includes("file")) return true;
  if(filter==="process" && (t.includes("process") || t.includes("guard"))) return true;
  if(filter==="net" && (t.includes("net") || ev.detail?.ip)) return true;
  if(filter==="ransom" && (t.includes("ransom") || ev.detail?.analysis?.suspicious)) return true;
  return false;
}

function rowMatchesSearch(ev, q){
  if(!q) return true;
  const hay = (String(ev.type) + " " + String(ev.action) + " " + JSON.stringify(ev.detail||{})).toLowerCase();
  return hay.includes(q.toLowerCase());
}

// ----------------------------
// Render
// ----------------------------
function renderTableFromMemory(){
  // Always re-query the tbody to avoid stale element reference
  tableBody = document.getElementById("eventsTableBody");
  if (!tableBody) return;

  const filter = document.querySelector(".filter-btn.active")?.dataset.filter || "";
  const q = (document.getElementById("eventSearch")?.value || "").toLowerCase();

  tableBody.innerHTML = "";

  let count = 0;
  for (let i = 0; i < recentEvents.length && count < VISIBLE_ROWS; i++){
    const ev = recentEvents[i];
    if(!rowMatchesFilter(ev, filter)) continue;
    if(!rowMatchesSearch(ev, q)) continue;
    tableBody.appendChild(createRow(ev));
    count++;
  }
}

// ----------------------------
// INIT TAB (robust)
// ----------------------------
export async function initEventsTab(container){
  containerEl = container;

  // ensure DOM & controls exist
  ensureTableExists(containerEl);

  // load historical events
  try {
    const data = await apiGet("/api/events").catch(_ => []);
    const arr = Array.isArray(data) ? data : (data.events || []);
    recentEvents = arr.slice(0, MAX_ROWS);
    for (let ev of recentEvents) if (ev && ev.ts && ev.ts < 1e12) ev.ts = ev.ts * 1000;
  } catch(e){
    console.warn("initEventsTab load failed:", e);
    recentEvents = [];
  }

  // merge buffer (if any)
  if (Array.isArray(window.__event_buffer) && window.__event_buffer.length){
    for (let ev of window.__event_buffer) {
      if (ev && ev.ts && ev.ts < 1e12) ev.ts = ev.ts * 1000;
      recentEvents.unshift(ev);
    }
    if (recentEvents.length > MAX_ROWS) recentEvents.length = MAX_ROWS;
    window.__event_buffer = [];
  }

  // initial render (immediate)
  renderTableFromMemory();

  // safe delayed re-render: re-query DOM and only render if tbody exists
  setTimeout(() => {
    try {
      tableBody = document.getElementById("eventsTableBody");
      if (tableBody) {
        renderTableFromMemory();
        // console.debug harmless info
        console.debug("events: delayed re-render rows=", tableBody.childElementCount);
      } else {
        console.debug("events: delayed re-render skipped, tbody missing");
      }
    } catch (e) {
      console.warn("events: delayed re-render failed:", e);
    }
  }, 120);
}

// ----------------------------
// Incoming events
// ----------------------------
export function handleEvent(ev){
  if (!ev || typeof ev !== "object") return;

  if (ev.ts && ev.ts < 1e12) ev.ts = ev.ts * 1000;

  recentEvents.unshift(ev);
  if (recentEvents.length > MAX_ROWS) recentEvents.length = MAX_ROWS;

  // ensure tableBody points to current DOM
  tableBody = document.getElementById("eventsTableBody");
  if (!tableBody) return;

  const filter = document.querySelector(".filter-btn.active")?.dataset.filter || "";
  const q = (document.getElementById("eventSearch")?.value || "").toLowerCase();

  if (rowMatchesFilter(ev, filter) && rowMatchesSearch(ev, q)){
    const row = createRow(ev);
    if (tableBody.firstChild) tableBody.insertBefore(row, tableBody.firstChild);
    else tableBody.appendChild(row);

    while (tableBody.childElementCount > VISIBLE_ROWS)
      tableBody.removeChild(tableBody.lastChild);
  }
}

// ----------------------------
export function getRecentEvents(){ return recentEvents; }
