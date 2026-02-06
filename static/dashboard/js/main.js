// static/dashboard/js/main.js
import { startSocket } from "./websocket.js";
import { initEventsTab, handleEvent as eventsHandle } from "./tabs/events.js";
import { initOverview, updateOverviewFromStatus, appendOverviewEventLine, handleOverviewEvent } from "./tabs/overview.js";
import { initBlockedTab, loadBlocked } from "./tabs/blocked.js";
import { initProcessesTab } from "./tabs/processes.js";
import { initMapTab, updateMap } from "./tabs/map.js";
import { initIntelTab } from "./tabs/intel.js";
import { initAlertsTab, handleEvent as alertsHandle } from "./tabs/alerts.js";
import { apiGet, apiPost } from "./api.js";
import { $ } from "./utils.js";

// expose for console / other non-module code
window.apiGet = apiGet;
window.apiPost = apiPost;

// ======================================================
// TAB SYSTEM
// ======================================================

const TABS = [
  { id: "overview", label: "Overview", init: initOverview },
  { id: "events", label: "Events", init: initEventsTab },
  { id: "blocked", label: "Blocked IPs", init: initBlockedTab },
  { id: "processes", label: "Processes", init: initProcessesTab },
  { id: "map", label: "Threat Map", init: initMapTab },
  { id: "ransom_alerts", label: "Ransomware Alerts", init: initAlertsTab },
  { id: "threat_intel", label: "Threat Intelligence", init: initIntelTab }
];

function buildShell() {
  const tabsBar = document.getElementById("tabs");
  const content = document.getElementById("content");
  if (!tabsBar || !content) return;

  // Make tab buttons
  TABS.forEach(t => {
    const btn = document.createElement("div");
    btn.className = "tab";
    btn.textContent = t.label;
    btn.dataset.tab = t.id;
    btn.addEventListener("click", () => showTab(t.id, t));
    tabsBar.appendChild(btn);
  });

  // Create <section> for each tab
  TABS.forEach(t => {
    const sec = document.createElement("section");
    sec.id = t.id;
    sec.className = "tab-section";
    sec.style.display = "none";
    content.appendChild(sec);
  });
}

function showTab(id, tabObj) {
  document.body.className = "theme-" + id;

  // Mark tab active
  document.querySelectorAll(".tab").forEach(btn => {
    btn.classList.toggle("active", btn.dataset.tab === id);
  });

  // Show / hide sections (IMPORTANT FIX)
  document.querySelectorAll(".tab-section").forEach(sec => {
    sec.style.display = (sec.id === id) ? "block" : "none";
  });

  // Initialize tab only once
  const sec = document.getElementById(id);
  if (tabObj && tabObj.init && sec && !sec.dataset.inited) {
    try {
      tabObj.init(sec);
      sec.dataset.inited = "1";
    } catch (e) {
      console.warn("Tab init failed:", id, e);
    }

    // Flush buffered events for Events tab
    if (id === "events" && Array.isArray(window.__event_buffer) && window.__event_buffer.length) {
      for (const ev of window.__event_buffer) {
        try { eventsHandle(ev); } catch (e) {}
      }
      window.__event_buffer = [];
    }
  }

  // Update map after switch
  if (id === "map") {
    setTimeout(() => {
      try { updateMap(); } catch (e) {}
    }, 250);
  }
}


buildShell();

// Show default tab (guard existence)
const firstTab = document.querySelectorAll(".tab")[0];
if (firstTab) firstTab.classList.add("active");
showTab("overview", TABS[0]);

// ======================================================
// WEBSOCKET → EVENT PIPELINE
// ======================================================

// Buffer for events BEFORE Events tab is initialized
window.__event_buffer = window.__event_buffer || [];

startSocket((data) => {
  // Defensive: ensure data exists
  if (!data) return;

  // ===== Overview graph update (always) =====
  try {
    handleOverviewEvent(data);
  } catch (e) {}

  // ===== Events tab handling =====
  const eventsSection = document.getElementById("events");
  const eventsInited = !!(
    eventsSection &&
    eventsSection.dataset &&
    eventsSection.dataset.inited === "1"
  );

  if (eventsInited) {
    try {
      eventsHandle(data);
    } catch (e) {
      console.warn("eventsHandle failed:", e);
    }
  } else {
    try {
      window.__event_buffer.push(data);
    } catch (e) {
      console.warn("buffer push failed:", e);
    }
  }

  // ===== Ransomware / Alerts tab (FILTERED) =====
  try {
    const t = (data.type || "").toLowerCase();
    const a = (data.action || "").toLowerCase();

    if (
      t.includes("ransom") ||
      t.includes("encrypt") ||
      t.includes("crypto") ||
      a.includes("ransom") ||
      a.includes("encrypt")
    ) {
      alertsHandle(data);
    }
  } catch (e) {
    /* ignore */
  }

  // ===== Overview event timeline =====
  try {
    const ts = data.ts
      ? (data.ts < 1e12 ? data.ts * 1000 : data.ts)
      : Date.now();

    const timestr = new Date(ts).toLocaleString();
    const line = `[${timestr}] ${data.type} ${data.action} ${JSON.stringify(
      data.detail || {}
    )}\n`;

    appendOverviewEventLine(line);
  } catch (e) {
    /* ignore */
  }

  // ===== Auto refresh blocked list & map =====
  if (
    data.type === "block" ||
    data.action === "block" ||
    data.type === "blocked_list_updated"
  ) {
    try {
      loadBlocked();
    } catch (_) {}

    try {
      updateMap();
    } catch (_) {}
  }
});


// ======================================================
// STATUS UPDATES
// ======================================================

async function refreshStatus() {
  try {
    const j = await apiGet("/api/live_status");
    if (j) updateOverviewFromStatus(j);
  } catch(e){
    // ignore network hiccups
  }
}
setInterval(refreshStatus, 3000);
refreshStatus();

// ======================================================
// THREAT INTEL POPUP SUPPORT
// ======================================================

window.__open_threat_intel_tab = function(ip){
  const btn = [...document.querySelectorAll(".tab")].find(b => b.dataset.tab === "threat_intel");
  if (btn) btn.click();
  setTimeout(() => {
    const el = document.getElementById("intelIp");
    if (el) el.value = ip;
    const lookup = document.getElementById("doLookup");
    lookup && lookup.click();
  }, 150);
};

// ======================================================
// MONITOR CONTROL
// ======================================================

const startBtn = document.getElementById("startMonitor");
if (startBtn) {
  startBtn.addEventListener("click", async () => {
    try {
      const j = await apiPost("/api/monitor/start", {});
      document.getElementById("monitorStatus").textContent = j.started ? "started" : JSON.stringify(j);
    } catch(e){
      document.getElementById("monitorStatus").textContent = "error";
    }
  });
}

const stopBtn = document.getElementById("stopMonitor");
if (stopBtn) {
  stopBtn.addEventListener("click", async () => {
    try {
      const j = await apiPost("/api/monitor/stop", {});
      document.getElementById("monitorStatus").textContent = j.stopped ? "stopped" : JSON.stringify(j);
    } catch(e){
      document.getElementById("monitorStatus").textContent = "error";
    }
  });
}
