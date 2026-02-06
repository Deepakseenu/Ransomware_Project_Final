import { apiPost } from "../api.js";

const severityStats = {
  critical: 0,
  high: 0,
  medium: 0,
  low: 0,
  ransomware: 0
};

let cpuEl, memEl, blockedEl, eventsEl, cpuBar, memBar;
let chart = null;

export function initOverview(container) {

  container.innerHTML = `
    <div class="overview-grid">

      <div class="card metric-card">
        <div class="metric-title">CPU Usage</div>
        <div id="cpuUsage" class="metric-value">--%</div>
        <div class="metric-bar-bg">
            <div id="cpuBar" class="metric-bar-fill"></div>
        </div>
        <div class="metric-sub">Live CPU usage (system)</div>
      </div>

      <div class="card metric-card">
        <div class="metric-title">Memory Usage</div>
        <div id="memUsage" class="metric-value">--%</div>
        <div class="metric-bar-bg">
            <div id="memBar" class="metric-bar-fill"></div>
        </div>
        <div class="metric-sub">Live memory usage</div>
      </div>

      <div class="card metric-card">
        <div class="metric-title">Firewall Stats</div>

        <div class="metric-small">Blocked IPs</div>
        <div id="blockedCount" class="metric-value small">--</div>

        <div class="metric-small mt-2">Recent Events</div>
        <div id="eventCount" class="metric-value small">--</div>

        <div class="input-row mt-3">
          <input id="blockIpInputOverview" placeholder="1.2.3.4" />
          <button id="blockIpBtnOverview" class="btn-primary">Block</button>
        </div>
      </div>

    </div>

    <div class="grid-logs">
      <div class="card timeline-card">
        <h3>Event Timeline</h3>
        <pre id="overviewEventLog"></pre>
      </div>

      <div class="card">
        <h3>Event Severity Distribution</h3>
        <canvas id="overviewChart" height="220"></canvas>
      </div>
    </div>
  `;

  cpuEl = document.getElementById("cpuUsage");
  memEl = document.getElementById("memUsage");
  blockedEl = document.getElementById("blockedCount");
  eventsEl = document.getElementById("eventCount");
  cpuBar = document.getElementById("cpuBar");
  memBar = document.getElementById("memBar");

  document.getElementById("blockIpBtnOverview").addEventListener("click", async () => {
    const ip = document.getElementById("blockIpInputOverview").value.trim();
    if (!ip) return alert("Enter IP");

    try {
      await apiPost("/api/block_ip", { ip });
      document.getElementById("blockIpInputOverview").value = "";
    } catch (e) {
      console.warn("Block error", e);
    }
  });
}

export function updateOverviewFromStatus(j) {
  if (!j) return;

  cpuEl.textContent = `${j.cpu}%`;
  memEl.textContent = `${j.memory}%`;
  blockedEl.textContent = j.blocked_ips ?? 0;
  eventsEl.textContent = j.recent_events ?? 0;

  cpuBar.style.width = `${Math.min(100, j.cpu)}%`;
  memBar.style.width = `${Math.min(100, j.memory)}%`;
}

export function appendOverviewEventLine(line) {
  const log = document.getElementById("overviewEventLog");
  if (!log) return;

  const lines = (log.textContent + line).split("\n");

  // 🔑 Keep only last 120 lines
  if (lines.length > 120) {
    log.textContent = lines.slice(lines.length - 120).join("\n");
  } else {
    log.textContent += line;
  }

  // Auto-scroll to bottom
  log.scrollTop = log.scrollHeight;
}


export function updateOverviewChart(data) {
  if (!chart) {
    const ctx = document.getElementById("overviewChart");

    chart = new Chart(ctx, {
      type: "bar",
      data: {
        labels: ["Critical", "High", "Medium", "Low", "Ransomware"],
        datasets: [{
          label: "Event Count",
          data: [0, 0, 0, 0, 0],
          backgroundColor: [
            "#ff005e",   // Critical
            "#ff3333",   // High
            "#ffaa33",   // Medium
            "#ffee55",   // Low
            "#00ffea"    // Ransomware
          ],
          borderRadius: 6,
          barThickness: 28
        }]
      },
      options: {
        indexAxis: "y",              // 🔑 horizontal bars
        responsive: true,
        maintainAspectRatio: false,  // fills card height nicely
        plugins: {
          legend: { display: false },
          tooltip: {
            backgroundColor: "#0f172a",
            titleColor: "#ffffff",
            bodyColor: "#ffffff"
          }
        },
        scales: {
          x: {
            beginAtZero: true,
            ticks: { color: "#cbd5e1" },
            grid: { color: "rgba(255,255,255,0.08)" }
          },
          y: {
            ticks: { color: "#cbd5e1" },
            grid: { display: false }
          }
        }
      }
    });
  }

  chart.data.datasets[0].data = [
    data.critical || 0,
    data.high || 0,
    data.medium || 0,
    data.low || 0,
    data.ransomware || 0
  ];

  chart.update();
}


export function handleOverviewEvent(ev) {
  if (!ev) return;

  const type = (ev.type || "").toLowerCase();
  const action = (ev.action || "").toLowerCase();

  if (type.includes("ransom")) {
    severityStats.ransomware++;
  } 
  else if (type.includes("process") || type.includes("guard")) {
    severityStats.high++;
  }
  else if (type.includes("block") || action.includes("block")) {
    severityStats.medium++;
  }
  else if (type.includes("file")) {
    severityStats.low++;
  }
  else {
    severityStats.low++;
  }

  updateOverviewChart(severityStats);
}

