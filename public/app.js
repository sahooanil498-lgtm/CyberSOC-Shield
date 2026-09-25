// ============================================================================
// SOC AUTOMATION DASHBOARD - CLIENT APP LOGIC
// Includes: Carousel widgets, Live Activity Sentinel, Static Malware Sandbox
// ============================================================================

// State tracking
let currentAlerts = [];
let rulesCache = [];
let currentAnalyzedSample = null;

// Carousel State
let telemSlideIdx = 0;
const telemSlideTitles = [
  "Host Telemetry: RAM & Uptime (1/3)",
  "Host Telemetry: Top Processes (2/3)",
  "Host Telemetry: Active Sockets (3/3)"
];

let storageSlideIdx = 0;
const storageSlideTitles = [
  "Quarantine Vault (1/2)",
  "Monitored Honeypot Directory (2/2)"
];

// Initialize on page load
document.addEventListener("DOMContentLoaded", () => {
  // Initial data fetches
  fetchStatus();
  fetchTelemetry();
  fetchAlerts();
  fetchRules();
  fetchActivityStream();
  fetchNetworkTraffic();

  // Setup drag-and-drop listeners for malware uploader
  setupDropZone();

  // Real-time polling
  setInterval(fetchStatus, 3000);
  setInterval(fetchTelemetry, 3000);
  setInterval(fetchAlerts, 3000);
  setInterval(fetchActivityStream, 4000);
  setInterval(fetchNetworkTraffic, 6000);
});

// ============================================================================
// TAB NAVIGATION
// ============================================================================
function switchTab(tabId) {
  document.querySelectorAll(".tab-panel").forEach(panel => {
    panel.classList.remove("active");
  });
  document.querySelectorAll(".tab-btn").forEach(btn => {
    btn.classList.remove("active");
  });

  const activePanel = document.getElementById(tabId);
  if (activePanel) {
    activePanel.classList.add("active");
  }

  // Update button active state
  const btnMap = {
    "tab-monitor": "btn-tab-monitor",
    "tab-activity": "btn-tab-activity",
    "tab-analyzer": "btn-tab-analyzer",
    "tab-simulator": "btn-tab-simulator",
    "tab-protection": "btn-tab-protection",
    "tab-rules": "btn-tab-rules"
  };

  if (btnMap[tabId]) {
    const btn = document.getElementById(btnMap[tabId]);
    if (btn) btn.classList.add("active");
  }

  // Refresh tab-specific data on activation
  if (tabId === "tab-activity") {
    fetchActivityStream();
    fetchNetworkTraffic();
  }
}

// ============================================================================
// SLIDABLE CAROUSEL CONTROLLERS
// ============================================================================

// Carousel 1: Host Telemetry (3 slides)
function setTelemSlide(idx) {
  telemSlideIdx = (idx + 3) % 3;
  
  // Update slides
  for (let i = 0; i < 3; i++) {
    const slide = document.getElementById(`telem-slide-${i}`);
    const dot = document.getElementById(`telem-dot-${i}`);
    if (slide) slide.classList.toggle("active", i === telemSlideIdx);
    if (dot) dot.classList.toggle("active", i === telemSlideIdx);
  }

  // Update title
  const titleEl = document.getElementById("telem-carousel-title");
  if (titleEl) {
    titleEl.textContent = telemSlideTitles[telemSlideIdx];
  }
}

function prevTelemSlide() {
  setTelemSlide(telemSlideIdx - 1);
}

function nextTelemSlide() {
  setTelemSlide(telemSlideIdx + 1);
}

// Carousel 2: Storage & Isolation (2 slides)
function setStorageSlide(idx) {
  storageSlideIdx = (idx + 2) % 2;

  // Update slides
  for (let i = 0; i < 2; i++) {
    const slide = document.getElementById(`storage-slide-${i}`);
    const dot = document.getElementById(`storage-dot-${i}`);
    if (slide) slide.classList.toggle("active", i === storageSlideIdx);
    if (dot) dot.classList.toggle("active", i === storageSlideIdx);
  }

  // Update title
  const titleEl = document.getElementById("storage-carousel-title");
  if (titleEl) {
    titleEl.textContent = storageSlideTitles[storageSlideIdx];
  }
}

function prevStorageSlide() {
  setStorageSlide(storageSlideIdx - 1);
}

function nextStorageSlide() {
  setStorageSlide(storageSlideIdx + 1);
}

// ============================================================================
// FETCH ENDPOINT SYSTEM STATUS & LAB ISOLATION
// ============================================================================
async function fetchStatus() {
  try {
    const res = await fetch("/api/status");
    if (!res.ok) return;
    const data = await res.json();

    // Host & IP
    const hostEl = document.getElementById("metric-host-ip");
    if (hostEl) hostEl.textContent = `${data.hostname} (${data.ip})`;

    // Sensors
    const fwTag = document.getElementById("sensor-fw-tag");
    if (fwTag) {
      if (data.firewall_containment && data.firewall_containment.includes("Active")) {
        fwTag.textContent = "CONTAINMENT ACTIVE";
        fwTag.className = "status-tag active";
      } else {
        fwTag.textContent = "STANDBY";
        fwTag.className = "status-tag warning";
      }
    }

    // Monitored Lab Files (Honeypot)
    const labFiles = data.lab_files || [];
    const labCountEl = document.getElementById("lab-files-count");
    if (labCountEl) labCountEl.textContent = `${labFiles.length} file(s)`;
    
    const labListEl = document.getElementById("lab-files-list");
    if (labListEl) {
      if (labFiles.length === 0) {
        labListEl.innerHTML = `<div style="color: var(--text-dim); text-align: center; padding: 1.2rem;">Folder is clean. Zero threat artifacts.</div>`;
      } else {
        labListEl.innerHTML = labFiles.map(f => {
          const isThreat = f.includes("invoice") || f.includes("ransom") || f.includes(".exe");
          const color = isThreat ? "var(--crimson)" : "var(--text-main)";
          return `
            <div class="vault-file-item" style="border-left: 3px solid ${color};">
              <span style="font-size: 1.1rem;">⚠️</span>
              <div style="flex: 1; min-width: 0;">
                <div style="color: ${color}; font-weight: 600; font-family: var(--font-mono); font-size: 0.82rem; word-break: break-all;">
                  ${escapeHtml(f)}
                </div>
                <div style="font-size: 0.72rem; color: var(--text-dim);">Uncontained threat artifact in honeypot</div>
              </div>
            </div>
          `;
        }).join("");
      }
    }

    // Quarantined Files (Isolation Vault)
    const qFiles = data.quarantine_files || [];
    const qCountEl = document.getElementById("quarantine-files-count");
    if (qCountEl) qCountEl.textContent = `${qFiles.length} item(s)`;

    const qListEl = document.getElementById("quarantine-files-list");
    if (qListEl) {
      if (qFiles.length === 0) {
        qListEl.innerHTML = `<div style="color: var(--text-dim); text-align: center; padding: 1.2rem;">No quarantined items. Threat vault is clear.</div>`;
      } else {
        qListEl.innerHTML = qFiles.map(f => `
          <div class="vault-file-item">
            <span style="font-size: 1.1rem;">🔒</span>
            <div style="flex: 1; min-width: 0;">
              <div style="color: var(--emerald); font-weight: 600; font-family: var(--font-mono); font-size: 0.82rem; word-break: break-all;">
                ${escapeHtml(f)}
              </div>
              <div style="font-size: 0.72rem; color: var(--text-dim); margin-top: 0.2rem;">
                <span class="status-tag active" style="font-size: 0.65rem; padding: 0.1rem 0.4rem;">LOCKED &amp; ISOLATED</span>
                <span style="margin-left: 0.5rem;">C:\\SOC_Lab_Quarantine</span>
              </div>
            </div>
          </div>
        `).join("");
      }
    }

    // Threat level calculation
    const threatLevelEl = document.getElementById("metric-threat-level");
    const threatSubEl = document.getElementById("metric-threat-sub");
    const beaconEl = document.getElementById("system-status-beacon");
    const beaconTextEl = document.getElementById("system-status-text");

    const activeThreats = currentAlerts.filter(a => a.status === "Active");
    if (activeThreats.length > 0) {
      const hasCritical = activeThreats.some(a => a.severity === "CRITICAL");
      if (hasCritical) {
        if (threatLevelEl) {
          threatLevelEl.textContent = "CRITICAL";
          threatLevelEl.style.color = "var(--crimson)";
        }
        if (threatSubEl) threatSubEl.textContent = `${activeThreats.length} Active Threat(s) Detected!`;
        if (beaconEl) {
          beaconEl.style.borderColor = "var(--crimson)";
          beaconEl.style.background = "rgba(255, 56, 96, 0.15)";
          beaconEl.style.color = "var(--crimson)";
        }
        if (beaconTextEl) beaconTextEl.textContent = "INTRUSION DETECTED";
      } else {
        if (threatLevelEl) {
          threatLevelEl.textContent = "ELEVATED";
          threatLevelEl.style.color = "var(--amber)";
        }
        if (threatSubEl) threatSubEl.textContent = `${activeThreats.length} Suspicious Event(s)`;
        if (beaconEl) {
          beaconEl.style.borderColor = "var(--amber)";
          beaconEl.style.background = "rgba(255, 184, 0, 0.15)";
          beaconEl.style.color = "var(--amber)";
        }
        if (beaconTextEl) beaconTextEl.textContent = "THREAT ELEVATED";
      }
    } else {
      if (threatLevelEl) {
        threatLevelEl.textContent = "NORMAL";
        threatLevelEl.style.color = "var(--emerald)";
      }
      if (threatSubEl) threatSubEl.textContent = "Zero uncontained intrusions";
      if (beaconEl) {
        beaconEl.style.borderColor = "var(--emerald)";
        beaconEl.style.background = "rgba(0, 255, 157, 0.12)";
        beaconEl.style.color = "var(--emerald)";
      }
      if (beaconTextEl) beaconTextEl.textContent = "SHIELD ACTIVE";
    }

  } catch (err) {
    console.error("Status fetch error:", err);
  }
}

// ============================================================================
// FETCH HARDWARE & PROCESS TELEMETRY
// ============================================================================
async function fetchTelemetry() {
  try {
    const res = await fetch("/api/telemetry");
    if (!res.ok) return;
    const data = await res.json();

    // Timestamp
    if (data.timestamp) {
      const tsEl = document.getElementById("telemetry-timestamp");
      if (tsEl) tsEl.textContent = `LIVE: ${data.timestamp}`;
    }

    // Memory Meter
    if (data.memory) {
      const mem = data.memory;
      const pct = mem.percent || 0;
      const ramTextEl = document.getElementById("ram-usage-text");
      const meterFill = document.getElementById("ram-meter-fill");
      if (ramTextEl) {
        ramTextEl.textContent = `${mem.used_mb.toLocaleString()} MB / ${mem.total_mb.toLocaleString()} MB (${pct}%)`;
      }
      if (meterFill) {
        meterFill.style.width = `${Math.min(pct, 100)}%`;
        if (pct > 88) {
          meterFill.style.background = "linear-gradient(90deg, var(--amber), var(--crimson))";
        } else if (pct > 75) {
          meterFill.style.background = "linear-gradient(90deg, var(--cyan), var(--amber))";
        } else {
          meterFill.style.background = "linear-gradient(90deg, var(--cyan), var(--emerald))";
        }
      }
    }

    // Top Processes (Slide 1)
    const tbody = document.getElementById("top-processes-tbody");
    if (tbody && data.processes && data.processes.length > 0) {
      tbody.innerHTML = data.processes.map(p => `
        <tr>
          <td><strong style="color: var(--text-main); font-family: var(--font-mono);">${escapeHtml(p.Name)}</strong></td>
          <td><span style="color: var(--cyan); font-family: var(--font-mono);">${escapeHtml(String(p.Id))}</span></td>
          <td><span style="color: var(--emerald); font-family: var(--font-mono);">${p.MemMB ? p.MemMB + ' MB' : '--'}</span></td>
        </tr>
      `).join("");
    }
  } catch (err) {
    console.error("Telemetry fetch error:", err);
  }
}

// ============================================================================
// CONTINUOUS LIVE ACTIVITY SENTINEL & AUDIT STREAM
// ============================================================================
async function refreshAllSentinel(btnElement) {
  let originalHtml = "";
  if (btnElement) {
    originalHtml = btnElement.innerHTML;
    btnElement.innerHTML = `<span style="display:inline-block; animation: spin 1s linear infinite;">⏳</span> Refreshing All Telemetry...`;
    btnElement.disabled = true;
  }

  await Promise.all([
    fetchActivityStream(),
    fetchNetworkTraffic(),
    fetchTelemetry()
  ]);

  if (btnElement) {
    btnElement.innerHTML = `✓ Sentinel Updated!`;
    setTimeout(() => {
      btnElement.innerHTML = originalHtml;
      btnElement.disabled = false;
    }, 900);
  }
}

async function fetchActivityStream(btnElement) {
  let originalHtml = "";
  if (btnElement) {
    originalHtml = btnElement.innerHTML;
    btnElement.innerHTML = `⏳ Refreshing...`;
    btnElement.disabled = true;
  }

  try {
    const res = await fetch("/api/activity-stream");
    if (!res.ok) throw new Error("Failed to fetch activity stream");
    const data = await res.json();

    // Active Window & App
    const winTitle = data.active_window || data.current_window || "Desktop / Windows Shell";
    const appName = data.active_app || data.current_app || "System";

    const winTitleEl = document.getElementById("sentinel-window-title");
    if (winTitleEl) {
      winTitleEl.innerHTML = `<span style="color: var(--cyan); font-weight: 700;">[${escapeHtml(appName)}]</span> &mdash; ${escapeHtml(winTitle)}`;
    }

    // Telemetry Slide 0 App
    const telemAppEl = document.getElementById("telem-active-app");
    if (telemAppEl) {
      telemAppEl.textContent = appName;
    }

    // Uptime & Boot Time
    if (data.uptime) {
      const uptimeStr = data.uptime.uptime_human || `${data.uptime.hours || 0}h ${data.uptime.minutes || 0}m ${data.uptime.seconds || 0}s`;
      const bootStr = (data.uptime.boot_time || data.uptime.boot_timestamp || "--").replace("T", " ");

      const topUptimeEl = document.getElementById("metric-uptime-text");
      if (topUptimeEl) topUptimeEl.textContent = uptimeStr;

      const topBootEl = document.getElementById("metric-boot-text");
      if (topBootEl) topBootEl.textContent = `Booted: ${bootStr}`;

      const telemBootEl = document.getElementById("telem-boot-time");
      if (telemBootEl) telemBootEl.textContent = bootStr;

      const sentinelUptimeBadge = document.getElementById("sentinel-uptime-badge");
      if (sentinelUptimeBadge) sentinelUptimeBadge.textContent = `Live Uptime: ${uptimeStr}`;
    }

    // Audit Timeline
    const stream = data.stream || data.activities || [];
    const timelineContainer = document.getElementById("activity-timeline-container");
    if (timelineContainer) {
      if (stream.length === 0) {
        timelineContainer.innerHTML = `<div style="text-align: center; padding: 2rem; color: var(--text-dim);">Listening for endpoint activity events...</div>`;
      } else {
        timelineContainer.innerHTML = stream.map(evt => {
          const isThreat = evt.severity === "CRITICAL" || evt.severity === "HIGH" || 
            (evt.title && (evt.title.toLowerCase().includes("malware") || evt.title.toLowerCase().includes("threat") || evt.title.toLowerCase().includes("quarantin")));
          const borderStyle = isThreat 
            ? "border-left: 3px solid var(--crimson); background: rgba(255, 56, 96, 0.08);" 
            : evt.severity === "MEDIUM" 
              ? "border-left: 3px solid var(--amber);" 
              : "border-left: 3px solid var(--cyan);";
          
          const appText = evt.app || (evt.details && evt.details.app_name) || "System Sentinel";
          const titleText = evt.title || (evt.details && (evt.details.window_title || evt.details.message || evt.details.filename || evt.details.file)) || evt.type || "Activity Event";

          return `
            <div class="activity-event-item" style="${borderStyle}">
              <div class="activity-event-time">${escapeHtml((evt.timestamp || "--").replace("T", " "))}</div>
              <div class="activity-event-app">${escapeHtml(appText)}</div>
              <div class="activity-event-title">${escapeHtml(titleText)}</div>
            </div>
          `;
        }).join("");
      }
    }
  } catch (err) {
    console.error("Activity stream fetch error:", err);
  } finally {
    if (btnElement) {
      setTimeout(() => {
        btnElement.innerHTML = originalHtml;
        btnElement.disabled = false;
      }, 350);
    }
  }
}

// ============================================================================
// LIVE NETWORK TRAFFIC MONITORING
// ============================================================================
async function fetchNetworkTraffic(btnElement) {
  let originalHtml = "";
  if (btnElement) {
    originalHtml = btnElement.innerHTML;
    btnElement.innerHTML = `⏳ Scanning...`;
    btnElement.disabled = true;
  }

  try {
    const res = await fetch("/api/network-traffic");
    if (!res.ok) throw new Error("Failed to fetch network traffic");
    const conns = await res.json();

    // Update count in Telemetry slide 2
    const telemCountEl = document.getElementById("telem-sockets-count");
    if (telemCountEl) telemCountEl.textContent = `${conns.length} active sockets`;

    // Slide 2 Sockets Table
    const telemTbody = document.getElementById("telem-sockets-tbody");
    if (telemTbody) {
      if (conns.length === 0) {
        telemTbody.innerHTML = `<tr><td colspan="3" style="text-align: center; color: var(--text-dim);">No active TCP connections</td></tr>`;
      } else {
        telemTbody.innerHTML = conns.slice(0, 15).map(c => {
          const isSuspicious = c.is_suspicious || (c.remote_addr && c.remote_addr.includes("203.0.113.50")) || c.is_threat;
          const rowStyle = isSuspicious ? "background: rgba(255, 56, 96, 0.15); color: var(--crimson);" : "";
          const remoteDisplay = c.remote || c.remote_addr || "--";
          const localDisplay = c.local || c.local_addr || "--";
          return `
            <tr style="${rowStyle}">
              <td style="font-family: var(--font-mono); font-size: 0.75rem;">${escapeHtml(localDisplay)}</td>
              <td style="font-family: var(--font-mono); font-size: 0.75rem;">
                ${isSuspicious ? '🚨 ' : ''}${escapeHtml(remoteDisplay)}
              </td>
              <td><span class="status-tag ${c.state === 'ESTABLISHED' ? 'active' : 'warning'}" style="font-size: 0.65rem;">${escapeHtml(c.state)}</span></td>
            </tr>
          `;
        }).join("");
      }
    }

    // Tab 2 Network Sentinel Full Table
    const sentinelTbody = document.getElementById("sentinel-network-tbody");
    if (sentinelTbody) {
      if (conns.length === 0) {
        sentinelTbody.innerHTML = `<tr><td colspan="4" style="text-align: center; color: var(--text-dim);">No active TCP connections</td></tr>`;
      } else {
        sentinelTbody.innerHTML = conns.map(c => {
          const isSuspicious = c.is_suspicious || (c.remote_addr && c.remote_addr.includes("203.0.113.50")) || c.is_threat;
          const rowStyle = isSuspicious ? "background: rgba(255, 56, 96, 0.2); font-weight: bold;" : "";
          const remoteDisplay = c.remote || c.remote_addr || "--";
          const localDisplay = c.local || c.local_addr || "--";
          return `
            <tr style="${rowStyle}">
              <td style="font-family: var(--font-mono);">${escapeHtml(localDisplay)}</td>
              <td style="font-family: var(--font-mono);">
                ${isSuspicious ? '<strong style="color: var(--crimson);">🚨 ' + escapeHtml(remoteDisplay) + ' (C2 THREAT)</strong>' : escapeHtml(remoteDisplay)}
              </td>
              <td><span class="status-tag ${c.state === 'ESTABLISHED' ? 'active' : 'warning'}">${escapeHtml(c.state)}</span></td>
              <td style="font-family: var(--font-mono); color: var(--cyan);">${escapeHtml(c.process || '--')}</td>
            </tr>
          `;
        }).join("");
      }
    }
  } catch (err) {
    console.error("Network traffic fetch error:", err);
  } finally {
    if (btnElement) {
      setTimeout(() => {
        btnElement.innerHTML = originalHtml;
        btnElement.disabled = false;
      }, 350);
    }
  }
}

// ============================================================================
// STATIC MALWARE SANDBOX & THREAT ANALYZER
// ============================================================================
function setupDropZone() {
  const dropzone = document.getElementById("dropzone");
  if (!dropzone) return;

  ["dragenter", "dragover"].forEach(evtName => {
    dropzone.addEventListener(evtName, (e) => {
      e.preventDefault();
      e.stopPropagation();
      dropzone.classList.add("dragover");
    }, false);
  });

  ["dragleave", "drop"].forEach(evtName => {
    dropzone.addEventListener(evtName, (e) => {
      e.preventDefault();
      e.stopPropagation();
      dropzone.classList.remove("dragover");
    }, false);
  });

  dropzone.addEventListener("drop", (e) => {
    const dt = e.dataTransfer;
    const files = dt.files;
    if (files.length > 0) {
      processUploadedFile(files[0]);
    }
  });
}

function handleFileSelect(event) {
  const files = event.target.files;
  if (files.length > 0) {
    processUploadedFile(files[0]);
  }
}

function processUploadedFile(file) {
  const reader = new FileReader();
  
  // Show analyzing status
  const card = document.getElementById("analyzer-result-card");
  card.style.display = "block";
  document.getElementById("analysis-file-name").textContent = file.name;
  document.getElementById("analysis-file-size").textContent = `${(file.size / 1024).toFixed(2)} KB (${file.size} bytes)`;
  
  const verdictBadge = document.getElementById("analysis-verdict-badge");
  verdictBadge.textContent = "ANALYZING FILE ARTIFACT...";
  verdictBadge.className = "status-tag warning";

  reader.onload = async (e) => {
    const arrayBuffer = e.target.result;
    const bytes = new Uint8Array(arrayBuffer);
    
    // Convert to binary string chunk by chunk to avoid call stack limits
    let binary = "";
    const len = bytes.byteLength;
    const chunkSize = 8192;
    for (let i = 0; i < len; i += chunkSize) {
      const chunk = bytes.subarray(i, Math.min(i + chunkSize, len));
      binary += String.fromCharCode.apply(null, chunk);
    }
    const base64Data = btoa(binary);

    try {
      const res = await fetch("/api/analyze-malware", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          filename: file.name,
          content_b64: base64Data
        })
      });

      if (!res.ok) {
        throw new Error(`Analysis failed with HTTP ${res.status}`);
      }

      const report = await res.json();
      currentAnalyzedSample = {
        filename: file.name,
        content_b64: base64Data,
        report: report
      };

      displayAnalysisReport(report);

    } catch (err) {
      verdictBadge.textContent = "ANALYSIS ERROR";
      verdictBadge.className = "status-tag critical";
      alert("Failed to analyze file: " + err.message);
    }
  };

  reader.readAsArrayBuffer(file);
}

function displayAnalysisReport(report) {
  // Score & Verdict
  const score = report.threat_score || 0;
  const verdict = report.verdict || "CLEAN";
  
  const verdictBadge = document.getElementById("analysis-verdict-badge");
  verdictBadge.textContent = verdict;
  if (verdict === "MALICIOUS") {
    verdictBadge.className = "status-tag critical";
  } else if (verdict === "SUSPICIOUS") {
    verdictBadge.className = "status-tag warning";
  } else {
    verdictBadge.className = "status-tag active";
  }

  // Score Number & Meter
  const scoreNum = document.getElementById("analysis-score-number");
  scoreNum.textContent = `${score} / 100`;
  
  const gaugeFill = document.getElementById("analysis-gauge-fill");
  gaugeFill.style.width = `${score}%`;
  if (score >= 70) {
    gaugeFill.style.background = "linear-gradient(90deg, var(--amber), var(--crimson))";
    scoreNum.style.color = "var(--crimson)";
  } else if (score >= 35) {
    gaugeFill.style.background = "linear-gradient(90deg, var(--cyan), var(--amber))";
    scoreNum.style.color = "var(--amber)";
  } else {
    gaugeFill.style.background = "linear-gradient(90deg, var(--cyan), var(--emerald))";
    scoreNum.style.color = "var(--emerald)";
  }

  // Hashes
  document.getElementById("hash-md5").textContent = report.hashes.md5 || "--";
  document.getElementById("hash-sha1").textContent = report.hashes.sha1 || "--";
  document.getElementById("hash-sha256").textContent = report.hashes.sha256 || "--";

  // Entropy
  const ent = report.entropy || 0;
  document.getElementById("entropy-value").textContent = ent.toFixed(2);
  const entEval = document.getElementById("entropy-eval");
  if (ent > 7.2) {
    entEval.innerHTML = `<strong style="color: var(--crimson);">High Entropy: Packed, encrypted, or compressed payload!</strong>`;
  } else if (ent > 6.0) {
    entEval.innerHTML = `<span style="color: var(--amber);">Moderate Entropy: Compiled executable or code bundle.</span>`;
  } else {
    entEval.innerHTML = `<span style="color: var(--emerald);">Normal Entropy: Plaintext script or uncompressed data.</span>`;
  }

  // Matched Indicators
  const indList = document.getElementById("analysis-indicators-list");
  if (!report.indicators || report.indicators.length === 0) {
    indList.innerHTML = `<span style="color: var(--emerald); font-size: 0.85rem;">Zero known threat indicators or suspicious APIs matched. Clean artifact.</span>`;
  } else {
    indList.innerHTML = report.indicators.map(ind => `
      <div style="background: rgba(255, 56, 96, 0.1); border-left: 3px solid var(--crimson); padding: 0.45rem 0.8rem; border-radius: 4px; font-size: 0.82rem;">
        <strong style="color: var(--crimson);">⚠️ ${escapeHtml(ind.name || 'Threat Indicator')}</strong>: 
        <span style="color: var(--text-main);">${escapeHtml(ind.desc || ind.pattern || '')}</span>
      </div>
    `).join("");
  }

  // Extracted Strings
  const stringsBox = document.getElementById("analysis-strings-preview");
  if (report.sample_strings && report.sample_strings.length > 0) {
    stringsBox.textContent = report.sample_strings.join("\n");
  } else {
    stringsBox.textContent = "(No printable ASCII strings extracted)";
  }
}

async function quarantineAnalyzedSample() {
  if (!currentAnalyzedSample) {
    alert("Please upload and analyze a file first.");
    return;
  }

  try {
    const res = await fetch("/api/quarantine-sample", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        filename: currentAnalyzedSample.filename,
        content_b64: currentAnalyzedSample.content_b64
      })
    });

    const data = await res.json();
    if (res.ok) {
      alert(`[🔒 VAULT QUARANTINE SUCCESS]\n${data.message}\nSaved as: ${data.vault_path}`);
      fetchStatus();
      fetchAlerts();
      fetchActivityStream();
    } else {
      alert("Quarantine failed: " + (data.error || "Unknown server error"));
    }
  } catch (err) {
    alert("Quarantine request failed: " + err);
  }
}

function copyHash(elementId) {
  const el = document.getElementById(elementId);
  if (!el) return;
  const text = el.textContent;
  navigator.clipboard.writeText(text).then(() => {
    alert(`Copied hash to clipboard:\n${text}`);
  }).catch(() => {
    prompt("Copy hash manually:", text);
  });
}

// ============================================================================
// FETCH ALERTS
// ============================================================================
async function fetchAlerts() {
  try {
    const res = await fetch("/api/alerts");
    if (!res.ok) return;
    const alerts = await res.json();
    currentAlerts = alerts;

    const countEl = document.getElementById("metric-alerts-count");
    if (countEl) countEl.textContent = alerts.filter(a => a.status === "Active").length;
    renderAlertFeed(alerts);
  } catch (err) {
    console.error("Alerts fetch error:", err);
  }
}

// RENDER ALERT FEED
function renderAlertFeed(alerts) {
  const container = document.getElementById("alert-feed-container");
  if (!container) return;

  if (!alerts || alerts.length === 0) {
    container.innerHTML = `
      <div style="text-align: center; padding: 3rem 1rem; color: var(--text-muted);">
        <svg width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" style="margin-bottom: 1rem; opacity: 0.5;"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><path d="M9 12l2 2 4-4"/></svg>
        <h4>No Active Threat Alerts</h4>
        <p style="font-size: 0.85rem; margin-top: 0.4rem;">Switch to the <strong>Attack Simulator Lab</strong> tab to trigger test security events.</p>
      </div>
    `;
    return;
  }

  container.innerHTML = alerts.map((a, index) => {
    const sevClass = a.severity.toLowerCase();
    return `
      <div class="alert-card ${sevClass}" onclick="openAlertModal(${index})">
        <div class="alert-card-top">
          <div style="display: flex; align-items: center; gap: 0.6rem;">
            <span class="status-tag ${sevClass === 'critical' ? 'critical' : sevClass === 'high' ? 'critical' : 'warning'}">${escapeHtml(a.severity)}</span>
            <span class="mitre-badge">${escapeHtml(a.mitre)}</span>
            <span style="font-size: 0.75rem; color: var(--text-dim); font-family: var(--font-mono);">Rule ${escapeHtml(a.rule_id)}</span>
          </div>
          <span style="font-size: 0.75rem; color: var(--text-dim); font-family: var(--font-mono);">${escapeHtml(a.time)}</span>
        </div>
        <div class="alert-title">${escapeHtml(a.title)}</div>
        <div class="alert-meta" style="margin-top: 0.5rem;">
          <span>Status: <strong style="color: ${a.status === 'Active' ? 'var(--crimson)' : 'var(--emerald)'};">${escapeHtml(a.status)}</strong></span>
          <span>Click to view forensic evidence &rarr;</span>
        </div>
      </div>
    `;
  }).join("");
}

// ============================================================================
// FETCH RULES FOR TAB 6
// ============================================================================
async function fetchRules() {
  try {
    const res = await fetch("/api/rules");
    if (!res.ok) return;
    const rules = await res.json();
    rulesCache = rules;

    const container = document.getElementById("rules-table-container");
    if (!container) return;

    container.innerHTML = `
      <table>
        <thead>
          <tr>
            <th>Rule ID</th>
            <th>Severity</th>
            <th>MITRE ATT&CK</th>
            <th>Detection Name &amp; Description</th>
            <th>Sensor Trigger</th>
            <th>Indicator Pattern</th>
          </tr>
        </thead>
        <tbody>
          ${rules.map(r => `
            <tr>
              <td><strong style="color: var(--cyan); font-family: var(--font-mono);">${escapeHtml(r.id)}</strong></td>
              <td><span class="status-tag ${r.severity === 'CRITICAL' ? 'critical' : r.severity === 'HIGH' ? 'critical' : 'warning'}">Level ${escapeHtml(String(r.level))} (${escapeHtml(r.severity)})</span></td>
              <td><span class="mitre-badge">${escapeHtml(r.mitre)} (${escapeHtml(r.tactic)})</span></td>
              <td><strong>${escapeHtml(r.name)}</strong></td>
              <td style="font-size: 0.82rem; color: var(--text-muted);">${escapeHtml(r.trigger)}</td>
              <td><code style="font-size: 0.78rem;">${escapeHtml(r.pattern)}</code></td>
            </tr>
          `).join("")}
        </tbody>
      </table>
    `;
  } catch (err) {
    console.error("Rules fetch error:", err);
  }
}

// ============================================================================
// SIMULATION ENGINE HANDLERS
// ============================================================================
async function runSimulation(testType) {
  const terminal = document.getElementById("terminal-console");
  if (!terminal) return;

  terminal.textContent += `\n\n[*] Launching Simulation Test [${testType}] in background...`;
  terminal.scrollTop = terminal.scrollHeight;

  try {
    const res = await fetch("/api/simulate", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ test: testType })
    });
    const data = await res.json();
    terminal.textContent += `\n${data.output || "[+] Simulation completed."}`;
    terminal.textContent += `\n[+] ${data.alerts_generated} Alert(s) generated & indexed!`;

    // If 'all', also run auth brute-force test so all scenarios execute
    if (testType === "all") {
      terminal.textContent += `\n\n[*] Triggering Test 5 (Brute-Force Authentication)...`;
      terminal.scrollTop = terminal.scrollHeight;
      const resAuth = await fetch("/api/simulate-auth", {
        method: "POST",
        headers: { "Content-Type": "application/json" }
      });
      const dataAuth = await resAuth.json();
      terminal.textContent += `\n${dataAuth.output || "[+] Brute-force simulation completed."}`;
      terminal.textContent += `\n[+] Complete Threat Suite Executed! 5 Alert types active.`;
    }

    terminal.scrollTop = terminal.scrollHeight;

    // Refresh telemetry and alerts
    fetchAlerts();
    fetchStatus();
    fetchActivityStream();
  } catch (err) {
    terminal.textContent += `\n[-] Simulation error: ${err}`;
  }
}

async function runAuthSimulation() {
  const terminal = document.getElementById("terminal-console");
  if (!terminal) return;

  terminal.textContent += `\n\n[*] Launching Brute-Force Authentication Test (4 rapid failed logons)...`;
  terminal.scrollTop = terminal.scrollHeight;

  try {
    const res = await fetch("/api/simulate-auth", {
      method: "POST",
      headers: { "Content-Type": "application/json" }
    });
    const data = await res.json();
    terminal.textContent += `\n${data.output || "[+] Brute-force simulation completed."}`;
    terminal.textContent += `\n[+] Alert 100006 generated & indexed!`;
    terminal.scrollTop = terminal.scrollHeight;

    fetchAlerts();
    fetchStatus();
    fetchActivityStream();
  } catch (err) {
    terminal.textContent += `\n[-] Simulation error: ${err}`;
  }
}

async function triggerContainment() {
  const terminal = document.getElementById("terminal-console");
  if (!terminal) return;

  terminal.textContent += `\n\n[🛡️] INITIATING DEFENSIVE CONTAINMENT PROTOCOL...`;
  terminal.scrollTop = terminal.scrollHeight;

  try {
    const res = await fetch("/api/containment", {
      method: "POST",
      headers: { "Content-Type": "application/json" }
    });
    const data = await res.json();
    data.actions.forEach(act => {
      terminal.textContent += `\n[+] ${act}`;
    });
    terminal.textContent += `\n[+] Status: ${data.status}`;
    terminal.scrollTop = terminal.scrollHeight;

    fetchAlerts();
    fetchStatus();
    fetchActivityStream();
  } catch (err) {
    terminal.textContent += `\n[-] Containment error: ${err}`;
  }
}

function clearTerminal() {
  const terminal = document.getElementById("terminal-console");
  if (terminal) terminal.textContent = "[*] Terminal cleared.";
}

async function clearAlerts() {
  await fetch("/api/clear", { method: "POST" });
  fetchAlerts();
  fetchStatus();
  fetchActivityStream();
}

// ============================================================================
// FORENSIC MODAL
// ============================================================================
function openAlertModal(index) {
  const alert = currentAlerts[index];
  if (!alert) return;

  document.getElementById("modal-alert-title").textContent = alert.title;
  document.getElementById("modal-alert-meta").textContent = `Time: ${alert.time} | MITRE ATT&CK: ${alert.mitre} | Severity: ${alert.severity}`;
  document.getElementById("modal-alert-json").textContent = JSON.stringify(alert, null, 2);
  document.getElementById("forensic-modal").classList.add("active");
}

function closeModal(event) {
  document.getElementById("forensic-modal").classList.remove("active");
}

function escapeHtml(str) {
  if (!str) return "";
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}
