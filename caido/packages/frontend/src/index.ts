/**
 * Titus Secret Scanner - Caido Frontend Plugin
 *
 * Provides a "Titus" tab in the Caido UI showing:
 *   - Scanner status and statistics
 *   - Findings table with rule name, secret preview, URL, severity
 *   - Settings toggles for passive scanning, request scanning, scope filtering
 */

import type { Caido } from "@caido/sdk-frontend";
import type { API } from "titus-backend";

type SDK = Caido<API>;

// --- Severity badge colors ---
const SEVERITY_COLORS: Record<string, string> = {
  high: "#e74c3c",
  medium: "#f39c12",
  low: "#3498db",
  info: "#95a5a6",
};

// --- Build the UI ---

function createPluginPage(sdk: SDK): HTMLElement {
  const container = document.createElement("div");
  container.className = "titus-container";

  // Header
  const header = document.createElement("div");
  header.className = "titus-header";
  header.innerHTML = `
    <h2>Titus Secret Scanner</h2>
    <p class="titus-subtitle">Scanning HTTP traffic for secrets with 444+ detection rules</p>
  `;
  container.appendChild(header);

  // Stats bar
  const statsBar = document.createElement("div");
  statsBar.className = "titus-stats";
  statsBar.id = "titus-stats";
  statsBar.innerHTML = `
    <div class="titus-stat">
      <span class="titus-stat-label">Status</span>
      <span class="titus-stat-value" id="titus-status">Initializing...</span>
    </div>
    <div class="titus-stat">
      <span class="titus-stat-label">Version</span>
      <span class="titus-stat-value" id="titus-version">-</span>
    </div>
    <div class="titus-stat">
      <span class="titus-stat-label">Responses Scanned</span>
      <span class="titus-stat-value" id="titus-scanned">0</span>
    </div>
    <div class="titus-stat">
      <span class="titus-stat-label">Total Hits</span>
      <span class="titus-stat-value" id="titus-total">0</span>
    </div>
    <div class="titus-stat">
      <span class="titus-stat-label">Unique Findings</span>
      <span class="titus-stat-value" id="titus-unique">0</span>
    </div>
  `;
  container.appendChild(statsBar);

  // Controls
  const controls = document.createElement("div");
  controls.className = "titus-controls";

  const passiveToggle = createToggle(
    "Passive Scan",
    "titus-passive",
    true,
    (enabled) => sdk.backend.setPassiveScan(enabled)
  );
  controls.appendChild(passiveToggle);

  const requestToggle = createToggle(
    "Scan Requests",
    "titus-requests",
    false,
    (enabled) => sdk.backend.setScanRequests(enabled)
  );
  controls.appendChild(requestToggle);

  const scopeToggle = createToggle(
    "Scope Only",
    "titus-scope",
    false,
    (enabled) => sdk.backend.setScopeOnly(enabled)
  );
  controls.appendChild(scopeToggle);

  const clearBtn = document.createElement("button");
  clearBtn.className = "titus-btn titus-btn-danger";
  clearBtn.textContent = "Clear Findings";
  clearBtn.addEventListener("click", async () => {
    await sdk.backend.clearFindings();
    refreshFindings(sdk);
  });
  controls.appendChild(clearBtn);

  const refreshBtn = document.createElement("button");
  refreshBtn.className = "titus-btn";
  refreshBtn.textContent = "Refresh";
  refreshBtn.addEventListener("click", () => {
    refreshStats(sdk);
    refreshFindings(sdk);
  });
  controls.appendChild(refreshBtn);

  container.appendChild(controls);

  // Findings table
  const tableContainer = document.createElement("div");
  tableContainer.className = "titus-table-container";
  tableContainer.innerHTML = `
    <table class="titus-table">
      <thead>
        <tr>
          <th>Severity</th>
          <th>Rule</th>
          <th>Secret</th>
          <th>Host</th>
          <th>URL</th>
          <th>Count</th>
          <th>First Seen</th>
        </tr>
      </thead>
      <tbody id="titus-findings-body">
        <tr><td colspan="7" class="titus-empty">No findings yet. Secrets will appear here as HTTP traffic is scanned.</td></tr>
      </tbody>
    </table>
  `;
  container.appendChild(tableContainer);

  return container;
}

function createToggle(
  label: string,
  id: string,
  defaultChecked: boolean,
  onChange: (enabled: boolean) => void
): HTMLElement {
  const wrapper = document.createElement("label");
  wrapper.className = "titus-toggle";
  wrapper.htmlFor = id;

  const input = document.createElement("input");
  input.type = "checkbox";
  input.id = id;
  input.checked = defaultChecked;
  input.addEventListener("change", () => onChange(input.checked));

  const span = document.createElement("span");
  span.textContent = label;

  wrapper.appendChild(input);
  wrapper.appendChild(span);
  return wrapper;
}

// --- Data refresh ---

async function refreshStats(sdk: SDK): Promise<void> {
  try {
    const stats = await sdk.backend.getStats();

    const statusEl = document.getElementById("titus-status");
    if (statusEl) {
      statusEl.textContent = stats.isRunning ? "Running" : "Stopped";
      statusEl.style.color = stats.isRunning ? "#2ecc71" : "#e74c3c";
    }

    const versionEl = document.getElementById("titus-version");
    if (versionEl) versionEl.textContent = stats.titusVersion;

    const scannedEl = document.getElementById("titus-scanned");
    if (scannedEl) scannedEl.textContent = String(stats.totalScanned);

    const totalEl = document.getElementById("titus-total");
    if (totalEl) totalEl.textContent = String(stats.totalFindings);

    const uniqueEl = document.getElementById("titus-unique");
    if (uniqueEl) uniqueEl.textContent = String(stats.uniqueFindings);
  } catch {
    // Backend may not be ready yet
  }
}

async function refreshFindings(sdk: SDK): Promise<void> {
  try {
    const findings = await sdk.backend.getFindings();
    const tbody = document.getElementById("titus-findings-body");
    if (!tbody) return;

    if (!findings || findings.length === 0) {
      tbody.innerHTML =
        '<tr><td colspan="7" class="titus-empty">No findings yet. Secrets will appear here as HTTP traffic is scanned.</td></tr>';
      return;
    }

    // Sort by first seen (newest first)
    const sorted = [...findings].sort(
      (a, b) =>
        new Date(b.firstSeen).getTime() - new Date(a.firstSeen).getTime()
    );

    tbody.innerHTML = sorted
      .map((f) => {
        const severity = getSeverityFromRuleId(f.ruleId);
        const color = SEVERITY_COLORS[severity] ?? SEVERITY_COLORS.info;
        const time = new Date(f.firstSeen).toLocaleTimeString();

        return `
        <tr>
          <td><span class="titus-severity" style="background:${color}">${severity.toUpperCase()}</span></td>
          <td class="titus-rule" title="${escapeHtml(f.ruleId)}">${escapeHtml(f.ruleName)}</td>
          <td class="titus-secret"><code>${escapeHtml(f.secretPreview)}</code></td>
          <td>${escapeHtml(f.host)}</td>
          <td class="titus-url" title="${escapeHtml(f.url)}">${escapeHtml(truncate(f.url, 60))}</td>
          <td>${f.occurrenceCount}</td>
          <td>${time}</td>
        </tr>
      `;
      })
      .join("");
  } catch {
    // Backend may not be ready yet
  }
}

function getSeverityFromRuleId(ruleId: string): string {
  const lower = ruleId.toLowerCase();
  const high = [
    "aws",
    "azure",
    "gcp",
    "auth",
    "oauth",
    "jwt",
    "database",
    "db",
    "postgres",
    "mysql",
    "mongodb",
    "private",
    "ssh",
    "rsa",
  ];
  if (high.some((c) => lower.includes(c))) return "high";

  const medium = [
    "slack",
    "github",
    "gitlab",
    "npm",
    "api",
    "password",
    "secret",
  ];
  if (medium.some((c) => lower.includes(c))) return "medium";

  if (lower.includes("generic")) return "low";
  return "medium";
}

function escapeHtml(str: string): string {
  return str
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

function truncate(str: string, maxLen: number): string {
  return str.length > maxLen ? str.substring(0, maxLen) + "..." : str;
}

// --- Plugin init ---

export function init(sdk: SDK) {
  // Register the Titus page
  const page = createPluginPage(sdk);

  sdk.navigation.addPage("/titus", {
    body: page,
  });

  sdk.sidebar.registerItem("Titus", "/titus", {
    icon: "fas fa-key",
  });

  // Listen for new findings from backend
  sdk.backend.onEvent("newFinding" as any, () => {
    refreshStats(sdk);
    refreshFindings(sdk);
  });

  // Periodic stats refresh
  setInterval(() => refreshStats(sdk), 5000);

  // Initial data load
  setTimeout(() => {
    refreshStats(sdk);
    refreshFindings(sdk);
  }, 2000);
}
