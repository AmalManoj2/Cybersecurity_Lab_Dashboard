/**
 * Main orchestrator: shared config/state, the color system every module UI
 * reuses, the Chart.js instance, and the shared result-rendering helpers.
 * Imports the four module UIs and wires them up on load.
 */
import { init as initPhishing } from "./modules/phishingUI.js";
import { init as initLinks } from "./modules/linksUI.js";
import { init as initCredentials } from "./modules/credentialsUI.js";
import { init as initLogin } from "./modules/loginUI.js";

export const API_BASE = "http://localhost:8000";

// Single source of truth for status -> color. Strictly grayscale + red +
// emerald, per the project's palette rule: red only means High/Critical,
// emerald only means Low/Safe, Medium stays a neutral gray badge rather
// than introducing a third accent color.
export const STATUS_STYLES = {
  Critical: { text: "text-red-500", ring: "ring-red-500/40", bar: "#ef4444" },
  High: { text: "text-red-400", ring: "ring-red-400/30", bar: "#f87171" },
  Medium: { text: "text-zinc-300", ring: "ring-zinc-500/30", bar: "#a1a1aa" },
  Low: { text: "text-emerald-500", ring: "ring-emerald-500/30", bar: "#10b981" },
  Safe: { text: "text-emerald-500", ring: "ring-emerald-500/30", bar: "#10b981" },
};

const UNRUN_STYLE = { text: "text-zinc-600", ring: "ring-zinc-800", bar: "#3f3f46" };

export function styleFor(status) {
  return STATUS_STYLES[status] || UNRUN_STYLE;
}

const MODULE_ORDER = ["phishing", "links", "credentials", "login"];
const MODULE_LABELS = { phishing: "Phishing", links: "URL", credentials: "Password", login: "Login" };

export const moduleResults = { phishing: null, links: null, credentials: null, login: null };

let chart = null;

// ─── HTML escaping ───────────────────────────────────────────────────────────
// Flag descriptions can embed user-supplied text the backend echoes back
// (a domain, a device string, a country name). Always escape before
// interpolating into innerHTML so a crafted input can't inject markup.
export function escapeHtml(value) {
  const div = document.createElement("div");
  div.textContent = String(value ?? "");
  return div.innerHTML;
}

// ─── Shared result rendering (used by every module UI) ───────────────────────
export function renderAnalysisResult(container, result, extraRowsHtml = "") {
  const style = styleFor(result.status);
  const flagsHtml = result.flags.length
    ? result.flags
        .map(
          (f) => `
        <li class="text-xs border-l-2 border-zinc-700 pl-2 py-1">
          <div class="flex items-start justify-between gap-2">
            <span class="font-semibold text-zinc-200">${escapeHtml(f.name)}</span>
            <span class="text-zinc-500 font-mono shrink-0">+${escapeHtml(f.weight)}</span>
          </div>
          <p class="text-zinc-400 mt-0.5 leading-snug">${escapeHtml(f.description)}</p>
        </li>`
        )
        .join("")
    : `<li class="text-xs text-emerald-500/80">No risk indicators detected.</li>`;

  container.innerHTML = `
    <div class="result-enter">
      <div class="flex items-center justify-between mb-2">
        <span class="text-3xl font-mono font-bold ${style.text}">${escapeHtml(result.risk_score)}</span>
        <span class="px-2 py-1 rounded-md text-[11px] font-mono tracking-wide ring-1 ${style.ring} ${style.text}">${escapeHtml(
    result.status.toUpperCase()
  )}</span>
      </div>
      ${extraRowsHtml}
      <ul class="space-y-2 mt-3 max-h-36 overflow-y-auto pr-1">${flagsHtml}</ul>
    </div>`;
}

export function renderError(container, message) {
  container.innerHTML = `<p class="text-xs text-red-400 font-mono">${escapeHtml(message)}</p>`;
}

export function renderPending(container, message) {
  container.innerHTML = `<p class="text-xs text-zinc-500 animate-pulse">${escapeHtml(message)}</p>`;
}

// Small status pill shown in each card's header, independent of the inline
// result pill inside renderAnalysisResult — gives an at-a-glance read
// before expanding to see the flags.
export function setCardStatus(pillEl, status) {
  const style = styleFor(status);
  pillEl.textContent = status ? status.toUpperCase() : "—";
  pillEl.className = `px-2 py-0.5 rounded-full text-[10px] font-mono tracking-wide ring-1 ${style.ring} ${style.text}`;
}

// ─── Unified hero score + Chart.js ─────────────────────────────────────────

function computeUnifiedScore() {
  const completed = MODULE_ORDER.map((k) => moduleResults[k]).filter(Boolean);
  if (completed.length === 0) return null;
  return Math.max(...completed.map((r) => r.risk_score));
}

function scoreToStatus(score) {
  if (score >= 75) return "Critical";
  if (score >= 50) return "High";
  if (score >= 25) return "Medium";
  return "Low";
}

function updateHero() {
  const score = computeUnifiedScore();
  const heroValue = document.getElementById("hero-score-value");
  const heroStatus = document.getElementById("hero-score-status");
  const heroCaption = document.getElementById("hero-score-caption");
  const heroRing = document.getElementById("hero-score-ring");
  const completedCount = MODULE_ORDER.filter((k) => moduleResults[k]).length;

  heroCaption.textContent = `Worst-case across ${completedCount}/4 completed scans`;

  if (score === null) {
    heroValue.textContent = "—";
    heroStatus.textContent = "AWAITING SCANS";
    heroValue.className = "text-7xl font-mono font-bold text-zinc-600";
    heroStatus.className = "text-sm font-mono tracking-widest text-zinc-600";
    heroRing.classList.remove("risk-glow");
    heroRing.style.color = "";
    return;
  }

  const status = scoreToStatus(score);
  const style = styleFor(status);
  heroValue.textContent = String(score);
  heroStatus.textContent = status.toUpperCase();
  heroValue.className = `text-7xl font-mono font-bold ${style.text}`;
  heroStatus.className = `text-sm font-mono tracking-widest ${style.text}`;
  heroRing.classList.add("risk-glow");
  heroRing.style.color = style.bar;
}

function initChart() {
  const ctx = document.getElementById("scoreChart");
  chart = new Chart(ctx, {
    type: "bar",
    data: {
      labels: MODULE_ORDER.map((k) => MODULE_LABELS[k]),
      datasets: [
        {
          data: MODULE_ORDER.map(() => 0),
          backgroundColor: MODULE_ORDER.map(() => UNRUN_STYLE.bar),
          borderRadius: 4,
          barThickness: 18,
        },
      ],
    },
    options: {
      indexAxis: "y",
      responsive: true,
      maintainAspectRatio: false,
      scales: {
        x: {
          min: 0,
          max: 100,
          grid: { color: "#27272a" },
          ticks: { color: "#71717a", font: { family: "monospace", size: 10 } },
        },
        y: {
          grid: { display: false },
          ticks: { color: "#d4d4d8", font: { family: "monospace", size: 11 } },
        },
      },
      plugins: {
        legend: { display: false },
        tooltip: {
          backgroundColor: "#18181b",
          borderColor: "#3f3f46",
          borderWidth: 1,
          titleColor: "#e4e4e7",
          bodyColor: "#a1a1aa",
        },
      },
    },
  });
}

function updateChart() {
  if (!chart) return;
  chart.data.datasets[0].data = MODULE_ORDER.map((k) => moduleResults[k]?.risk_score ?? 0);
  chart.data.datasets[0].backgroundColor = MODULE_ORDER.map((k) => {
    const r = moduleResults[k];
    return r ? styleFor(r.status).bar : UNRUN_STYLE.bar;
  });
  chart.update();
}

export function reportResult(moduleKey, result) {
  moduleResults[moduleKey] = result;
  updateHero();
  updateChart();
}

// ─── Backend health check ───────────────────────────────────────────────────

async function pingHealth() {
  const dot = document.getElementById("health-dot");
  const label = document.getElementById("health-label");
  try {
    const res = await fetch(`${API_BASE}/api/health`, { signal: AbortSignal.timeout(3000) });
    if (!res.ok) throw new Error("bad status");
    dot.className = "w-2 h-2 rounded-full bg-emerald-500";
    label.textContent = "backend online";
  } catch {
    dot.className = "w-2 h-2 rounded-full bg-red-500";
    label.textContent = "backend offline";
  }
}

// ─── Boot ───────────────────────────────────────────────────────────────────

function init() {
  initChart();
  updateHero();
  pingHealth();
  setInterval(pingHealth, 30000);

  initPhishing();
  initLinks();
  initCredentials();
  initLogin();
}

document.addEventListener("DOMContentLoaded", init);
