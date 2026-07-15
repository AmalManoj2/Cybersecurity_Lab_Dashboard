import {
  API_BASE,
  reportResult,
  renderAnalysisResult,
  renderError,
  renderPending,
  setCardStatus,
  escapeHtml,
} from "../app.js";

export function init() {
  const form = document.getElementById("links-form");
  const input = document.getElementById("links-input");
  const button = document.getElementById("links-submit");
  const resultEl = document.getElementById("links-result");
  const statusPill = document.getElementById("links-status-pill");

  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    const url = input.value.trim();
    if (!url) return;

    button.disabled = true;
    const originalLabel = button.textContent;
    button.textContent = "Scanning…";
    renderPending(resultEl, "Parsing URL structure…");

    try {
      const res = await fetch(`${API_BASE}/api/links/analyze`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url }),
      });
      if (!res.ok) throw new Error(`API error ${res.status}`);
      const data = await res.json();
      const extra = `<p class="text-xs text-zinc-500 font-mono mb-2">domain: ${escapeHtml(
        data.parsed_domain || "—"
      )}</p>`;
      renderAnalysisResult(resultEl, data, extra);
      setCardStatus(statusPill, data.status);
      reportResult("links", data);
    } catch (err) {
      renderError(resultEl, `Scan failed — is the backend running on :8000? (${err.message})`);
    } finally {
      button.disabled = false;
      button.textContent = originalLabel;
    }
  });
}
