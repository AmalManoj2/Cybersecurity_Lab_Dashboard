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
  const form = document.getElementById("credentials-form");
  const input = document.getElementById("credentials-input");
  const toggleBtn = document.getElementById("credentials-toggle");
  const button = document.getElementById("credentials-submit");
  const resultEl = document.getElementById("credentials-result");
  const statusPill = document.getElementById("credentials-status-pill");

  toggleBtn.addEventListener("click", () => {
    const isHidden = input.type === "password";
    input.type = isHidden ? "text" : "password";
    toggleBtn.textContent = isHidden ? "Hide" : "Show";
  });

  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    const password = input.value;
    if (!password) return;

    button.disabled = true;
    const originalLabel = button.textContent;
    button.textContent = "Auditing…";
    renderPending(resultEl, "Scoring entropy and patterns…");

    try {
      const res = await fetch(`${API_BASE}/api/credentials/analyze`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ password }),
      });
      if (!res.ok) throw new Error(`API error ${res.status}`);
      const data = await res.json();
      const extra = `
        <div class="flex justify-between text-xs text-zinc-500 font-mono mb-2 gap-2">
          <span>entropy: ${escapeHtml(data.entropy_bits)} bits</span>
          <span class="text-right">crack time: ${escapeHtml(data.crack_time_estimate)}</span>
        </div>`;
      renderAnalysisResult(resultEl, data, extra);
      setCardStatus(statusPill, data.status);
      reportResult("credentials", data);
    } catch (err) {
      renderError(resultEl, `Audit failed — is the backend running on :8000? (${err.message})`);
    } finally {
      button.disabled = false;
      button.textContent = originalLabel;
    }
  });
}
