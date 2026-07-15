import { API_BASE, reportResult, renderAnalysisResult, renderError, renderPending, setCardStatus } from "../app.js";

export function init() {
  const form = document.getElementById("phishing-form");
  const textarea = document.getElementById("phishing-input");
  const button = document.getElementById("phishing-submit");
  const resultEl = document.getElementById("phishing-result");
  const statusPill = document.getElementById("phishing-status-pill");

  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    const email_text = textarea.value.trim();
    if (!email_text) return;

    button.disabled = true;
    const originalLabel = button.textContent;
    button.textContent = "Analyzing…";
    renderPending(resultEl, "Running phishing heuristics…");

    try {
      const res = await fetch(`${API_BASE}/api/phishing/analyze`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email_text }),
      });
      if (!res.ok) throw new Error(`API error ${res.status}`);
      const data = await res.json();
      renderAnalysisResult(resultEl, data);
      setCardStatus(statusPill, data.status);
      reportResult("phishing", data);
    } catch (err) {
      renderError(resultEl, `Analysis failed — is the backend running on :8000? (${err.message})`);
    } finally {
      button.disabled = false;
      button.textContent = originalLabel;
    }
  });
}
