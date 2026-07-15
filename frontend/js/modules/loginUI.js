import {
  API_BASE,
  reportResult,
  renderAnalysisResult,
  renderError,
  renderPending,
  setCardStatus,
} from "../app.js";

// Fixed, deterministic "current attempt" timestamp — this is a
// deterministic simulation platform, so every submission reproduces the
// same backend verdict for the same field selections rather than drifting
// with wall-clock time. Mid-afternoon UTC so the off-hours heuristic stays
// silent by default — no time-of-day control is exposed in Section A.
const CURRENT_TIMESTAMP = "2026-07-14T14:00:00Z";

// Section A "Country" resolves to a fixed lat/lon pair rather than being a
// free-text field. The backend's impossible-travel math needs real
// coordinates, and this is a deliberately offline, pure-function simulator
// with no geocoding call available — so Country is a dropdown over a small
// fixed gazetteer instead of an unresolvable free-text string.
const COUNTRY_PRESETS = {
  "United States — New York": { country: "United States", lat: 40.7128, lon: -74.006 },
  "United States — San Francisco": { country: "United States", lat: 37.7749, lon: -122.4194 },
  "United Kingdom — London": { country: "United Kingdom", lat: 51.5074, lon: -0.1278 },
  "Nigeria — Lagos": { country: "Nigeria", lat: 6.5244, lon: 3.3792 },
  "South Korea — Seoul": { country: "South Korea", lat: 37.5665, lon: 126.978 },
  "Russia — Moscow": { country: "Russia", lat: 55.7558, lon: 37.6173 },
  "Australia — Sydney": { country: "Australia", lat: -33.8688, lon: 151.2093 },
};

// Section A "Device Type". Values must match verbatim against a baseline
// profile's history device strings for the backend's known-device
// comparison to recognize a returning device.
const DEVICE_PRESETS = {
  "Chrome / Windows": "Chrome/Windows",
  "Safari / macOS": "Safari/macOS",
  "Firefox / Linux": "Firefox/Linux",
  "Mobile Safari / iOS": "Mobile Safari/iOS",
  "curl (automation script)": "curl/8.4.0",
  "python-requests (script)": "python-requests/2.31",
};

// Section B baseline login-history presets. Timestamps sit ~3 hours before
// CURRENT_TIMESTAMP on the same day, so picking a Country far from a
// profile's home city produces a realistic impossible-travel verdict
// (large distance covered in a short elapsed time).
const BASELINE_PROFILES = {
  standard_nyc: {
    label: "Standard NYC User Profile",
    history: [
      {
        timestamp: "2026-07-13T13:00:00Z",
        ip: "203.0.113.10",
        device: "Chrome/Windows",
        country: "United States",
        lat: 40.7128,
        lon: -74.006,
      },
      {
        timestamp: "2026-07-14T11:00:00Z",
        ip: "203.0.113.10",
        device: "Chrome/Windows",
        country: "United States",
        lat: 40.7128,
        lon: -74.006,
      },
    ],
  },
  sf_corporate: {
    label: "San Francisco Corporate Profile",
    history: [
      {
        timestamp: "2026-07-13T15:00:00Z",
        ip: "198.51.100.42",
        device: "Safari/macOS",
        country: "United States",
        lat: 37.7749,
        lon: -122.4194,
      },
      {
        timestamp: "2026-07-14T10:30:00Z",
        ip: "198.51.100.42",
        device: "Safari/macOS",
        country: "United States",
        lat: 37.7749,
        lon: -122.4194,
      },
    ],
  },
  no_history: {
    label: "No Active History Profile",
    history: [],
  },
};

// Named scenarios that fill in Section A/B's real, still-editable fields —
// a convenience shortcut on top of the manual form, not a replacement for
// it. Picking a scenario sets the same inputs a person would set by hand;
// nothing gets locked/disabled, so any field can still be hand-tuned
// afterward and whatever the fields hold at submit time is what's sent.
// "Custom / Manual" intentionally has no preset object — the change
// handler treats it as a no-op, leaving current field values untouched.
const SCENARIO_PRESETS = {
  normal: {
    label: "Normal Login",
    ip: "203.0.113.10",
    country: "United States — New York",
    device: "Chrome / Windows",
    failedAttempts: 0,
    baseline: "standard_nyc",
  },
  impossible_travel: {
    label: "Impossible Travel",
    ip: "45.33.12.9",
    country: "Russia — Moscow",
    device: "Chrome / Windows",
    failedAttempts: 0,
    baseline: "standard_nyc",
  },
  new_device: {
    label: "New Device",
    ip: "203.0.113.10",
    country: "United States — New York",
    device: "curl (automation script)",
    failedAttempts: 0,
    baseline: "standard_nyc",
  },
  new_country: {
    label: "New Country",
    ip: "203.0.113.10",
    country: "United Kingdom — London",
    device: "Chrome / Windows",
    failedAttempts: 0,
    baseline: "standard_nyc",
  },
  brute_force: {
    label: "Brute Force Attempt",
    ip: "203.0.113.10",
    country: "United States — New York",
    device: "Chrome / Windows",
    failedAttempts: 7,
    baseline: "standard_nyc",
  },
  custom: {
    label: "Custom / Manual",
  },
};

function populateSelect(selectEl, optionsMap) {
  selectEl.innerHTML = Object.keys(optionsMap)
    .map((label) => `<option value="${label}">${label}</option>`)
    .join("");
}

export function init() {
  const form = document.getElementById("login-form");
  const scenarioSelect = document.getElementById("login-scenario");
  const ipInput = document.getElementById("login-ip");
  const countrySelect = document.getElementById("login-country");
  const deviceSelect = document.getElementById("login-device");
  const failedInput = document.getElementById("login-failed-attempts");
  const baselineSelect = document.getElementById("login-baseline");
  const button = document.getElementById("login-submit");
  const resultEl = document.getElementById("login-result");
  const statusPill = document.getElementById("login-status-pill");

  scenarioSelect.innerHTML = Object.entries(SCENARIO_PRESETS)
    .map(([key, preset]) => `<option value="${key}">${preset.label}</option>`)
    .join("");
  populateSelect(countrySelect, COUNTRY_PRESETS);
  populateSelect(deviceSelect, DEVICE_PRESETS);
  baselineSelect.innerHTML = Object.entries(BASELINE_PROFILES)
    .map(([key, profile]) => `<option value="${key}">${profile.label}</option>`)
    .join("");

  // Defaults form a "normal" baseline out of the box: matching country,
  // matching device, no failed attempts, standard history profile.
  ipInput.value = "203.0.113.10";
  countrySelect.value = "United States — New York";
  deviceSelect.value = "Chrome / Windows";
  failedInput.value = 0;
  baselineSelect.value = "standard_nyc";
  scenarioSelect.value = "custom";

  // Fills Section A/B's real inputs from a named preset — a shortcut for
  // hand-setting the same fields, not a hidden/locked override. "custom"
  // has no preset object, so it deliberately falls through and leaves
  // whatever the fields already hold untouched.
  scenarioSelect.addEventListener("change", () => {
    const preset = SCENARIO_PRESETS[scenarioSelect.value];
    if (!preset || preset.ip === undefined) return;
    ipInput.value = preset.ip;
    countrySelect.value = preset.country;
    deviceSelect.value = preset.device;
    failedInput.value = preset.failedAttempts;
    baselineSelect.value = preset.baseline;
  });

  form.addEventListener("submit", async (event) => {
    event.preventDefault();

    const countryPreset = COUNTRY_PRESETS[countrySelect.value];
    const deviceValue = DEVICE_PRESETS[deviceSelect.value];
    const baseline = BASELINE_PROFILES[baselineSelect.value];

    // Synthesize the split Section A/B form fields into the nested
    // {current, history} shape the backend's LoginRequest schema expects.
    const payload = {
      current: {
        timestamp: CURRENT_TIMESTAMP,
        ip: ipInput.value.trim() || "203.0.113.10",
        device: deviceValue,
        failed_attempts: Number(failedInput.value) || 0,
        country: countryPreset.country,
        lat: countryPreset.lat,
        lon: countryPreset.lon,
      },
      history: baseline.history,
    };

    button.disabled = true;
    const originalLabel = button.textContent;
    button.textContent = "Checking…";
    renderPending(resultEl, "Comparing against login history…");

    try {
      const res = await fetch(`${API_BASE}/api/login/analyze`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      });
      if (!res.ok) throw new Error(`API error ${res.status}`);
      const data = await res.json();
      const distanceLabel =
        data.distance_km != null ? `${data.distance_km} km @ ${data.speed_kmh} km/h` : "no prior login to compare";
      const extra = `
        <div class="flex justify-between text-xs text-zinc-500 font-mono mb-2 gap-2">
          <span>impossible travel: ${data.impossible_travel ? "yes" : "no"}</span>
          <span class="text-right">${distanceLabel}</span>
        </div>`;
      renderAnalysisResult(resultEl, data, extra);
      setCardStatus(statusPill, data.status);
      reportResult("login", data);
    } catch (err) {
      renderError(resultEl, `Check failed — is the backend running on :8000? (${err.message})`);
    } finally {
      button.disabled = false;
      button.textContent = originalLabel;
    }
  });
}
