# Cyber-Sim Analyzer

A web-based cybersecurity simulation platform that analyzes phishing attempts, malicious links, weak credentials, and anomalous login behavior. It combines **automated risk detection** — deterministic, rule-based heuristic engines with a fully transparent scoring audit trail — with **interactive visualizations** that help users understand *why* a given input is risky, not just that it is.

The platform is built as a decoupled client/server application: a stateless FastAPI backend exposes four pure-function analyzers over a JSON REST API, and a vanilla-JS single-page dashboard renders the results with live Chart.js visualizations.

---

## Table of Contents

- [Core Features & Modules](#core-features--modules)
- [Project Architecture](#project-architecture)
- [Setup & Installation](#setup--installation)
- [How to Run the Application](#how-to-run-the-application)
- [API Reference](#api-reference)
- [Technology Stack](#technology-stack)

---

## Core Features & Modules

The dashboard is organized into four independent analysis labs, each backed by its own pure-function heuristic engine in `backend/analyzers/`.

### 🎣 Phishing Email & Message Analyzer
Paste the raw text content of a suspicious email or message to evaluate it for social engineering indicators. Detects:
- Urgency/pressure language ("act now", "account suspended", "within 24 hours")
- Requests for sensitive information (passwords, SSNs, credit cards, PINs)
- Generic greetings ("Dear Customer") typical of mass phishing campaigns
- Threat-of-consequence phrasing (account closure, legal action)
- Excessive emphasis (ALL-CAPS runs, repeated punctuation)
- Malicious link indicators embedded in the message (raw IP links, URL shorteners, insecure HTTP links)
- **Brand impersonation**, including lookalike spellings (e.g. `PAYPA1`, `AMAZ0N`) detected both in hyperlink domains *and* in plain body text

### 🔗 URL Scanner
Performs static, offline analysis of a single URL against a layered set of structural and reputation heuristics — no domain needs to be on an explicit blocklist to be flagged:
- Raw IP-literal hosts and `@`-symbol obfuscation tricks
- Known URL shorteners and insecure (HTTP) transport
- Suspicious/high-risk TLDs (`.zip`, `.top`, `.xyz`, `.tk`, `.ru`, `.to`, etc.)
- **Brand impersonation & combosquatting**, via leetspeak-normalized token matching (e.g. `amaz0n-rewards.com`)
- **Compound threat scoring**: a spoofed brand token stacked with a high-risk TLD (`.zip`/`.ru`) earns an additional structural penalty beyond the sum of its parts
- **Shannon entropy analysis** to catch algorithmically generated (DGA-style) domain labels
- **Structural anomaly detection**: numeric leading subdomain labels and **TLD chaining** — a real TLD string (e.g. `xyz`) stacked as a throwaway subdomain ahead of the actual TLD, a classic obfuscation trick (e.g. `123.xyz.to`)
- Excessive subdomain depth and excessive URL length

### 🔑 Password Auditor
Evaluates credential strength as an inverse risk score, combining an entropy estimate with pattern-based cracking heuristics:
- Character-class coverage (upper/lower/digit/symbol) and length thresholds
- Direct hits against a common/breached password list
- Common dictionary-word bases with predictable mutation suffixes (e.g. `Password123!`)
- **Unmutated dictionary words**: any purely alphabetic password with zero digit/symbol mutation (e.g. `mother`, `elephant`) is automatically floored to **High Risk**, reflecting how quickly a dictionary/wordlist attack tries it regardless of length
- Sequential runs, near-sequential/transposed digit runs (e.g. `12354`), keyboard walks (`qwerty`, `asdf`), and repeated-character runs
- Absolute risk floors for trivially short or short-numeric-only passwords
- A human-readable offline crack-time estimate

### 🕵️ Anomaly Detection Simulator
Simulates real-world anomalous login behavior by comparing a "current" login attempt against a historical login profile:
- **Impossible travel** detection via haversine distance / implied-speed math against the account's most recent prior login
- New-country and new-device detection against the account's login history
- Off-hours login and excessive-failed-attempts (brute-force) detection
- A split, fully manual configuration form — **Current Attempt** (IP, country, device, failed entry count) and **Historical Profile** (baseline login history preset) — layered under quick-start **Simulation Type presets** (`Normal Login`, `Impossible Travel`, `New Device`, `New Country`, `Brute Force Attempt`, `Custom / Manual`) that populate the manual fields without locking them, so any field can still be hand-tuned before submitting

---

## Project Architecture

```text
Cybersecurity-Dashboard/
├── CLAUDE.md                   # Project conventions & development rules
├── README.md                   # This file
├── backend/
│   ├── app.py                  # FastAPI entry point, routes, and Pydantic schemas
│   ├── requirements.txt        # Backend dependencies (fastapi, uvicorn, pydantic)
│   ├── venv/                   # Local Python virtual environment
│   └── analyzers/              # Modular, pure-function business logic
│       ├── __init__.py
│       ├── phishing.py         # analyze_phishing(email_text)
│       ├── links.py            # analyze_url(url_text)
│       ├── credentials.py      # analyze_password(password)
│       └── anomalous_login.py  # analyze_login(login_metadata)
└── frontend/
    ├── index.html               # Single-page dashboard UI shell
    ├── css/
    │   └── styles.css           # Styling rules
    └── js/
        ├── app.js               # Main orchestrator (imports modules, updates Chart.js)
        └── modules/              # Feature-specific API clients & UI controllers
            ├── phishingUI.js
            ├── linksUI.js
            ├── credentialsUI.js
            └── loginUI.js
```

Each file in `backend/analyzers/` exposes a single pure function that returns a structured dictionary (`risk_score`, `status`, `flags[]`, plus module-specific fields) — there is no shared or global state, and no database. `app.py` contains routing and schema validation only; all scoring logic lives in the analyzer modules.

---

## Setup & Installation

### Prerequisites

| Requirement | Version | Notes |
|---|---|---|
| Python | 3.10+ | Backend runtime |
| pip | Latest | Comes bundled with Python |
| A modern web browser | Chrome, Firefox, Edge, Safari (latest) | Frontend uses ES6 modules, Tailwind CDN, and Chart.js CDN |
| Internet access (frontend only) | — | Required once, to load the Tailwind CSS and Chart.js CDN scripts referenced in `index.html` |

No database, Node.js toolchain, or build step is required — the frontend is plain HTML/CSS/JS served as static files.

### 1. Navigate to the project directory

```bash
cd Cybersecurity-Dashboard
```

### 2. Set up the backend virtual environment

```bash
cd backend
python3 -m venv venv
```

Activate it:

```bash
# macOS / Linux
source venv/bin/activate

# Windows (PowerShell)
venv\Scripts\Activate.ps1
```

### 3. Install backend dependencies

```bash
pip install -r requirements.txt
```

This installs `fastapi`, `uvicorn[standard]`, and `pydantic`.

---

## How to Run the Application

The backend and frontend run as two independent processes. Start the backend first, then serve the frontend.

### Step 1 — Launch the backend API server

From the `backend/` directory, with the virtual environment activated:

```bash
uvicorn app:app --reload --port 8000
```

- The API will be available at **`http://localhost:8000`**
- Interactive Swagger docs are available at **`http://localhost:8000/docs`**
- `--reload` enables auto-restart on code changes; omit it in production-like usage

### Step 2 — Serve the frontend

The frontend calls the API at `http://localhost:8000` (configured in `frontend/js/app.js`), and uses ES6 module imports, which most browsers block when loaded via a bare `file://` path — so serve it over HTTP rather than double-clicking `index.html`.

From the `frontend/` directory, in a **separate terminal**:

```bash
cd frontend
python3 -m http.server 8080
```

Then open your browser to:

```
http://localhost:8080/index.html
```

The dashboard's health indicator (top-right) will confirm connectivity to the backend automatically. Because CORS is fully permissive on the backend (`allow_origins=["*"]`), the frontend can also be served on any other local static-file server or port of your choosing.

---

## API Reference

All endpoints accept and return JSON, and share a common response shape of `risk_score` (0–100), `status` (`Low` | `Medium` | `High` | `Critical`), and a `flags[]` audit trail explaining every point contributed to the score.

| Method | Endpoint | Request Body | Description |
|---|---|---|---|
| `POST` | `/api/phishing/analyze` | `{ "email_text": string }` | Analyze raw email/message text for phishing indicators |
| `POST` | `/api/links/analyze` | `{ "url": string }` | Analyze a single URL for malicious/phishing indicators |
| `POST` | `/api/credentials/analyze` | `{ "password": string }` | Audit password strength (inverse risk scoring) |
| `POST` | `/api/login/analyze` | `{ "current": {...}, "history": [...] }` | Compare a login event against historical login behavior |
| `GET` | `/api/health` | — | Health check, returns `{ "status": "ok" }` |

Full request/response schemas are available via the auto-generated Swagger UI at `http://localhost:8000/docs` once the backend is running.

---

## Technology Stack

**Backend**
- Python 3
- FastAPI + Uvicorn (ASGI server)
- Pydantic (request/response schema validation)
- Stateless JSON REST API with CORS enabled

**Frontend**
- Semantic HTML5
- Tailwind CSS (via CDN)
- Modular vanilla JavaScript (ES6 imports/exports, no build step)
- Chart.js (via CDN) for interactive dashboard statistics

**Design philosophy:** every analyzer is a deterministic, side-effect-free pure function — the same input always produces the same output, with no hidden state, mock data, or black-box scoring. Every point contributing to a risk score is explained in that response's `flags[]` array.
