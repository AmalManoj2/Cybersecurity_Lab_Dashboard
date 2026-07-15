"""
FastAPI entry point for the Cyber-Sim Analyzer API.

Defines the request/response Pydantic schemas and the four analysis
routes. Route handlers are thin: validate input via a Pydantic model, hand
plain Python values to the matching pure function in `analyzers/`, and
return the resulting dict (validated against the declared response_model).
No business logic lives in this file — it's routing + schema only.
"""

from typing import List, Optional

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from analyzers.phishing import analyze_phishing
from analyzers.links import analyze_url
from analyzers.credentials import analyze_password
from analyzers.anomalous_login import analyze_login

app = FastAPI(
    title="Cyber-Sim Analyzer API",
    description="Deterministic heuristic analyzers for phishing emails, "
                 "URLs, passwords, and login anomalies.",
    version="1.0.0",
)

# The frontend is a decoupled static site (opened directly or served by a
# simple static server), so permissive CORS is appropriate for this local
# demo scope — there's no session/cookie auth to protect.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


# ─── Shared response schema pieces ─────────────────────────────────────────

class FlagDetail(BaseModel):
    name: str
    description: str
    weight: int


class AnalysisResult(BaseModel):
    risk_score: int
    status: str
    flags: List[FlagDetail]


# ─── Phishing ───────────────────────────────────────────────────────────────

class PhishingRequest(BaseModel):
    email_text: str = Field(..., min_length=1, description="Raw email subject+body text")


@app.post("/api/phishing/analyze", response_model=AnalysisResult, tags=["phishing"])
def phishing_analyze(payload: PhishingRequest) -> dict:
    return analyze_phishing(payload.email_text)


# ─── Links / URLs ───────────────────────────────────────────────────────────

class URLRequest(BaseModel):
    url: str = Field(..., min_length=1, description="A single URL to analyze")


class LinkAnalysisResult(AnalysisResult):
    parsed_domain: str


@app.post("/api/links/analyze", response_model=LinkAnalysisResult, tags=["links"])
def links_analyze(payload: URLRequest) -> dict:
    return analyze_url(payload.url)


# ─── Credentials / passwords ─────────────────────────────────────────────────

class PasswordRequest(BaseModel):
    password: str = Field(..., min_length=1)


class PasswordAnalysisResult(AnalysisResult):
    entropy_bits: float
    crack_time_estimate: str


@app.post("/api/credentials/analyze", response_model=PasswordAnalysisResult, tags=["credentials"])
def credentials_analyze(payload: PasswordRequest) -> dict:
    return analyze_password(payload.password)


# ─── Anomalous login ─────────────────────────────────────────────────────────

class LoginEvent(BaseModel):
    timestamp: str = Field(..., description="ISO-8601 timestamp")
    ip: str
    country: str
    city: Optional[str] = None
    lat: float
    lon: float
    device: str
    failed_attempts: Optional[int] = 0


class LoginRequest(BaseModel):
    current: LoginEvent
    history: List[LoginEvent] = Field(default_factory=list, description="Prior logins, oldest first")


class LoginAnalysisResult(AnalysisResult):
    impossible_travel: bool
    distance_km: Optional[float] = None
    speed_kmh: Optional[float] = None


@app.post("/api/login/analyze", response_model=LoginAnalysisResult, tags=["login"])
def login_analyze(payload: LoginRequest) -> dict:
    return analyze_login(payload.model_dump())


# ─── Health check ─────────────────────────────────────────────────────────────

@app.get("/api/health", tags=["health"])
def health() -> dict:
    return {"status": "ok"}
