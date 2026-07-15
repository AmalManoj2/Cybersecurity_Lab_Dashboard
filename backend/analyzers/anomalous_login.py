"""
Anomalous login detector.

Compares a "current" login event against the user's login "history" to
flag impossible travel, new countries/devices, off-hours activity, and
excessive failed attempts. Pure function, no external geo/IP lookups —
lat/lon/country/device are expected to already be resolved by the caller
(the frontend's simulated login events, in this project's case).
"""

import math
from datetime import datetime

# Fastest plausible commercial travel speed. Any implied speed above this
# between two logins means the same person could not physically have
# traveled between those two locations in that time window.
IMPOSSIBLE_TRAVEL_SPEED_KMH = 900

EARTH_RADIUS_KM = 6371.0


def _status(score: int) -> str:
    if score >= 75:
        return "Critical"
    if score >= 50:
        return "High"
    if score >= 25:
        return "Medium"
    return "Low"


def _parse_timestamp(ts: str) -> datetime:
    """Parse an ISO-8601 timestamp, tolerating a trailing 'Z' (UTC) which
    Python's fromisoformat doesn't accept directly."""
    return datetime.fromisoformat(ts.replace("Z", "+00:00"))


def _haversine_km(lat1, lon1, lat2, lon2) -> float:
    """Great-circle distance between two lat/lon points, in kilometers."""
    phi1, phi2 = math.radians(lat1), math.radians(lat2)
    dphi = math.radians(lat2 - lat1)
    dlambda = math.radians(lon2 - lon1)
    a = math.sin(dphi / 2) ** 2 + math.cos(phi1) * math.cos(phi2) * math.sin(dlambda / 2) ** 2
    return 2 * EARTH_RADIUS_KM * math.asin(math.sqrt(a))


def analyze_login(login_metadata: dict) -> dict:
    """
    Analyze a login event against the account's login history.
    Expects: {"current": {timestamp, ip, country, lat, lon, device,
    failed_attempts?}, "history": [ ...same shape..., oldest first ]}

    Returns a dict with:
      - risk_score: int 0-100, higher = more anomalous
      - status: "Low" | "Medium" | "High" | "Critical"
      - flags: list of {name, description, weight} for every heuristic that fired
      - impossible_travel: bool
      - distance_km / speed_kmh: floats, or None if there's no prior login to compare against
    """
    current = (login_metadata or {}).get("current") or {}
    history = (login_metadata or {}).get("history") or []

    flags = []
    score = 0
    impossible_travel = False
    distance_km = None
    speed_kmh = None

    def flag(name, description, weight):
        nonlocal score
        score += weight
        flags.append({"name": name, "description": description, "weight": weight})

    # --- Impossible travel: compare against the most recent prior login ---
    if history and all(k in current for k in ("timestamp", "lat", "lon")):
        previous = history[-1]
        if all(k in previous for k in ("timestamp", "lat", "lon")):
            try:
                t_curr = _parse_timestamp(current["timestamp"])
                t_prev = _parse_timestamp(previous["timestamp"])
                hours = abs((t_curr - t_prev).total_seconds()) / 3600.0
                distance_km = _haversine_km(
                    previous["lat"], previous["lon"], current["lat"], current["lon"]
                )
                if hours > 0:
                    speed_kmh = distance_km / hours
                    if speed_kmh > IMPOSSIBLE_TRAVEL_SPEED_KMH:
                        impossible_travel = True
                        flag(
                            "impossible_travel",
                            f"Implied travel speed of {speed_kmh:.0f} km/h between "
                            f"consecutive logins ({distance_km:.0f} km in {hours:.2f}h) "
                            "exceeds the fastest plausible commercial travel speed.",
                            40,
                        )
                elif distance_km > 50:
                    # Same instant (or effectively so) but a large distance apart —
                    # can't compute a finite speed, but the distance alone is damning.
                    impossible_travel = True
                    flag(
                        "impossible_travel",
                        f"Two logins {distance_km:.0f} km apart occurred at "
                        "effectively the same timestamp.",
                        40,
                    )
            except (ValueError, TypeError):
                pass  # unparseable timestamps — skip this heuristic rather than guess

    # --- New country ---------------------------------------------------------
    known_countries = {h.get("country") for h in history if h.get("country")}
    if current.get("country") and known_countries and current["country"] not in known_countries:
        flag(
            "new_country",
            f"Login originates from '{current['country']}', a country never "
            "seen before in this account's login history.",
            20,
        )

    # --- New device ---------------------------------------------------------
    known_devices = {h.get("device") for h in history if h.get("device")}
    if current.get("device") and known_devices and current["device"] not in known_devices:
        flag(
            "new_device",
            f"Login uses device/user-agent '{current['device']}', never "
            "seen before in this account's login history.",
            15,
        )

    # --- Off-hours login -------------------------------------------------
    if current.get("timestamp"):
        try:
            hour = _parse_timestamp(current["timestamp"]).hour
            if 1 <= hour <= 5:
                flag(
                    "off_hours_login",
                    f"Login occurred at {hour:02d}:00, outside typical "
                    "waking hours (1am-5am window).",
                    10,
                )
        except (ValueError, TypeError):
            pass

    # --- Excessive failed attempts -----------------------------------------
    if current.get("failed_attempts", 0) >= 5:
        flag(
            "excessive_failed_attempts",
            f"{current['failed_attempts']} failed attempts preceded this "
            "login, consistent with brute-force or credential-stuffing.",
            25,
        )

    score = max(0, min(100, score))
    return {
        "risk_score": score,
        "status": _status(score),
        "flags": flags,
        "impossible_travel": impossible_travel,
        "distance_km": round(distance_km, 1) if distance_km is not None else None,
        "speed_kmh": round(speed_kmh, 1) if speed_kmh is not None else None,
    }
