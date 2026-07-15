"""
Phishing email analyzer.

Scores raw email text (subject + body pasted together, no parsed headers)
against a set of independent heuristics. Each heuristic that fires
contributes a fixed weight to `risk_score`; weights are summed and clamped
to the 0-100 range, then mapped to a human status label. This mirrors how a
simple rule-based phishing filter works in practice: no single signal is
proof of phishing, but several signals firing together push the score up
fast (e.g. urgency language + a raw-IP link + a brand-impersonation domain
is a very strong combined signal even though each one alone is weak).
"""

import re
from urllib.parse import urlparse

# Known brand names an attacker commonly impersonates, mapped to their real
# registrable domain. Used to catch "the email talks about PayPal but the
# link goes somewhere that isn't paypal.com" style mismatches.
KNOWN_BRANDS = {
    "paypal": "paypal.com",
    "amazon": "amazon.com",
    "microsoft": "microsoft.com",
    "apple": "apple.com",
    "netflix": "netflix.com",
    "bank of america": "bankofamerica.com",
    "wells fargo": "wellsfargo.com",
    "chase": "chase.com",
    "google": "google.com",
    "irs": "irs.gov",
}

# Leetspeak/lookalike-character normalization, digit/symbol -> real letter
# only (one direction). Applied simultaneously via str.translate rather than
# as chained .replace() calls: chaining a substitution table that contains
# both a mapping and its inverse (e.g. "0"->"o" and "o"->"0") causes later
# rules to silently undo earlier ones on the same string.
LEET_TRANSLATE = str.maketrans({
    "1": "l", "0": "o", "3": "e", "4": "a", "5": "s", "7": "t",
    "@": "a", "$": "s",
})

URL_SHORTENERS = {"bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly", "is.gd"}

URGENCY_PHRASES = [
    r"immediately", r"act now", r"urgent(?:ly)?", r"as soon as possible",
    r"within 24 hours", r"account (?:will be|has been) suspended",
    r"verify your account", r"confirm your account", r"unusual activity",
]

SENSITIVE_INFO_PHRASES = [
    r"\bpassword\b", r"\bssn\b", r"social security number",
    r"credit card", r"verify your identity", r"bank account number",
    r"\bpin\b(?:\s*number)?",
]

GENERIC_GREETINGS = [
    r"dear customer", r"dear user", r"dear valued customer",
    r"dear account holder", r"dear sir/madam",
]

THREAT_PHRASES = [
    r"account will be closed", r"legal action", r"account will be locked",
    r"permanently disabled", r"suspended permanently",
]

URL_RE = re.compile(r"https?://[^\s<>\"']+", re.IGNORECASE)


def _status(score: int) -> str:
    """Map a clamped 0-100 risk_score to a human severity label."""
    if score >= 75:
        return "Critical"
    if score >= 50:
        return "High"
    if score >= 25:
        return "Medium"
    return "Low"


DOMAIN_TOKEN_RE = re.compile(r"[a-z0-9]+")


def _domain_tokens(domain: str) -> list:
    return DOMAIN_TOKEN_RE.findall(domain)


def _brand_impersonated(domain: str, brand_token: str, real_domain: str) -> bool:
    """
    True if `domain` impersonates a brand: it is not the brand's real
    domain (or a legitimate subdomain of it), but one of its hyphen/dot-
    separated tokens equals the brand name either exactly (combosquatting,
    e.g. "amazon-security-alert.com") or via a common lookalike character
    substitution (e.g. "amaz0n-rewards.com" -> token "amaz0n" -> "amazon").
    Token-level matching — instead of a raw substring search over the
    whole domain — avoids false positives like "first" containing "irs".
    """
    if not domain:
        return False
    if domain == real_domain or domain.endswith("." + real_domain):
        return False  # the brand's real domain, or a legitimate subdomain of it
    for token in _domain_tokens(domain):
        if token == brand_token:
            return True
        normalized = token.translate(LEET_TRANSLATE).replace("rn", "m").replace("vv", "w")
        if normalized == brand_token:
            return True
    return False


WORD_TOKEN_RE = re.compile(r"[a-zA-Z0-9]+")


def _text_contains_lookalike_brand(text_lower: str):
    """
    Scan every alphanumeric word in the raw email text — not just URL
    domains — for a leetspeak/lookalike spelling of a known brand (e.g.
    "PAYPA1", "AMAZ0N"). A phishing email doesn't need a link at all to
    impersonate a brand in the visible copy, and the URL-only check above
    can't see that. Returns the matched brand name, or None.

    The `token != brand_token` guard means typing the real brand name
    normally (e.g. "PayPal") never fires — only an altered spelling that
    normalizes back to the brand name via the same leet-translation table
    used for domain checking counts as impersonation.
    """
    for token in WORD_TOKEN_RE.findall(text_lower):
        normalized = token.translate(LEET_TRANSLATE).replace("rn", "m").replace("vv", "w")
        for brand, real_domain in KNOWN_BRANDS.items():
            brand_token = real_domain.split(".")[0].replace(" ", "")
            if token != brand_token and normalized == brand_token:
                return brand
    return None


def _extract_domain(url: str) -> str:
    try:
        return (urlparse(url).netloc or "").lower().split(":")[0]
    except ValueError:
        return ""


def analyze_phishing(email_text: str) -> dict:
    """
    Analyze a raw email (subject/body as a single string) for phishing
    indicators. Returns a dict with:
      - risk_score: int 0-100, higher = more likely phishing
      - status: "Low" | "Medium" | "High" | "Critical"
      - flags: list of {name, description, weight} for every heuristic
        that fired, forming an audit trail of why the score is what it is
    """
    text = email_text or ""
    lower = text.lower()
    flags = []
    score = 0

    def flag(name, description, weight):
        nonlocal score
        score += weight
        flags.append({"name": name, "description": description, "weight": weight})

    # --- Urgency / pressure language ---------------------------------
    if any(re.search(p, lower) for p in URGENCY_PHRASES):
        flag(
            "urgency_language",
            "Email uses urgency/pressure phrasing typical of phishing (e.g. "
            "'act now', 'account suspended', 'within 24 hours').",
            15,
        )

    # --- Requests for sensitive information ---------------------------
    if any(re.search(p, lower) for p in SENSITIVE_INFO_PHRASES):
        flag(
            "sensitive_info_request",
            "Email asks the recipient to provide or verify sensitive "
            "information (password, SSN, credit card, bank details, PIN).",
            20,
        )

    # --- Generic greeting ----------------------------------------------
    if any(re.search(p, lower) for p in GENERIC_GREETINGS):
        flag(
            "generic_greeting",
            "Email uses a generic greeting ('Dear Customer') instead of "
            "the recipient's name, common in mass phishing campaigns.",
            10,
        )

    # --- Threat-of-consequence language --------------------------------
    if any(re.search(p, lower) for p in THREAT_PHRASES):
        flag(
            "threat_of_consequence",
            "Email threatens a negative consequence (account closure, "
            "legal action) to pressure the recipient into acting quickly.",
            15,
        )

    # --- Excessive urgency punctuation ----------------------------------
    if text.count("!!!") >= 1 or len(re.findall(r"[A-Z]{6,}", text)) >= 1:
        flag(
            "excessive_emphasis",
            "Email uses excessive punctuation or ALL-CAPS runs to create "
            "a false sense of urgency.",
            5,
        )

    # --- Inspect every URL found in the email ---------------------------
    urls = URL_RE.findall(text)
    seen_shortener = False
    seen_ip = False
    seen_insecure = False
    seen_lookalike = False

    for url in urls:
        parsed = urlparse(url)
        domain = _extract_domain(url)

        if not seen_ip and re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", domain):
            seen_ip = True

        if not seen_shortener and domain in URL_SHORTENERS:
            seen_shortener = True

        if not seen_insecure and parsed.scheme == "http":
            seen_insecure = True

        # Check every link's domain against every known brand, regardless
        # of whether the brand name is literally typed in the email body —
        # a phishing email doesn't need to say "PayPal" to link to
        # paypa1.com, and gating this on a text mention let obvious
        # lookalike-domain phishing through with a risk_score of 0.
        if not seen_lookalike:
            for brand, real_domain in KNOWN_BRANDS.items():
                brand_token = real_domain.split(".")[0].replace(" ", "")
                if _brand_impersonated(domain, brand_token, real_domain):
                    seen_lookalike = True
                    break

    if seen_ip:
        flag(
            "raw_ip_link",
            "Email contains a link that points directly to a raw IP "
            "address instead of a domain name, a common evasion tactic.",
            25,
        )
    if seen_shortener:
        flag(
            "url_shortener",
            "Email contains a shortened URL (bit.ly/tinyurl/etc), which "
            "hides the true destination from the recipient.",
            15,
        )
    if seen_insecure:
        flag(
            "insecure_link",
            "Email contains a plain HTTP (non-HTTPS) link.",
            10,
        )
    if seen_lookalike:
        flag(
            "brand_impersonation",
            "Email references a known brand but links to a lookalike "
            "domain that is not the brand's real domain.",
            25,
        )

    # --- Lookalike brand mention in plain body text (no URL required) ---
    text_lookalike_brand = _text_contains_lookalike_brand(lower)
    if text_lookalike_brand:
        flag(
            "brand_lookalike_in_text",
            f"Email body contains a leetspeak/lookalike spelling of the "
            f"brand '{text_lookalike_brand}' (e.g. 'PAYPA1', 'AMAZ0N') "
            "outside of any hyperlink — impersonating a brand name in the "
            "visible text is itself a phishing signal even when the email "
            "contains no link at all, or a link whose domain wasn't "
            "caught by the URL-based check above.",
            35,
        )

    score = max(0, min(100, score))
    return {"risk_score": score, "status": _status(score), "flags": flags}
