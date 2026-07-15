"""
URL / link analyzer.

Parses a single URL (no network calls — this is a static, offline analysis)
and scores it against structural heuristics attackers commonly rely on:
IP-literal hosts, credential-obfuscation tricks, shortener redirection,
suspicious TLDs, brand-lookalike domains, high-entropy (DGA-style) domain
labels, insecure transport, excessive subdomains, and excessive length.
"""

import math
import re
from urllib.parse import urlparse

KNOWN_BRANDS = {
    "paypal": "paypal.com",
    "amazon": "amazon.com",
    "microsoft": "microsoft.com",
    "apple": "apple.com",
    "netflix": "netflix.com",
    "google": "google.com",
    "chase": "chase.com",
    "wellsfargo": "wellsfargo.com",
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

SUSPICIOUS_TLDS = {".zip", ".top", ".xyz", ".gq", ".tk", ".country", ".click", ".work", ".ru", ".to"}

# Subset of SUSPICIOUS_TLDS that, combined with a spoofed/lookalike brand
# token in the same domain, forms a textbook malicious-redirector pattern
# rather than two merely-independent weak signals — see the compound
# check below.
HIGH_DANGER_TLDS = {".zip", ".ru"}

# Tokens that are themselves real top-level domains. Used only to detect
# *chaining* — one of these appearing as a non-final domain label ahead of
# the actual TLD (e.g. "xyz" in "123.xyz.to") — not as a domain blocklist.
TLD_LIKE_TOKENS = {
    "com", "net", "org", "io", "co", "gov", "edu",
    "xyz", "top", "gq", "tk", "ru", "to", "zip", "click", "work", "country",
}

# Domain-label entropy above this is treated as "looks randomly generated"
# (DGA-style C2 domains, obfuscated redirectors). Typical dictionary-word
# domains sit well under this; base32/hex-looking labels sit well over it.
ENTROPY_THRESHOLD = 3.6


def _status(score: int) -> str:
    if score >= 75:
        return "Critical"
    if score >= 50:
        return "High"
    if score >= 25:
        return "Medium"
    return "Low"


def _shannon_entropy(s: str) -> float:
    """Shannon entropy (bits/char) of a string — higher means less
    predictable / more random-looking, a signal for algorithmically
    generated domains."""
    if not s:
        return 0.0
    freq = {}
    for ch in s:
        freq[ch] = freq.get(ch, 0) + 1
    length = len(s)
    return -sum((count / length) * math.log2(count / length) for count in freq.values())


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


def _has_tld_chaining(labels: list) -> bool:
    """True if a TLD-shaped token (e.g. 'xyz') appears as a non-final
    domain label ahead of the real TLD (e.g. '123.xyz.to') — stacking a
    second real TLD string as a throwaway subdomain is a structural trick
    to make a disposable domain look more complex/legitimate than a plain
    single-TLD registration. Purely structural: it fires on the *shape* of
    the label sequence, independent of any blocklist lookup, so it catches
    domains that were never seen before rather than only known-bad ones.
    """
    return any(label in TLD_LIKE_TOKENS for label in labels[:-1])


def _has_numeric_leading_label(labels: list) -> bool:
    """True if the leftmost domain label is purely digits (e.g. '123' in
    '123.xyz.to') — atypical of human-registered hostnames, common in
    algorithmically generated or disposable redirector domains.
    """
    return bool(labels) and labels[0].isdigit()


def analyze_url(url_text: str) -> dict:
    """
    Analyze a single URL for phishing/malicious indicators.
    Returns a dict with:
      - risk_score: int 0-100, higher = more suspicious
      - status: "Low" | "Medium" | "High" | "Critical"
      - flags: list of {name, description, weight} for every heuristic that fired
      - parsed_domain: the extracted hostname (empty string if unparseable)
    """
    url = (url_text or "").strip()
    flags = []
    score = 0

    def flag(name, description, weight):
        nonlocal score
        score += weight
        flags.append({"name": name, "description": description, "weight": weight})

    parsed = urlparse(url if "://" in url else f"http://{url}")
    domain = (parsed.netloc or "").lower().split(":")[0]
    domain_label = domain.split(".")[0] if domain else ""

    # --- Raw IP as host --------------------------------------------------
    if domain and re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", domain):
        flag(
            "raw_ip_host",
            "URL uses a raw IP address instead of a domain name, a common "
            "evasion tactic to avoid domain-reputation blocklists.",
            25,
        )

    # --- '@' obfuscation trick -------------------------------------------
    if "@" in url:
        flag(
            "at_symbol_obfuscation",
            "URL contains an '@' character — everything before it is "
            "ignored by browsers, letting attackers disguise the real host "
            "(e.g. https://paypal.com@evil.net actually goes to evil.net).",
            25,
        )

    # --- Shortener ----------------------------------------------------
    if domain in URL_SHORTENERS:
        flag(
            "url_shortener",
            "URL uses a known link-shortening service, which hides the "
            "true destination until the link is followed.",
            15,
        )

    # --- Suspicious TLD --------------------------------------------------
    if any(domain.endswith(tld) for tld in SUSPICIOUS_TLDS):
        flag(
            "suspicious_tld",
            "URL uses a top-level domain frequently associated with "
            "spam/phishing campaigns due to low registration cost/scrutiny.",
            15,
        )

    # --- Brand lookalike / combosquatting -----------------------------------
    lookalike_hit = False
    for brand, real_domain in KNOWN_BRANDS.items():
        brand_token = real_domain.split(".")[0]
        if _brand_impersonated(domain, brand_token, real_domain):
            flag(
                "brand_lookalike",
                f"Domain '{domain}' impersonates '{brand}' ({real_domain}) "
                "— it contains the brand name as a lookalike or combosquat "
                "token (e.g. character substitution like '1' for 'l', or "
                "the brand name plus an extra word like '-security-alert').",
                30,
            )
            lookalike_hit = True
            break

    # --- Compound structural penalty: spoofed brand token + throwaway TLD ---
    # A domain that stacks a lookalike brand token with a high-risk,
    # low-scrutiny TLD (.zip, .ru) isn't just two independent weak signals
    # added together — it's a specific, textbook malicious-redirector
    # construction (spoof the brand, register it somewhere disposable), so
    # it earns an additional structural penalty on top of each individual
    # flag rather than being scored as a simple sum of unrelated parts.
    if lookalike_hit and any(domain.endswith(tld) for tld in HIGH_DANGER_TLDS):
        flag(
            "compound_spoofing_structure",
            f"Domain '{domain}' combines a brand-lookalike token with a "
            "high-risk, disposable-registration TLD (.zip/.ru) — this "
            "specific combination is a textbook malicious-redirector "
            "pattern, not just two independently weak signals.",
            25,
        )

    # --- Domain entropy ---------------------------------------------------
    if domain_label and _shannon_entropy(domain_label) > ENTROPY_THRESHOLD:
        flag(
            "high_entropy_domain",
            "The domain label looks algorithmically generated (high "
            "character-level entropy) rather than a human-chosen name, "
            "typical of DGA/C2 or obfuscated redirect domains.",
            15,
        )

    # --- Structural anomaly: TLD-chaining / numeric subdomain labels --------
    # Even without a known-brand token or a blocklisted TLD, a domain's
    # *shape* can itself be a strong phishing/redirector signal — e.g.
    # "123.xyz.to" stacks a real-TLD-shaped subdomain ("xyz") ahead of the
    # actual TLD ("to") behind a numeric leading label, a combination no
    # brand/entropy/TLD check above individually catches.
    labels = domain.split(".") if domain else []
    if _has_tld_chaining(labels):
        flag(
            "tld_chaining",
            f"Domain '{domain}' stacks a TLD-shaped token as a subdomain "
            "label ahead of its real TLD (e.g. 'xyz' in '123.xyz.to') — a "
            "structural trick to make a disposable domain look more "
            "complex/legitimate than a plain single-TLD registration.",
            35,
        )
    if _has_numeric_leading_label(labels):
        flag(
            "numeric_subdomain_label",
            f"Domain '{domain}' has a purely numeric leading label — "
            "atypical of human-registered hostnames and common in "
            "algorithmically generated or disposable redirector domains.",
            20,
        )

    # --- Insecure transport -------------------------------------------------
    if parsed.scheme == "http":
        flag(
            "insecure_scheme",
            "URL uses plain HTTP instead of HTTPS.",
            10,
        )

    # --- Excessive subdomains -------------------------------------------------
    if domain.count(".") > 3:
        flag(
            "excessive_subdomains",
            "URL has an unusually high number of subdomain levels, often "
            "used to bury the real registrable domain or impersonate a "
            "brand (e.g. paypal.com.login.evil.net).",
            10,
        )

    # --- Excessive length -------------------------------------------------
    if len(url) > 100:
        flag(
            "excessive_length",
            "URL is unusually long, often used to obscure the destination "
            "or embed encoded payloads.",
            5,
        )

    score = max(0, min(100, score))
    return {
        "risk_score": score,
        "status": _status(score),
        "flags": flags,
        "parsed_domain": domain,
    }
