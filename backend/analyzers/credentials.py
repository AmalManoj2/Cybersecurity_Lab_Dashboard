"""
Password / credential strength analyzer.

Unlike the other analyzers, "risk" here is the inverse of strength: a weak,
easily-guessed password gets a HIGH risk_score. Combines an entropy
estimate, character-class coverage, common-password list membership, and
pattern detection (sequential runs, keyboard walks, repeated characters)
into a single score, plus a rough crack-time estimate for context.
"""

import math
import re

# A small sample of extremely common passwords (real deployments would use
# a much larger breach-derived list like rockyou.txt; this is enough to
# demonstrate the direct-hit heuristic).
COMMON_PASSWORDS = {
    "password", "123456", "123456789", "12345678", "12345", "qwerty",
    "abc123", "password1", "111111", "123123", "admin", "letmein",
    "welcome", "monkey", "login", "iloveyou", "starwars", "dragon",
    "sunshine", "master", "football", "shadow", "michael", "superman",
    "trustno1", "1234567", "1234567890", "qwerty123", "passw0rd",
    "p@ssw0rd", "password123", "1q2w3e4r", "qazwsx", "baseball",
    "hello", "freedom", "whatever", "666666", "121212", "000000",
    # Basic numeric increments ("1" through "123456") — trivial-keyspace
    # entries that are common-password-list material in their own right,
    # not just short strings that happen to fall under a length floor.
    "1", "12", "123", "1234",
}

# Dictionary words/names that show up constantly as the *base* of real-world
# passwords, mutated with capitalization + a digit/symbol suffix to satisfy
# naive complexity rules (e.g. "Password123!", "Welcome2024!", "Summer99#").
# This is exactly the mutation pattern password-cracking rule sets (hashcat
# "best64", John the Ripper rules) are built to break in seconds — a
# password can have high theoretical entropy (all 4 char classes, 12+
# chars) and still be trivially guessable because it's a dictionary word
# with a predictable suffix, not a random string. Checked as a substring
# so it catches the base word regardless of surrounding digits/symbols.
COMMON_PASSWORD_BASES = {
    "password", "welcome", "admin", "login", "master", "dragon", "shadow",
    "football", "baseball", "monkey", "letmein", "iloveyou", "starwars",
    "superman", "sunshine", "freedom", "whatever", "princess", "summer",
    "winter", "spring", "autumn", "ninja", "tiger", "hunter", "soccer",
    "hockey", "batman", "computer", "internet", "security", "changeme",
    "default", "guest", "hello", "mustang", "cheese", "purple", "orange",
    "google", "facebook", "qwerty",
}

SEQUENTIAL_RUNS = [
    "abcdefghijklmnopqrstuvwxyz",
    "0123456789",
]

KEYBOARD_WALKS = [
    "qwerty", "asdfgh", "zxcvbn", "qazwsx", "1qaz2wsx",
]


def _status(score: int) -> str:
    if score >= 75:
        return "Critical"
    if score >= 50:
        return "High"
    if score >= 25:
        return "Medium"
    return "Low"


def _charset_size(password: str) -> int:
    """Estimate the size of the character set the password draws from,
    based on which classes of characters are actually present."""
    size = 0
    if re.search(r"[a-z]", password):
        size += 26
    if re.search(r"[A-Z]", password):
        size += 26
    if re.search(r"\d", password):
        size += 10
    if re.search(r"[^a-zA-Z0-9]", password):
        size += 33  # approx count of common printable symbols
    return size or 1


def _entropy_bits(password: str) -> float:
    """Classic entropy estimate: log2(charset_size) bits per character,
    times the number of characters. This is an upper bound — it assumes
    fully random selection from the charset, which is why the pattern-
    based heuristics below exist to catch predictable passwords that
    would otherwise score as "high entropy"."""
    if not password:
        return 0.0
    return len(password) * math.log2(_charset_size(password))


def _has_sequential_run(lower: str, run_len: int = 4) -> bool:
    for alphabet in SEQUENTIAL_RUNS:
        for i in range(len(alphabet) - run_len + 1):
            chunk = alphabet[i:i + run_len]
            if chunk in lower or chunk[::-1] in lower:
                return True
    return False


def _has_repeated_run(password: str, run_len: int = 3) -> bool:
    return bool(re.search(r"(.)\1{" + str(run_len - 1) + r",}", password))


def _is_near_sequential_digits(s: str, min_len: int = 4) -> bool:
    """True if `s` is all-digit, at least `min_len` characters, and its
    digits — sorted — form a contiguous ascending run (each value exactly
    one more than the last). This catches transposed/typo'd variants of a
    classic sequence (e.g. "12354" is "12345" with the last two digits
    swapped: sorted -> [1,2,3,4,5]) that a rigid "is '1234' a literal
    substring" regex misses entirely, without having to enumerate every
    possible transposition by hand. Drawn from the same tiny, first-guess
    keyspace as a straight sequential run, so it earns the same weight.
    """
    if len(s) < min_len or not s.isdigit():
        return False
    digits = sorted(int(c) for c in s)
    return all(b - a == 1 for a, b in zip(digits, digits[1:]))


def _crack_time_estimate(entropy_bits: float) -> str:
    """Rough offline-attack crack time assuming 10 billion guesses/sec
    (a realistic GPU-cluster hash-cracking rate for a fast hash), taking
    the average case as half the keyspace."""
    guesses_per_second = 1e10
    seconds = (2 ** entropy_bits) / 2 / guesses_per_second

    if seconds < 1:
        return "instantly"
    if seconds < 60:
        return f"{seconds:.0f} seconds"
    minutes = seconds / 60
    if minutes < 60:
        return f"{minutes:.0f} minutes"
    hours = minutes / 60
    if hours < 24:
        return f"{hours:.0f} hours"
    days = hours / 24
    if days < 365:
        return f"{days:.0f} days"
    years = days / 365
    if years < 1000:
        return f"{years:.0f} years"
    if years < 1_000_000:
        return f"{years / 1000:.0f} thousand years"
    return "billions of years"


def analyze_password(password: str) -> dict:
    """
    Analyze password strength. Returns a dict with:
      - risk_score: int 0-100, higher = weaker/riskier password
      - status: "Low" | "Medium" | "High" | "Critical"
      - flags: list of {name, description, weight} for every heuristic that fired
      - entropy_bits: estimated entropy in bits
      - crack_time_estimate: human-readable offline crack-time estimate
    """
    pw = password or ""
    lower = pw.lower()
    flags = []
    score = 0

    def flag(name, description, weight):
        nonlocal score
        score += weight
        flags.append({"name": name, "description": description, "weight": weight})

    entropy = _entropy_bits(pw)

    # --- Direct hit against common-password list -------------------------
    common_hit = lower in COMMON_PASSWORDS
    if common_hit:
        flag(
            "common_password",
            "Password appears in a list of extremely common/breached "
            "passwords and would be guessed in the first few attempts of "
            "any credential-stuffing attack.",
            60,
        )

    # --- Dictionary word base + mutation (skip if already an exact common-
    # password hit above, to avoid double-counting the same weakness) -----
    elif any(base in lower for base in COMMON_PASSWORD_BASES):
        flag(
            "common_word_base",
            "Password is a common dictionary word/name with a predictable "
            "capitalization + digit/symbol suffix (e.g. 'Password123!'). "
            "This mutation pattern is exactly what password-cracking rule "
            "sets (hashcat/John the Ripper) are built to break in seconds, "
            "regardless of the password's theoretical entropy.",
            35,
        )

    # --- Length ------------------------------------------------------------
    if len(pw) < 8:
        flag(
            "too_short",
            "Password is under 8 characters, well below modern minimum "
            "length recommendations (NIST SP 800-63B suggests 8+ minimum, "
            "12+ preferred).",
            25,
        )
    elif len(pw) < 12:
        flag(
            "below_recommended_length",
            "Password is under the commonly recommended 12-character "
            "minimum for resilience against offline cracking.",
            10,
        )

    # --- Character class coverage -----------------------------------------
    if not re.search(r"[a-z]", pw):
        flag("no_lowercase", "Password contains no lowercase letters.", 10)
    if not re.search(r"[A-Z]", pw):
        flag("no_uppercase", "Password contains no uppercase letters.", 10)
    if not re.search(r"\d", pw):
        flag("no_digit", "Password contains no digits.", 10)
    if not re.search(r"[^a-zA-Z0-9]", pw):
        flag("no_symbol", "Password contains no special/symbol characters.", 10)

    # --- Pattern detection -----------------------------------------------
    if (
        any(walk in lower for walk in KEYBOARD_WALKS)
        or _has_sequential_run(lower)
        or _is_near_sequential_digits(pw)
    ):
        flag(
            "predictable_pattern",
            "Password contains a sequential run (abcd, 1234), a near-"
            "sequential/transposed digit run (e.g. 12354), or a keyboard-"
            "walk pattern (qwerty, asdf) — all trivially guessable.",
            20,
        )

    if _has_repeated_run(pw):
        flag(
            "repeated_characters",
            "Password contains a run of 3+ repeated characters (e.g. "
            "'aaa', '111'), reducing effective entropy.",
            15,
        )

    # --- Absolute floors for trivially-weak passwords ---------------------
    # The additive model above scores independent weaknesses, but it can't
    # guarantee a minimum for passwords that dodge every individual pattern
    # regex while still being globally trivial to brute-force purely by
    # virtue of length or a tiny numeric keyspace. These floors only ever
    # raise the score (never lower it) and only add a flag for the delta
    # actually applied, so a password that already scored above the floor
    # via other flags isn't double-counted.
    if pw and len(pw) < 6 and score < 90:
        flag(
            "extremely_short",
            f"Password is under 6 characters ({len(pw)} chars) — "
            "regardless of character-class variety, a keyspace this small "
            "is exhausted by brute force in well under a second, so risk "
            "is floored to a minimum of 90.",
            90 - score,
        )

    if pw and pw.isdigit() and len(pw) < 8 and score < 85:
        flag(
            "short_numeric_only",
            f"Password is {len(pw)} digits with no letters or symbols — "
            "pure numeric strings under 8 digits (PIN/phone-number style) "
            "are among the very first patterns any cracking tool tries, "
            "so risk is floored to a minimum of 85 regardless of the "
            "specific digit sequence.",
            85 - score,
        )

    # A password that is purely alphabetic (any case, no digits/symbols at
    # all — i.e. zero mutation) within typical single-dictionary-word
    # length is exactly the shape a dictionary/wordlist attack tries in
    # its first pass, regardless of whether the specific word happens to
    # be hardcoded in COMMON_PASSWORD_BASES above. Capped at 16 chars so
    # long random-letter passphrases (a materially stronger, different
    # password class already scored on their own entropy) aren't caught.
    if pw and pw.isalpha() and 4 <= len(pw) <= 16 and score < 65:
        flag(
            "unmutated_dictionary_word",
            f"Password is purely alphabetic ({len(pw)} letters) with no "
            "digits, symbols, or numeric mutation at all — this is "
            "exactly the shape of a single unmutated dictionary/wordlist "
            "entry, which any offline dictionary attack (not just a "
            "brute-force keyspace search) tries in its first pass "
            "regardless of the specific word, so risk is floored to a "
            "minimum of 65.",
            65 - score,
        )

    score = max(0, min(100, score))
    return {
        "risk_score": score,
        "status": _status(score),
        "flags": flags,
        "entropy_bits": round(entropy, 1),
        "crack_time_estimate": _crack_time_estimate(entropy),
    }
