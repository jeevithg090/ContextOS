"""PII indicators used by sensitivity classification (not redacted; they raise sensitivity).

Precision over recall: payment card numbers must have a real issuer prefix, a card-like grouping
and pass the Luhn checksum; IBANs must have a known country length and pass ISO 7064 mod-97;
SSNs need nearby "SSN"/"social security" wording; e-mail addresses only count in bulk.
"""

from __future__ import annotations

import re

BULK_EMAIL_THRESHOLD = 5

_EMAIL_RE = re.compile(
    r"(?<![A-Za-z0-9._%+\-])[A-Za-z0-9._%+\-]{1,64}@(?P<domain>[A-Za-z0-9\-]{1,63}(?:\.[A-Za-z0-9\-]{1,63})*\.[A-Za-z]{2,24})"
    r"(?![A-Za-z0-9\-])"
)
_EXAMPLE_DOMAINS = ("example.com", "example.org", "example.net", "test.com", "localhost", "users.noreply.github.com")

_CARD_RE = re.compile(r"(?<![\d.\-])\d(?:[ \-]?\d){12,18}(?![\d\-]|\.\d)")
_IBAN_RE = re.compile(r"(?<![A-Za-z0-9])[A-Z]{2}\d{2}(?: ?[A-Z0-9]{4}){2,7}(?: ?[A-Z0-9]{1,4})?(?![A-Za-z0-9])")
_SSN_RE = re.compile(
    r"(?i)\b(?:ssn|social\s+security(?:\s+(?:number|no\.?))?|soc\.?\s*sec\.?)\b[^0-9\n]{0,20}"
    r"(?P<ssn>\d{3}-\d{2}-\d{4})\b"
)

_IBAN_LENGTHS = {
    "AD": 24, "AE": 23, "AT": 20, "AZ": 28, "BA": 20, "BE": 16, "BG": 22, "BH": 22, "BR": 29, "CH": 21,
    "CR": 22, "CY": 28, "CZ": 24, "DE": 22, "DK": 18, "DO": 28, "EE": 20, "EG": 29, "ES": 24, "FI": 18,
    "FO": 18, "FR": 27, "GB": 22, "GE": 22, "GI": 23, "GL": 18, "GR": 27, "GT": 28, "HR": 21, "HU": 28,
    "IE": 22, "IL": 23, "IS": 26, "IT": 27, "JO": 30, "KW": 30, "KZ": 20, "LB": 28, "LI": 21, "LT": 20,
    "LU": 20, "LV": 21, "MC": 27, "MD": 24, "ME": 22, "MK": 19, "MR": 27, "MT": 31, "MU": 30, "NL": 18,
    "NO": 15, "PK": 24, "PL": 28, "PS": 29, "PT": 25, "QA": 29, "RO": 24, "RS": 22, "SA": 24, "SE": 24,
    "SI": 19, "SK": 24, "SM": 27, "TN": 24, "TR": 26, "UA": 29, "VG": 24, "XK": 20,
}


def luhn_valid(digits: str) -> bool:
    total = 0
    for i, ch in enumerate(reversed(digits)):
        n = ord(ch) - 48
        if i % 2 == 1:
            n = n * 2 - 9 if n > 4 else n * 2
        total += n
    return total % 10 == 0


def _issuer_matches(d: str) -> bool:
    n = len(d)
    two, four, six = int(d[:2]), int(d[:4]), int(d[:6])
    if d[0] == "4":
        return n in (13, 16, 19)
    if 51 <= two <= 55 or 2221 <= four <= 2720:
        return n == 16
    if two in (34, 37):
        return n == 15
    if four == 6011 or two == 65 or 644 <= int(d[:3]) <= 649 or 622126 <= six <= 622925:
        return 16 <= n <= 19
    if 3528 <= four <= 3589:
        return 16 <= n <= 19
    if 300 <= int(d[:3]) <= 305 or two in (36, 38, 39):
        return 14 <= n <= 19
    if two == 62:
        return 16 <= n <= 19
    return False


def _grouping_ok(raw: str) -> bool:
    separators = {ch for ch in raw if not ch.isdigit()}
    if not separators:
        return True
    if len(separators) > 1:
        return False
    groups = [len(g) for g in re.split(r"[ \-]", raw)]
    if groups in ([4, 6, 5], [4, 6, 4]):
        return True
    return len(groups) >= 3 and all(g == 4 for g in groups[:-1]) and 1 <= groups[-1] <= 7


def find_payment_cards(text: str) -> int:
    count = 0
    for m in _CARD_RE.finditer(text):
        raw = m.group(0)
        digits = re.sub(r"\D", "", raw)
        if 13 <= len(digits) <= 19 and len(set(digits)) > 1 and _grouping_ok(raw) and _issuer_matches(digits):
            count += luhn_valid(digits)
    return count


def iban_valid(candidate: str) -> bool:
    iban = candidate.replace(" ", "")
    if _IBAN_LENGTHS.get(iban[:2]) != len(iban):
        return False
    rearranged = iban[4:] + iban[:4]
    numeric = "".join(str(int(ch, 36)) for ch in rearranged)
    return int(numeric) % 97 == 1


def find_ibans(text: str) -> int:
    return sum(1 for m in _IBAN_RE.finditer(text) if iban_valid(m.group(0)))


def _ssn_valid(ssn: str) -> bool:
    area, group, serial = ssn.split("-")
    return area not in {"000", "666"} and not area.startswith("9") and group != "00" and serial != "0000"


def find_ssns(text: str) -> int:
    return sum(1 for m in _SSN_RE.finditer(text) if _ssn_valid(m.group("ssn")))


def count_distinct_emails(text: str) -> int:
    seen: set[str] = set()
    for m in _EMAIL_RE.finditer(text):
        domain = m.group("domain").lower()
        if domain.endswith(_EXAMPLE_DOMAINS):
            continue
        seen.add(m.group(0).lower())
    return len(seen)


def pii_indicators(text: str) -> list[str]:
    """Plain-language list of PII kinds present in ``text`` (empty when none)."""
    found: list[str] = []
    if any(ch.isdigit() for ch in text):
        if find_payment_cards(text):
            found.append("payment card number")
        if find_ibans(text):
            found.append("bank account (IBAN)")
        if find_ssns(text):
            found.append("US social security number")
    if "@" in text and count_distinct_emails(text) >= BULK_EMAIL_THRESHOLD:
        found.append("bulk e-mail addresses")
    return found
