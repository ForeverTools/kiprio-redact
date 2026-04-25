"""kiprio-redact — local PII redaction CLI + library.

Same regex muscles as https://kiprio.com/v1/redact (offline subset).
For context-aware / higher-recall redaction use the API.
"""
from __future__ import annotations

import re
import socket
import uuid as _uuid
from typing import Iterable

__version__ = "0.1.0"

ALL_TYPES = ("email", "phone", "iban", "card", "nino", "uuid", "jwt", "ip")

# --- regexes ----------------------------------------------------------------
_EMAIL = re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b")
_PHONE = re.compile(r"(?<![A-Za-z0-9])\+?\d[\d \-().]{7,20}\d(?![A-Za-z0-9])")
_IBAN = re.compile(r"\b[A-Z]{2}\d{2}(?:[ ]?[A-Z0-9]){10,30}\b")
_CARD = re.compile(r"(?<![\d])(?:\d[ \-]?){12,18}\d(?![\d])")
_NINO = re.compile(
    r"\b[A-CEGHJ-PR-TW-Z][A-CEGHJ-NPR-TW-Z]\s?\d{2}\s?\d{2}\s?\d{2}\s?[A-D]?\b"
)
_UUID = re.compile(
    r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
    r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b"
)
_JWT = re.compile(
    r"\beyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\b"
)
_IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_IPV6 = re.compile(
    r"(?<![0-9A-Fa-f:])"
    r"(?:[0-9A-Fa-f]{1,4}:){1,7}(?::|(?::[0-9A-Fa-f]{1,4})+|[0-9A-Fa-f]{1,4})"
    r"(?![0-9A-Fa-f:])"
)
_ISO_DATE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
_DOTTED_QUAD = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")

_NINO_BAD_PREFIXES = {"BG", "GB", "KN", "NK", "NT", "TN", "ZZ"}


# --- validators -------------------------------------------------------------
def _luhn(digits: str) -> bool:
    if not digits.isdigit():
        return False
    total = 0
    for i, ch in enumerate(reversed(digits)):
        n = int(ch)
        if i % 2 == 1:
            n *= 2
            if n > 9:
                n -= 9
        total += n
    return total % 10 == 0


def _iban_ok(s: str) -> bool:
    s = s.replace(" ", "").upper()
    if not (15 <= len(s) <= 34):
        return False
    rearr = s[4:] + s[:4]
    out = []
    for ch in rearr:
        if ch.isdigit():
            out.append(ch)
        elif "A" <= ch <= "Z":
            out.append(str(ord(ch) - 55))
        else:
            return False
    try:
        return int("".join(out)) % 97 == 1
    except ValueError:
        return False


def _ipv4_ok(s: str) -> bool:
    parts = s.split(".")
    return len(parts) == 4 and all(p.isdigit() and 0 <= int(p) <= 255 for p in parts)


def _ipv6_ok(s: str) -> bool:
    try:
        socket.inet_pton(socket.AF_INET6, s)
        return True
    except OSError:
        return False


def _nino_ok(s: str) -> bool:
    c = s.replace(" ", "").upper()
    if len(c) not in (8, 9):
        return False
    if c[:2] in _NINO_BAD_PREFIXES:
        return False
    if c[0] in "DFIQUV" or c[1] in "DFIOQUV":
        return False
    if not c[2:8].isdigit():
        return False
    if len(c) == 9 and c[8] not in "ABCD":
        return False
    return True


def _phone_ok(s: str) -> bool:
    s = s.strip()
    digits = re.sub(r"\D", "", s)
    if not 7 <= len(digits) <= 15:
        return False
    if len(set(digits)) <= 1:
        return False
    if _ISO_DATE.match(s) or _DOTTED_QUAD.match(s):
        return False
    return True


def _uuid_ok(s: str) -> bool:
    try:
        _uuid.UUID(s)
        return True
    except ValueError:
        return False


# --- per-type span finders --------------------------------------------------
def _spans_email(t):
    return [(m.start(), m.end(), m.group(0)) for m in _EMAIL.finditer(t)]


def _spans_phone(t):
    return [
        (m.start(), m.end(), m.group(0))
        for m in _PHONE.finditer(t) if _phone_ok(m.group(0))
    ]


def _spans_iban(t):
    return [
        (m.start(), m.end(), m.group(0))
        for m in _IBAN.finditer(t) if _iban_ok(m.group(0))
    ]


def _spans_card(t):
    out = []
    for m in _CARD.finditer(t):
        digits = re.sub(r"[ \-]", "", m.group(0))
        if 13 <= len(digits) <= 19 and _luhn(digits):
            out.append((m.start(), m.end(), m.group(0)))
    return out


def _spans_nino(t):
    return [
        (m.start(), m.end(), m.group(0))
        for m in _NINO.finditer(t) if _nino_ok(m.group(0))
    ]


def _spans_uuid(t):
    return [
        (m.start(), m.end(), m.group(0))
        for m in _UUID.finditer(t) if _uuid_ok(m.group(0))
    ]


def _spans_jwt(t):
    return [(m.start(), m.end(), m.group(0)) for m in _JWT.finditer(t)]


def _spans_ip(t):
    out = [
        (m.start(), m.end(), m.group(0))
        for m in _IPV4.finditer(t) if _ipv4_ok(m.group(0))
    ]
    out += [
        (m.start(), m.end(), m.group(0))
        for m in _IPV6.finditer(t) if _ipv6_ok(m.group(0))
    ]
    return out


_EXTRACTORS = {
    "email": _spans_email,
    "phone": _spans_phone,
    "iban": _spans_iban,
    "card": _spans_card,
    "nino": _spans_nino,
    "uuid": _spans_uuid,
    "jwt": _spans_jwt,
    "ip": _spans_ip,
}

# Earlier wins on overlap.
_PRIORITY = {
    "iban": 0, "card": 1, "jwt": 2, "uuid": 3, "email": 4,
    "ip": 5, "phone": 6, "nino": 7,
}


def find_spans(text: str, types: Iterable[str] | None = None) -> list[dict]:
    """Find PII spans in `text`. Returns list of {type,start,end,raw}."""
    types = list(types) if types else list(ALL_TYPES)
    raw = []
    for t in types:
        fn = _EXTRACTORS.get(t)
        if not fn:
            continue
        for s, e, r in fn(text):
            raw.append((s, e, r, t))
    if not raw:
        return []
    raw.sort(key=lambda x: (x[0], _PRIORITY.get(x[3], 99), -(x[1] - x[0])))
    accepted = []
    for s, e, r, t in raw:
        if any(s < ae and e > as_ for as_, ae, _, _ in accepted):
            continue
        accepted.append((s, e, r, t))
    accepted.sort(key=lambda x: x[0])
    return [{"type": t, "start": s, "end": e, "raw": r}
            for (s, e, r, t) in accepted]


def redact(
    text: str,
    types: Iterable[str] | None = None,
    *,
    mask: str | None = None,
    replacement: str | None = None,
) -> tuple[str, list[dict]]:
    """Return (redacted_text, findings).

    `mask` (single char) replaces each character of the match.
    `replacement` (string) replaces the entire match. Default = '[REDACTED]'.
    Pass exactly one of `mask` or `replacement`; if neither, default is used.
    """
    if mask is not None and replacement is not None:
        raise ValueError("pass mask OR replacement, not both")
    findings = find_spans(text, types)
    if not findings:
        return text, []
    out = []
    cursor = 0
    for f in findings:
        out.append(text[cursor:f["start"]])
        if mask is not None:
            out.append(mask * (f["end"] - f["start"]))
        else:
            out.append(replacement if replacement is not None else "[REDACTED]")
        cursor = f["end"]
    out.append(text[cursor:])
    return "".join(out), findings
