"""Secret and personal-data detection with redaction.

Secrets: well-known credential formats (cloud keys, tokens, private keys, JWTs,
connection strings and password assignments). PII: emails, phone numbers,
payment cards (Luhn-checked), IBANs (mod-97 checked), IPv4 addresses and
Malaysian NRIC numbers. Matches are replaced with typed placeholders such as
[REDACTED:EMAIL], so the model still understands the sentence.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Callable

from ..types import Finding


@dataclass(frozen=True)
class Pattern:
    kind: str
    regex: re.Pattern
    severity: str = "high"
    validator: Callable[[str], bool] | None = None
    group: int = 0


def _p(kind, rx, severity="high", validator=None, flags=0, group=0):
    return Pattern(kind, re.compile(rx, flags), severity, validator, group)


def luhn_ok(s: str) -> bool:
    digits = [int(c) for c in s if c.isdigit()]
    if not 13 <= len(digits) <= 19:
        return False
    total, parity = 0, len(digits) % 2
    for i, d in enumerate(digits):
        if i % 2 == parity:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


def iban_ok(s: str) -> bool:
    s = s.replace(" ", "").upper()
    if not 15 <= len(s) <= 34:
        return False
    moved = s[4:] + s[:4]
    num = "".join(str(int(c, 36)) for c in moved)
    return int(num) % 97 == 1


def ipv4_ok(s: str) -> bool:
    parts = s.split(".")
    return len(parts) == 4 and all(p.isdigit() and 0 <= int(p) <= 255 for p in parts) and not s.startswith(("0.", "127.", "255."))


SECRET_PATTERNS: list[Pattern] = [
    _p("private_key", r"-----BEGIN (RSA |EC |OPENSSH |DSA |PGP |ENCRYPTED )?PRIVATE KEY( BLOCK)?-----[\s\S]+?-----END [A-Z ]*PRIVATE KEY( BLOCK)?-----", "critical"),
    _p("aws_access_key", r"\b(AKIA|ASIA)[0-9A-Z]{16}\b", "critical"),
    _p("aws_secret_key", r"(?i)aws(.{0,20})?(secret|private)?(.{0,10})?['\"=: ]{1,4}([A-Za-z0-9/+=]{40})\b", "critical", group=4),
    _p("github_token", r"\b(gh[pousr]_[A-Za-z0-9]{36,255}|github_pat_[A-Za-z0-9_]{22,255})\b", "critical"),
    _p("anthropic_key", r"\bsk-ant-[A-Za-z0-9_\-]{20,}\b", "critical"),
    _p("openai_key", r"\bsk-(proj-|svcacct-)?[A-Za-z0-9_\-]{20,}\b", "critical"),
    _p("google_api_key", r"\bAIza[0-9A-Za-z_\-]{35}\b", "critical"),
    _p("slack_token", r"\bxox[abpors]-[A-Za-z0-9-]{10,}\b", "high"),
    _p("stripe_key", r"\b(sk|rk)_(live|test)_[A-Za-z0-9]{16,}\b", "critical"),
    _p("jwt", r"\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b", "high"),
    _p("connection_string", r"\b(mongodb(\+srv)?|postgres(ql)?|mysql|redis|amqp|mssql)://[^\s:/@]+:[^\s@/]{3,}@[^\s]+", "critical"),
    _p("password_assignment", r"(?i)\b(password|passwd|pwd|secret|api[_-]?key|access[_-]?token)\b\s*[:=]\s*['\"]?([^\s'\",;]{6,})", "high", group=2),
]

PII_PATTERNS: dict[str, Pattern] = {
    "email": _p("email", r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b", "medium"),
    "credit_card": _p("credit_card", r"\b(?:\d[ -]?){13,19}\b", "high", validator=luhn_ok),
    "iban": _p("iban", r"\b[A-Z]{2}\d{2}(?: ?[A-Z0-9]{4}){2,7}(?: ?[A-Z0-9]{1,4})?\b", "high", validator=iban_ok),
    "my_nric": _p("my_nric", r"\b\d{6}-\d{2}-\d{4}\b", "high"),
    "phone": _p("phone", r"(?<![\w-])(?:\+\d{1,3}[\s.-]?)?(?:\(\d{1,4}\)[\s.-]?)?\d{2,4}[\s.-]\d{3,4}[\s.-]?\d{3,4}(?![\w-])", "medium"),
    "ipv4": _p("ipv4", r"\b(?:\d{1,3}\.){3}\d{1,3}\b", "low", validator=ipv4_ok),
}
# Order matters: cards and IBANs are checked before phone numbers.
PII_ORDER = ["email", "credit_card", "iban", "my_nric", "phone", "ipv4"]


@dataclass
class RedactionResult:
    text: str
    findings: list[Finding]

    @property
    def changed(self) -> bool:
        return bool(self.findings)


def _apply(text: str, patterns: list[Pattern], layer: str, location: str) -> RedactionResult:
    findings: list[Finding] = []
    for p in patterns:
        def repl(m: re.Match) -> str:
            value = m.group(p.group)
            if p.validator and not p.validator(value):
                return m.group(0)
            findings.append(Finding(layer, p.kind, p.severity, 1.0, f"{p.kind} ({len(value)} chars)", location))
            tag = f"[REDACTED:{p.kind.upper()}]"
            if p.group:
                start, end = m.start(p.group) - m.start(0), m.end(p.group) - m.start(0)
                full = m.group(0)
                return full[:start] + tag + full[end:]
            return tag
        text = p.regex.sub(repl, text)
    return RedactionResult(text, findings)


def redact_secrets(text: str, location: str = "") -> RedactionResult:
    return _apply(text, SECRET_PATTERNS, "secrets", location)


def redact_pii(text: str, types: list[str] | None = None, location: str = "") -> RedactionResult:
    types = types or PII_ORDER
    pats = [PII_PATTERNS[t] for t in PII_ORDER if t in types]
    return _apply(text, pats, "pii", location)
