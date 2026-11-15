"""Text normalisation that removes common obfuscation before detection runs.

Attackers hide instructions with zero-width characters, Unicode tag characters,
homoglyphs, leetspeak, extra spacing and base64. Detection runs on the original
text and on the normalised views produced here.
"""
from __future__ import annotations

import base64
import binascii
import re
import unicodedata

ZERO_WIDTH = dict.fromkeys(map(ord, "​‌‍⁠﻿­᠎"), None)
LEET = str.maketrans({"0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "7": "t", "@": "a", "$": "s"})
B64_RE = re.compile(r"(?<![A-Za-z0-9+/=])[A-Za-z0-9+/]{24,}={0,2}(?![A-Za-z0-9+/=])")


def has_tag_characters(text: str) -> bool:
    """Unicode 'tag' characters (U+E0000 to U+E007F) are invisible and used to smuggle text."""
    return any(0xE0000 <= ord(c) <= 0xE007F for c in text)


def decode_tag_characters(text: str) -> str:
    return "".join(chr(ord(c) - 0xE0000) for c in text if 0xE0020 <= ord(c) <= 0xE007E)


def has_zero_width(text: str) -> bool:
    return any(ord(c) in ZERO_WIDTH for c in text)


def basic(text: str) -> str:
    """NFKC fold (maps many homoglyphs and full-width letters), drop zero-width, lower-case, collapse spaces."""
    t = unicodedata.normalize("NFKC", text).translate(ZERO_WIDTH)
    t = "".join(c for c in t if not (0xE0000 <= ord(c) <= 0xE007F))
    t = t.lower()
    return re.sub(r"\s+", " ", t).strip()


def deleet(text: str) -> str:
    return basic(text).translate(LEET)


def despace(text: str) -> str:
    """Joins letters split by spaces or punctuation, e.g. 'i g n o r e' or 'i.g.n.o.r.e'."""
    t = basic(text)
    return re.sub(r"(?<=\b\w)[\s.\-_*](?=\w\b)", "", t)


def decoded_base64_segments(text: str, limit: int = 5) -> list[str]:
    out: list[str] = []
    for m in B64_RE.finditer(text):
        chunk = m.group(0)
        try:
            raw = base64.b64decode(chunk + "=" * (-len(chunk) % 4), validate=True)
            s = raw.decode("utf-8")
        except (binascii.Error, UnicodeDecodeError, ValueError):
            continue
        printable = sum(ch.isprintable() or ch.isspace() for ch in s) / max(len(s), 1)
        if printable > 0.95 and re.search(r"[a-zA-Z]{3,}", s):
            out.append(s)
        if len(out) >= limit:
            break
    return out


SPACED_RUN = re.compile(r"(?:\b\w\b[\s.\-_*]+){5,}\b\w\b")


def has_spaced_letters(text: str) -> bool:
    """True for text written letter by letter, e.g. 'i g n o r e' or 'i.g.n.o.r.e'."""
    return bool(SPACED_RUN.search(basic(text)))


def compact(text: str) -> str:
    """Letters only, no spaces: used only when letter-spacing obfuscation is present."""
    return re.sub(r"[^a-z]", "", deleet(text))


def views(text: str) -> dict[str, str]:
    """All views detection should look at, keyed by name."""
    v = {"basic": basic(text), "deleet": deleet(text), "despace": despace(text)}
    if has_spaced_letters(text):
        v["compact"] = compact(text)
    if has_tag_characters(text):
        v["tags"] = basic(decode_tag_characters(text))
    for i, seg in enumerate(decoded_base64_segments(text)):
        v[f"base64_{i}"] = basic(seg)
    return v
