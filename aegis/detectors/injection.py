"""Prompt-injection and jailbreak detection.

A rule set of weighted signals, each tied to an attack technique. Rules run over
several normalised views of the text (see normalize.py), so spacing, leetspeak,
homoglyphs, invisible characters and base64 do not hide them. Signals are
combined with a noisy-OR over the strongest signal per technique, which gives a
score from 0 to 1.

Untrusted content (retrieved documents, tool results, web pages) is also checked
for signals that are harmless in a user's own message but suspicious inside data,
such as text addressed to "the AI" or "the assistant".
"""
from __future__ import annotations

import re
from dataclasses import dataclass

from .. import normalize
from ..types import Finding


@dataclass(frozen=True)
class Rule:
    technique: str
    weight: float
    pattern: re.Pattern
    untrusted_only: bool = False


def _r(technique: str, weight: float, pattern: str, untrusted_only: bool = False) -> Rule:
    return Rule(technique, weight, re.compile(pattern, re.IGNORECASE), untrusted_only)


IGNORE = r"(ignore|disregard|forget|override|bypass|skip|drop|abandon|discard)"
PRIOR = r"(all |any |the |your |these |those |every )*(previous|prior|above|earlier|preceding|original|initial|existing|system|developer|safety)"
RULES_WORDS = r"(instructions?|prompts?|rules?|guidelines?|directives?|context|policies|policy|guardrails?|restrictions?|constraints?)"

RULES: list[Rule] = [
    # Direct attempts to cancel the system prompt.
    _r("instruction_override", 0.85, rf"\b{IGNORE}\b.{{0,30}}\b{PRIOR}\b.{{0,20}}\b{RULES_WORDS}\b"),
    _r("instruction_override", 0.7, rf"\b{IGNORE}\b (everything|all) (you were|you've been|you have been) (told|given|instructed)"),
    _r("instruction_override", 0.6, r"\b(new|updated|revised|real) (system )?(instructions?|rules|directives?)\s*[:\-]"),
    _r("instruction_override", 0.55, r"\bfrom now on,? (you|your answers?) (will|must|should|are)\b"),
    _r("instruction_override", 0.5, r"\bdo not follow (your|the) (rules|guidelines|instructions|policy)"),
    # Persona and jailbreak frames.
    _r("jailbreak_persona", 0.85, r"\b(dan|do anything now|stan|dude|aim|developer mode|god mode|jailbreak(ed)? mode|unfiltered mode)\b.{0,40}\b(mode|enabled|activated|now|persona)\b"),
    _r("jailbreak_persona", 0.6, r"\byou are (now|no longer)\b.{0,40}\b(unrestricted|unfiltered|uncensored|without (any )?(rules|limits|restrictions|filters)|free from)"),
    _r("jailbreak_persona", 0.65, r"\b(pretend|imagine|act as if|roleplay as|role-play as)\b.{0,40}\b(no (rules|restrictions|limits|filters|guidelines)|unrestricted|evil|without ethics)"),
    _r("jailbreak_persona", 0.5, r"\b(stay in character|never break character|you must answer every question)"),
    _r("jailbreak_persona", 0.45, r"\b(opposite mode|anti-?gpt|evil (twin|confidant|assistant))\b"),
    # System prompt and secret extraction.
    _r("prompt_extraction", 0.75, r"\b(reveal|print|show|repeat|output|display|tell me|give me|leak|dump|write out|recite)\b.{0,40}\b(your|the|initial|hidden|secret|original) (system )?(prompt|instructions|rules|configuration|guidelines)\b"),
    _r("prompt_extraction", 0.65, r"\b(what|which) (are|were) (your|the) (exact |original |initial |hidden )?(system )?(instructions|prompt|rules)\b"),
    _r("prompt_extraction", 0.6, r"\brepeat (the|all|everything)( text| words)? (above|before)\b"),
    _r("prompt_extraction", 0.55, r"\b(begin|start) your (reply|answer|response) with\b.{0,30}\b(system|instructions|prompt)"),
    _r("prompt_extraction", 0.6, r"\b(api[_ ]?keys?|passwords?|credentials|secrets?|tokens?)\b.{0,30}\b(you (have|were given|know)|in your (context|prompt|instructions|memory))"),
    # Fake chat-format delimiters that try to start a new system or assistant turn.
    _r("delimiter_injection", 0.8, r"(<\|?(im_start|im_end|system|endoftext)\|?>|\[/?inst\]|<</?sys>>|<\|start_header_id\|>)"),
    _r("delimiter_injection", 0.6, r"(^|\n|\s)(#{2,}|={3,}|-{3,})\s*(system|developer|admin|new instructions?)\b"),
    _r("delimiter_injection", 0.5, r"\b(end of (user )?(input|prompt|message)|system override|admin override|priority override)\b"),
    # Data exfiltration through links, images and outbound calls.
    _r("exfiltration", 0.75, r"!\[[^\]]*\]\(https?://[^)]*(\?|&)[a-z_]*=?\{?[^)]*\)"),
    _r("exfiltration", 0.65, r"\b(send|post|upload|forward|exfiltrate|transmit|leak)\b.{0,60}\b(to|at) (https?://|www\.|[a-z0-9-]+\.(com|net|io|xyz|ru|top))"),
    _r("exfiltration", 0.55, r"\b(append|include|add|encode)\b.{0,40}\b(conversation|chat history|user data|the (above|previous) (messages?|data)|secrets?)\b.{0,40}\b(url|link|query|parameter|image)"),
    # Pushing an agent into actions.
    _r("tool_coercion", 0.7, r"\b(call|invoke|use|run|execute|trigger)\b.{0,20}\b(the )?(tool|function|command|shell|terminal)\b.{0,40}\b(now|immediately|without (asking|confirmation|approval))"),
    _r("tool_coercion", 0.75, r"\b(rm -rf|del /f|format c:|drop table|shutdown -|curl [^ ]+ ?\| ?(sh|bash)|wget [^ ]+ ?\| ?(sh|bash)|chmod 777|nc -e|/etc/passwd|powershell -enc)"),
    _r("tool_coercion", 0.55, r"\b(transfer|wire|send)\b.{0,20}\b(all |the )?(funds|money|balance|payment|crypto|bitcoin)\b"),
    # Obfuscation markers.
    _r("obfuscation", 0.45, r"\b(decode|base64|rot13|hex|reverse)\b.{0,30}\b(and (then )?(follow|execute|obey|run|do)|the following (and|then))"),
    _r("obfuscation", 0.4, r"\b(translate|respond) .{0,25}\b(and then|then) (ignore|follow|execute)"),
    # Signals that only matter inside untrusted data.
    _r("indirect_instruction", 0.55, r"\b(ai|assistant|chatbot|language model|llm|gpt|claude|model|agent|bot)s?,? (reading|processing|summari[sz]ing|seeing|analy[sz]ing) (this|these)\b", untrusted_only=True),
    _r("indirect_instruction", 0.5, r"\b(attention|note|important|instruction|message) (to|for) (the )?(ai|assistant|model|llm|agent|chatbot|bot)\b", untrusted_only=True),
    _r("indirect_instruction", 0.45, r"\b(when|if) (you|the (ai|assistant|model)) (summari[sz]e|read|process|answer|respond)\b.{0,60}\b(you must|always|instead|make sure|do not|don't)\b", untrusted_only=True),
    _r("indirect_instruction", 0.4, r"\b(you must|you should|you will|always|never)\b.{0,30}\b(tell|recommend|say|respond|reply|answer|output|include|mention|claim)\b", untrusted_only=True),
    _r("indirect_instruction", 0.35, r"\b(hidden|secret) (instruction|message|note)\b", untrusted_only=True),
]

# Signatures for the letters-only view (used only when letter-spacing obfuscation is found).
COMPACT_RULES: list[Rule] = [
    _r("instruction_override", 0.85, r"(ignore|disregard|forget|override|bypass)(all|any|the|your|every)*(previous|prior|above|earlier|system|original)(instructions?|prompts?|rules|guidelines|directives)"),
    _r("prompt_extraction", 0.75, r"(reveal|print|show|repeat|output|tellme|giveme|leak|dump)(your|the|initial|hidden|secret|original)*(system)?(prompt|instructions)"),
    _r("jailbreak_persona", 0.8, r"(developermode|godmode|doanythingnow|jailbreakmode|unfilteredmode)"),
]

# Phrases that look like attacks but are usually benign questions about the topic.
BENIGN_CONTEXT = re.compile(
    r"\b(what is|what are|explain|how (do|can|does)|define|definition of|examples? of|protect against|defend against|prevent|detect|mitigat\w*)\b.{0,40}\b(prompt injection|jailbreak\w*|injection attacks?)\b",
    re.IGNORECASE,
)


@dataclass
class InjectionResult:
    score: float
    findings: list[Finding]

    @property
    def techniques(self) -> list[str]:
        return sorted({f.kind for f in self.findings})


def scan(text: str, untrusted: bool = False, location: str = "") -> InjectionResult:
    if not text or not text.strip():
        return InjectionResult(0.0, [])
    views = normalize.views(text)
    best: dict[str, tuple[float, str, str]] = {}
    if "compact" in views:
        for rule in COMPACT_RULES:
            m = rule.pattern.search(views["compact"])
            if m:
                w = min(1.0, rule.weight + 0.1)
                if w > best.get(rule.technique, (0.0, "", ""))[0]:
                    best[rule.technique] = (w, "compact", m.group(0)[:80])
    for rule in RULES:
        if rule.untrusted_only and not untrusted:
            continue
        for view_name, view in views.items():
            if view_name == "compact":
                continue
            m = rule.pattern.search(view)
            if m:
                w = rule.weight
                # Obfuscated hits are more suspicious, not less.
                if view_name != "basic":
                    w = min(1.0, w + 0.1)
                if w > best.get(rule.technique, (0.0, "", ""))[0]:
                    best[rule.technique] = (w, view_name, m.group(0)[:80])
                break

    extra: list[Finding] = []
    if normalize.has_tag_characters(text):
        best.setdefault("hidden_unicode", (0.6, "raw", "unicode tag characters"))
    elif normalize.has_zero_width(text) and best:
        extra.append(Finding("injection", "zero_width_characters", "low", 0.1, "zero-width characters around a signal", location))

    if not best:
        return InjectionResult(0.0, extra)

    weights = [w for w, _, _ in best.values()]
    p_clean = 1.0
    for w in weights:
        p_clean *= (1.0 - w)
    score = 1.0 - p_clean

    # Questions about prompt injection itself are common and benign; damp them
    # unless several techniques fire together.
    if not untrusted and BENIGN_CONTEXT.search(views["basic"]) and len(best) <= 1:
        score *= 0.5

    findings = [
        Finding("injection", tech, _severity(w), round(w, 2), f"{view}: '{snippet}'", location)
        for tech, (w, view, snippet) in sorted(best.items(), key=lambda kv: -kv[1][0])
    ]
    return InjectionResult(round(min(score, 1.0), 3), findings + extra)


def _severity(w: float) -> str:
    return "critical" if w >= 0.8 else "high" if w >= 0.6 else "medium" if w >= 0.4 else "low"
