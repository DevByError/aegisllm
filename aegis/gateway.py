"""The inspection pipeline. Framework-free, so it can be used as a library or behind the HTTP proxy.

Request path:  rate limit -> size and max_tokens caps -> per-message inspection
               (injection on trusted and untrusted content, secret and PII redaction)
               -> system-prompt canary.
Response path: tool-call policy (allow, review, deny) -> secret and PII redaction
               -> output checks (canary leak, link exfiltration, size).
"""
from __future__ import annotations

import copy
import re
import time
from dataclasses import dataclass, field
from typing import Any

from . import output as output_checks
from . import tools as tool_policy
from .detectors import injection, sensitive
from .policy import Policy
from .ratelimit import TokenBucket
from .types import Finding, Verdict

DOC_BLOCK = re.compile(r"(<document\b[^>]*>)([\s\S]*?)(</document>)", re.IGNORECASE)
REMOVED_DOC = "[document removed by AegisLLM: it contained instructions aimed at the AI]"
REFUSAL = "This request was blocked by the AegisLLM security policy."


@dataclass
class RequestContext:
    client: str
    canary: str | None = None
    started: float = field(default_factory=time.perf_counter)


class Gateway:
    def __init__(self, policy: Policy, judge=None) -> None:
        self.policy = policy
        rl = policy.rate_limit
        self.bucket = TokenBucket(rl.requests_per_minute, rl.burst) if rl.enabled else None
        self.approvals = tool_policy.ApprovalQueue()
        self.judge = judge
        jp = policy.injection.judge
        if self.judge is None and jp.enabled:
            import os
            from .detectors.judge import Judge
            key = os.environ.get(policy.upstream.api_key_env) if policy.upstream.api_key_env else None
            self.judge = Judge(jp.base_url or policy.upstream.base_url, jp.model, key)

    def _judge_flags(self, text: str, untrusted: bool, loc: str, verdict: Verdict) -> bool:
        if not self.judge or not text.strip():
            return False
        attack, conf = self.judge.classify(text, untrusted)
        if attack and conf >= self.policy.injection.judge.min_confidence:
            verdict.findings.append(Finding("injection", "judge_flagged", "high", round(conf, 2), "local model classifier flagged the text", loc))
            return True
        return False

    # ------------------------------------------------------------------ request
    def inspect_request(self, body: dict[str, Any], client: str = "anonymous") -> tuple[Verdict, dict[str, Any], RequestContext]:
        p = self.policy
        ctx = RequestContext(client)
        verdict = Verdict()
        body = copy.deepcopy(body)
        messages = body.get("messages")
        if not isinstance(messages, list) or not messages:
            verdict.escalate("block", "request has no messages")
            verdict.findings.append(Finding("request", "malformed", "medium", 1.0, "messages missing"))
            return verdict, body, ctx

        if self.bucket and not self.bucket.allow(client):
            verdict.escalate("block", "rate limit exceeded")
            verdict.findings.append(Finding("rate_limit", "rate_limited", "medium", 1.0, f"client {client}"))
            return verdict, body, ctx

        total_chars = sum(len(_text_of(m)) for m in messages)
        if p.rate_limit.enabled and total_chars > p.rate_limit.max_request_chars:
            verdict.escalate("block", "request too large")
            verdict.findings.append(Finding("rate_limit", "request_too_large", "medium", 1.0, f"{total_chars} chars"))
            return verdict, body, ctx
        if p.rate_limit.enabled:
            for key in ("max_tokens", "max_completion_tokens"):
                if isinstance(body.get(key), int) and body[key] > p.rate_limit.max_tokens_cap:
                    body[key] = p.rate_limit.max_tokens_cap
            if "max_tokens" not in body and "max_completion_tokens" not in body:
                body["max_tokens"] = p.rate_limit.max_tokens_cap

        for i, msg in enumerate(messages):
            role = msg.get("role")
            if role == "system":
                continue
            loc = f"messages[{i}]"
            untrusted_message = role == "tool"
            new_content = self._inspect_content(msg.get("content"), untrusted_message, loc, verdict)
            if verdict.blocked:
                return verdict, body, ctx
            msg["content"] = new_content

        if p.output.enabled and p.output.system_prompt_canary:
            ctx.canary = output_checks.new_canary()
            marker = output_checks.canary_instruction(ctx.canary)
            if messages[0].get("role") == "system" and isinstance(messages[0].get("content"), str):
                messages[0]["content"] = messages[0]["content"] + "\n\n" + marker
            else:
                messages.insert(0, {"role": "system", "content": marker})
        return verdict, body, ctx

    def _inspect_content(self, content: Any, untrusted: bool, loc: str, verdict: Verdict) -> Any:
        if isinstance(content, list):  # OpenAI content parts
            for j, part in enumerate(content):
                if isinstance(part, dict) and part.get("type") == "text":
                    part["text"] = self._inspect_text(part.get("text", ""), untrusted, f"{loc}.content[{j}]", verdict)
                    if verdict.blocked:
                        break
            return content
        if isinstance(content, str):
            return self._inspect_text(content, untrusted, loc, verdict)
        return content

    def _inspect_text(self, text: str, untrusted: bool, loc: str, verdict: Verdict) -> str:
        p = self.policy
        if p.injection.enabled:
            if untrusted:
                text = self._check_untrusted(text, loc, verdict)
                if verdict.blocked:
                    return text
            else:
                # Documents embedded by a RAG app are untrusted even inside a user message.
                def handle_doc(m: re.Match) -> str:
                    inner = self._check_untrusted(m.group(2), f"{loc}<document>", verdict)
                    return m.group(1) + inner + m.group(3)
                text = DOC_BLOCK.sub(handle_doc, text)
                if verdict.blocked:
                    return text
                outside = DOC_BLOCK.sub(" ", text)
                res = injection.scan(outside, untrusted=False, location=loc)
                if res.score >= p.injection.block_threshold:
                    verdict.findings.extend(res.findings)
                    verdict.escalate("block", f"prompt injection (score {res.score})")
                    return text
                if self._judge_flags(outside, False, loc, verdict):
                    verdict.findings.extend(res.findings)
                    verdict.escalate("block", "prompt injection (classifier)")
                    return text
                if res.findings and res.score >= 0.3:
                    verdict.findings.extend(res.findings)

        if p.secrets.enabled:
            r = sensitive.redact_secrets(text, loc)
            if r.changed:
                verdict.findings.extend(r.findings)
                if p.secrets.inbound_action == "block":
                    verdict.escalate("block", "secret in request")
                    return text
                verdict.escalate("redact", "secret redacted")
                text = r.text
        if p.pii.enabled:
            r = sensitive.redact_pii(text, p.pii.types, loc)
            if r.changed:
                verdict.findings.extend(r.findings)
                if p.pii.inbound_action == "block":
                    verdict.escalate("block", "personal data in request")
                    return text
                verdict.escalate("redact", "personal data redacted")
                text = r.text
        return text

    def _check_untrusted(self, text: str, loc: str, verdict: Verdict) -> str:
        p = self.policy.injection
        res = injection.scan(text, untrusted=True, location=loc)
        flagged = res.score >= p.untrusted_block_threshold or self._judge_flags(text, True, loc, verdict)
        if flagged:
            verdict.findings.extend(res.findings)
            if p.untrusted_action == "block":
                verdict.escalate("block", f"indirect prompt injection (score {res.score})")
                return text
            verdict.escalate("redact", f"untrusted content removed (score {res.score})")
            verdict.findings.append(Finding("injection", "document_dropped", "high", res.score, "untrusted content removed", loc))
            return REMOVED_DOC
        return text

    # ----------------------------------------------------------------- response
    def inspect_response(self, resp: dict[str, Any], ctx: RequestContext) -> tuple[Verdict, dict[str, Any]]:
        p = self.policy
        verdict = Verdict()
        resp = copy.deepcopy(resp)
        pending: list[dict[str, str]] = []
        for ci, choice in enumerate(resp.get("choices") or []):
            msg = choice.get("message") or {}
            loc = f"choices[{ci}]"

            calls = msg.get("tool_calls") or []
            if p.tools.enabled and calls:
                kept = []
                notes = []
                for ti, call in enumerate(calls):
                    fn = (call.get("function") or {})
                    name, args = fn.get("name", ""), fn.get("arguments", "{}")
                    d = tool_policy.evaluate(name, args, p.tools, f"{loc}.tool_calls[{ti}]")
                    verdict.findings.extend(d.findings)
                    if d.action == "allow":
                        kept.append(call)
                    elif d.action == "review":
                        item = self.approvals.add(name, args if isinstance(args, str) else str(args), ctx.client)
                        pending.append({"approval_id": item.id, "tool": name})
                        verdict.findings.append(Finding("tools", "approval_required", "medium", 1.0, f"'{name}' held for approval {item.id}", f"{loc}.tool_calls[{ti}]"))
                        verdict.escalate("review", "tool call needs approval")
                        verdict.approval_id = item.id
                        notes.append(f"The action '{name}' needs human approval (request {item.id}).")
                    else:
                        verdict.escalate("redact", "tool call removed")
                        notes.append(f"The action '{name}' was blocked by policy.")
                if kept:
                    msg["tool_calls"] = kept
                else:
                    msg.pop("tool_calls", None)
                    if choice.get("finish_reason") == "tool_calls":
                        choice["finish_reason"] = "stop"
                if notes:
                    msg["content"] = ((msg.get("content") or "") + "\n" + " ".join(notes)).strip()

            text = msg.get("content")
            if isinstance(text, str) and text:
                if p.secrets.enabled:
                    r = sensitive.redact_secrets(text, loc)
                    if r.changed:
                        verdict.findings.extend(r.findings)
                        if p.secrets.outbound_action == "block":
                            verdict.escalate("block", "secret in reply")
                        else:
                            verdict.escalate("redact", "secret redacted from reply")
                            text = r.text
                if p.pii.enabled:
                    r = sensitive.redact_pii(text, p.pii.types, loc)
                    if r.changed:
                        verdict.findings.extend(r.findings)
                        if p.pii.outbound_action == "block":
                            verdict.escalate("block", "personal data in reply")
                        else:
                            verdict.escalate("redact", "personal data redacted from reply")
                            text = r.text
                if p.output.enabled:
                    text, f, block = output_checks.check(text, p.output, ctx.canary, loc)
                    verdict.findings.extend(f)
                    if block:
                        verdict.escalate("block", "system prompt leak")
                    elif f:
                        verdict.escalate("redact", "reply modified by output policy")
                msg["content"] = REFUSAL if verdict.blocked else text

        if pending:
            resp["aegis_pending_approvals"] = pending
        return verdict, resp


def _text_of(msg: dict[str, Any]) -> str:
    c = msg.get("content")
    if isinstance(c, str):
        return c
    if isinstance(c, list):
        return " ".join(p.get("text", "") for p in c if isinstance(p, dict))
    return ""


def blocked_response(model: str, verdict: Verdict) -> dict[str, Any]:
    return {
        "id": "aegis-blocked",
        "object": "chat.completion",
        "created": int(time.time()),
        "model": model,
        "choices": [{"index": 0, "finish_reason": "content_filter",
                     "message": {"role": "assistant", "content": REFUSAL}}],
        "aegis": {"action": verdict.action, "reason": verdict.reason,
                  "findings": [f.to_dict() for f in verdict.findings]},
    }
