"""Agent tool-call policy: allowlist, argument validation and human approval."""
from __future__ import annotations

import json
import re
import threading
import time
import uuid
from dataclasses import dataclass, field
from typing import Any

from .detectors import injection
from .policy import ArgRule, ToolPolicy
from .types import Finding


@dataclass
class ToolDecision:
    name: str
    action: str                      # allow | review | deny
    findings: list[Finding] = field(default_factory=list)


def _check_arg(name: str, value: Any, rule: ArgRule) -> str | None:
    t = rule.type
    if t == "string" and not isinstance(value, str):
        return f"'{name}' must be a string"
    if t == "integer" and not (isinstance(value, int) and not isinstance(value, bool)):
        return f"'{name}' must be an integer"
    if t == "number" and not (isinstance(value, (int, float)) and not isinstance(value, bool)):
        return f"'{name}' must be a number"
    if t == "boolean" and not isinstance(value, bool):
        return f"'{name}' must be a boolean"
    if isinstance(value, str):
        if rule.max_length is not None and len(value) > rule.max_length:
            return f"'{name}' is longer than {rule.max_length}"
        if rule.pattern and not re.fullmatch(rule.pattern, value):
            return f"'{name}' does not match the allowed pattern"
        if rule.enum and value not in rule.enum:
            return f"'{name}' is not one of the allowed values"
        for dp in rule.deny_patterns:
            if re.search(dp, value, re.IGNORECASE):
                return f"'{name}' contains a denied pattern"
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        if rule.minimum is not None and value < rule.minimum:
            return f"'{name}' is below {rule.minimum}"
        if rule.maximum is not None and value > rule.maximum:
            return f"'{name}' is above {rule.maximum}"
    return None


def evaluate(name: str, raw_args: str | dict | None, policy: ToolPolicy, location: str = "") -> ToolDecision:
    rule = policy.rules.get(name)
    if rule is None:
        if policy.default == "allow":
            return ToolDecision(name, "allow")
        return ToolDecision(name, "deny", [Finding("tools", "tool_not_allowed", "high", 1.0, f"tool '{name}' is not on the allowlist", location)])
    if rule.action == "deny":
        return ToolDecision(name, "deny", [Finding("tools", "tool_denied", "high", 1.0, f"tool '{name}' is denied by policy", location)])

    try:
        args = raw_args if isinstance(raw_args, dict) else json.loads(raw_args or "{}")
    except json.JSONDecodeError:
        return ToolDecision(name, "deny", [Finding("tools", "invalid_arguments", "high", 1.0, "arguments are not valid JSON", location)])
    if not isinstance(args, dict):
        return ToolDecision(name, "deny", [Finding("tools", "invalid_arguments", "high", 1.0, "arguments must be an object", location)])

    problems: list[str] = []
    for arg_name, arg_rule in rule.args.items():
        if arg_name not in args:
            problems.append(f"missing '{arg_name}'")
            continue
        err = _check_arg(arg_name, args[arg_name], arg_rule)
        if err:
            problems.append(err)
    if not rule.allow_extra_args:
        extra = sorted(set(args) - set(rule.args))
        if extra:
            problems.append(f"unexpected arguments: {', '.join(extra)}")

    # Arguments are model output and may carry an injection meant for the next system.
    for k, v in args.items():
        if isinstance(v, str):
            res = injection.scan(v, untrusted=True, location=f"{location}.{k}")
            if res.score >= 0.6:
                problems.append(f"'{k}' contains instruction-like content")

    if problems:
        return ToolDecision(name, "deny", [Finding("tools", "argument_violation", "high", 1.0, "; ".join(problems), location)])
    return ToolDecision(name, rule.action)


@dataclass
class PendingApproval:
    id: str
    tool: str
    arguments: str
    client: str
    created: float
    status: str = "pending"          # pending | approved | denied


class ApprovalQueue:
    """In-memory queue of tool calls waiting for a human decision."""

    def __init__(self) -> None:
        self._items: dict[str, PendingApproval] = {}
        self._lock = threading.Lock()

    def add(self, tool: str, arguments: str, client: str) -> PendingApproval:
        item = PendingApproval(uuid.uuid4().hex[:12], tool, arguments, client, time.time())
        with self._lock:
            self._items[item.id] = item
        return item

    def decide(self, approval_id: str, approve: bool) -> PendingApproval | None:
        with self._lock:
            item = self._items.get(approval_id)
            if item and item.status == "pending":
                item.status = "approved" if approve else "denied"
            return item

    def get(self, approval_id: str) -> PendingApproval | None:
        return self._items.get(approval_id)

    def list(self, status: str | None = None) -> list[PendingApproval]:
        with self._lock:
            return [i for i in self._items.values() if status is None or i.status == status]
