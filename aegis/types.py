"""Shared result types."""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any

SEVERITY = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


@dataclass
class Finding:
    layer: str            # injection | secrets | pii | tools | output | rate_limit
    kind: str             # e.g. instruction_override, aws_key, email, tool_denied
    severity: str = "medium"
    score: float = 0.0
    detail: str = ""
    location: str = ""    # e.g. "messages[2]" or "response.tool_calls[0]"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class Verdict:
    """Outcome of inspecting one request or response."""
    action: str = "allow"                 # allow | redact | block | review
    findings: list[Finding] = field(default_factory=list)
    reason: str = ""
    approval_id: str | None = None

    def escalate(self, action: str, reason: str = "") -> None:
        order = {"allow": 0, "redact": 1, "review": 2, "block": 3}
        if order[action] > order[self.action]:
            self.action = action
            if reason:
                self.reason = reason

    @property
    def blocked(self) -> bool:
        return self.action == "block"
