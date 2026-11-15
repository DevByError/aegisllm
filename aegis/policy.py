"""Policy model, loaded from YAML. Every field has a safe default."""
from __future__ import annotations

from pathlib import Path
from typing import Literal

import yaml
from pydantic import BaseModel, Field

Action = Literal["allow", "redact", "block", "review", "deny"]


class UpstreamPolicy(BaseModel):
    base_url: str = "http://localhost:11434/v1"
    api_key_env: str = "UPSTREAM_API_KEY"
    timeout_s: float = 120


class JudgePolicy(BaseModel):
    enabled: bool = False
    model: str = "qwen2.5-coder:7b"
    base_url: str | None = None            # defaults to the upstream base_url
    min_confidence: float = 0.6


class InjectionPolicy(BaseModel):
    enabled: bool = True
    block_threshold: float = 0.6
    untrusted_block_threshold: float = 0.35
    untrusted_action: Literal["block", "drop_document"] = "drop_document"
    judge: JudgePolicy = Field(default_factory=JudgePolicy)


class RedactionPolicy(BaseModel):
    enabled: bool = True
    inbound_action: Literal["redact", "block"] = "redact"
    outbound_action: Literal["redact", "block"] = "redact"


class PiiPolicy(RedactionPolicy):
    types: list[str] = Field(default_factory=lambda: ["email", "phone", "credit_card", "iban", "ipv4", "my_nric"])


class OutputPolicy(BaseModel):
    enabled: bool = True
    system_prompt_canary: bool = True
    allowed_link_domains: list[str] = Field(default_factory=list)
    max_output_chars: int = 20000


class ArgRule(BaseModel):
    type: Literal["string", "integer", "number", "boolean"] = "string"
    max_length: int | None = None
    pattern: str | None = None
    enum: list[str] | None = None
    deny_patterns: list[str] = Field(default_factory=list)
    minimum: float | None = None
    maximum: float | None = None


class ToolRule(BaseModel):
    action: Literal["allow", "review", "deny"] = "deny"
    args: dict[str, ArgRule] = Field(default_factory=dict)
    allow_extra_args: bool = False


class ToolPolicy(BaseModel):
    enabled: bool = True
    default: Literal["allow", "deny"] = "deny"
    rules: dict[str, ToolRule] = Field(default_factory=dict)


class RateLimitPolicy(BaseModel):
    enabled: bool = True
    requests_per_minute: int = 60
    burst: int = 20
    max_request_chars: int = 50000
    max_tokens_cap: int = 2048


class AuditPolicy(BaseModel):
    path: str = "logs/audit.jsonl"
    store_snippets: bool = True


class Policy(BaseModel):
    upstream: UpstreamPolicy = Field(default_factory=UpstreamPolicy)
    injection: InjectionPolicy = Field(default_factory=InjectionPolicy)
    secrets: RedactionPolicy = Field(default_factory=RedactionPolicy)
    pii: PiiPolicy = Field(default_factory=PiiPolicy)
    output: OutputPolicy = Field(default_factory=OutputPolicy)
    tools: ToolPolicy = Field(default_factory=ToolPolicy)
    rate_limit: RateLimitPolicy = Field(default_factory=RateLimitPolicy)
    audit: AuditPolicy = Field(default_factory=AuditPolicy)

    @classmethod
    def load(cls, path: str | Path | None) -> "Policy":
        if path is None:
            return cls()
        data = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
        return cls.model_validate(data)
