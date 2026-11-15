"""Structured audit log in JSON Lines. Stores findings and decisions, never raw secrets."""
from __future__ import annotations

import json
import threading
import time
import uuid
from collections import Counter
from pathlib import Path
from typing import Any

from .types import Verdict


class AuditLog:
    def __init__(self, path: str | Path, store_snippets: bool = True) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.store_snippets = store_snippets
        self._lock = threading.Lock()

    def write(self, *, client: str, stage: str, verdict: Verdict, model: str = "", latency_ms: float | None = None,
              extra: dict[str, Any] | None = None) -> str:
        event_id = uuid.uuid4().hex[:16]
        record = {
            "id": event_id,
            "ts": round(time.time(), 3),
            "client": client,
            "stage": stage,                       # request | response | tool
            "model": model,
            "action": verdict.action,
            "reason": verdict.reason,
            "findings": [
                {k: v for k, v in f.to_dict().items() if self.store_snippets or k != "detail"}
                for f in verdict.findings
            ],
        }
        if latency_ms is not None:
            record["gateway_ms"] = round(latency_ms, 2)
        if verdict.approval_id:
            record["approval_id"] = verdict.approval_id
        if extra:
            record.update(extra)
        line = json.dumps(record, ensure_ascii=False)
        with self._lock, self.path.open("a", encoding="utf-8") as fh:
            fh.write(line + "\n")
        return event_id

    def read(self, limit: int = 1000) -> list[dict[str, Any]]:
        if not self.path.exists():
            return []
        lines = self.path.read_text(encoding="utf-8").splitlines()[-limit:]
        out = []
        for ln in lines:
            try:
                out.append(json.loads(ln))
            except json.JSONDecodeError:
                continue
        return out

    def stats(self, limit: int = 5000) -> dict[str, Any]:
        events = self.read(limit)
        actions = Counter(e["action"] for e in events)
        kinds = Counter(f"{f['layer']}:{f['kind']}" for e in events for f in e.get("findings", []))
        return {"events": len(events), "actions": dict(actions), "top_findings": kinds.most_common(15)}
