"""Per-client token-bucket rate limiting (OWASP LLM10: unbounded consumption)."""
from __future__ import annotations

import threading
import time


class TokenBucket:
    def __init__(self, rate_per_minute: int, burst: int) -> None:
        self.rate = rate_per_minute / 60.0
        self.burst = burst
        self._state: dict[str, tuple[float, float]] = {}
        self._lock = threading.Lock()

    def allow(self, key: str, now: float | None = None) -> bool:
        now = time.monotonic() if now is None else now
        with self._lock:
            tokens, last = self._state.get(key, (float(self.burst), now))
            tokens = min(self.burst, tokens + (now - last) * self.rate)
            if tokens < 1:
                self._state[key] = (tokens, now)
                return False
            self._state[key] = (tokens - 1, now)
            return True
