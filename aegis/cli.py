"""Command line: `aegisllm serve` runs the proxy, `aegisllm scan` checks text from stdin."""
from __future__ import annotations

import argparse
import json
import sys


def main(argv: list[str] | None = None) -> None:
    ap = argparse.ArgumentParser(prog="aegisllm")
    sub = ap.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("serve", help="run the OpenAI-compatible security proxy")
    s.add_argument("--policy", default="policy.yaml")
    s.add_argument("--host", default="127.0.0.1")
    s.add_argument("--port", type=int, default=8088)
    c = sub.add_parser("scan", help="scan text from stdin for injection, secrets and PII")
    c.add_argument("--untrusted", action="store_true", help="treat the text as a retrieved document or tool result")
    a = ap.parse_args(argv)

    if a.cmd == "serve":
        import uvicorn
        from .policy import Policy
        from .server import create_app
        uvicorn.run(create_app(Policy.load(a.policy)), host=a.host, port=a.port)
    else:
        from .detectors import injection, sensitive
        text = sys.stdin.read()
        inj = injection.scan(text, untrusted=a.untrusted)
        sec = sensitive.redact_secrets(text)
        pii = sensitive.redact_pii(sec.text)
        print(json.dumps({
            "injection_score": inj.score,
            "findings": [f.to_dict() for f in inj.findings + sec.findings + pii.findings],
            "redacted": pii.text,
        }, indent=2))


if __name__ == "__main__":
    main()
