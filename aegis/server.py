"""OpenAI-compatible HTTP proxy that puts the gateway in front of any upstream model."""
from __future__ import annotations

import html
import os
import time
from typing import Any

import httpx
from fastapi import FastAPI, HTTPException, Request
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import HTMLResponse, JSONResponse

from . import __version__
from .audit import AuditLog
from .gateway import Gateway, blocked_response
from .policy import Policy


class Upstream:
    """Forwards chat completions to an OpenAI-compatible API (Ollama, vLLM, OpenAI, ...)."""

    def __init__(self, base_url: str, api_key: str | None, timeout_s: float, transport: httpx.AsyncBaseTransport | None = None):
        headers = {"Authorization": f"Bearer {api_key}"} if api_key else {}
        self.client = httpx.AsyncClient(base_url=base_url.rstrip("/"), headers=headers, timeout=timeout_s, transport=transport)

    async def chat(self, body: dict[str, Any]) -> dict[str, Any]:
        r = await self.client.post("/chat/completions", json=body)
        r.raise_for_status()
        return r.json()

    async def models(self) -> dict[str, Any]:
        r = await self.client.get("/models")
        r.raise_for_status()
        return r.json()


def _client_id(request: Request) -> str:
    return request.headers.get("x-aegis-client") or (request.client.host if request.client else "unknown")


def create_app(policy: Policy, upstream: Upstream | None = None) -> FastAPI:
    gw = Gateway(policy)
    audit = AuditLog(policy.audit.path, policy.audit.store_snippets)
    if upstream is None:
        key = os.environ.get(policy.upstream.api_key_env) if policy.upstream.api_key_env else None
        upstream = Upstream(policy.upstream.base_url, key, policy.upstream.timeout_s)

    app = FastAPI(title="AegisLLM", version=__version__)
    app.state.gateway, app.state.audit = gw, audit

    @app.get("/aegis/health")
    async def health() -> dict[str, Any]:
        return {"status": "ok", "version": __version__}

    @app.get("/v1/models")
    async def models() -> Any:
        try:
            return await upstream.models()
        except httpx.HTTPError as e:
            raise HTTPException(502, f"upstream error: {e}") from e

    @app.post("/v1/chat/completions")
    async def chat(request: Request) -> Any:
        body = await request.json()
        client = _client_id(request)
        model = str(body.get("model", ""))
        if body.get("stream"):
            # Responses are inspected as a whole, so streaming is served as a single response.
            body["stream"] = False

        t0 = time.perf_counter()
        verdict, safe_body, ctx = await run_in_threadpool(gw.inspect_request, body, client)
        req_ms = (time.perf_counter() - t0) * 1000
        audit.write(client=client, stage="request", verdict=verdict, model=model, latency_ms=req_ms)
        if verdict.blocked:
            status = 429 if any(f.kind == "rate_limited" for f in verdict.findings) else 200
            return JSONResponse(blocked_response(model, verdict), status_code=status)

        try:
            resp = await upstream.chat(safe_body)
        except httpx.HTTPError as e:
            raise HTTPException(502, f"upstream error: {e}") from e

        t1 = time.perf_counter()
        rverdict, safe_resp = gw.inspect_response(resp, ctx)
        resp_ms = (time.perf_counter() - t1) * 1000
        audit.write(client=client, stage="response", verdict=rverdict, model=model, latency_ms=resp_ms)
        safe_resp["aegis"] = {
            "request_action": verdict.action,
            "response_action": rverdict.action,
            "findings": [f.to_dict() for f in verdict.findings + rverdict.findings],
            "gateway_ms": round(req_ms + resp_ms, 2),
        }
        return safe_resp

    @app.get("/aegis/approvals")
    async def approvals(status: str | None = "pending") -> list[dict[str, Any]]:
        return [vars(a) for a in gw.approvals.list(status)]

    @app.get("/aegis/approvals/{approval_id}")
    async def approval(approval_id: str) -> dict[str, Any]:
        item = gw.approvals.get(approval_id)
        if not item:
            raise HTTPException(404, "unknown approval id")
        return vars(item)

    @app.post("/aegis/approvals/{approval_id}")
    async def decide(approval_id: str, request: Request) -> dict[str, Any]:
        data = await request.json()
        item = gw.approvals.decide(approval_id, bool(data.get("approve")))
        if not item:
            raise HTTPException(404, "unknown approval id")
        from .types import Finding, Verdict
        v = Verdict(action="allow" if item.status == "approved" else "block",
                    findings=[Finding("tools", f"approval_{item.status}", "info", 1.0, item.tool)])
        audit.write(client=item.client, stage="tool", verdict=v, extra={"approval_id": item.id})
        return vars(item)

    @app.get("/aegis/stats")
    async def stats() -> dict[str, Any]:
        return audit.stats()

    @app.get("/aegis/dashboard", response_class=HTMLResponse)
    async def dashboard() -> str:
        return _dashboard_html(audit.stats(), audit.read(30), [vars(a) for a in gw.approvals.list("pending")])

    return app


def _dashboard_html(stats: dict[str, Any], recent: list[dict[str, Any]], pending: list[dict[str, Any]]) -> str:
    e = html.escape
    acts = "".join(f"<div class='k'><b>{e(str(v))}</b><span>{e(k)}</span></div>" for k, v in sorted(stats["actions"].items()))
    tops = "".join(f"<tr><td>{e(k)}</td><td>{v}</td></tr>" for k, v in stats["top_findings"]) or "<tr><td colspan=2>No findings yet</td></tr>"
    rows = "".join(
        f"<tr><td>{time.strftime('%H:%M:%S', time.localtime(r['ts']))}</td><td>{e(r['client'])}</td><td>{e(r['stage'])}</td>"
        f"<td class='a-{e(r['action'])}'>{e(r['action'])}</td><td>{e(', '.join(f['kind'] for f in r.get('findings', [])) or '-')}</td></tr>"
        for r in reversed(recent))
    pend = "".join(f"<tr><td>{e(p['id'])}</td><td>{e(p['tool'])}</td><td><code>{e(p['arguments'][:120])}</code></td></tr>" for p in pending) \
        or "<tr><td colspan=3>None</td></tr>"
    return f"""<!doctype html><html><head><meta charset=utf-8><title>AegisLLM</title><meta http-equiv=refresh content=10>
<style>body{{font:14px system-ui,sans-serif;margin:24px;color:#111;background:#f7f8fa}}h1{{margin:0 0 4px}}
.ks{{display:flex;gap:12px;margin:16px 0}}.k{{background:#fff;border:1px solid #ddd;padding:12px 16px;border-radius:8px}}
.k b{{display:block;font-size:22px}}table{{border-collapse:collapse;background:#fff;width:100%;margin-bottom:20px}}
td,th{{border-bottom:1px solid #eee;padding:6px 10px;text-align:left}}.a-block{{color:#b91c1c;font-weight:600}}
.a-redact{{color:#b45309}}.a-review{{color:#7c3aed}}.a-allow{{color:#15803d}}</style></head><body>
<h1>AegisLLM</h1><div>{stats['events']} audited events</div><div class=ks>{acts}</div>
<h3>Pending tool approvals</h3><table><tr><th>ID</th><th>Tool</th><th>Arguments</th></tr>{pend}</table>
<h3>Top findings</h3><table><tr><th>Layer:kind</th><th>Count</th></tr>{tops}</table>
<h3>Recent events</h3><table><tr><th>Time</th><th>Client</th><th>Stage</th><th>Action</th><th>Findings</th></tr>{rows}</table>
</body></html>"""
