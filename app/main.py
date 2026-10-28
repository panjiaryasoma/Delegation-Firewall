"""Single-origin FastAPI sandbox. Real providers are intentionally not connected."""

from __future__ import annotations

import os
import re
import secrets
import threading
import time
from collections import defaultdict, deque
from pathlib import Path
from typing import Literal

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from app.engine import SCENARIOS, execute
from app.nebius import MODEL, InferenceError, NebiusClient
from app.policy import CAPABILITIES, PlanSigner, PolicyError, approved_policy, signing_key

ROOT = Path(__file__).resolve().parent.parent
_key, _configured_secret = signing_key()
signer = PlanSigner(_key)
app = FastAPI(title="Delegation Firewall", version="0.2.0", docs_url=None, redoc_url=None)
app.mount("/static", StaticFiles(directory=ROOT / "static"), name="static")

# In-process budget controls, NOT a distributed enforcement guarantee.
_window_lock = threading.Lock()
_hits: dict[str, deque[float]] = defaultdict(deque)
_inference_slots = threading.BoundedSemaphore(2)


class PlanRequest(BaseModel):
    intent: str = Field(min_length=20, max_length=500)


class RunRequest(BaseModel):
    plan_token: str = Field(min_length=20, max_length=4000)
    approved_capabilities: list[str] = Field(max_length=6)
    scenario: Literal["normal", "overreach", "prompt_injection"] = "prompt_injection"


@app.middleware("http")
async def security_headers(request: Request, call_next):
    if request.url.path in {"/api/plan", "/api/run"}:
        raw_length = request.headers.get("content-length")
        if raw_length is not None:
            try:
                if int(raw_length) > 8192:
                    return JSONResponse(
                        status_code=413, content={"detail": "Request body too large"},
                        headers={"Cache-Control": "no-store", "X-Content-Type-Options": "nosniff"},
                    )
            except ValueError:
                return JSONResponse(
                    status_code=400, content={"detail": "Invalid content length"},
                    headers={"Cache-Control": "no-store", "X-Content-Type-Options": "nosniff"},
                )
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; script-src 'self'; style-src 'self'; "
        "connect-src 'self'; img-src 'self' data:; object-src 'none'; "
        "base-uri 'none'; frame-ancestors 'none'; form-action 'self'"
    )
    if request.url.path.startswith("/api/"):
        response.headers["Cache-Control"] = "no-store"
    return response


def require_access(request: Request) -> None:
    """Protect paid inference behind a server-side shared demo password."""
    client = NebiusClient()
    if client.demo:
        return
    if not client.api_key:
        raise HTTPException(status_code=503, detail="Nebius inference is not configured")
    if not _configured_secret:
        raise HTTPException(status_code=503, detail="APP_SIGNING_KEY is required in live mode")
    expected = os.getenv("APP_ACCESS_KEY", "")
    if len(expected) < 24:
        raise HTTPException(status_code=503, detail="APP_ACCESS_KEY is required in live mode")
    received = request.headers.get("X-Demo-Access-Key", "")
    if not secrets.compare_digest(expected, received):
        raise HTTPException(status_code=401, detail="Invalid demo access key")


def check_budget(request: Request) -> None:
    # Proxy addresses can be shared. This limit is per worker and intentionally conservative.
    identity = request.client.host if request.client else "unknown"
    now = time.monotonic()
    with _window_lock:
        global_events = _hits["__process_total__"]
        while global_events and now - global_events[0] > 60:
            global_events.popleft()
        if len(global_events) >= 24:
            raise HTTPException(status_code=429, detail="Instance request budget reached")
        events = _hits[identity]
        while events and now - events[0] > 60:
            events.popleft()
        if len(events) >= 12:
            raise HTTPException(status_code=429, detail="Request limit reached; retry later")
        events.append(now)
        global_events.append(now)
        # Do not accumulate stale identities forever in this small demonstration service.
        if len(_hits) > 1024:
            for key, history in list(_hits.items()):
                if not history or now - history[-1] > 60:
                    del _hits[key]


def inference_slot():
    if not _inference_slots.acquire(blocking=False):
        raise HTTPException(status_code=429, detail="Inference capacity reached; retry later")
    return _inference_slots


@app.get("/")
def home():
    return FileResponse(ROOT / "static" / "index.html")


@app.get("/api/health")
def health():
    client = NebiusClient()
    mode = "SIMULATED" if client.demo else ("NEBIUS_CONFIGURED" if client.api_key else "NO_API_KEY")
    return {
        "service": "delegation-firewall",
        "status": "ok",
        "mode": mode,
        "model": MODEL,
        "signing_key_configured": _configured_secret,
        "access_key_required": not client.demo,
        "sandbox_only": True,
    }


@app.get("/api/capabilities")
def capabilities():
    return {"capabilities": sorted(CAPABILITIES), "scenarios": SCENARIOS}


@app.post("/api/plan")
def plan(payload: PlanRequest, request: Request):
    check_budget(request)
    require_access(request)
    intent = payload.intent.strip()
    lowered = " ".join(intent.casefold().split())
    # Fail closed for negated instructions or requests involving unsupported side effects.
    required = (
        r"\b(?:read|check|scan|extract|find|baca|cari|periksa)\b",
        r"\b(?:email|emails|inbox|e-mail|e-mails|mail|mails)\b",
        r"\b(?:deadline|tenggat|submission)\b",
        r"\b(?:add|create|schedule|put|masukkan|tambahkan|buat|catat)\b",
        r"\b(?:calendar|kalender)\b",
    )
    excluded = (
        r"\b(?:no|not|never|without|don't|dont|jangan|tidak|bukan|except|kecuali)\b",
        r"\b(?:send|delete|remove|forward|reply|export|share|hapus|kirim|balas)\b",
    )
    if not all(re.search(pattern, lowered) for pattern in required) or any(
        re.search(pattern, lowered) for pattern in excluded
    ):
        raise HTTPException(
            status_code=422,
            detail="Only an explicit positive email-to-calendar deadline task is supported",
        )
    client = NebiusClient()
    slot = inference_slot()
    try:
        proposed, reason = client.plan(intent)
    except InferenceError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    finally:
        slot.release()
    if not proposed:
        raise HTTPException(status_code=422, detail="No supported capability identified")
    token = signer.issue(intent, proposed, client.mode)
    return {
        "intent": intent,
        "proposed_capabilities": proposed,
        "not_required": sorted(CAPABILITIES - set(proposed)),
        "reason": reason,
        "plan_token": token,
        "mode": client.mode,
        "model": None if client.demo else MODEL,
        "expires_in_seconds": 900,
    }


@app.post("/api/run")
def run(payload: RunRequest, request: Request):
    check_budget(request)
    require_access(request)
    try:
        signed = signer.verify(payload.plan_token)
        policy = approved_policy(signed["proposed"], payload.approved_capabilities)
    except PolicyError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    client = NebiusClient()
    if signed["mode"] != client.mode:
        raise HTTPException(status_code=409, detail="Inference mode changed; analyze again")
    slot = inference_slot()
    try:
        return execute(signed["intent"], payload.scenario, policy, client)
    finally:
        slot.release()


@app.exception_handler(InferenceError)
async def inference_handler(_request, exc: InferenceError):
    return JSONResponse(status_code=503, content={"detail": str(exc)})
