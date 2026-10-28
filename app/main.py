"""Single-origin FastAPI application; no real Gmail/Calendar access in this MVP."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Literal

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from app.engine import SCENARIOS, execute
from app.nebius import MODEL, InferenceError, NebiusClient
from app.policy import CAPABILITIES, PlanSigner, PolicyError, approved_policy, signing_key

ROOT = Path(__file__).resolve().parent.parent
_key, _configured_secret = signing_key()
signer = PlanSigner(_key)
app = FastAPI(title="Delegation Firewall", version="0.1.0", docs_url="/api/docs")
app.mount("/static", StaticFiles(directory=ROOT / "static"), name="static")


class PlanRequest(BaseModel):
    intent: str = Field(min_length=20, max_length=500)


class RunRequest(BaseModel):
    plan_token: str = Field(min_length=20, max_length=4000)
    approved_capabilities: list[str] = Field(max_length=6)
    scenario: Literal["normal", "overreach", "prompt_injection"] = "prompt_injection"


@app.get("/")
def home():
    return FileResponse(ROOT / "static" / "index.html")


@app.get("/api/health")
def health():
    client = NebiusClient()
    return {
        "service": "delegation-firewall",
        "status": "ok",
        "mode": client.mode if client.demo else ("NEBIUS_CONFIGURED" if client.api_key else "NO_API_KEY"),
        "model": MODEL,
        "signing_key_configured": _configured_secret,
        "sandbox_only": True,
    }


@app.get("/api/capabilities")
def capabilities():
    return {"capabilities": sorted(CAPABILITIES), "scenarios": SCENARIOS}


@app.post("/api/plan")
def plan(payload: PlanRequest):
    client = NebiusClient()
    try:
        proposed, reason = client.plan(payload.intent.strip())
    except InferenceError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    if not proposed:
        raise HTTPException(status_code=422, detail="No supported capability identified for this task")
    token = signer.issue(payload.intent.strip(), proposed, client.mode)
    return {
        "intent": payload.intent.strip(),
        "proposed_capabilities": proposed,
        "not_required": sorted(CAPABILITIES - set(proposed)),
        "reason": reason,
        "plan_token": token,
        "mode": client.mode,
        "model": None if client.demo else MODEL,
        "expires_in_seconds": 1800,
    }


@app.post("/api/run")
def run(payload: RunRequest):
    try:
        signed = signer.verify(payload.plan_token)
        policy = approved_policy(signed["proposed"], payload.approved_capabilities)
    except PolicyError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    client = NebiusClient()
    if signed["mode"] != client.mode:
        raise HTTPException(status_code=409, detail="Inference mode changed; analyze again")
    if not client.demo and not client.api_key:
        raise HTTPException(status_code=503, detail="Nebius key not configured")
    return execute(signed["intent"], payload.scenario, policy, client)


@app.exception_handler(InferenceError)
async def inference_handler(_request, exc: InferenceError):
    from fastapi.responses import JSONResponse
    return JSONResponse(status_code=503, content={"detail": str(exc)})
