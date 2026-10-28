"""Adversarial regression tests for the tool firewall and signed policy."""

import base64
import hashlib
import hmac
import json
from datetime import datetime

import pytest
from fastapi.testclient import TestClient

from app.engine import Audit, Sandbox, execute
from app.policy import CAPABILITIES, PlanSigner, Policy, PolicyError


class WrongDateModel:
    demo = False
    mode = "NEBIUS"

    def decide(self, _intent, _inbox):
        return [{"tool": "create_calendar_event", "arguments": {
            "title": "Hackathon deadline", "start_at": "2026-11-01T10:00:00-07:00"
        }}]


def test_wrong_event_never_means_completed():
    report = execute("Read email deadline and add it to calendar", "normal",
                     Policy(frozenset({"email.read", "calendar.create"})), WrongDateModel())
    assert report["completed"] is False
    assert report["calendar"] == []
    assert report["rejected_count"] >= 1


def test_naive_timestamp_rejected():
    sandbox = Sandbox(Policy(frozenset({"calendar.create"})), Audit(), "normal")
    assert sandbox.call("create_calendar_event", {
        "title": "Hackathon deadline", "start_at": "2026-10-30T10:00:00"
    })["error"] == "invalid_arguments"


def test_same_instant_other_offset_allowed():
    sandbox = Sandbox(Policy(frozenset({"calendar.create"})), Audit(), "normal")
    event = sandbox.call("create_calendar_event", {
        "title": "Hackathon deadline", "start_at": "2026-10-30T17:00:00+00:00"
    })
    assert datetime.fromisoformat(event["start_at"]).hour == 17


def test_duplicate_event_rejected():
    sandbox = Sandbox(Policy(frozenset({"calendar.create"})), Audit(), "normal")
    event = {"title": "Hackathon deadline", "start_at": "2026-10-30T10:00:00-07:00"}
    assert sandbox.call("create_calendar_event", event)["id"] == "event-001"
    assert sandbox.call("create_calendar_event", event)["error"] == "invalid_arguments"
    assert len(sandbox.calendar) == 1


def test_malformed_plan_signatures_fail_closed():
    signer = PlanSigner("safe-signing-key-0123456789-abcdefghijklmnop")
    token = signer.issue("Read my hackathon emails into my calendar", ["email.read"], "NEBIUS")
    body, signature = token.split(".")
    for invalid in ("***", "abc!", "a" * 4001):
        with pytest.raises(PolicyError):
            signer.verify(f"{body}.{invalid}")
    with pytest.raises(PolicyError):
        signer.verify("a.b.c")
    assert signer.verify(token)["proposed"] == ["email.read"]


def test_signed_but_invalid_envelope_rejected():
    signer = PlanSigner("safe-signing-key-0123456789-abcdefghijklmnop")
    token = signer.issue("Read my hackathon emails into my calendar", ["email.read"], "NEBIUS")
    body, _ = token.split(".")
    payload = json.loads(base64.urlsafe_b64decode(body + "=" * (-len(body) % 4)))
    payload["iat"] = "not an integer"
    raw = signer._encode(json.dumps(payload).encode())
    mac = signer._encode(hmac.new(signer._key, raw.encode(), hashlib.sha256).digest())
    with pytest.raises(PolicyError):
        signer.verify(f"{raw}.{mac}")


def test_only_relevant_email_exposed():
    inbox = Sandbox(Policy(frozenset({"email.read"})), Audit(), "normal").call("read_email")
    assert len(inbox) == 1 and inbox[0]["id"] == "msg-001"


def test_sandbox_state_not_shared():
    permission = Policy(frozenset({"email.read", "calendar.create"}))
    first = Sandbox(permission, Audit(), "normal")
    second = Sandbox(permission, Audit(), "normal")
    first.call("create_calendar_event", {
        "title": "Hackathon deadline", "start_at": "2026-10-30T10:00:00-07:00"
    })
    assert len(first.calendar) == 1 and second.calendar == []


def test_prompt_injection_never_grants_send():
    sandbox = Sandbox(Policy(frozenset({"email.read", "calendar.create"})),
                      Audit(), "prompt_injection")
    assert sandbox.call("send_email", {"to": "attacker@example.com"})["error"] == (
        "permission_denied"
    )
    assert not sandbox.outbox


@pytest.mark.parametrize("mask", range(64))
@pytest.mark.parametrize("tool,capability", [
    ("read_email", "email.read"), ("send_email", "email.send"),
    ("delete_email", "email.delete"), ("create_calendar_event", "calendar.create"),
    ("read_calendar", "calendar.read"), ("delete_calendar_event", "calendar.delete"),
])
def test_permission_matrix(mask, tool, capability):
    enabled = frozenset(
        cap for index, cap in enumerate(sorted(CAPABILITIES))
        if mask & (1 << index)
    )
    assert Policy(enabled).authorize(tool)[0] is (capability in enabled)


def test_unknown_tool_denied_even_with_every_permission():
    assert not Policy(frozenset(CAPABILITIES)).authorize("execute_shell")[0]


def test_unsupported_workflow_rejected(monkeypatch):
    monkeypatch.setenv("DEMO_MODE", "true")
    from app.main import app

    response = TestClient(app).post("/api/plan", json={
        "intent": "Read emails from my inbox and summarize everything in them"
    })
    assert response.status_code == 422


def test_live_inference_requires_demo_access_key(monkeypatch):
    monkeypatch.setenv("DEMO_MODE", "false")
    monkeypatch.setenv("NEBIUS_API_KEY", "fake-test-key")
    monkeypatch.setenv("APP_ACCESS_KEY", "long-test-access-key-1234567890")
    from app import main

    monkeypatch.setattr(main, "_configured_secret", True)
    response = TestClient(main.app).post("/api/plan", json={
        "intent": "Read hackathon email deadline and add to calendar"
    })
    assert response.status_code == 401
    assert response.headers["cache-control"] == "no-store"


def test_response_security_headers():
    from app.main import app

    response = TestClient(app).get("/")
    assert response.headers["x-frame-options"] == "DENY"
    assert "script-src 'self'" in response.headers["content-security-policy"]


def test_oversized_body_is_rejected_before_parsing():
    from app.main import app

    response = TestClient(app).post(
        "/api/plan", content=b"x" * 9000,
        headers={"Content-Type": "application/json"},
    )
    assert response.status_code == 413
    assert response.headers["cache-control"] == "no-store"


def test_process_wide_budget_even_across_different_ips():
    from types import SimpleNamespace
    from fastapi import HTTPException
    from app import main

    main._hits.clear()
    try:
        for n in range(24):
            request = SimpleNamespace(client=SimpleNamespace(host=f"198.51.100.{n + 1}"))
            main.check_budget(request)
        request = SimpleNamespace(client=SimpleNamespace(host="203.0.113.3"))
        with pytest.raises(HTTPException) as error:
            main.check_budget(request)
        assert error.value.status_code == 429
    finally:
        main._hits.clear()
