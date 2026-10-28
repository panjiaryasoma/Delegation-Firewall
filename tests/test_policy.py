import base64
import json
import time

import pytest

from app.policy import PlanSigner, Policy, PolicyError, approved_policy


@pytest.fixture
def signer():
    return PlanSigner("test-key-" * 7)


def test_default_deny_unknown_tool():
    assert Policy(frozenset({"email.read"})).authorize("run_shell")[0] is False


def test_allowed_only_when_capability_approved():
    policy = Policy(frozenset({"email.read"}))
    assert policy.authorize("read_email")[0] is True
    assert policy.authorize("send_email")[0] is False
    assert policy.authorize("delete_email")[0] is False
    assert policy.authorize("create_calendar_event")[0] is False


def test_cannot_escalate_signed_plan():
    with pytest.raises(PolicyError):
        approved_policy(["email.read"], ["email.read", "email.send"])


def test_reject_duplicate_approvals():
    with pytest.raises(PolicyError):
        approved_policy(["email.read"], ["email.read", "email.read"])


def test_signed_plan_tampering_fails(signer):
    token = signer.issue("Read hackathon emails and create an event", ["email.read"], "NEBIUS")
    assert signer.verify(token)["proposed"] == ["email.read"]
    body, mac = token.split(".")
    payload = json.loads(base64.urlsafe_b64decode(body + "=" * (-len(body) % 4)))
    payload["proposed"].append("email.delete")
    fake_body = base64.urlsafe_b64encode(json.dumps(payload).encode()).rstrip(b"=").decode()
    with pytest.raises(PolicyError):
        signer.verify(f"{fake_body}.{mac}")


def test_signed_plan_expiration(monkeypatch):
    signer = PlanSigner("long-secret-" * 4, ttl_seconds=1)
    token = signer.issue("Read hackathon emails and create an event", ["email.read"], "NEBIUS")
    current = time.time()
    monkeypatch.setattr("app.policy.time.time", lambda: current + 100)
    with pytest.raises(PolicyError, match="expired"):
        signer.verify(token)


def test_unknown_capability_rejected_at_issuance(signer):
    with pytest.raises(PolicyError):
        signer.issue("Read email", ["shell.exec"], "NEBIUS")
