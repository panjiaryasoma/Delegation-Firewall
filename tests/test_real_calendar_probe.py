"""Real-provider probe tests using a fake calendar client; never call Google."""

import pytest

from app.policy import Policy
from scripts.google_calendar_real_probe import CalendarProbeError, run_probe


class FakeModel:
    def decide(self, intent, inbox):
        assert "hackathon" in intent.lower()
        assert len(inbox) == 1
        return [{
            "tool": "create_calendar_event",
            "arguments": {
                "title": "Hackathon submission deadline",
                "start_at": "2026-10-30T10:00:00-07:00",
            },
        }]


class FakeProvider:
    def __init__(self):
        self.calls = []
        self.events = {}

    def create_event(self, event):
        self.calls.append("POST")
        recorded = {"id": "google-test-event", "start": {"dateTime": event["start_at"]}}
        self.events[recorded["id"]] = recorded
        return {"id": recorded["id"], "start_at": event["start_at"]}

    def get_event(self, event_id):
        self.calls.append("GET")
        return self.events[event_id]


def test_real_probe_is_authorized_and_verifies_provider_read_back():
    provider = FakeProvider()
    result = run_probe(FakeModel(), provider)
    assert result["provider"] == "GOOGLE_CALENDAR_REAL"
    assert result["source_inbox"] == "FICTIONAL_SANDBOX_FIXTURE"
    assert result["blocked_delete"] is True
    assert result["outbound_delete_requests"] == 0
    assert provider.calls == ["POST", "GET"]


def test_unapproved_calendar_write_never_reaches_provider():
    provider = FakeProvider()
    with pytest.raises(CalendarProbeError, match="did not create"):
        run_probe(FakeModel(), provider, Policy(frozenset({"email.read"})))
    assert provider.calls == []


def test_no_email_read_permission_prevents_google_write():
    provider = FakeProvider()
    with pytest.raises(CalendarProbeError, match="No authorized inbox"):
        run_probe(FakeModel(), provider, Policy(frozenset({"calendar.create"})))
    assert provider.calls == []


def test_untrusted_send_request_does_not_trigger_external_provider():
    class OverreachingModel(FakeModel):
        def decide(self, intent, inbox):
            return [
                {"tool": "send_email", "arguments": {"to": "attacker@example.com"}},
                *super().decide(intent, inbox),
            ]

    provider = FakeProvider()
    result = run_probe(OverreachingModel(), provider)
    assert any(e["action"] == "send_email" and e["verdict"] == "BLOCKED"
               for e in result["audit_events"])
    assert result["outbound_delete_requests"] == 0
    assert provider.calls == ["POST", "GET"]


def test_google_verification_failure_does_not_claim_success():
    class BrokenProvider(FakeProvider):
        def get_event(self, event_id):
            self.calls.append("GET")
            return {"id": "wrong-event"}

    provider = BrokenProvider()
    with pytest.raises(CalendarProbeError, match="Remote event missing"):
        run_probe(FakeModel(), provider)
