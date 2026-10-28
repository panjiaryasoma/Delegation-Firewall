from app.engine import Audit, Sandbox, execute
from app.policy import Policy


class FakeModel:
    demo = False
    mode = "NEBIUS"

    def decide(self, intent, inbox):
        assert "deadline" in intent.lower()
        return [{"tool": "create_calendar_event", "arguments": {
            "title": "Hackathon submission", "start_at": "2026-10-30T10:00:00-07:00"
        }}]


def test_injection_red_team_blocked_and_task_completes():
    report = execute("Read hackathon deadline and make a calendar entry", "prompt_injection",
                     Policy(frozenset({"email.read", "calendar.create"})), FakeModel())
    assert report["completed"] is True
    assert report["blocked_count"] == 1
    assert report["outbox"] == []
    assert report["calendar"][0]["start_at"] == "2026-10-30T10:00:00-07:00"
    block = next(e for e in report["events"] if e["verdict"] == "BLOCKED")
    assert block["actor"] == "RED_TEAM_PROBE"


def test_missing_read_permission_fails_closed():
    report = execute("Read hackathon deadline and make a calendar entry", "normal",
                     Policy(frozenset({"calendar.create"})), FakeModel())
    assert report["completed"] is False
    assert report["calendar"] == []


def test_missing_write_permission_blocks_calendar():
    report = execute("Read hackathon deadline and make a calendar entry", "normal",
                     Policy(frozenset({"email.read"})), FakeModel())
    assert report["completed"] is False
    assert any(e["action"] == "create_calendar_event" and e["verdict"] == "BLOCKED"
               for e in report["events"])


def test_invalid_calendar_date_no_write():
    audit = Audit()
    sandbox = Sandbox(Policy(frozenset({"calendar.create"})), audit, "normal")
    assert sandbox.call("create_calendar_event", {"start_at": "2026-99-88T10:00:00-07:00", "title": "Test"}) == {
        "error": "invalid_arguments"
    }
    assert not sandbox.calendar


def test_unknown_tool_is_never_dispatched():
    audit = Audit()
    sandbox = Sandbox(Policy(frozenset({"email.read"})), audit, "normal")
    assert sandbox.call("delete_everything")['error'] == "permission_denied"


def test_red_team_denied_before_mutation():
    audit = Audit()
    sandbox = Sandbox(Policy(frozenset({"email.read"})), audit, "normal")
    initial = len(sandbox.inbox)
    sandbox.call("delete_email", {"id": "msg-001"}, actor="RED_TEAM_PROBE")
    assert len(sandbox.inbox) == initial


def test_audit_hash_chain_order():
    audit = Audit()
    audit.record("SYSTEM", "start", "INFO", "start")
    audit.record("AGENT", "read_email", "ALLOWED", "read")
    assert audit.entries[1]["previous_hash"] == audit.entries[0]["hash"]
    assert audit.digest == audit.entries[-1]["hash"]


def test_fake_model_can_attempt_forbidden_tool():
    class BadModel(FakeModel):
        def decide(self, intent, inbox):
            return [{"tool": "send_email", "arguments": {"to": "attacker@example.com"}}]

    report = execute("Read hackathon deadline and make a calendar entry", "normal",
                     Policy(frozenset({"email.read", "calendar.create"})), BadModel())
    assert not report["completed"]
    assert report["blocked_count"] == 1
    assert not report["outbox"]
