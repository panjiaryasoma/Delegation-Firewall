"""Token Factory wire-contract tests. No live credentials or paid inference required."""

import json

import httpx
import pytest

from app import nebius
from app.nebius import InferenceError, NebiusClient, json_object


@pytest.mark.parametrize("raw", [
    '{"actions":[]}',
    f'{chr(96) * 3}json\n{{"actions":[]}}\n{chr(96) * 3}',
    '<think>Reasoning not intended as output.</think>\n{"actions":[]}',
])
def test_json_parser_accepts_one_complete_object(raw):
    assert json_object(raw) == {"actions": []}


@pytest.mark.parametrize("raw", [
    'Here is the answer: {"actions":[]}',
    '{"actions":[]} trailing explanation',
    '<think>unfinished reasoning\n{"actions":[]}',
    '{"actions":',
    '[]',
])
def test_json_parser_rejects_ambiguous_or_incomplete_output(raw):
    with pytest.raises(InferenceError):
        json_object(raw)


def wire_client(monkeypatch, handler):
    real_client = httpx.Client

    def fake_client(**kwargs):
        return real_client(transport=httpx.MockTransport(handler), **kwargs)

    monkeypatch.setattr(nebius.httpx, "Client", fake_client)
    monkeypatch.setenv("NEBIUS_API_KEY", "test-value-not-a-real-key")
    monkeypatch.setenv("DEMO_MODE", "false")
    return NebiusClient()


def test_requests_structured_json_without_thinking(monkeypatch):
    calls = []

    def handler(request):
        payload = json.loads(request.content)
        calls.append(payload)
        return httpx.Response(200, json={
            "choices": [{
                "finish_reason": "stop",
                "message": {
                    "content": '{"capabilities":["email.read","calendar.create"],"reason":"OK"}'
                },
            }],
        })

    model = wire_client(monkeypatch, handler)
    scope, reason = model.plan(
        "Read hackathon emails and add the submission deadline to my calendar."
    )
    assert scope == ["calendar.create", "email.read"]
    assert reason == "OK"
    assert len(calls) == 1
    assert calls[0]["response_format"] == {"type": "json_object"}
    assert calls[0]["chat_template_kwargs"] == {"enable_thinking": False}
    assert calls[0]["model"] == nebius.MODEL


def test_incomplete_response_is_rejected_without_actions(monkeypatch):
    def handler(_request):
        return httpx.Response(200, json={
            "choices": [{"finish_reason": "length", "message": {"content": '{"actions":'}}],
        })

    client = wire_client(monkeypatch, handler)
    with pytest.raises(InferenceError, match="incomplete"):
        client.decide("Task", [{"subject": "Hackathon submission", "body": "deadline"}])


def test_known_unsupported_parameter_triggers_compatibility_retry(monkeypatch):
    calls = []

    def handler(request):
        payload = json.loads(request.content)
        calls.append(payload)
        if len(calls) == 1:
            return httpx.Response(400, json={
                "detail": "Unknown parameter: chat_template_kwargs"
            })
        return httpx.Response(200, json={
            "choices": [{"finish_reason": "stop", "message": {"content": '{"actions":[]}'}}],
        })

    client = wire_client(monkeypatch, handler)
    assert client.decide("Task", []) == []
    assert len(calls) == 2
    assert "chat_template_kwargs" not in calls[1]
    assert calls[1]["response_format"] == {"type": "json_object"}


def test_unrelated_bad_request_never_retries(monkeypatch):
    calls = []

    def handler(request):
        calls.append(request)
        return httpx.Response(400, json={"detail": "Invalid model selection"})

    client = wire_client(monkeypatch, handler)
    with pytest.raises(InferenceError, match="HTTP 400"):
        client.decide("Task", [])
    assert len(calls) == 1


def test_malformed_model_output_is_never_repaired_with_guesswork(monkeypatch):
    def handler(_request):
        return httpx.Response(200, json={
            "choices": [{
                "finish_reason": "stop",
                "message": {"content": 'I propose {"actions":[]}'},
            }],
        })

    client = wire_client(monkeypatch, handler)
    with pytest.raises(InferenceError, match="invalid JSON"):
        client.decide("Task", [])
