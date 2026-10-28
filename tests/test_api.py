import os

os.environ["DEMO_MODE"] = "true"
os.environ["APP_SIGNING_KEY"] = "test-signing-key-0123456789-abcd-efgh"

from fastapi.testclient import TestClient  # noqa: E402

from app.main import app  # noqa: E402

client = TestClient(app)
INTENT = "Read my hackathon emails and add the submission deadline to my calendar."


def test_full_user_approved_flow():
    response = client.post("/api/plan", json={"intent": INTENT})
    assert response.status_code == 200
    plan = response.json()
    assert plan["mode"] == "SIMULATED"
    assert plan["proposed_capabilities"] == ["email.read", "calendar.create"]
    result = client.post("/api/run", json={
        "plan_token": plan["plan_token"],
        "approved_capabilities": plan["proposed_capabilities"],
        "scenario": "prompt_injection",
    })
    assert result.status_code == 200
    assert result.json()["completed"] is True
    assert result.json()["blocked_count"] == 1
    assert result.json()["mode"] == "SIMULATED"


def test_client_cannot_add_unsuggested_permission():
    plan = client.post("/api/plan", json={"intent": INTENT}).json()
    result = client.post("/api/run", json={
        "plan_token": plan["plan_token"],
        "approved_capabilities": ["email.read", "calendar.create", "email.delete"],
    })
    assert result.status_code == 403


def test_invalid_input():
    assert client.post("/api/plan", json={"intent": "hi"}).status_code == 422


def test_health_and_static():
    assert client.get("/api/health").status_code == 200
    assert "Agents need boundaries" in client.get("/").text
