# Delegation Firewall

**Give an AI agent a task, not your entire account.**

Delegation Firewall is a minimal, single-origin web application that converts human intent into a proposed tool capability set using **NVIDIA Nemotron on Nebius Token Factory**, asks for explicit human approval, then enforces the approved policy at **every tool invocation**. A seeded inbox/calendar sandbox provides an isolated, reproducible test environment.

![Status](https://img.shields.io/badge/track-Best%20Apps%20%26%20Agents-246a4d) ![Python](https://img.shields.io/badge/backend-FastAPI-246a4d)

## Why it matters

Agents should not inherit broad account privileges for narrow tasks. A user who asks to read a hackathon announcement and create a calendar event does **not** authorize sending email, deleting email, or exporting inbox contents. LLM prompts alone are not an authorization system.

**Trust boundary:** `human intent -> Nemotron proposal -> user-approved scope -> deterministic policy gate -> sandbox tool -> audit trace`.

## Demo workflow

1. Enter: `Read my hackathon emails and add the submission deadline to my calendar.`
2. Nemotron proposes `email.read` and `calendar.create`; human approves the scope.
3. Choose **Prompt injection + gate probe**. The sandbox inbox includes an untrusted email attempting to instruct an agent to exfiltrate messages.
4. The system performs a **clearly labeled scripted red-team probe** using `send_email` and blocks it at the policy gate. Independently, Nemotron reads the messages and proposes a calendar action. If it attempts an unauthorized tool, that attempt is blocked too.
5. Inspect the **verified timestamp** (October 30, 2026 at 10:00 PDT / October 31 at 00:00 WIB), final calendar artifact and SHA-256-linked audit records. Incorrect dates, timezone-naive timestamps and duplicate event attempts are rejected.

**Security honesty:** A blocked red-team probe is **not** evidence that Nemotron itself obeyed a malicious email. The UI labels the probe `RED_TEAM_PROBE`, separate from `AGENT` calls. The sandbox never touches real Gmail, Calendar, external recipients, or personal information. The digest is not a persisted immutable log.

## Stack

| Layer | Technology | Role |
| --- | --- | --- |
| API | Python 3.11+, FastAPI | Input validation, orchestration, single-origin hosting |
| Inference | NVIDIA `Nemotron-3_5-Lightning` via Nebius Token Factory | Natural-language capability extraction, inbox-to-action reasoning |
| Enforcement | Python capability registry + immutable policy + default-deny gate | Authoritative tool authorization, independent of model text |
| Integrity | HMAC-SHA256 signed plan envelope, 15-minute expiry | Prevent client-side capability escalation between plan and execution |
| Tools | In-process disposable email/calendar sandbox | Safe real tool dispatch with no external side effects |
| UI | Vanilla JavaScript + CSS | Intent, scope, approval, trace, results |
| CI | GitHub Actions, Ruff, pytest | Static lint and automated tests |

### Local development

```bash
python -m venv .venv
source .venv/bin/activate      # Windows PowerShell: .venv\Scripts\Activate.ps1
pip install -e '.[dev]'
cp .env.example .env          # set values in your shell; .env is not auto-loaded
export NEBIUS_API_KEY='your-token-factory-key'
export APP_SIGNING_KEY="$(python -c 'import secrets; print(secrets.token_urlsafe(48))')"
export APP_ACCESS_KEY="$(python -c 'import secrets; print(secrets.token_urlsafe(32))')"
uvicorn app.main:app --reload
```

Open `http://localhost:8000`. The API key stays on the server; never enter it into the frontend or commit it to GitHub. Configure the same environment variables on your deployment provider. `NEBIUS_BASE_URL` defaults to `https://api.tokenfactory.nebius.com/v1`. The model ID can be changed with `NEBIUS_MODEL`, but must remain an eligible NVIDIA open model for the hackathon.

**Offline preview (explicitly simulated, not a hackathon-qualified inference run):**

```bash
DEMO_MODE=true uvicorn app.main:app --reload
```

On Windows PowerShell: `$env:DEMO_MODE='true'; uvicorn app.main:app --reload`.

### Optional real Google Calendar proof

For independent provider-side verification, use the **local-only, opt-in**
[Google Calendar integration test](REAL_CALENDAR_TEST.md). It uses the same
permission gate, a fictional inbox, and a dedicated Google test calendar to
create and read back a real event. No OAuth credentials are deployed on Vercel.

### Testing

```bash
ruff check .
python -m compileall -q app
node --check static/app.js
pytest -q
```

The tests use a stubbed model and do not require credits. The inference wire-contract suite checks JSON-mode requests, thinking-disabled output, truncated answers, compatibility fallback, and strict fail-closed parsing. The security matrix checks 64 capability combinations against all six registered tools (384 allow/deny cases). They cover policy default-deny, signed-plan tampering, authorization escalation, permission subsets, blocked malicious tool attempts, invalid arguments, audit chaining, and end-to-end API flow.

### Deploy

**Vercel:** Import this GitHub repository as a Python/FastAPI project, The FastAPI ASGI application is `app.main:app` (see the explicit `[tool.vercel]` entrypoint in `pyproject.toml`). There is no root `app.py`; do not configure an old root-module entrypoint. Set **all** of `NEBIUS_API_KEY`, `APP_SIGNING_KEY` and `APP_ACCESS_KEY`, and optionally `NEBIUS_MODEL`. Give judges the private access key; never put it into source control. Keep `DEMO_MODE=false`. All data is request-local and stateless; no database or durable tool actions are required.

**Docker / VPS / Railway:** `docker build -t delegation-firewall . && docker run -p 8000:8000 --env-file .env delegation-firewall`. Environment files are read by Docker, not by the Python app itself.

The application does **not** connect production providers. Adding real providers requires OAuth lifecycle, refresh/revocation, resource-scoped permissions, idempotency, replay prevention, durable event storage, rate limiting, background jobs, and per-user identity. The current proof-of-concept must not be represented as a production security gateway.

## Source-of-truth boundaries

- **LLM:** Proposes capabilities and agent actions; untrusted output always validated.
- **Human:** UI checkbox approves a *subset* of the signed proposal; server rejects added capabilities. This is NOT authenticated human-attestation or per-user identity.
- **Policy engine:** Maps server-registered tool names to immutable capabilities. Unknown tools are denied. Every tool attempt must traverse the gate.
- **Sandbox:** Performs isolated in-memory mutations and returns real execution records. No outgoing email, no real user data.
- **Audit:** Per-execution hash-linked event sequence; no claim of durable persistence/tamper-proof external storage.

## Known limits

- Model-generated proposals can be wrong, incomplete, or overly broad; human scope review is mandatory.
- Plan tokens expire after 15 minutes and are signed but are **not single-use/revocable**. This is acceptable only because all tools are synthetic and isolated.
- No external provider integrations, real authorization delegation, identity management, webhook processing, or sandbox hardening against arbitrary code (none is executed).
- Inference availability/model JSON quality and latency require live Nebius key validation. Live mode requires a shared private `APP_ACCESS_KEY`; 12 requests/minute per source, 24 requests/minute total per process and at most 2 concurrent inference operations are **per worker**, not distributed. Request Content-Length over 8 KiB is rejected before JSON parsing; this is not full streaming body enforcement. Invalid model output fails closed.
- The red-team probe verifies policy enforcement; full autonomous prompt-injection susceptibility is not guaranteed or implied.
- The application rejects explicit negations (e.g. “do not add this to my calendar”) and unsupported side-effect verbs before inference. This is a conservative admission filter, **not** a general semantic authorization proof.
- The entire application is **one fixed email-to-calendar deadline workflow**. Capability inference is not general-purpose: the two allowed permissions for this workflow are fixed. The task's deadline and timezone are verified against a known **sandbox fixture**, not arbitrary real-world sources.
- The UI checkbox is not a cryptographic proof that an authenticated human approved the action. The audit hash chain is response-local and not externally anchored.
- For Devpost judging, configure a *live* Nebius key and verify both plan and execution show `NEBIUS` mode. Offline simulation alone does not satisfy model-use requirements.

Read [SECURITY_AUDIT.md](SECURITY_AUDIT.md) for the review loop, fixed findings, tests, and accepted risks.

## License

MIT. See [LICENSE](LICENSE).
