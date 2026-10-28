# Delegation Firewall — Security / Engineering Audit

Scope: FastAPI + NVIDIA Nemotron (Nebius Token Factory) **fictional email/calendar sandbox only**. Analysis includes static review, adversarial fixture tests and repeated GitHub Actions checks. No real provider OAuth, no public production deployment and no live Nemotron call were available to verify.

## Fixed in audit loop

| Severity | Finding | Fix |
| --- | --- | --- |
| High | Any created calendar item previously made the task appear completed, even if the time was wrong | Timezone-aware UTC equivalence to verified fixture; wrong/naive timestamps and duplicate events rejected |
| High | If exposed publicly, unauthenticated API calls could burn Nebius inference credits | Server-side shared `APP_ACCESS_KEY` required for live mode, per-source limiter (12/min), process-wide budget (24/min), concurrency cap (2), and 8 KiB Content-Length gate |
| Medium | Malformed base64 signature/envelope could yield a 500 | Strict base64/HMAC/payload validation with fail-closed `PolicyError` |
| Medium | Calendar lost the actual 10:00 PDT deadline, which is midnight in Jakarta | Preserve `start_at` as offset-aware ISO 8601; verify absolute UTC instant |
| Medium | Irrelevant mail contents were exposed to the model | Filter sandbox read to only the relevant fictional email |
| Medium | UI advertised read-only summary though the engine only supported deadline-to-calendar | Remove unsupported preset; reject unsupported intent (422) |
| Medium | API payloads lacked no-store and response CSP | CSP, frame denial, nosniff, no-referrer and API no-store headers |
| Medium | One auth test passed only in the whole suite | Test config made independent of import order |
| Low | Stale plan could render after the user edited intent while analysis was running | Revision counter ignores old responses |
| Low | Unexpected model response type might raise a raw 500 | Catch TypeError and fail closed |

## Verification

- Local: **425 checks passed** after the hardening patch. This includes **384** capability-by-tool combinations: all 64 permission sets against six mapped tools. Tests of signed-plan tampering, wrong date, duplicate event, unauthorized send, sandbox isolation, access-gating and CSP are included.
- GitHub Actions: see current final commit's CI status; the final commit must pass both Ruff and pytest before claiming a release gate. Local testing alone is not sufficient.
- Model identity: default `nvidia/Nemotron-3_5-Lightning` on Nebius Token Factory. No live key was available to prove production inference.
- Scripted probe is labeled `RED_TEAM_PROBE`. A blocked scripted attempt is not evidence of a successfully induced real model jailbreak.

## Residual risk, deliberately NOT fixed in this MVP

1. **Not a production authorization gateway.** There is no authenticated multi-tenant approval, no OAuth scopes, no revocation, no provider-side enforcement, no real accounts, and no resource ownership boundary.
2. **Signed plans are replayable for up to 15 minutes.** Real side effects would require persistent nonce consumption, idempotency and durable distributed state. In this MVP each synthetic run starts with a fresh sandbox.
3. **Worker-local limiter is not distributed.** A shared demo password might leak; quotas can reset on instance lifecycle. External rate limiting and cost caps are required before general public access.
4. **Human approval is UI-level, not authenticated attestation.** A client can choose any subset of the server-signed proposal without the server proving which human clicked a checkbox.
5. **Audit trace is response-local, not an immutable security ledger.** An adversary controlling the response can recompute hashes.
6. **Fixed single workflow:** model capability proposal is constrained to `email.read` and `calendar.create`; this is not evidence of general intent-to-permission compilation. The ground-truth deadline is known in a fictional fixture.
7. **No live model or public-deployment verification, distributed concurrency test, third-party penetration test or dependency CVE scan.** Passing synthetic tests cannot establish these properties.

## Release gate still required

- Final commit CI green (Ruff + pytest).
- Private `NEBIUS_API_KEY`, `APP_SIGNING_KEY` and `APP_ACCESS_KEY` configured in the backend.
- Deployed HTTPS URL reachable by judges with credential provided separately.
- Real Nebius plan and run complete; response explicitly shows `mode=NEBIUS`.
- Manual browser smoke test, error case smoke test, and demo video honestly distinguish the probe from real agent behavior.

**Audit conclusion:** no presently known authorization-bypass in the fictional tool gate under tested scenarios. That is narrowly scoped evidence, not a zero-defect guarantee or production certification.
