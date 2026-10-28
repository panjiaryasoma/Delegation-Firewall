# Real Google Calendar acceptance test (opt-in)

This is NOT a production integration or a feature of the deployed Vercel UI. The inbox stays fictional. This local probe reuses the same policy gate and live Nemotron agent used by the MVP to write a real Google Calendar test event and verify it independently using Google's GET endpoint.

## 1. Dedicated test account and calendar

Use a SEPARATE Google account exclusively for this test. In https://calendar.google.com create a secondary calendar using Other calendars > + > Create new calendar, name it Delegation Firewall Test, then open Settings > Integrate calendar and copy its Calendar ID. Do not use the primary calendar.

The scope https://www.googleapis.com/auth/calendar.events.owned grants read, create, change, and delete for calendars owned by the test Google account. Google does not limit this scope to create-only. Our deterministic gate must prevent delete calls separately.

## 2. Google Cloud setup

1. At https://console.cloud.google.com create a project called delegation-firewall-test.
2. APIs & Services > Library > Google Calendar API > Enable.
3. Google Auth platform > Branding: provide app name and support email.
4. Audience: choose External, keep Testing, add the dedicated test Google account under Test users.
5. Data Access: include scope https://www.googleapis.com/auth/calendar.events.owned.
6. Clients > Create Client > Desktop app. Download the OAuth client JSON and store it at repository root under the filename google-oauth-client.json (gitignored). This is a LOCAL probe; no Vercel callback is needed.

For External apps in Testing mode, Calendar-scope refresh tokens generally expire after 7 days. This script keeps OAuth credentials in memory and requests login every run.

## 3. Run locally using PowerShell

From a Windows terminal:

    git clone https://github.com/panjiaryasoma/Delegation-Firewall.git
    cd Delegation-Firewall
    python -m venv .venv
    .\.venv\Scripts\Activate.ps1
    pip install -e '.[dev]'
    pip install google-api-python-client google-auth-oauthlib

    $env:DEMO_MODE = "false"
    $env:NEBIUS_API_KEY = Read-Host "Nebius Token Factory API key"
    python -m scripts.google_calendar_real_probe --calendar-id "PASTE_YOUR_TEST_CALENDAR_ID" --approve-real-write

The --approve-real-write flag is mandatory. The script opens a Google OAuth browser consent flow, creates ONE real 15-minute test event, or verifies an existing event with the same deterministic ID. This test event does not invite attendees and sends no updates.

Never commit OAuth JSON or tokens; never share them in chat. The Google OAuth credential stays in the local process; it is not passed to Nemotron or to the deployed website.

## 4. Evidence and acceptance

A successful result reports:
- provider = GOOGLE_CALENDAR_REAL
- source_inbox = FICTIONAL_SANDBOX_FIXTURE
- Google event ID and its timestamp from read-back via the real Google API
- blocked_delete = true and outbound_delete_requests = 0
- provider_request_methods with POST and GET, but never DELETE

Verify the event independently in Google Calendar: 30 October 2026 10:00 PDT = 31 October 2026 00:00 WIB. Confirm the item still exists after the rejected delete probe.

This proves a constrained real-provider execution path. It does not prove general security, multi-user OAuth, or a production-ready firewall. The script's method counter is application-level evidence; a formal security assessment should also capture HTTP egress independently.

## 5. After the test

Delete the test event manually when finished and revoke the OAuth grant if no longer needed. Production use would additionally need account identity, refresh-token lifecycle, encrypted storage, user-bound policies, state/PKCE, replay prevention, external observability, and stronger egress isolation.

References: https://developers.google.com/workspace/calendar/api/auth and https://developers.google.com/identity/protocols/oauth2/