"""Deterministic capability authorization and short-lived signed plan envelopes."""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
import os
import secrets
import time
from dataclasses import dataclass
from enum import StrEnum
from typing import Any


class Capability(StrEnum):
    EMAIL_READ = "email.read"
    EMAIL_SEND = "email.send"
    EMAIL_DELETE = "email.delete"
    CALENDAR_CREATE = "calendar.create"
    CALENDAR_READ = "calendar.read"
    CALENDAR_DELETE = "calendar.delete"


CAPABILITIES = frozenset(item.value for item in Capability)
WORKFLOW_CAPABILITIES = frozenset({"email.read", "calendar.create"})
TOOL_CAPABILITIES = {
    "read_email": Capability.EMAIL_READ,
    "send_email": Capability.EMAIL_SEND,
    "delete_email": Capability.EMAIL_DELETE,
    "create_calendar_event": Capability.CALENDAR_CREATE,
    "read_calendar": Capability.CALENDAR_READ,
    "delete_calendar_event": Capability.CALENDAR_DELETE,
}


class PolicyError(ValueError):
    """A request violates a capability boundary or plan integrity."""


@dataclass(frozen=True, slots=True)
class Policy:
    approved: frozenset[str]

    def authorize(self, tool: str) -> tuple[bool, str]:
        capability = TOOL_CAPABILITIES.get(tool)
        if capability is None:
            return False, "Unknown tool: default deny"
        if capability.value not in self.approved:
            return False, f"{capability.value} was not approved by the user"
        return True, f"{capability.value} was explicitly approved"


class PlanSigner:
    """HMAC binds scope, intent and inference mode. Not a one-time-use token."""

    def __init__(self, secret: str, ttl_seconds: int = 900):
        if len(secret) < 32:
            raise ValueError("APP_SIGNING_KEY must contain at least 32 characters")
        if not 1 <= ttl_seconds <= 3600:
            raise ValueError("Invalid plan TTL")
        self._key = secret.encode("utf-8")
        self._ttl = ttl_seconds

    @staticmethod
    def _encode(raw: bytes) -> str:
        return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")

    @staticmethod
    def _decode(raw: str) -> bytes:
        if not raw or len(raw) > 4000:
            raise PolicyError("Invalid base64 payload")
        return base64.b64decode(raw + "=" * (-len(raw) % 4), altchars=b"-_", validate=True)

    def issue(self, intent: str, proposed: list[str], mode: str) -> str:
        if not isinstance(intent, str) or not 20 <= len(intent) <= 500:
            raise PolicyError("Invalid intent")
        if not isinstance(proposed, list) or not proposed or any(
            not isinstance(item, str) or item not in WORKFLOW_CAPABILITIES for item in proposed
        ):
            raise PolicyError("Unsupported workflow capability in plan")
        if mode not in {"SIMULATED", "NEBIUS"}:
            raise PolicyError("Invalid inference mode")
        payload = {
            "intent": intent,
            "proposed": sorted(set(proposed)),
            "mode": mode,
            "iat": int(time.time()),
            "nonce": secrets.token_hex(16),
        }
        body = self._encode(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode())
        mac = hmac.new(self._key, body.encode(), hashlib.sha256).digest()
        return f"{body}.{self._encode(mac)}"

    def verify(self, token: str) -> dict[str, Any]:
        try:
            if not isinstance(token, str) or len(token) > 4000:
                raise PolicyError("Invalid plan length")
            body, signature = token.split(".")
            expected = hmac.new(self._key, body.encode(), hashlib.sha256).digest()
            provided = self._decode(signature)
            if len(provided) != 32 or not hmac.compare_digest(expected, provided):
                raise PolicyError("Plan signature mismatch")
            payload = json.loads(self._decode(body))
            if not isinstance(payload, dict):
                raise PolicyError("Invalid plan payload")
            issued = payload["iat"]
            if type(issued) is not int:
                raise PolicyError("Invalid plan timestamp")
            age = int(time.time()) - issued
            if age < -60 or age > self._ttl:
                raise PolicyError("Plan expired: analyze the task again")
            proposed = payload["proposed"]
            if not isinstance(proposed, list) or not proposed or any(
                not isinstance(p, str) or p not in WORKFLOW_CAPABILITIES for p in proposed
            ):
                raise PolicyError("Invalid plan capabilities")
            if not isinstance(payload["intent"], str) or not 20 <= len(payload["intent"]) <= 500:
                raise PolicyError("Invalid plan intent")
            if payload["mode"] not in {"SIMULATED", "NEBIUS"}:
                raise PolicyError("Invalid plan mode")
            if not isinstance(payload["nonce"], str) or len(payload["nonce"]) != 32:
                raise PolicyError("Invalid plan nonce")
            return payload
        except (ValueError, KeyError, TypeError, UnicodeError, binascii.Error) as exc:
            if isinstance(exc, PolicyError):
                raise
            raise PolicyError("Invalid signed plan") from exc


def approved_policy(proposed: list[str], approved: list[str]) -> Policy:
    if any(not isinstance(p, str) for p in approved):
        raise PolicyError("Invalid permission type")
    if len(approved) != len(set(approved)):
        raise PolicyError("Duplicate permissions are not allowed")
    if set(approved) - set(proposed):
        raise PolicyError("Cannot approve permissions outside the signed plan")
    return Policy(approved=frozenset(approved))


def signing_key() -> tuple[str, bool]:
    configured = os.getenv("APP_SIGNING_KEY", "")
    return (configured, True) if configured else (secrets.token_urlsafe(48), False)
