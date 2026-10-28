"""Tool authorization. This module is the only enforcement authority."""

from __future__ import annotations

import base64
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
TOOL_CAPABILITIES = {
    "read_email": Capability.EMAIL_READ,
    "send_email": Capability.EMAIL_SEND,
    "delete_email": Capability.EMAIL_DELETE,
    "create_calendar_event": Capability.CALENDAR_CREATE,
    "read_calendar": Capability.CALENDAR_READ,
    "delete_calendar_event": Capability.CALENDAR_DELETE,
}


class PolicyError(ValueError):
    """Request violates the immutable permission boundary."""


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
    """Stateless HMAC-signed, expiring plan envelope. Prevents client plan escalation."""

    def __init__(self, secret: str, ttl_seconds: int = 1800):
        if len(secret) < 32:
            raise ValueError("APP_SIGNING_KEY must contain at least 32 characters")
        self._key = secret.encode("utf-8")
        self._ttl = ttl_seconds

    @staticmethod
    def _encode(raw: bytes) -> str:
        return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")

    @staticmethod
    def _decode(raw: str) -> bytes:
        return base64.urlsafe_b64decode(raw + "=" * (-len(raw) % 4))

    def issue(self, intent: str, proposed: list[str], mode: str) -> str:
        if any(item not in CAPABILITIES for item in proposed):
            raise PolicyError("Unsupported capability in plan")
        payload = {
            "intent": intent,
            "proposed": sorted(set(proposed)),
            "mode": mode,
            "iat": int(time.time()),
            "nonce": secrets.token_hex(8),
        }
        body = self._encode(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode())
        mac = hmac.new(self._key, body.encode(), hashlib.sha256).digest()
        return f"{body}.{self._encode(mac)}"

    def verify(self, token: str) -> dict[str, Any]:
        try:
            body, signature = token.split(".", maxsplit=1)
            expected = hmac.new(self._key, body.encode(), hashlib.sha256).digest()
            if not hmac.compare_digest(expected, self._decode(signature)):
                raise PolicyError("Plan signature mismatch")
            payload = json.loads(self._decode(body))
            age = int(time.time()) - payload["iat"]
            if age < -60 or age > self._ttl:
                raise PolicyError("Plan expired: analyze the task again")
            proposed = payload["proposed"]
            if not isinstance(proposed, list) or any(x not in CAPABILITIES for x in proposed):
                raise PolicyError("Invalid plan capabilities")
            if not isinstance(payload["intent"], str):
                raise PolicyError("Invalid plan intent")
            return payload
        except (ValueError, KeyError, TypeError, UnicodeError) as exc:
            if isinstance(exc, PolicyError):
                raise
            raise PolicyError("Invalid signed plan") from exc


def approved_policy(proposed: list[str], approved: list[str]) -> Policy:
    if len(approved) != len(set(approved)):
        raise PolicyError("Duplicate permissions are not allowed")
    unknown = set(approved) - set(proposed)
    if unknown:
        raise PolicyError(f"Cannot approve permissions outside the signed plan: {sorted(unknown)}")
    return Policy(approved=frozenset(approved))


def signing_key() -> tuple[str, bool]:
    configured = os.getenv("APP_SIGNING_KEY", "")
    return (configured, True) if configured else (secrets.token_urlsafe(48), False)
