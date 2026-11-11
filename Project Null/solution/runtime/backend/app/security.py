from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
import time
from collections import defaultdict, deque
from typing import Any

from .config import RATE_LIMIT_PER_MINUTE, SECRET_KEY


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def _b64url_decode(data: str) -> bytes:
    padding = "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode((data + padding).encode("ascii"))


def issue_activation_token(session_id: str, layer: int, nonce: str, expires_at_epoch: int) -> str:
    payload: dict[str, Any] = {
        "session_id": session_id,
        "layer": layer,
        "nonce": nonce,
        "exp": expires_at_epoch,
    }
    payload_bytes = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
    encoded = _b64url_encode(payload_bytes)
    signature = hmac.new(SECRET_KEY.encode("utf-8"), encoded.encode("ascii"), hashlib.sha256).digest()
    return f"{encoded}.{_b64url_encode(signature)}"


def verify_activation_token(token: str) -> dict[str, Any] | None:
    try:
        encoded, provided_sig = token.split(".", 1)
    except ValueError:
        return None

    expected_sig = hmac.new(SECRET_KEY.encode("utf-8"), encoded.encode("ascii"), hashlib.sha256).digest()
    if not hmac.compare_digest(_b64url_encode(expected_sig), provided_sig):
        return None

    try:
        payload = json.loads(_b64url_decode(encoded).decode("utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError):
        return None

    if int(payload.get("exp", 0)) < int(time.time()):
        return None

    return payload


def new_nonce() -> str:
    return secrets.token_urlsafe(16)


class SessionRateLimiter:
    def __init__(self, limit_per_minute: int = RATE_LIMIT_PER_MINUTE) -> None:
        self.limit = limit_per_minute
        self.buckets: dict[str, deque[float]] = defaultdict(deque)

    def allow(self, session_id: str) -> bool:
        now = time.time()
        window_start = now - 60
        bucket = self.buckets[session_id]
        while bucket and bucket[0] < window_start:
            bucket.popleft()
        if len(bucket) >= self.limit:
            return False
        bucket.append(now)
        return True
