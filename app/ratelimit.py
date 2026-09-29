"""A small in-process rate limiter.

This protects the API's own endpoints. It does NOT protect login: tokens are
issued by Keycloak, so password guessing never touches this code. That is
Keycloak's brute-force detection, configured on the realm.
"""

import json
import os
import time
from collections import defaultdict, deque

from fastapi import Request
from fastapi.responses import JSONResponse

WINDOW_SECONDS = 60
DEFAULT_LIMIT = int(os.environ.get("RATE_LIMIT_PER_MINUTE", "120"))
DOWNLOAD_LIMIT = int(os.environ.get("DOWNLOAD_LIMIT_PER_MINUTE", "20"))

# Monitoring and the schema must stay reachable even under load.
EXEMPT_PATHS = {"/health", "/docs", "/openapi.json"}

# key -> timestamps of recent requests, oldest first
_hits: dict[tuple[str, str], deque] = defaultdict(deque)
_MAX_TRACKED_KEYS = 10_000


def _subject(request: Request) -> str:
    """Best-effort user id from the token, WITHOUT verifying it.

    An unverified claim is fine as a bucket label: the worst an attacker can
    do by forging it is share a bucket they are already inside, because the
    key also includes their address.
    """
    header = request.headers.get("authorization", "")
    if not header.lower().startswith("bearer "):
        return "-"
    try:
        import base64

        payload = header[7:].split(".")[1]
        payload += "=" * (-len(payload) % 4)
        return str(json.loads(base64.urlsafe_b64decode(payload)).get("sub", "-"))[:64]
    except Exception:
        return "-"


def _identity(request: Request) -> str:
    # Address AND subject. Keying on the token alone would let a caller reset
    # their own limit simply by asking Keycloak for a new token.
    address = request.client.host if request.client else "unknown"
    return f"{address}|{_subject(request)}"


def _bucket(request: Request) -> tuple[str, int]:
    # Downloads move real data, so they get a tighter limit than metadata.
    if request.url.path.endswith("/file"):
        return "download", DOWNLOAD_LIMIT
    return "default", DEFAULT_LIMIT


def _purge_if_large() -> None:
    if len(_hits) <= _MAX_TRACKED_KEYS:
        return
    for key in [k for k, v in _hits.items() if not v]:
        del _hits[key]


async def rate_limit_middleware(request: Request, call_next):
    if request.url.path in EXEMPT_PATHS:
        return await call_next(request)

    bucket, limit = _bucket(request)
    key = (_identity(request), bucket)
    now = time.monotonic()

    hits = _hits[key]
    # Sliding window: drop anything older than the window before counting.
    while hits and now - hits[0] > WINDOW_SECONDS:
        hits.popleft()

    if len(hits) >= limit:
        retry_after = int(WINDOW_SECONDS - (now - hits[0])) + 1
        return JSONResponse(
            status_code=429,
            content={"detail": "Too many requests"},
            headers={"Retry-After": str(retry_after)},
        )

    hits.append(now)
    _purge_if_large()
    return await call_next(request)
