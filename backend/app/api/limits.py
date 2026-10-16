"""
PraHari — Request Size and Rate Limits (blueprint §4.2, §6, §12)

Two controls the blueprint requires at the ingestion boundary, and that
`/audit/config` already reported as if they existed:

* **Payload size.** `AppConfig.max_request_size_mb` has been a configuration
  value since the first schema. Nothing read it. A client could post a body
  of any size and the server would buffer all of it before a single
  validator ran.
* **Rate.** §4.2 requires the central service to validate "identity, schema,
  timestamps, payload size, rate" before accepting records. No rate control
  of any kind existed.

Both fail closed at the boundary, before parsing, so a hostile body is
rejected on the strength of its headers rather than its contents.

Deliberate limits of this implementation
----------------------------------------
The rate limiter is a fixed-window counter held **in this process**. That is
honest for a single-process deployment and is what PraHari currently is; it
is NOT a distributed limiter, and running several workers multiplies the
effective allowance by the worker count. §16 requires measurement before any
numerical service target is claimed, and none is claimed here.

A fixed window also permits a burst of up to 2x the limit across a window
boundary. A sliding window would not, at the cost of retaining a timestamp
per request. The counter is the smaller, bounded choice; the boundary burst
is stated rather than hidden.
"""

from __future__ import annotations

import logging
import threading
import time
from typing import Optional

from fastapi import status
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse

logger = logging.getLogger(__name__)

BYTES_PER_MB = 1024 * 1024

# Applied to request bodies only. A GET carries none, and a query that is
# merely long is bounded by the server's own header limits.
_BODY_METHODS = frozenset({"POST", "PUT", "PATCH"})


class RequestSizeLimitMiddleware(BaseHTTPMiddleware):
    """
    Reject a body larger than the configured maximum.

    Decided from `Content-Length` where the client sends one, so an
    oversized body is refused before it is read. A chunked request has no
    such header; rather than buffering it to find out, the body is read in
    bounded increments and abandoned as soon as the limit is passed.
    """

    def __init__(self, app, max_bytes: int):
        super().__init__(app)
        self.max_bytes = max_bytes

    def _too_large(self, observed: Optional[int]) -> JSONResponse:
        return JSONResponse(
            status_code=413,  # Content Too Large
            content={
                "detail": {
                    "error": "payload_too_large",
                    "message": (
                        "Request body exceeds the configured maximum of "
                        f"{self.max_bytes // BYTES_PER_MB} MB. Split the "
                        "submission into smaller batches."
                    ),
                    "max_bytes": self.max_bytes,
                    # The size the server saw, which the client already
                    # knows. Nothing about the body's content.
                    "observed_bytes": observed,
                }
            },
        )

    async def dispatch(self, request, call_next):
        if request.method not in _BODY_METHODS:
            return await call_next(request)

        declared = request.headers.get("content-length")
        if declared is not None:
            try:
                if int(declared) > self.max_bytes:
                    logger.warning(
                        "Rejected oversized request to %s (%s bytes declared)",
                        request.url.path, declared,
                    )
                    return self._too_large(int(declared))
            except ValueError:
                # A malformed Content-Length is not something to guess at.
                return JSONResponse(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    content={
                        "detail": {
                            "error": "malformed_content_length",
                            "message": "Content-Length is not an integer.",
                        }
                    },
                )
            return await call_next(request)

        # No Content-Length: a chunked or streamed body. Read it bounded,
        # and hand the already-read bytes to the application so the route
        # still sees its payload.
        body = b""
        async for chunk in request.stream():
            body += chunk
            if len(body) > self.max_bytes:
                logger.warning(
                    "Rejected oversized chunked request to %s", request.url.path
                )
                return self._too_large(len(body))

        async def receive():
            return {"type": "http.request", "body": body, "more_body": False}

        request._receive = receive  # noqa: SLF001 — the documented ASGI replay idiom
        return await call_next(request)


class FixedWindowRateLimiter:
    """
    Request counter per key over a fixed wall-clock window.

    Bounded by construction: a key is forgotten as soon as its window
    expires, so a flood of distinct keys cannot grow the table without
    bound beyond one window's worth.
    """

    def __init__(self, max_requests: int, window_seconds: float):
        if max_requests < 1:
            raise ValueError("max_requests must be at least 1")
        if window_seconds <= 0:
            raise ValueError("window_seconds must be positive")
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self._lock = threading.Lock()
        # key -> (window_started_at, count)
        self._windows: dict[str, tuple[float, int]] = {}

    def check(self, key: str, now: Optional[float] = None) -> tuple[bool, int, float]:
        """
        Count one request against `key`.

        Returns (allowed, remaining, seconds_until_reset). A refused
        request is still counted against nothing — refusing it must not
        extend the caller's penalty, or a client in a retry loop could
        never recover.
        """
        now = now if now is not None else time.monotonic()
        with self._lock:
            started, count = self._windows.get(key, (now, 0))
            if now - started >= self.window_seconds:
                started, count = now, 0

            if count >= self.max_requests:
                self._windows[key] = (started, count)
                return False, 0, max(0.0, self.window_seconds - (now - started))

            count += 1
            self._windows[key] = (started, count)
            self._prune(now)
            return True, self.max_requests - count, self.window_seconds - (now - started)

    def _prune(self, now: float) -> None:
        """Drop expired windows. Called under the lock."""
        if len(self._windows) < 1024:
            return
        expired = [
            k for k, (started, _) in self._windows.items()
            if now - started >= self.window_seconds
        ]
        for k in expired:
            del self._windows[k]

    def reset(self) -> None:
        with self._lock:
            self._windows.clear()


class RateLimitMiddleware(BaseHTTPMiddleware):
    """
    Bound how fast one caller may submit.

    Keyed by the **authenticated principal** where there is one, so a
    source cannot escape its allowance by changing address, and by client
    address otherwise. The authenticated key is preferred deliberately:
    addresses are shared behind NAT, and penalising every sensor behind
    one gateway for the behaviour of a single sensor would be wrong.
    """

    def __init__(self, app, limiter: FixedWindowRateLimiter, exempt_paths: tuple[str, ...] = ()):
        super().__init__(app)
        self.limiter = limiter
        self.exempt_paths = exempt_paths

    def _key(self, request) -> str:
        principal = getattr(request.state, "principal", None)
        if principal is not None:
            return f"credential:{principal.credential_id}"
        client = request.client
        return f"address:{client.host if client else 'unknown'}"

    async def dispatch(self, request, call_next):
        path = request.url.path
        if any(path == p or path.startswith(p.rstrip("/") + "/") for p in self.exempt_paths):
            return await call_next(request)

        allowed, remaining, reset_in = self.limiter.check(self._key(request))
        if not allowed:
            logger.warning("Rate limit reached for a caller on %s", path)
            return JSONResponse(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                headers={"Retry-After": str(max(1, int(reset_in) + 1))},
                content={
                    "detail": {
                        "error": "rate_limit_exceeded",
                        "message": (
                            "Too many requests. This limit is per credential "
                            "where authenticated, otherwise per client address."
                        ),
                        "limit": self.limiter.max_requests,
                        "window_seconds": self.limiter.window_seconds,
                        "retry_after_seconds": round(reset_in, 1),
                    }
                },
            )

        response = await call_next(request)
        response.headers["X-RateLimit-Limit"] = str(self.limiter.max_requests)
        response.headers["X-RateLimit-Remaining"] = str(remaining)
        return response
