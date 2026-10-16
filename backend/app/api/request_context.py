"""
PraHari — Request Correlation IDs (ADR-063)

An unexplained `descriptive_analyses` row (ADR-062) took a code trace to
attribute, because `audit_events` records only
`user_identity="local_operator"` — no request id, no method, no path. The
database could say *what* changed and *when*, never *which request*.

This supplies the missing link.

Why a contextvar
----------------
`log_audit` is a method on `Database`, which has no request object and
should not grow one: the storage layer must stay usable from the
collector, the CLI and tests, none of which have an HTTP request.

Threading the id through every call site would touch a dozen routes and
would be forgotten by the next one added. A `ContextVar` set by the
middleware is visible to every audit write under that request —
including from synchronous handlers, because Starlette runs those in a
worker thread via anyio, which copies the context across.

Outside a request — collector polls, CLI, tests — the var is unset and
the id is recorded as NULL, which is accurate rather than a fabricated
placeholder.

Privacy
-------
The id is a random UUID or whatever the client supplied, and nothing
else. No address, no user agent, no query string: those would put
potentially identifying data in a table that is kept for a long time,
and the correlation id alone is enough to tie a row to a log line.

A client-supplied `X-Request-ID` is accepted so a caller can correlate
across systems, but it is **length-capped and sanitised** — it lands in
stored audit records, so an unbounded or control-character value would be
a log-injection vector.
"""

from __future__ import annotations

import re
import uuid
from contextvars import ContextVar
from typing import Optional

from starlette.middleware.base import BaseHTTPMiddleware

REQUEST_ID_HEADER = "X-Request-ID"
MAX_REQUEST_ID_LENGTH = 64

# Conservative on purpose: this value is persisted and shown in reports.
_SAFE_REQUEST_ID = re.compile(r"^[A-Za-z0-9._:-]+$")

_request_id: ContextVar[Optional[str]] = ContextVar("prahari_request_id", default=None)


def get_request_id() -> Optional[str]:
    """
    The current request's correlation id, or None outside a request.

    None is the honest answer for a collector poll, a CLI invocation or a
    test: there was no request, so there is no id to record.
    """
    return _request_id.get()


def set_request_id(value: Optional[str]):
    """Set the id for this context. Returns the token for resetting."""
    return _request_id.set(value)


def reset_request_id(token) -> None:
    _request_id.reset(token)


def sanitise_request_id(raw: Optional[str]) -> Optional[str]:
    """
    Accept a client-supplied id only if it is safe to persist.

    Rejected rather than trimmed: silently truncating a 10 KB header into
    something that looks like a legitimate id would be worse than
    generating a fresh one, because the stored value would no longer
    match what the client holds.
    """
    if not raw:
        return None
    candidate = raw.strip()
    if not candidate or len(candidate) > MAX_REQUEST_ID_LENGTH:
        return None
    if not _SAFE_REQUEST_ID.match(candidate):
        return None
    return candidate


class RequestIdMiddleware(BaseHTTPMiddleware):
    """
    Attach a correlation id to every request and echo it back.

    Installed in both deployment modes: attribution is not a central-mode
    concern, and the write that motivated this came from a loopback
    deployment.
    """

    async def dispatch(self, request, call_next):
        request_id = (
            sanitise_request_id(request.headers.get(REQUEST_ID_HEADER))
            or uuid.uuid4().hex
        )
        token = set_request_id(request_id)
        request.state.request_id = request_id
        try:
            response = await call_next(request)
        finally:
            # Reset even on an exception, so a failed request cannot leak
            # its id into whatever reuses the context next.
            reset_request_id(token)
        response.headers[REQUEST_ID_HEADER] = request_id
        return response
