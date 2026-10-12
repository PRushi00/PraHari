"""
PraHari — Central-Mode Request Authentication

Installed as middleware only when `deployment_mode == CENTRAL`. In local
(loopback) mode nothing here runs and no behaviour changes.

The middleware authenticates every request outside the configured public
path list, attaches a `Principal` to `request.state`, and lets route
handlers enforce source scoping through `require_principal`.
"""

from __future__ import annotations

import logging
from typing import Optional

from fastapi import HTTPException, Request, status
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse

from app.core.security import (
    CredentialStore,
    InvalidCredentialError,
    Principal,
    Role,
    SourceAccessDenied,
    redact,
)

logger = logging.getLogger(__name__)

AUTH_HEADER = "Authorization"
BEARER_PREFIX = "Bearer "


def _extract_token(request: Request) -> Optional[str]:
    header = request.headers.get(AUTH_HEADER, "")
    if header.startswith(BEARER_PREFIX):
        return header[len(BEARER_PREFIX):].strip()
    return None


class CentralAuthMiddleware(BaseHTTPMiddleware):
    """
    Authenticates central-mode requests.

    Default deny: a request that is not on the public list and does not
    present a valid credential is rejected before reaching any handler.
    """

    def __init__(self, app, store: CredentialStore, public_paths: list[str]):
        super().__init__(app)
        self.store = store
        self.public_paths = tuple(public_paths)

    def _is_public(self, path: str) -> bool:
        return any(path == p or path.startswith(p.rstrip("/") + "/")
                   for p in self.public_paths)

    async def dispatch(self, request: Request, call_next):
        path = request.url.path

        if self._is_public(path):
            return await call_next(request)

        token = _extract_token(request)
        if not token:
            # The error says what is required, never what was received.
            logger.warning(
                "Unauthenticated central request to %s (%s)",
                path, redact(token),
            )
            return JSONResponse(
                status_code=status.HTTP_401_UNAUTHORIZED,
                headers={"WWW-Authenticate": "Bearer"},
                content={
                    "detail": {
                        "error": "authentication_required",
                        "message": (
                            "Central deployment requires a bearer credential. "
                            "Send Authorization: Bearer <token>."
                        ),
                    }
                },
            )

        try:
            principal = self.store.authenticate(token)
        except InvalidCredentialError:
            logger.warning(
                "Rejected central credential for %s (%s)", path, redact(token)
            )
            return JSONResponse(
                status_code=status.HTTP_401_UNAUTHORIZED,
                headers={"WWW-Authenticate": "Bearer"},
                content={
                    "detail": {
                        "error": "invalid_credential",
                        # Deliberately identical wording whether the token is
                        # unknown or disabled: distinguishing them would tell
                        # an attacker which source ids exist.
                        "message": "Credential is not recognised.",
                    }
                },
            )

        request.state.principal = principal
        response = await call_next(request)
        response.headers["X-PraHari-Source"] = principal.source_id
        return response


def get_principal(request: Request) -> Optional[Principal]:
    """The authenticated principal, or None in local mode."""
    return getattr(request.state, "principal", None)


def require_principal(request: Request) -> Principal:
    """
    The authenticated principal, or an error.

    Used by routes that must not be reachable unauthenticated even if the
    middleware were misconfigured — defence in depth.
    """
    principal = get_principal(request)
    if principal is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={
                "error": "authentication_required",
                "message": "This route requires an authenticated principal.",
            },
        )
    return principal


def require_admin(request: Request) -> Principal:
    """Administrative routes: audit, configuration, retention, experiments."""
    principal = require_principal(request)
    if not principal.is_admin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={
                "error": "insufficient_privilege",
                "message": (
                    f"Role {principal.role.value!r} may not access this "
                    "resource; the admin role is required."
                ),
            },
        )
    return principal


def scope_source(request: Request, requested: Optional[str]) -> Optional[str]:
    """
    Resolve the source a request may act on.

    In local mode the requested value passes through unchanged. In central
    mode a non-admin principal is confined to its own source, and an
    explicit request for another source is refused rather than quietly
    rewritten — a client asking for the wrong data should be told.
    """
    principal = get_principal(request)
    if principal is None:
        return requested
    try:
        scoped = principal.assert_source_access(requested)
    except SourceAccessDenied as exc:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={
                "error": "cross_source_access_denied",
                "message": str(exc),
            },
        )
    return scoped or requested
