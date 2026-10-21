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
        # Published for the audit layer (ADR-067), and reset even when the
        # route raises, so one request's identity cannot leak into the
        # next request served from the same context.
        from app.api.request_context import (
            describe_principal,
            reset_principal_identity,
            set_principal_identity,
        )

        identity_token = set_principal_identity(describe_principal(principal))
        try:
            response = await call_next(request)
        finally:
            reset_principal_identity(identity_token)
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


def local_producer_owning(source_id: str) -> Optional[str]:
    """
    Name the in-process producer that owns `source_id`, or None (ADR-090).

    Two layers, so the answer never depends on what has run so far:

    * Reserved ids, owned whether or not their producer exists yet: the host
      collector's default source and the host UDP-endpoint observer. The
      collector is created lazily - on the dashboard's first status poll -
      so a registry check alone would accept stream data into the live host
      source after a restart and refuse it once someone opened the page.
    * Any other id under which a host collector has registered its adapter,
      such as a collector started with a custom source id.

    Imported lazily: storage, services and the API must not import each
    other at module load.
    """
    from app.adapters.base import get_adapter_registry
    from app.adapters.windows_telemetry import WindowsConnectionAdapter
    from app.api.v1.hostobs import UDP_SOURCE_ID
    from app.core.config import InvalidCollectorSourceId, get_config
    from app.services.collector import DEFAULT_SOURCE_ID

    reserved = {
        DEFAULT_SOURCE_ID: "the host connection-table collector",
        UDP_SOURCE_ID: "the host UDP-endpoint observer",
    }
    # The collector's CONFIGURED id is reserved for the same reason the
    # default is (ADR-099): the collector is built lazily, so between a
    # restart and the first status poll the registry is empty and the
    # registry layer alone would accept external telemetry into the live
    # host source. A misconfigured id must not open that window either, so
    # a rejected value falls back to protecting the default rather than
    # protecting nothing.
    try:
        reserved.setdefault(
            get_config().resolved_collector_source_id(),
            "the host connection-table collector",
        )
    except InvalidCollectorSourceId:
        pass
    if source_id in reserved:
        return reserved[source_id]
    if isinstance(get_adapter_registry().get(source_id), WindowsConnectionAdapter):
        return "a host connection-table collector running in this process"
    return None


def resolve_ingest_source(request: Request, claimed: Optional[str]) -> str:
    """
    The source identity telemetry will actually be stored under, provided
    it may be written from outside (ADR-090).

    Identity is resolved first (see `_resolve_claimed_source`). The result
    is then refused if an in-process producer owns it. External telemetry
    filed under the host collector's own source would mix a remote or
    synthetic sender's records into the local host's provenance; on the
    stream path it also crashed with a 500, because the registry handed
    back the collector's connection-table adapter, which cannot parse
    NDJSON.
    """
    source_id = _resolve_claimed_source(request, claimed)
    owner = local_producer_owning(source_id) if source_id else None
    if owner:
        # 403, not 409: the sensor agent counts every 409 as an event-identity
        # conflict, and this is a refusal of the destination, not a conflict
        # between events. It is permanent, so the agent will not retry it.
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={
                "error": "source_reserved_for_local_producer",
                "message": (
                    f"Source {source_id!r} is written only by {owner}. "
                    "Submit external telemetry under a different source id."
                ),
                "source_id": source_id,
            },
        )
    return source_id


def _resolve_claimed_source(request: Request, claimed: Optional[str]) -> str:
    """
    The source identity telemetry will actually be stored under.

    This is the ingestion trust boundary. Everything downstream — the
    adapter id, the UUIDv5 idempotency namespace, `event.source_id`, the
    source-health record — is derived from the value returned here, so a
    caller that cannot influence this value cannot impersonate another
    source anywhere in the pipeline.

    Local (loopback) mode is unauthenticated by design: there is no
    principal, the operator is the only caller, and the claimed value
    passes through unchanged. That is the pre-existing contract and this
    function does not alter it.

    Central mode:

    * A principal is required. There is no fallback to the request body —
      if authentication did not happen, ingestion does not happen.
    * The credential must carry a write role. A `read_only` credential
      submitting telemetry is a misconfiguration, and silently accepting
      it would make the role meaningless.
    * A non-admin principal ingests as itself. Claiming another source is
      **refused**, not quietly rewritten: a sensor sending the wrong id is
      misconfigured and should be told so rather than having its data
      filed somewhere it did not intend.
    * An admin may ingest on behalf of any source, but must say which —
      an admin credential is not itself a sensor.
    """
    principal = get_principal(request)
    if principal is None:
        # Local mode. Unauthenticated by design; see module docstring.
        return claimed or ""

    if not principal.may_write():
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={
                "error": "write_not_permitted",
                "message": (
                    f"Role {principal.role.value!r} may not submit telemetry; "
                    "an ingest credential is required."
                ),
            },
        )

    if principal.is_admin:
        if not claimed:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail={
                    "error": "source_id_required",
                    "message": (
                        "An admin credential is not bound to a source. State "
                        "the source_id this telemetry belongs to."
                    ),
                },
            )
        return claimed

    if claimed and claimed != principal.source_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={
                "error": "source_identity_mismatch",
                # Names only the caller's own identity. Confirming whether
                # the claimed source exists would enumerate the fleet.
                "message": (
                    "This credential may only submit telemetry for source "
                    f"{principal.source_id!r}."
                ),
            },
        )
    return principal.source_id


def require_admin_in_central(request: Request) -> Optional[Principal]:
    """
    Admin-only in central mode; a no-op on a loopback deployment.

    Used as a route dependency. The local-mode pass-through mirrors
    `scope_source`: there is no principal to check, the operator is the
    only caller, and `require_admin` alone would turn every local request
    into a 401.

    `security.py` states that a sensor's credential cannot read the audit
    log. That was a property of the design, not of the code — nothing
    called `require_admin` — so an ingest credential could read the audit
    trail of the whole fleet. This closes it.
    """
    if get_principal(request) is None:
        return None
    return require_admin(request)
