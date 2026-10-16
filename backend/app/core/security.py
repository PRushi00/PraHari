"""
PraHari — Central-Mode Authentication and Source Isolation

Local (loopback) deployment is unauthenticated by design: the service binds
to 127.0.0.1 and the operator is the only principal.

**Central** deployment accepts telemetry from distinct remote sources and
therefore requires authentication, per-source identity and source-scoped
access. This module provides those controls and, critically, **fails
closed**: central mode refuses to start without credentials rather than
starting open.

Design notes
------------
* Credentials are **hashed** (PBKDF2-HMAC-SHA256, per-credential salt).
  A readable store would hand an attacker every source's key.
* Comparison is **constant-time** to avoid leaking a prefix by timing.
* Credentials are loaded from the environment or a file **outside** source
  control; nothing is defaulted, generated silently, or embedded.
* A token identifies exactly one `source_id`. A source can only read and
  write its own telemetry — cross-source access is rejected, not filtered
  silently, so a misconfigured client fails loudly.
* The admin role is separate from ingest: a sensor's credential cannot read
  the audit log or change configuration.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import secrets
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

PBKDF2_ITERATIONS = 240_000
SALT_BYTES = 16
TOKEN_BYTES = 32  # 256-bit tokens



def _file_stamp(path: Optional[Path]) -> Optional[tuple[float, int]]:
    """(mtime, size) for change detection, or None when unreadable."""
    if path is None:
        return None
    try:
        st = path.stat()
        return (st.st_mtime, st.st_size)
    except OSError:
        return None


class Role(str, Enum):
    """
    Capability granted by a credential.

    INGEST is deliberately narrow: a compromised sensor credential must not
    expose other sources' telemetry or the audit trail.
    """
    INGEST = "ingest"      # write own telemetry, read own telemetry
    READ_ONLY = "read_only"  # read own telemetry
    ADMIN = "admin"        # read all sources, audit, configuration


class AuthError(Exception):
    """Base class for authentication and authorization failures."""


class MissingCredentialsError(AuthError):
    """Central mode was requested without a credential store."""


class InvalidCredentialError(AuthError):
    """The presented token is unknown, malformed or disabled."""


class SourceAccessDenied(AuthError):
    """A valid principal attempted to act on another source's data."""


def hash_token(token: str, salt: bytes) -> str:
    """PBKDF2-HMAC-SHA256 digest of a token."""
    return hashlib.pbkdf2_hmac(
        "sha256", token.encode("utf-8"), salt, PBKDF2_ITERATIONS
    ).hex()


def generate_token() -> str:
    """A new high-entropy credential. Shown once; only its hash is stored."""
    return secrets.token_urlsafe(TOKEN_BYTES)


@dataclass(frozen=True)
class Credential:
    """One source identity. Stores only a hash, never the token."""
    credential_id: str
    source_id: str
    role: Role
    salt: str          # hex
    token_hash: str    # hex
    enabled: bool = True
    created_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    description: str = ""
    # ── Lifecycle (ADR-055) ──
    # Optional, UTC, ISO-8601. None means "does not expire", which is the
    # behaviour every credential had before this field existed — adding it
    # must not silently invalidate a store an operator is already running.
    not_after: Optional[str] = None
    # Set when a credential is deliberately withdrawn. Distinct from
    # `enabled=False`: disabled is a pause an operator may undo, revoked is
    # permanent and is recorded with its reason.
    revoked_at: Optional[str] = None
    revoked_reason: str = ""
    # The credential this one replaces, recorded so an operator can see a
    # rotation rather than two unrelated credentials for one source.
    replaces_credential_id: Optional[str] = None

    def is_expired(self, now: Optional[datetime] = None) -> bool:
        """
        Whether `not_after` has passed.

        An unparseable `not_after` counts as EXPIRED. The alternative —
        treating a value we cannot read as "no expiry" — would turn a
        corrupted store into an indefinitely valid credential.
        """
        if not self.not_after:
            return False
        now = now or datetime.now(timezone.utc)
        try:
            deadline = datetime.fromisoformat(self.not_after)
        except (TypeError, ValueError):
            logger.warning(
                "Credential %s has an unreadable not_after; treating as expired.",
                self.credential_id,
            )
            return True
        if deadline.tzinfo is None:
            # A naive deadline is read as UTC rather than as local time, so
            # the same store behaves identically on every host.
            deadline = deadline.replace(tzinfo=timezone.utc)
        return now >= deadline

    @property
    def is_revoked(self) -> bool:
        return bool(self.revoked_at)

    def usable(self, now: Optional[datetime] = None) -> bool:
        """Every lifecycle gate, independent of whether a token matches."""
        return self.enabled and not self.is_revoked and not self.is_expired(now)

    def verify(self, token: str, now: Optional[datetime] = None) -> bool:
        """
        Constant-time verification, after the lifecycle gates.

        The gates are checked first deliberately: an expired or revoked
        credential must fail whether or not the presented token is the
        right one.
        """
        if not token or not self.usable(now):
            return False
        candidate = hash_token(token, bytes.fromhex(self.salt))
        return hmac.compare_digest(candidate, self.token_hash)

    def to_record(self) -> dict:
        return {
            "credential_id": self.credential_id,
            "source_id": self.source_id,
            "role": self.role.value,
            "salt": self.salt,
            "token_hash": self.token_hash,
            "enabled": self.enabled,
            "created_at": self.created_at,
            "description": self.description,
            "not_after": self.not_after,
            "revoked_at": self.revoked_at,
            "revoked_reason": self.revoked_reason,
            "replaces_credential_id": self.replaces_credential_id,
        }

    @classmethod
    def create(
        cls,
        source_id: str,
        role: Role = Role.INGEST,
        description: str = "",
        not_after: Optional[str] = None,
        replaces_credential_id: Optional[str] = None,
    ) -> tuple["Credential", str]:
        """
        Mint a credential.

        Returns (credential, plaintext_token). The token is returned once
        and never recoverable afterwards.
        """
        token = generate_token()
        salt = secrets.token_bytes(SALT_BYTES)
        return (
            cls(
                credential_id=secrets.token_hex(8),
                source_id=source_id,
                role=role,
                salt=salt.hex(),
                token_hash=hash_token(token, salt),
                description=description,
                not_after=not_after,
                replaces_credential_id=replaces_credential_id,
            ),
            token,
        )


@dataclass(frozen=True)
class Principal:
    """An authenticated caller."""
    credential_id: str
    source_id: str
    role: Role

    @property
    def is_admin(self) -> bool:
        return self.role is Role.ADMIN

    def may_write(self) -> bool:
        return self.role in (Role.INGEST, Role.ADMIN)

    def may_access_source(self, source_id: Optional[str]) -> bool:
        """
        Admins see everything. Every other principal is confined to its own
        source, and an unscoped query is NOT treated as "all sources".
        """
        if self.is_admin:
            return True
        if source_id is None:
            return False
        return source_id == self.source_id

    def assert_source_access(self, source_id: Optional[str]) -> str:
        """Return the source id this principal may act on, or refuse."""
        if self.is_admin:
            return source_id or ""
        if source_id is None:
            # Scope the request rather than exposing everything.
            return self.source_id
        if source_id != self.source_id:
            raise SourceAccessDenied(
                f"Credential for source {self.source_id!r} may not access "
                f"source {source_id!r}."
            )
        return source_id


class CredentialStore:
    """
    In-memory credential set, loaded from outside source control.

    Sources:
      * ``PRAHARI_CREDENTIALS_FILE`` — path to a JSON credential file.
      * ``PRAHARI_CREDENTIALS_JSON`` — the JSON itself (for container envs).

    The file holds hashes only. It is never written by the application
    during normal operation, and its path is excluded from version control.
    """

    def __init__(
        self,
        credentials: Optional[list[Credential]] = None,
        source_path: Optional[Path] = None,
    ):
        self._by_id: dict[str, Credential] = {}
        for cred in credentials or []:
            self._by_id[cred.credential_id] = cred
        # When the store came from a file, remember it so a revocation
        # written by the admin CLI takes effect without a restart
        # (ADR-055).
        self._source_path = source_path
        self._stamp = _file_stamp(source_path) if source_path else None

    def reload_if_changed(self) -> bool:
        """
        Re-read the credential file when it has changed on disk.

        Revocation has to be fast. Before this, `disable` edited the file
        and the running process kept honouring the credential until
        someone restarted it — which is not revocation, it is a note to
        self.

        Change is detected by (mtime, size). A corrupt or unreadable file
        leaves the in-memory store **untouched**: an operator who breaks
        the file must not thereby unauthenticate the whole fleet, and
        must not have a half-parsed store silently swapped in either.
        """
        if self._source_path is None:
            return False
        stamp = _file_stamp(self._source_path)
        if stamp == self._stamp:
            return False

        try:
            records = json.loads(self._source_path.read_text(encoding="utf-8"))
            replacement = self.from_records(records)
        except (OSError, json.JSONDecodeError, MissingCredentialsError) as exc:
            logger.error(
                "Credential file changed but could not be re-read (%s); "
                "keeping the previously loaded credentials.", exc,
            )
            # Do not advance the stamp: retry on the next request, so a
            # fixed file is picked up without a restart.
            return False

        if not replacement._by_id:
            logger.error(
                "Credential file changed to an empty set; refusing to apply it."
            )
            return False

        self._by_id = replacement._by_id
        self._stamp = stamp
        logger.info(
            "Reloaded %d credential(s) after a change to the credential file",
            len(self._by_id),
        )
        return True

    def __len__(self) -> int:
        return len(self._by_id)

    def add(self, credential: Credential) -> None:
        self._by_id[credential.credential_id] = credential

    def all(self) -> list[Credential]:
        return list(self._by_id.values())

    def authenticate(self, token: str) -> Principal:
        """
        Resolve a bearer token to a principal.

        Every enabled credential is checked so the work done does not depend
        on which credential matches.
        """
        if not token:
            raise InvalidCredentialError("No credential presented.")

        # Pick up a revocation written since the last request.
        self.reload_if_changed()

        now = datetime.now(timezone.utc)
        matched: Optional[Credential] = None
        for cred in self._by_id.values():
            if cred.verify(token, now=now):
                matched = cred
        if matched is None:
            # One wording for unknown, disabled, revoked and expired. The
            # caller learns that it may not proceed and nothing else:
            # distinguishing them would confirm which source ids exist and
            # which credentials were once valid.
            raise InvalidCredentialError("Credential is not recognised.")
        return Principal(
            credential_id=matched.credential_id,
            source_id=matched.source_id,
            role=matched.role,
        )

    # ──────────────── loading ────────────────

    @classmethod
    def from_records(cls, records: list[dict]) -> "CredentialStore":
        creds: list[Credential] = []
        for i, rec in enumerate(records):
            try:
                creds.append(
                    Credential(
                        credential_id=str(rec["credential_id"]),
                        source_id=str(rec["source_id"]),
                        role=Role(rec.get("role", "ingest")),
                        salt=str(rec["salt"]),
                        token_hash=str(rec["token_hash"]),
                        enabled=bool(rec.get("enabled", True)),
                        created_at=str(rec.get("created_at", "")),
                        description=str(rec.get("description", "")),
                        not_after=(
                            str(rec["not_after"]) if rec.get("not_after") else None
                        ),
                        revoked_at=(
                            str(rec["revoked_at"]) if rec.get("revoked_at") else None
                        ),
                        revoked_reason=str(rec.get("revoked_reason", "")),
                        replaces_credential_id=(
                            str(rec["replaces_credential_id"])
                            if rec.get("replaces_credential_id")
                            else None
                        ),
                    )
                )
            except (KeyError, ValueError) as exc:
                raise MissingCredentialsError(
                    f"Credential record {i} is invalid: {exc}"
                ) from exc
        return cls(creds)

    @classmethod
    def load(cls, config) -> "CredentialStore":
        """
        Load the credential store for central mode.

        Raises MissingCredentialsError when central mode is requested with
        no usable credentials — failing closed rather than serving open.
        """
        raw_json = os.environ.get("PRAHARI_CREDENTIALS_JSON", "").strip()
        path_value = (
            os.environ.get("PRAHARI_CREDENTIALS_FILE", "").strip()
            or getattr(config, "credentials_file", "")
        )

        records: Optional[list] = None
        origin = ""

        if raw_json:
            try:
                records = json.loads(raw_json)
                origin = "PRAHARI_CREDENTIALS_JSON"
            except json.JSONDecodeError as exc:
                raise MissingCredentialsError(
                    f"PRAHARI_CREDENTIALS_JSON is not valid JSON: {exc}"
                ) from exc
        elif path_value:
            path = Path(path_value)
            if not path.exists():
                raise MissingCredentialsError(
                    f"Credential file not found: {path}. Central mode will not "
                    "start without credentials."
                )
            try:
                records = json.loads(path.read_text(encoding="utf-8"))
                origin = str(path)
            except json.JSONDecodeError as exc:
                raise MissingCredentialsError(
                    f"Credential file {path} is not valid JSON: {exc}"
                ) from exc

        if records is None:
            raise MissingCredentialsError(
                "Central deployment requires credentials. Set "
                "PRAHARI_CREDENTIALS_FILE or PRAHARI_CREDENTIALS_JSON. "
                "PraHari will not run centrally without authentication."
            )
        if not isinstance(records, list) or not records:
            raise MissingCredentialsError(
                f"Credential source {origin!r} contains no credentials. "
                "Refusing to start central mode with an empty credential set."
            )

        store = cls.from_records(records)
        if path_value and not raw_json:
            store._source_path = Path(path_value)
            store._stamp = _file_stamp(store._source_path)
        logger.info(
            "Loaded %d central credential(s) from %s", len(store), origin
        )
        return store


def redact(token: Optional[str]) -> str:
    """
    Render a token safely for logs and errors.

    Never prints enough to be useful to a reader of the logs.
    """
    if not token:
        return "<none>"
    return f"<token:{len(token)} chars>"
