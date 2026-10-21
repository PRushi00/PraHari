"""
PraHari — Application Configuration

Validated, profile-based configuration. Secrets come from environment
variables, never committed to source control.
"""

from __future__ import annotations

import os
import re
from enum import Enum
from pathlib import Path
from functools import lru_cache

from pydantic import Field
from pydantic_settings import BaseSettings


class DeploymentMode(str, Enum):
    LOCAL = "local"
    CENTRAL = "central"


class UnsupportedDatabaseURL(ValueError):
    """A configured database URL that the application wiring cannot serve."""


class InvalidCollectorSourceId(ValueError):
    """A configured host-collector source id that must not be used (ADR-099)."""


# A source id travels into event ids, URLs, audit records and the source
# registry, so it is restricted to characters that are unambiguous in all
# four rather than merely legal in one.
_COLLECTOR_SOURCE_ID_RE = re.compile(r"[a-z][a-z0-9_-]*")


class AppConfig(BaseSettings):
    """
    Validated application configuration.

    Values can be set via environment variables (prefixed with PRAHARI_)
    or a .env file.
    """

    # Deployment
    deployment_mode: DeploymentMode = DeploymentMode.LOCAL
    app_name: str = "PraHari — The Digital Sentinel"
    app_version: str = "0.1.0"
    debug: bool = False

    # Server
    host: str = "127.0.0.1"  # Loopback by default — safe local default
    port: int = 8000
    cors_origins: list[str] = Field(default=["http://localhost:5173", "http://127.0.0.1:5173"])

    # Database
    database_url: str = "sqlite:///./prahari.db"
    test_database_url: str = "sqlite:///./prahari_test.db"

    # ── Research data store (separate from operational telemetry) ──
    # Benchmark corpora (CSE-CIC-IDS2018 and similar) are third-party
    # artefacts with their own labels, provenance and licence. They are kept
    # out of the operational telemetry database, which is the operator's only
    # copy of genuine local observations.
    #
    # Empty by default and deliberately NOT defaulted to a path: a research
    # import with no dedicated store configured is refused, not redirected.
    # See app/core/research_store.py.
    research_database_url: str = ""
    # The schema a PostgreSQL operational store uses (ADR-097). Ignored
    # for SQLite. Scoping to a schema is what lets a test run, a tenant or
    # a trial migration share one server without colliding.
    postgres_schema: str = "public"

    # Paths
    data_dir: str = "./data"
    models_dir: str = "./models"
    fixtures_dir: str = "./tests/fixtures"
    # Where experiment manifests are written (ADR-074). Empty keeps the
    # historical location, <project root>/experiments; a relative path is
    # resolved against the project root, like database_url.
    experiments_dir: str = ""

    # Logging
    log_level: str = "INFO"
    log_format: str = "json"

    # Request limits (blueprint §4.2, §12). Enforced by
    # app/api/limits.py — see ADR-052. These were configuration values
    # with no enforcement until that record.
    max_request_size_mb: int = 50
    max_import_records: int = 100_000

    # Rate limiting. Generous by default: the limiter exists to bound
    # resource exhaustion, not to police a legitimate sensor's cadence,
    # and no numerical service target is claimed without the measurement
    # §16 requires. Set max_requests_per_window to 0 to disable.
    rate_limit_requests: int = 600
    rate_limit_window_seconds: float = 60.0

    # Retention
    retention_days: int = 365
    # Analysis history (ADR-064). 0 means KEEP EVERYTHING, which is the
    # default: an analysis is a historical record of what was computed,
    # and nothing prunes it automatically. A positive value is only a
    # SUGGESTED keep-count for the explicitly confirmed prune endpoint;
    # it still never runs on its own.
    analysis_history_limit: int = 0
    raw_payload_storage: bool = False

    # ── Host collector identity (ADR-099) ──
    # The source id the local connection-table collector files its
    # telemetry under. Empty means the historical default,
    # `windows_local_host`, so an existing installation keeps its source
    # and its stored events.
    #
    # It must be set to something distinct on each machine BEFORE two
    # hosts' telemetry is ever brought together: event identity is a hash
    # whose first component is this id (`WindowsConnectionAdapter.
    # fingerprint`), so two hosts sharing it produce colliding event ids
    # for a connection that matches on the rest of the tuple, and the
    # surviving row is attributed to whichever host was stored first.
    collector_source_id: str = ""

    # ── Security ──
    # Local (loopback) mode is unauthenticated by design. CENTRAL mode
    # requires credentials and refuses to start without them; see
    # app/core/security.py.
    require_authentication: bool = False  # Local mode default
    # Path to a JSON credential file holding HASHES only. Never commit it.
    credentials_file: str = ""
    # Public routes that stay reachable without a credential in central
    # mode, so an operator can diagnose a deployment that is otherwise
    # refusing them.
    central_public_paths: list[str] = Field(
        default=["/api/v1/health", "/docs", "/redoc", "/openapi.json"]
    )

    # ── Optional application-layer telemetry ──
    # Disabled by default. Enabling only opens an ingestion endpoint for an
    # authorized producer the operator runs themselves; PraHari never
    # configures a proxy, installs a certificate, or intercepts traffic.
    enable_application_layer_ingest: bool = False
    # Query strings frequently carry search terms, tokens and identifiers,
    # so they are stripped unless the operator explicitly opts in.
    applayer_retain_query_strings: bool = False

    model_config = {
        "env_prefix": "PRAHARI_",
        "env_file": ".env",
        "env_file_encoding": "utf-8",
        "extra": "ignore",
    }

    # ──────────────── store identity (ADR-097) ────────────────
    #
    # Two protections were written against a database FILE PATH:
    # research-store isolation and the protected-database guard. A second
    # backend has no path, so they are expressed here as an IDENTITY that
    # both kinds of store can produce, rather than being dropped for one
    # of them.

    def resolved_collector_source_id(self) -> str:
        """
        The source id the host collector must use (ADR-099).

        Unset yields the historical default, so an upgrade changes nothing.
        A configured value is validated here rather than at the point of
        use: an id that reached the adapter would already be baked into
        event identity, and a bad one could not be corrected without
        orphaning every event already stored under it.
        """
        from app.services.collector import DEFAULT_SOURCE_ID

        raw = (self.collector_source_id or "").strip()
        if not raw:
            return DEFAULT_SOURCE_ID

        if len(raw) > 64:
            raise InvalidCollectorSourceId(
                f"collector_source_id is {len(raw)} characters; the limit is 64."
            )
        if not _COLLECTOR_SOURCE_ID_RE.fullmatch(raw):
            raise InvalidCollectorSourceId(
                f"collector_source_id {raw!r} must be lowercase letters, digits, "
                "'-' or '_', and start with a letter. It becomes part of every "
                "event id, so it cannot be changed later without orphaning the "
                "events already stored under it."
            )

        # The UDP endpoint observer is a DIFFERENT in-process producer with
        # its own reserved id (ADR-090). Letting the connection-table
        # collector take it would put two producers on one source, and the
        # reservation guard could no longer name which one owns it.
        from app.api.v1.hostobs import UDP_SOURCE_ID

        if raw == UDP_SOURCE_ID:
            raise InvalidCollectorSourceId(
                f"collector_source_id {raw!r} is reserved for the host "
                "UDP-endpoint observer. Choose another id."
            )
        return raw

    def store_scheme(self) -> str:
        """`sqlite` or `postgresql`, from the configured URL."""
        raw = (self.database_url or "").strip().lower()
        if raw.startswith("postgresql://") or raw.startswith("postgres://"):
            return "postgresql"
        return "sqlite"

    def store_identity(self) -> str:
        """
        A canonical, comparable name for the configured store.

        Credential-free on purpose: it is compared, logged and reported,
        and a DSN password must never travel with it.
        """
        if self.store_scheme() == "postgresql":
            from urllib.parse import urlparse

            parsed = urlparse(self.database_url)
            where = parsed.hostname or parsed.path or "local"
            database = (parsed.path or "").lstrip("/") or "?"
            return f"postgresql:{where}/{database}#{self.postgres_schema}"
        return f"sqlite:{self.get_database_path()}"

    def store_descriptor(self) -> str:
        """The identity, for display. Never contains a credential."""
        return self.store_identity()

    def get_database_path(self) -> Path:
        """
        Absolute path of the SQLite database file.

        A relative URL such as ``sqlite:///./prahari.db`` is resolved against
        the PROJECT ROOT, not the process working directory. Resolving
        against the CWD silently produced different databases depending on
        how the app was started — the launcher (run from the project root)
        and a backend-directory invocation each created their own file, so
        telemetry collected through one was invisible to the other.

        A URL that is not SQLite is **refused** (ADR-094). It previously
        fell back to ``prahari.db`` — the operator's live telemetry — so
        setting ``PRAHARI_DATABASE_URL`` to a PostgreSQL URL would quietly
        read and write the local SQLite file while appearing to be
        configured for PostgreSQL. §13's rule is that configuration is
        validated and fails closed; a silent fallback to a different store
        than the one configured is the opposite of that.
        """
        raw = self.database_url
        if not raw.startswith("sqlite:///"):
            raise UnsupportedDatabaseURL(
                f"database_url {raw!r} is not a SQLite URL. PraHari's "
                "application wiring currently supports sqlite:/// only: "
                "research-store isolation and operational-database identity "
                "are defined in terms of a database FILE PATH "
                "(app/core/research_store.py), and those protections would "
                "not apply to another store. A conforming PostgreSQL backend "
                "exists and is tested (app/storage/postgres.py, ADR-092/093), "
                "but selecting it here is not wired up, so this refuses "
                "rather than silently using the local SQLite database."
            )
        candidate = Path(raw[len("sqlite:///"):])

        if candidate.is_absolute():
            return candidate
        return (self.project_root / candidate).resolve()

    def get_experiments_dir(self) -> Path:
        """Absolute path of the experiment-manifest directory (not created)."""
        if not self.experiments_dir.strip():
            return self.project_root / "experiments"
        candidate = Path(self.experiments_dir)
        if candidate.is_absolute():
            return candidate
        return (self.project_root / candidate).resolve()

    def get_research_database_path(self) -> Path:
        """
        Absolute path of the research database, or raise.

        Deliberately raises rather than returning a default: see
        app.core.research_store.resolve_research_database for why there is no
        fallback to the operational database.
        """
        from app.core.research_store import resolve_research_database

        return resolve_research_database(self)

    @property
    def research_database_configured(self) -> bool:
        """Whether a research store is configured and usable."""
        from app.core.research_store import ResearchStoreError

        try:
            self.get_research_database_path()
        except ResearchStoreError:
            return False
        return True

    @property
    def project_root(self) -> Path:
        """
        Repository root — the directory containing ``backend/`` and
        ``frontend/``. Derived from this file's location so it does not
        depend on the working directory.
        """
        return Path(__file__).resolve().parent.parent.parent.parent


@lru_cache()
def get_config() -> AppConfig:
    """Get cached application configuration."""
    return AppConfig()
