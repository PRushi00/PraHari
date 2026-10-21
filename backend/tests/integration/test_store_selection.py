"""
PraHari — Selecting the storage backend from configuration (ADR-097).

ADR-094 recorded why PostgreSQL was NOT wired up, even though the backend
conformed and the application ran on it under test: two protections were
defined in terms of a database **file path**, and a backend swap that
silently dropped research isolation would be worse than not offering the
choice.

These pin the resolution:

* a store identity both kinds of store can produce, credential-free,
  because it is compared, logged and reported;
* `get_db` selecting the backend from the URL's scheme, so a PostgreSQL
  URL does what it says rather than silently reading the local SQLite
  file (the ADR-094 defect);
* the protected-store guard covering a PostgreSQL schema, which the
  path-based guard cannot see;
* research-store isolation holding when the operational store has no
  path at all.
"""

from __future__ import annotations

import os

import pytest

from app.core.config import AppConfig
from app.core.research_store import operational_database_paths
from app.storage.guard import (
    ProtectedDatabaseError,
    assert_safe_schema_to_initialize,
)

PG_URL = "postgresql://user:hunter2@dbhost:5432/prahari"


# ──────────────────────────────────────────────────────────────────
# Store identity
# ──────────────────────────────────────────────────────────────────


def test_a_sqlite_url_identifies_as_its_resolved_path():
    config = AppConfig(database_url="sqlite:///./prahari.db")
    identity = config.store_identity()
    resolved = config.get_database_path()

    assert config.store_scheme() == "sqlite"
    # The identity is the scheme followed by the RESOLVED ABSOLUTE path. It is
    # deliberately NOT a URI, so the path is spelled the way the host spells
    # it: POSIX absolute paths open with "/", Windows ones with a drive
    # letter. Asserting a leading slash here asserted POSIX, not the contract
    # (ADR-101).
    assert resolved.is_absolute()
    assert identity == f"sqlite:{resolved}"
    assert identity.endswith("prahari.db")


def test_the_sqlite_identity_makes_no_posix_path_assumption():
    """
    Regression test for ADR-101.

    `store_identity()` was pinned as `startswith("sqlite:/")`, which holds
    only where an absolute path begins with a separator. On Windows the
    resolved path opens with a drive letter, so the identity reads
    `sqlite:C:` and then the path, and the assertion failed — the one
    Windows failure in an otherwise green suite, on a store-selection suite
    (ADR-097) that had only ever run on Linux.

    The contract is "scheme plus resolved absolute path", which is what this
    asserts on every platform.
    """
    config = AppConfig(database_url="sqlite:///./prahari.db")
    identity = config.store_identity()
    resolved = config.get_database_path()

    assert identity == f"sqlite:{resolved}"
    assert resolved.is_absolute()
    # Still unambiguously a SQLite identity, and still credential-free.
    assert identity.startswith("sqlite:")
    assert identity.split("sqlite:", 1)[1] == str(resolved)


def test_a_postgres_url_identifies_by_host_database_and_schema():
    config = AppConfig(database_url=PG_URL, postgres_schema="central")

    assert config.store_scheme() == "postgresql"
    assert config.store_identity() == "postgresql:dbhost/prahari#central"


def test_the_identity_never_carries_a_credential():
    """It is compared, logged and reported. A DSN password must not travel."""
    config = AppConfig(database_url=PG_URL, postgres_schema="central")

    for rendered in (config.store_identity(), config.store_descriptor()):
        assert "hunter2" not in rendered
        assert "user" not in rendered.split("#")[0].split(":", 1)[1]


def test_two_schemas_on_one_server_are_different_stores():
    """Scoping by schema is what lets one server hold several stores."""
    a = AppConfig(database_url=PG_URL, postgres_schema="tenant_a")
    b = AppConfig(database_url=PG_URL, postgres_schema="tenant_b")

    assert a.store_identity() != b.store_identity()


# ──────────────────────────────────────────────────────────────────
# Backend selection
# ──────────────────────────────────────────────────────────────────


def test_get_db_builds_a_postgres_store_for_a_postgres_url(monkeypatch):
    """
    The ADR-094 defect: a PostgreSQL URL silently read the local SQLite
    file. It must now build the backend it names.
    """
    pytest.importorskip("psycopg")
    from app.api import deps
    from app.storage.postgres import PostgresStore

    built: dict = {}

    class _Recorder(PostgresStore):
        def initialize(self):  # never touches a server
            built["dsn"] = self.dsn
            built["schema"] = self.schema

    monkeypatch.setattr("app.storage.postgres.PostgresStore", _Recorder)
    deps.reset_db_singleton()
    try:
        store = deps.get_db(
            AppConfig(database_url=PG_URL, postgres_schema="prahari_pg_sel")
        )
        assert isinstance(store, PostgresStore)
        assert built["schema"] == "prahari_pg_sel"
        assert built["dsn"] == PG_URL
    finally:
        deps.reset_db_singleton()


def test_get_db_builds_sqlite_by_default(tmp_path, monkeypatch):
    from app.api import deps

    deps.reset_db_singleton()
    monkeypatch.setenv("PRAHARI_ALLOW_NONTEMP_TEST_DB", "0")
    try:
        store = deps.get_db(
            AppConfig(database_url=f"sqlite:///{tmp_path / 'sel.db'}")
        )
        from app.storage.database import Database

        assert isinstance(store, Database)
    finally:
        deps.reset_db_singleton()


# ──────────────────────────────────────────────────────────────────
# The guard reaches a store with no path
# ──────────────────────────────────────────────────────────────────


def test_the_guard_refuses_a_non_throwaway_schema_under_pytest():
    """
    `path_is_temporary` cannot see a PostgreSQL store. Without this, a
    test against a configured server would run DDL in `public` — the
    schema a deployment would use.
    """
    with pytest.raises(ProtectedDatabaseError) as exc:
        assert_safe_schema_to_initialize("public", "dbhost/prahari")

    assert "public" in str(exc.value)
    assert "throwaway schema" in str(exc.value)


def test_the_guard_allows_a_throwaway_schema():
    for schema in ("prahari_contract_abc123", "prahari_pg_deadbeef", "test_x"):
        assert_safe_schema_to_initialize(schema) is None


def test_the_guard_honours_the_same_explicit_opt_out(monkeypatch):
    monkeypatch.setenv("PRAHARI_ALLOW_NONTEMP_TEST_DB", "1")
    assert assert_safe_schema_to_initialize("public") is None


# ──────────────────────────────────────────────────────────────────
# Research isolation survives a path-less operational store
# ──────────────────────────────────────────────────────────────────


def test_research_isolation_holds_when_the_operational_store_has_no_path():
    """
    Under PostgreSQL the operational store contributes no path, so a
    SQLite research store cannot collide with it. The well-known
    operational filenames stay protected regardless.
    """
    config = AppConfig(database_url=PG_URL, postgres_schema="central")

    paths = operational_database_paths(config)

    assert paths, "the well-known operational names must stay protected"
    assert any(p.name == "prahari.db" for p in paths)
    # And it did not raise, which is the behaviour being pinned: the
    # path lookup refuses a non-SQLite URL (ADR-094).
    with pytest.raises(Exception):
        config.get_database_path()
