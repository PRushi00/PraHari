"""
PraHari — The Protected-Database Guard (ADR-054).

A real incident, not a hypothetical: an ad-hoc diagnostic imported
`app.main.app` without overriding `get_db`, the FastAPI lifespan called
`initialize()`, and the pending additive `received_at` migration was
applied to the operator's live `prahari.db` — 3,669 rows.

These tests prove the guard refuses that shape of mistake, and that it
does not get in the way of the temporary databases every real test uses.

Nothing here opens, reads or writes either protected database. The
operational paths appear only as *strings* handed to the guard, which
raises before any file is touched.
"""

from __future__ import annotations

import os
import sqlite3
import tempfile
from pathlib import Path

import pytest

from app.storage.database import Database
from app.storage.guard import (
    ProtectedDatabaseError,
    assert_safe_to_initialize,
    is_under_test,
    path_is_temporary,
)

# A string only. No file at this path is opened by any test in this module.
OPERATIONAL_NAME = "prahari.db"


# ──────────────────────────────────────────────────────────────────
# The guard refuses what caused the incident
# ──────────────────────────────────────────────────────────────────


def test_initializing_a_repository_local_database_is_refused(tmp_path, monkeypatch):
    """
    The incident shape: a relative `./prahari.db` resolved against the
    repository root rather than a temp directory.
    """
    monkeypatch.chdir(tmp_path)
    fake_repo = tmp_path / "repo-like"
    fake_repo.mkdir()
    target = fake_repo / OPERATIONAL_NAME

    # tmp_path IS temporary, so make the guard see a non-temporary root.
    monkeypatch.setattr(
        "app.storage.guard._temp_roots", lambda: [Path("/nonexistent-temp-root")]
    )

    with pytest.raises(ProtectedDatabaseError) as exc:
        Database(db_path=str(target)).initialize()

    assert OPERATIONAL_NAME in str(exc.value)
    assert not target.exists(), "the guard must refuse BEFORE creating the file"


def test_the_refusal_names_the_protected_database_explicitly(monkeypatch):
    monkeypatch.setattr(
        "app.storage.guard._temp_roots", lambda: [Path("/nonexistent-temp-root")]
    )

    with pytest.raises(ProtectedDatabaseError) as exc:
        assert_safe_to_initialize("/some/checkout/prahari.db")

    message = str(exc.value)
    assert "PROTECTED operational database" in message
    assert "tmp_path" in message, "the error must say what to do instead"


def test_a_non_protected_name_is_still_refused_when_non_temporary(monkeypatch):
    """
    The guard is about location first and name second. Any non-temporary
    database under test is refused, not only ones called prahari.db.
    """
    monkeypatch.setattr(
        "app.storage.guard._temp_roots", lambda: [Path("/nonexistent-temp-root")]
    )

    with pytest.raises(ProtectedDatabaseError) as exc:
        assert_safe_to_initialize("/var/lib/someone-elses.db")

    assert "non-temporary database" in str(exc.value)


# ──────────────────────────────────────────────────────────────────
# ...and stays out of the way of real tests
# ──────────────────────────────────────────────────────────────────


def test_a_tmp_path_database_initializes_normally(tmp_path):
    db = Database(db_path=str(tmp_path / "fine.db"))
    db.initialize()

    with db.get_connection() as conn:
        tables = {
            r[0] for r in conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            )
        }
    db.close()

    assert "normalized_events" in tables


def test_an_in_memory_database_is_permitted():
    """Touching no file at all is the strongest isolation available."""
    assert path_is_temporary(":memory:")
    assert_safe_to_initialize(":memory:")


def test_the_system_temp_directory_is_recognised():
    assert path_is_temporary(Path(tempfile.gettempdir()) / "x" / "y.db")


def test_the_guard_knows_it_is_under_test():
    assert is_under_test(), "these tests run under pytest by definition"


def test_the_guard_is_inert_outside_a_test_run(monkeypatch):
    """
    Production upgrades must not need a second switch. Gating real
    migrations behind a flag would weaken deployment to accommodate
    tests, which is the wrong trade.
    """
    monkeypatch.setattr("app.storage.guard.is_under_test", lambda: False)

    assert_safe_to_initialize("/var/lib/prahari/prahari.db")  # no raise


def test_an_explicit_opt_out_is_honoured(monkeypatch):
    monkeypatch.setattr(
        "app.storage.guard._temp_roots", lambda: [Path("/nonexistent-temp-root")]
    )
    monkeypatch.setenv("PRAHARI_ALLOW_NONTEMP_TEST_DB", "1")

    assert_safe_to_initialize("/some/checkout/prahari.db")  # no raise


# ──────────────────────────────────────────────────────────────────
# The incident path specifically
# ──────────────────────────────────────────────────────────────────


def test_building_the_app_without_a_db_override_cannot_migrate_live_data(monkeypatch):
    """
    Drive the actual failure: a TestClient over the real app with no
    `get_db` override. The lifespan calls `initialize()`, which the guard
    must now refuse rather than migrating whatever the default path
    resolves to.
    """
    from fastapi.testclient import TestClient

    monkeypatch.setattr(
        "app.storage.guard._temp_roots", lambda: [Path("/nonexistent-temp-root")]
    )
    from app.main import app

    with pytest.raises(ProtectedDatabaseError):
        with TestClient(app):
            pass


# ──────────────────────────────────────────────────────────────────
# Migration behaviour is unchanged where it is allowed to run
# ──────────────────────────────────────────────────────────────────


def test_an_additive_migration_still_works_on_a_temporary_database(tmp_path):
    """
    The guard must not have broken the migration it was written about.
    Builds a pre-migration schema from the real DDL and confirms the
    column is added and existing rows are preserved with NULL.
    """
    from app.storage.database import TABLES_DDL

    db_file = tmp_path / "legacy.db"
    legacy_ddl = "\n".join(
        line for line in TABLES_DDL.splitlines() if "received_at" not in line
    )
    con = sqlite3.connect(db_file)
    con.executescript(legacy_ddl)
    con.execute(
        "INSERT INTO telemetry_sources (source_id, name, source_type, created_at) "
        "VALUES ('s1', 's1', 'json_stream', '2026-01-01T00:00:00+00:00')"
    )
    con.execute(
        "INSERT INTO normalized_events "
        "(event_id, schema_version, source_id, data_category, observed_at, "
        " ingested_at, event_type, label_provenance) "
        "VALUES ('e1', '1.0.0', 's1', 'live_telemetry', "
        "'2026-01-01T00:00:00+00:00', '2026-01-01T00:00:00+00:00', "
        "'network_flow', 'unlabeled')"
    )
    con.commit()
    before = con.execute("SELECT COUNT(*) FROM normalized_events").fetchone()[0]
    cols_before = {r[1] for r in con.execute("PRAGMA table_info(normalized_events)")}
    con.close()

    assert "received_at" not in cols_before

    db = Database(db_path=str(db_file))
    db.initialize()
    with db.get_connection() as conn:
        cols_after = {r["name"] for r in conn.execute("PRAGMA table_info(normalized_events)")}
        after = conn.execute("SELECT COUNT(*) FROM normalized_events").fetchone()[0]
        nulls = conn.execute(
            "SELECT COUNT(*) FROM normalized_events WHERE received_at IS NULL"
        ).fetchone()[0]
    db.close()

    assert "received_at" in cols_after
    assert after == before == 1, "migration must preserve every existing row"
    assert nulls == 1, "an existing row must NOT be given fabricated receipt evidence"


def test_migrating_a_populated_table_logs_a_warning(tmp_path, caplog):
    """
    The incident was invisible because the migration logged at INFO,
    indistinguishable from ordinary startup noise.
    """
    import logging

    from app.storage.database import TABLES_DDL

    db_file = tmp_path / "noisy.db"
    legacy_ddl = "\n".join(
        line for line in TABLES_DDL.splitlines() if "received_at" not in line
    )
    con = sqlite3.connect(db_file)
    con.executescript(legacy_ddl)
    con.execute(
        "INSERT INTO telemetry_sources (source_id, name, source_type, created_at) "
        "VALUES ('s1', 's1', 'json_stream', '2026-01-01T00:00:00+00:00')"
    )
    con.execute(
        "INSERT INTO normalized_events "
        "(event_id, schema_version, source_id, data_category, observed_at, "
        " ingested_at, event_type, label_provenance) "
        "VALUES ('e1', '1.0.0', 's1', 'live_telemetry', "
        "'2026-01-01T00:00:00+00:00', '2026-01-01T00:00:00+00:00', "
        "'network_flow', 'unlabeled')"
    )
    con.commit()
    con.close()

    with caplog.at_level(logging.WARNING, logger="app.storage.database"):
        db = Database(db_path=str(db_file))
        db.initialize()
        db.close()

    warnings = [r for r in caplog.records if r.levelno >= logging.WARNING]
    assert any("SCHEMA MIGRATION" in r.getMessage() for r in warnings), (
        "a migration against populated data must be loud"
    )


def test_an_empty_table_migration_stays_quiet(tmp_path, caplog):
    """No data at risk, so no alarm — otherwise the warning means nothing."""
    import logging

    with caplog.at_level(logging.WARNING, logger="app.storage.database"):
        db = Database(db_path=str(tmp_path / "fresh.db"))
        db.initialize()
        db.close()

    assert not [
        r for r in caplog.records if "SCHEMA MIGRATION" in r.getMessage()
    ]
