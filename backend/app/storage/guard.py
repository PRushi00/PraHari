"""
PraHari — Protected-Database Guard (ADR-054)

A test run must never create or migrate a real database.

`tests/conftest.py` already points `PRAHARI_DATABASE_URL` at a throwaway
directory before `app.core.config` is imported, and that has always
worked. What it cannot cover is a test that builds a `Database` with its
own path, or an ad-hoc script run outside pytest from the repository
root — where `database_url` defaults to `sqlite:///./prahari.db`, which
IS the operator's live telemetry.

That is exactly how the incident in ADR-054 happened: a one-off
diagnostic imported `app.main.app` without overriding `get_db`, the
FastAPI lifespan called `initialize()`, and the pending additive
migration was applied to 3,669 live rows.

The control
-----------
Under pytest, `initialize()` refuses any database that is not inside a
temporary directory. It fails **closed**: the error names the path and
says what to do, rather than quietly writing somewhere unexpected.

Deliberately NOT a production gate. Outside pytest this is a no-op, so a
real deployment migrates exactly as it did before. Gating real migrations
behind a flag would weaken production to accommodate tests, which is the
wrong trade — the blueprint's §13 rule is that configuration fails closed,
not that upgrades need a second switch.

`PRAHARI_ALLOW_NONTEMP_TEST_DB=1` escapes the guard for the rare test that
genuinely needs a fixed path. It is an explicit, greppable opt-in rather
than a silent fallback.
"""

from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path

__all__ = [
    "ProtectedDatabaseError",
    "assert_safe_schema_to_initialize",
    "assert_safe_to_initialize",
    "is_under_test",
    "path_is_temporary",
]

# Names that are operational databases in a normal checkout. Matching on
# the name as well as the location means the guard still bites if a test
# somehow runs with the repository root as its temp directory.
PROTECTED_BASENAMES = frozenset({"prahari.db"})

_OPT_OUT = "PRAHARI_ALLOW_NONTEMP_TEST_DB"


class ProtectedDatabaseError(RuntimeError):
    """A test tried to create or migrate a non-temporary database."""


def is_under_test() -> bool:
    """
    Whether this process is a pytest run.

    Both signals are checked: `PYTEST_CURRENT_TEST` is set per test and is
    absent during collection and at import time, while the module check
    covers the whole session.
    """
    return "PYTEST_CURRENT_TEST" in os.environ or "pytest" in sys.modules


def _temp_roots() -> list[Path]:
    roots = [Path(tempfile.gettempdir())]
    for var in ("TMPDIR", "TEMP", "TMP", "RUNNER_TEMP"):
        value = os.environ.get(var)
        if value:
            roots.append(Path(value))
    resolved = []
    for root in roots:
        try:
            resolved.append(root.resolve())
        except OSError:
            continue
    return resolved


def path_is_temporary(db_path: str | os.PathLike[str]) -> bool:
    """
    Whether `db_path` lives under a temporary directory.

    `:memory:` counts: it touches no file at all, which is the strongest
    form of isolation there is.
    """
    text = str(db_path)
    if text == ":memory:" or text.startswith("file::memory:"):
        return True

    try:
        target = Path(text).resolve()
    except OSError:
        return False

    for root in _temp_roots():
        try:
            target.relative_to(root)
            return True
        except ValueError:
            continue
    return False


def assert_safe_to_initialize(db_path: str | os.PathLike[str]) -> None:
    """
    Refuse to create or migrate a non-temporary database under pytest.

    No-op outside pytest, and no-op when the opt-out is set.
    """
    if not is_under_test():
        return
    if os.environ.get(_OPT_OUT, "").strip().lower() in {"1", "true", "yes"}:
        return
    if path_is_temporary(db_path):
        return

    name = Path(str(db_path)).name
    protected = name in PROTECTED_BASENAMES
    raise ProtectedDatabaseError(
        f"Refusing to initialize {'the PROTECTED operational database' if protected else 'a non-temporary database'} "
        f"at {db_path!r} from a test run.\n"
        "initialize() creates tables and applies schema migrations, so this "
        "would alter real data.\n"
        "Use a tmp_path fixture: Database(db_path=str(tmp_path / 'test.db')). "
        f"If a fixed path is genuinely required, set {_OPT_OUT}=1 for that run."
    )


# Schemas a test run may create or migrate. A PostgreSQL store has no
# path, so `path_is_temporary` cannot protect it; the equivalent question
# is whether the schema is a throwaway one (ADR-097).
TEST_SCHEMA_PREFIXES = ("prahari_contract_", "prahari_pg_", "prahari_app_", "test_")


def assert_safe_schema_to_initialize(schema: str, descriptor: str = "") -> None:
    """
    Refuse to create or migrate a non-throwaway PostgreSQL schema under pytest.

    The file-path guard above cannot see a PostgreSQL store. Without this,
    a test that built a `PostgresStore` against a configured server would
    run DDL in `public` - the schema a real deployment would use.

    No-op outside pytest, and no-op under the same explicit opt-out.
    """
    if not is_under_test():
        return
    if os.environ.get(_OPT_OUT, "").strip().lower() in {"1", "true", "yes"}:
        return
    if schema.startswith(TEST_SCHEMA_PREFIXES):
        return

    raise ProtectedDatabaseError(
        f"Refusing to initialize PostgreSQL schema {schema!r}"
        + (f" ({descriptor})" if descriptor else "")
        + " from a test run.\n"
        "initialize() creates tables and applies schema migrations, so this "
        "would alter a schema a deployment may be using.\n"
        "Use a throwaway schema - one starting with "
        f"{', '.join(TEST_SCHEMA_PREFIXES)} - as the conformance suite does. "
        f"If a fixed schema is genuinely required, set {_OPT_OUT}=1 for that run."
    )
