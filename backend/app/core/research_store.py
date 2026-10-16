"""
PraHari — Research Data Store Isolation

Benchmark research data and live operational telemetry must not share a
database.

They are different kinds of thing. The operational store holds genuine
network observations from this host — the only copy, collected over time,
unlabelled. A research corpus is a third-party artefact with its own
labels, its own provenance and its own licence. Mixing them produces a
training set whose provenance cannot be reconstructed afterwards, and risks
a bulk import landing in the operator's only telemetry record.

The guard here is **fail closed**: a research import with no dedicated
database configured, or one that resolves to the operational database, is
refused *before any write occurs*. There is deliberately no fallback.

This module resolves and validates the target. It never creates, migrates
or deletes a database on import of this module.
"""

from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import Optional

from app.core.config import AppConfig

logger = logging.getLogger(__name__)

# The database file the live collector writes to, relative to the project
# root, plus the legacy location an earlier version used. Both are treated
# as operational: an import must not land in either.
OPERATIONAL_FILENAMES = ("prahari.db",)
LEGACY_OPERATIONAL_RELATIVE = Path("backend") / "prahari.db"

# Categories whose data is research material rather than observation of
# this host. An import carrying one of these must use the research store.
RESEARCH_CATEGORIES = ("historical_import",)


class ResearchStoreError(RuntimeError):
    """Base class for research-store configuration refusals."""


class ResearchDatabaseNotConfigured(ResearchStoreError):
    """No research database was configured, so nothing may be imported."""


class ResearchDatabaseCollision(ResearchStoreError):
    """The research target resolves to an operational database."""


class ResearchDatabaseInvalid(ResearchStoreError):
    """The configured research target is not a usable SQLite path."""


def _sqlite_path(url: str) -> Optional[Path]:
    """
    Extract a filesystem path from a SQLite URL.

    Accepts ``sqlite:///relative/path.db`` and ``sqlite:////absolute.db``,
    matching the form the rest of the project already uses, and a bare path
    for convenience. Anything else returns None rather than being guessed
    at — a mis-parsed URL is exactly how data ends up somewhere unintended.
    """
    raw = (url or "").strip()
    if not raw:
        return None
    if raw.startswith("sqlite:///"):
        remainder = raw[len("sqlite:///") :]
        if not remainder:
            return None
        return Path(remainder)
    if raw.startswith("sqlite:"):
        # sqlite://host/path and other variants are not supported here.
        return None
    if "://" in raw:
        return None
    return Path(raw)


def _canonical(path: Path, config: AppConfig) -> Path:
    """
    Absolute, normalised path for comparison.

    Relative paths resolve against the project root, matching
    ``AppConfig.get_database_path``. ``resolve()`` is used so that symlinks,
    ``..`` segments and (on Windows) case differences cannot be used to
    present the operational database as a different file.
    """
    candidate = path if path.is_absolute() else (config.project_root / path)
    try:
        return candidate.resolve()
    except OSError:
        return candidate.absolute()


def operational_database_paths(config: AppConfig) -> set[Path]:
    """Every path that must be treated as operational telemetry storage."""
    paths = {_canonical(Path(config.get_database_path()), config)}
    paths.add(_canonical(LEGACY_OPERATIONAL_RELATIVE, config))
    for name in OPERATIONAL_FILENAMES:
        paths.add(_canonical(Path(name), config))
    return paths


def is_operational_database(db_path: str | Path, config: AppConfig) -> bool:
    """True when the given path is an operational telemetry database."""
    resolved = _canonical(Path(str(db_path)), config)
    return resolved in operational_database_paths(config)


def resolve_research_database(config: AppConfig) -> Path:
    """
    Resolve the research database target, or refuse.

    Raises rather than returning a fallback. Every failure mode here means
    "we do not know where this data should go", and the only safe answer to
    that is to write nothing.
    """
    url = (config.research_database_url or "").strip()
    if not url:
        raise ResearchDatabaseNotConfigured(
            "No research database is configured. Set PRAHARI_RESEARCH_DATABASE_URL "
            "to a dedicated SQLite path (for example "
            "sqlite:///./research/benchmark.db) before importing research data. "
            "PraHari will not fall back to the operational telemetry database."
        )

    path = _sqlite_path(url)
    if path is None:
        raise ResearchDatabaseInvalid(
            f"PRAHARI_RESEARCH_DATABASE_URL={url!r} is not a supported SQLite "
            "target. Use sqlite:///relative/path.db or an absolute path."
        )

    resolved = _canonical(path, config)

    if resolved in operational_database_paths(config):
        raise ResearchDatabaseCollision(
            f"The configured research database resolves to {resolved}, which is "
            "an operational telemetry database. Research imports are refused "
            "rather than written into the operator's live telemetry record."
        )

    if resolved.exists() and resolved.is_dir():
        raise ResearchDatabaseInvalid(
            f"The research database path {resolved} is a directory."
        )

    parent = resolved.parent
    if not parent.exists():
        raise ResearchDatabaseInvalid(
            f"The research database directory {parent} does not exist. Create it "
            "deliberately; PraHari does not create storage locations implicitly."
        )
    if not os.access(parent, os.W_OK):
        raise ResearchDatabaseInvalid(
            f"The research database directory {parent} is not writable."
        )

    return resolved


def assert_safe_research_target(db_path: str | Path, config: AppConfig) -> None:
    """
    Last check immediately before a research write.

    ``resolve_research_database`` validates configuration; this validates the
    database object actually in hand, so a caller that obtained its
    connection by some other route (a test override, a CLI argument) still
    cannot write research data into operational storage.
    """
    if is_operational_database(db_path, config):
        raise ResearchDatabaseCollision(
            f"Refusing to write research data to {db_path}, which is an "
            "operational telemetry database."
        )


def requires_research_store(data_category: str) -> bool:
    """Whether a given data category must be written to the research store."""
    return str(data_category) in RESEARCH_CATEGORIES
