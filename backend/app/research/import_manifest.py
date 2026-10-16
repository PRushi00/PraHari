"""
PraHari — Research Import Manifest

A record of what was imported, from which bytes, under which policy.

The experiment manifest (``research/experiment.py``) fingerprints the
*events in the database*. This one records the *acquisition*: the source
file's hash, the adapter and policy that read it, and the quality
accounting. They answer different questions and both are needed — an event
fingerprint cannot tell you that two imports came from the same file, and a
file hash cannot tell you what ended up stored.

What a hash does and does not prove
-----------------------------------
A SHA-256 proves **byte identity**: the same hash means the same bytes.
It does **not** prove the file is authentic, that it came from the
publisher it claims, or that its labels are correct. Treat it as a way to
detect change, not as provenance in itself.

This module never fetches anything. It hashes bytes already on disk.
"""

from __future__ import annotations

import json
import logging
import os
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from pydantic import BaseModel, Field

from app.adapters.research_csv import ADAPTER_VERSION, ImportQuality
from app.schemas.events import SCHEMA_VERSION

logger = logging.getLogger(__name__)

MANIFEST_VERSION = "1.0.0"


class ImportManifest(BaseModel):
    """
    One research import, described completely enough to be re-examined.

    Mutable on disk. It is a durable record, not a tamper-proof one, and is
    not described as immutable anywhere.
    """

    manifest_version: str = MANIFEST_VERSION
    schema_version: str = SCHEMA_VERSION
    adapter_version: str = ADAPTER_VERSION

    # Operator-supplied identity. PraHari cannot determine these from the
    # bytes, and does not guess them.
    dataset_name: str
    dataset_release: Optional[str] = None

    # Source bytes
    source_filename: str
    source_sha256: str
    source_size_bytes: int

    imported_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    source_id: str
    data_category: str

    # Policy actually applied
    policy: dict[str, Any] = Field(default_factory=dict)
    unit_conversions: list[str] = Field(default_factory=list)
    field_mapping: dict[str, str] = Field(default_factory=dict)
    label_policy: str = (
        "The source Label column is stored verbatim as dataset_ground_truth. "
        "Any label outside {benign, normal, unlabeled, empty} counts as an "
        "incident for target construction."
    )

    quality: dict[str, Any] = Field(default_factory=dict)
    warnings: list[str] = Field(default_factory=list)

    notes: list[str] = Field(
        default_factory=lambda: [
            "source_sha256 proves byte identity only. It is not evidence of authenticity, provenance or label correctness.",
            "This manifest is a durable record on disk; it can be edited and is not tamper-proof.",
            "Timestamps are stored UTC-aware. Where the source timezone is unknown that is recorded in policy.source_timezone and absolute times may be offset.",
        ]
    )

    def summary(self) -> str:
        return (
            f"{self.dataset_name} <{self.source_filename}> "
            f"sha256={self.source_sha256[:16]}… "
            f"accepted={self.quality.get('accepted')} "
            f"rejected={self.quality.get('rejected')}"
        )


def build_manifest(
    *,
    dataset_name: str,
    dataset_release: Optional[str],
    source_filename: str,
    source_sha256: str,
    source_size_bytes: int,
    source_id: str,
    data_category: str,
    policy: dict[str, Any],
    quality: ImportQuality,
    unit_conversions: Optional[list[str]] = None,
    field_mapping: Optional[dict[str, str]] = None,
) -> ImportManifest:
    """Assemble a manifest from an import that has just completed."""
    return ImportManifest(
        dataset_name=dataset_name,
        dataset_release=dataset_release,
        # Only the base name is recorded: an absolute path would leak the
        # operator's home directory and machine layout into a shareable file.
        source_filename=Path(source_filename).name,
        source_sha256=source_sha256,
        source_size_bytes=source_size_bytes,
        source_id=source_id,
        data_category=data_category,
        policy=policy,
        quality=quality.as_dict(),
        warnings=list(quality.warnings),
        unit_conversions=unit_conversions or [],
        field_mapping=field_mapping or {},
    )


def manifest_path(directory: Path, source_sha256: str) -> Path:
    """Deterministic filename, so the same bytes map to the same manifest."""
    return Path(directory) / f"import-{source_sha256[:32]}.json"


def save_manifest(manifest: ImportManifest, directory: Path) -> Path:
    """
    Write a manifest atomically.

    A partially written manifest would be worse than none: it would look
    like a record of an import while describing something else. The payload
    is written to a temporary file in the same directory and then moved into
    place, so a reader sees either the previous manifest or the complete new
    one.
    """
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True)
    target = manifest_path(directory, manifest.source_sha256)

    payload = manifest.model_dump_json(indent=2)
    handle = tempfile.NamedTemporaryFile(
        "w", encoding="utf-8", dir=str(directory), delete=False, suffix=".tmp"
    )
    try:
        with handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(handle.name, target)
    except Exception:
        Path(handle.name).unlink(missing_ok=True)
        raise

    return target


def load_manifest(path: Path) -> ImportManifest:
    return ImportManifest.model_validate_json(Path(path).read_text(encoding="utf-8"))


def list_manifests(directory: Path) -> list[ImportManifest]:
    directory = Path(directory)
    if not directory.exists():
        return []
    manifests: list[ImportManifest] = []
    for candidate in sorted(directory.glob("import-*.json")):
        try:
            manifests.append(load_manifest(candidate))
        except Exception:  # noqa: BLE001
            logger.warning("Skipping unreadable manifest %s", candidate, exc_info=True)
    return manifests
