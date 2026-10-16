"""
Ignore-rule scoping.

Regression for a defect introduced while adding research-data exclusions:
an unanchored ``research/`` pattern matched ``backend/app/research/`` and
silently removed the source package from version control. Nothing failed —
the files simply stopped being tracked.

An ignore rule that is too broad is invisible until something is missing
from a clone, so both directions are asserted: data paths excluded, source
and documentation still visible.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[3]


def _is_ignored(relative: str) -> bool:
    """Ask git itself; re-implementing pattern matching would prove nothing."""
    result = subprocess.run(
        ["git", "check-ignore", "-q", relative],
        cwd=str(ROOT),
        capture_output=True,
    )
    if result.returncode not in (0, 1):
        pytest.skip(f"git check-ignore unavailable: {result.stderr!r}")
    return result.returncode == 0


@pytest.mark.parametrize(
    "path",
    [
        "backend/app/research/evaluation.py",
        "backend/app/research/selection.py",
        "backend/app/research/import_manifest.py",
        "backend/app/research/experiment.py",
        "backend/app/research/readiness.py",
        "backend/app/research/feasibility.py",
        "backend/app/core/research_store.py",
        "backend/app/adapters/research_csv.py",
        "backend/app/api/v1/research_import.py",
        "backend/tests/integration/test_research_ingestion.py",
        "README.md",
        "docs/DATASET_ACQUISITION.md",
        ".env.research.example",
    ],
)
def test_source_and_documentation_are_not_ignored(path):
    assert not _is_ignored(path), (
        f"{path} is excluded by an ignore rule. An unanchored directory "
        "pattern will match a source package of the same name."
    )


@pytest.mark.parametrize(
    "path",
    [
        "research/benchmark.db",
        "datasets/flows.csv",
        "data/raw/capture.pcap",
        "sample.csv",
        "prahari.db",
        "secrets/credentials.json",
    ],
)
def test_data_and_secrets_are_ignored(path):
    assert _is_ignored(path), f"{path} would be committable"


def test_research_pattern_is_root_anchored():
    """The specific mistake, asserted against the file itself."""
    text = (ROOT / ".gitignore").read_text(encoding="utf-8")
    assert "/research/" in text
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("#") or not stripped:
            continue
        assert stripped != "research/", (
            "unanchored 'research/' matches backend/app/research/ at any depth"
        )


def test_dockerignore_covers_the_same_data_paths():
    text = (ROOT / ".dockerignore").read_text(encoding="utf-8")
    for pattern in ("/research/", "/datasets/", "*.pcap", "*.db", "secrets/"):
        assert pattern in text, f".dockerignore is missing {pattern}"
