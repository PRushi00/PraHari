"""
Container configuration validation.

Docker is not installed on this host and installing it is outside the
agreed boundary, so the image is never built or run here. These tests are
what can honestly be checked without a daemon: that the Dockerfile and
compose file are internally consistent, that the paths they reference are
the ones the application actually uses, and that the build context cannot
carry telemetry or secrets off the machine.

They are **not** a substitute for a runtime check, and nothing here should
be read as evidence that the image builds.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[3]
DOCKERFILE = ROOT / "Dockerfile"
COMPOSE = ROOT / "docker-compose.yml"
DOCKERIGNORE = ROOT / ".dockerignore"


@pytest.fixture(scope="module")
def dockerfile() -> str:
    assert DOCKERFILE.exists(), "Dockerfile is missing"
    return DOCKERFILE.read_text(encoding="utf-8")


@pytest.fixture(scope="module")
def compose() -> str:
    assert COMPOSE.exists(), "docker-compose.yml is missing"
    return COMPOSE.read_text(encoding="utf-8")


@pytest.fixture(scope="module")
def dockerignore() -> str:
    assert DOCKERIGNORE.exists(), (
        "No .dockerignore: the whole repository, including prahari.db, "
        "would be sent to the Docker daemon as build context"
    )
    return DOCKERIGNORE.read_text(encoding="utf-8")


# ──────────────────────────────────────────────────────────────────
# The build context must not carry telemetry or secrets
# ──────────────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "pattern",
    ["*.db", "secrets/", ".git/", "experiments/", ".env"],
)
def test_build_context_excludes_sensitive_paths(dockerignore, pattern):
    """
    The COPY instructions are narrow, so this data would not reach the
    image. It would still leave the machine: a build context is sent to
    the daemon in full and is recoverable from it, or from a CI log.
    """
    assert pattern in dockerignore, f".dockerignore does not exclude {pattern}"


def test_operational_database_would_not_enter_the_context(dockerignore):
    assert "*.db" in dockerignore
    for suffix in ("*.db-wal", "*.db-shm"):
        assert suffix in dockerignore, (
            f"{suffix} carries recent writes and must be excluded too"
        )


def test_no_credential_material_is_baked_into_the_image(dockerfile, compose):
    """A token in an image layer survives every later deletion."""
    forbidden = re.compile(
        r"(PRAHARI_CREDENTIALS_JSON\s*=|Bearer\s+[A-Za-z0-9_\-]{16,}|token_hash)",
        re.IGNORECASE,
    )
    assert not forbidden.search(dockerfile), "Dockerfile embeds credential material"
    assert not forbidden.search(compose), "compose embeds credential material"


# ──────────────────────────────────────────────────────────────────
# Paths must match what the application actually resolves
# ──────────────────────────────────────────────────────────────────


def test_frontend_is_copied_where_main_py_looks_for_it(dockerfile):
    """
    main.py resolves the SPA as
    ``Path(__file__).parent.parent.parent / "frontend" / "dist"``. With
    WORKDIR /app and the app package at /app/app, __file__ is
    /app/app/main.py, so three parents up is "/" and the expected location
    is /frontend/dist. A mismatch here serves the API with no dashboard,
    and only at runtime.
    """
    main_py = (ROOT / "backend" / "app" / "main.py").read_text(encoding="utf-8")
    assert 'parent.parent.parent / "frontend" / "dist"' in main_py.replace("\n", " ") or (
        "frontend" in main_py and "dist" in main_py
    )

    assert "COPY backend/app ./app" in dockerfile, (
        "the app package must land at /app/app for the SPA path to resolve"
    )
    assert "WORKDIR /app" in dockerfile
    assert re.search(r"COPY --from=frontend-builder\s+\S+\s+/frontend/dist", dockerfile), (
        "compiled frontend must be copied to /frontend/dist"
    )


def test_database_url_points_at_the_mounted_volume(dockerfile, compose):
    """
    Four slashes means an absolute path. ``sqlite:///data/...`` (three)
    would be relative and would put collected telemetry inside the
    container's writable layer, where it is destroyed on recreate.
    """
    assert "sqlite:////data/prahari.db" in dockerfile
    assert "sqlite:////data/prahari.db" in compose
    assert 'VOLUME ["/data"]' in dockerfile
    assert "prahari_data:/data" in compose


def test_runtime_user_owns_the_data_directory(dockerfile):
    assert "USER prahari" in dockerfile, "the container must not run as root"
    assert re.search(r"chown -R prahari:prahari[^\n]*/data", dockerfile), (
        "a non-root user cannot write to /data unless it owns it"
    )


def test_python_version_matches_the_pinned_toolchain(dockerfile):
    assert "python:3.12" in dockerfile, (
        "the image must match the Python version the dependency pins target"
    )


def test_requirements_are_installed_from_the_pinned_file(dockerfile):
    assert "COPY backend/requirements.txt" in dockerfile
    assert "pip install --no-cache-dir -r requirements.txt" in dockerfile


# ──────────────────────────────────────────────────────────────────
# Network exposure
# ──────────────────────────────────────────────────────────────────


def test_host_port_binding_is_loopback_only(compose):
    """
    Local mode is unauthenticated by design, so an exposed port is an
    unauthenticated ingest and query endpoint on the LAN.
    """
    published = re.findall(r'^\s*-\s*"([^"]+:\d+|\d+:\d+)"', compose, re.MULTILINE)
    assert published, "no published ports found to check"
    for mapping in published:
        assert mapping.startswith("127.0.0.1:"), (
            f"port mapping {mapping!r} publishes beyond loopback"
        )


def test_container_listens_on_all_interfaces_only_inside_its_namespace(dockerfile):
    """
    0.0.0.0 inside the container is correct and necessary — it is the only
    address reachable across the namespace boundary. The protection is the
    host-side binding, asserted above. This test exists so the pairing is
    explicit rather than accidental.
    """
    assert '"--host", "0.0.0.0"' in dockerfile
    assert "127.0.0.1:8000:8000" in COMPOSE.read_text(encoding="utf-8")


def test_healthcheck_targets_loopback_inside_the_container(dockerfile, compose):
    assert "http://127.0.0.1:8000/api/v1/health" in dockerfile
    assert "http://127.0.0.1:8000/api/v1/health" in compose


def test_compose_does_not_declare_an_obsolete_version_key(compose):
    """Compose v2 warns on the `version` key; it has no effect."""
    assert not re.match(r"^\s*version:", compose), (
        "the top-level `version` key is obsolete in Compose v2"
    )


def test_default_deployment_mode_is_local(compose):
    assert "PRAHARI_DEPLOYMENT_MODE=local" in compose, (
        "central mode must not be the container default"
    )


def test_security_rationale_is_recorded_beside_the_configuration(compose):
    """
    A future edit changing the binding should have to read why it is there.
    """
    lowered = compose.lower()
    assert "loopback" in lowered
    assert "unauthenticated" in lowered
