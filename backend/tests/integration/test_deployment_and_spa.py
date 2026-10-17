"""
Test unified deployment, static file serving, SPA fallback,
deep linking, and asset protection.
"""
import asyncio
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.main import app, create_app

client = TestClient(app)


def test_api_routes_remain_accessible():
    response = client.get("/api/v1/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"


def test_production_frontend_index_served():
    # If dist directory exists, GET / must return index.html
    frontend_dist = Path(__file__).resolve().parent.parent.parent.parent / "frontend" / "dist"
    if (frontend_dist / "index.html").exists():
        response = client.get("/")
        assert response.status_code == 200
        assert "text/html" in response.headers.get("content-type", "")
        assert "PraHari" in response.text
    else:
        # If not built, fallback JSON informs user
        response = client.get("/")
        assert response.status_code == 200


def test_spa_deep_links_serve_index_html():
    frontend_dist = Path(__file__).resolve().parent.parent.parent.parent / "frontend" / "dist"
    if (frontend_dist / "index.html").exists():
        for route in ["/events", "/forecast", "/analytics", "/stream", "/audit"]:
            response = client.get(route)
            assert response.status_code == 200, f"Route {route} failed with {response.status_code}"
            assert "text/html" in response.headers.get("content-type", "")
            assert "PraHari" in response.text


def test_missing_assets_return_404():
    frontend_dist = Path(__file__).resolve().parent.parent.parent.parent / "frontend" / "dist"
    if frontend_dist.exists():
        response = client.get("/assets/completely_missing_asset_12345.js")
        assert response.status_code == 404

        response = client.get("/missing_image.png")
        assert response.status_code == 404


def test_path_traversal_protection():
    """
    Literal dot segments against the real app never disclose a file.

    Note what this does NOT exercise: httpx (under TestClient) removes
    ``..`` segments before sending, so the app receives ``/etc/passwd``,
    ``/.env`` and ``/backend/app/main.py``. The app's own ``..`` guard is
    therefore tested with raw ASGI scopes below, against a hermetic build.

    Whether a path with no extension gets the SPA shell depends on a built
    frontend (ADR-006): with ``frontend/dist`` present it does; without it
    no fallback route exists and the answer is 404.
    """
    spa_built = (_REPO_DIST / "index.html").exists()

    response = client.get("/../../backend/app/main.py")
    assert response.status_code == 404
    assert "create_app" not in response.text

    response_env = client.get("/../../.env")
    assert response_env.status_code == 404

    response_passwd = client.get("/../../etc/passwd")
    assert "root:x:0:0" not in response_passwd.text
    if spa_built:
        assert response_passwd.status_code == 200  # SPA shell for React Router
        assert "PraHari" in response_passwd.text
    else:
        assert response_passwd.status_code == 404


# ──────────────────────────────────────────────────────────────────
# Hermetic SPA build: the fallback's guards, independent of `npm run build`
# ──────────────────────────────────────────────────────────────────

_REPO_DIST = Path(__file__).resolve().parent.parent.parent.parent / "frontend" / "dist"
_SPA_MARKER = "PraHari SPA shell (test build)"
_SECRET = "TOP-SECRET-OUTSIDE-DIST"


def _asgi_get(asgi_app, path: str) -> tuple[int, str]:
    """
    Deliver ``path`` to the app exactly as written.

    Bypasses the HTTP client so dot segments are not normalized away -
    this is the path a server passes on for a percent-encoded request such
    as ``/%2e%2e/%2e%2e/etc/passwd``. No socket is opened.
    """
    scope = {
        "type": "http",
        "asgi": {"version": "3.0"},
        "http_version": "1.1",
        "method": "GET",
        "scheme": "http",
        "path": path,
        "raw_path": path.encode(),
        "root_path": "",
        "query_string": b"",
        "headers": [(b"host", b"testserver")],
        "client": ("127.0.0.1", 50000),
        "server": ("testserver", 80),
    }
    messages: list[dict] = []

    async def receive():
        return {"type": "http.request", "body": b"", "more_body": False}

    async def send(message):
        messages.append(message)

    asyncio.run(asgi_app(scope, receive, send))
    status = next(m["status"] for m in messages if m["type"] == "http.response.start")
    body = b"".join(m.get("body", b"") for m in messages if m["type"] == "http.response.body")
    return status, body.decode("utf-8", errors="replace")


@pytest.fixture
def built_spa(tmp_path):
    """An app serving a throwaway dist, with a secret just outside it."""
    root = tmp_path / "frontend"
    dist = root / "dist"
    (dist / "assets").mkdir(parents=True)
    (dist / "index.html").write_text(f"<html>{_SPA_MARKER}</html>", encoding="utf-8")
    (dist / "assets" / "app.js").write_text("console.log('ok')", encoding="utf-8")
    (dist / "favicon.svg").write_text("<svg/>", encoding="utf-8")
    secret = root / "secret.env"
    secret.write_text(_SECRET, encoding="utf-8")
    (root / "prahari.db").write_text(_SECRET, encoding="utf-8")
    return create_app(frontend_dist=dist), dist, secret


def test_built_spa_serves_shell_and_files_and_404s_missing_assets(built_spa):
    spa_app, _, _ = built_spa
    c = TestClient(spa_app)

    for route in ["/", "/events", "/etc/passwd"]:
        r = c.get(route)
        assert r.status_code == 200, route
        assert _SPA_MARKER in r.text

    assert c.get("/favicon.svg").text == "<svg/>"
    assert c.get("/assets/app.js").status_code == 200

    # A missing file must not be answered with the shell.
    for missing in ["/assets/missing.js", "/missing.png", "/.env", "/backend/app/main.py"]:
        r = c.get(missing)
        assert r.status_code == 404, missing
        assert _SPA_MARKER not in r.text

    # Nor may an unknown API path.
    r = c.get("/api/v1/definitely-not-an-endpoint")
    assert r.status_code == 404
    assert r.headers["content-type"].startswith("application/json")


@pytest.mark.parametrize(
    "path",
    [
        "/../../etc/passwd",
        "/../../.env",
        "/../../backend/app/main.py",
        "/../secret.env",
        "/../prahari.db",
        "/events/../../secret.env",
        "/..",
    ],
)
def test_dot_segments_reaching_the_app_are_refused(built_spa, path):
    spa_app, _, _ = built_spa

    status, body = _asgi_get(spa_app, path)

    assert status == 400
    assert _SECRET not in body
    assert _SPA_MARKER not in body
    assert "root:x:0:0" not in body


@pytest.mark.parametrize("path", ["/assets/../../secret.env", "/assets/../../../etc/passwd"])
def test_dot_segments_under_the_assets_mount_are_refused(built_spa, path):
    spa_app, _, _ = built_spa

    status, body = _asgi_get(spa_app, path)

    assert status == 404
    assert _SECRET not in body
    assert "root:x:0:0" not in body


def test_a_symlink_out_of_dist_is_not_followed(built_spa):
    spa_app, dist, secret = built_spa
    try:
        (dist / "leak.txt").symlink_to(secret)
    except OSError as exc:  # Windows without Developer Mode or elevation
        pytest.skip(f"this host does not permit creating symlinks: {exc}")

    status, body = _asgi_get(spa_app, "/leak.txt")

    assert status == 400
    assert _SECRET not in body


def test_without_a_build_there_is_no_fallback_and_nothing_leaks(tmp_path):
    bare_app = create_app(frontend_dist=tmp_path / "no-dist")
    c = TestClient(bare_app)

    assert c.get("/").json()["health"] == "/api/v1/health"
    for path in ["/etc/passwd", "/events", "/../../.env"]:
        r = c.get(path)
        assert r.status_code == 404, path
        assert "root:x:0:0" not in r.text
    status, body = _asgi_get(bare_app, "/../../etc/passwd")
    assert status == 404
    assert "root:x:0:0" not in body
