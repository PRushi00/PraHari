"""
Test unified deployment, static file serving, SPA fallback,
deep linking, and asset protection.
"""
from fastapi.testclient import TestClient
from pathlib import Path
from app.main import app

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
    # Attempting to access backend source code via traversal returns 404 and does not leak code
    response = client.get("/../../backend/app/main.py")
    assert response.status_code == 404
    assert "create_app" not in response.text

    response_env = client.get("/../../.env")
    assert response_env.status_code == 404

    # Traversal without extension falls back to SPA shell without leaking system files
    response_passwd = client.get("/../../etc/passwd")
    assert "root:x:0:0" not in response_passwd.text
    assert response_passwd.status_code == 200  # Returns SPA index.html for React Router to handle
    assert "PraHari" in response_passwd.text
