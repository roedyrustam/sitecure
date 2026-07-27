import pytest
from fastapi.testclient import TestClient
from app.main import app
from app.services.cache_service import scan_cache

client = TestClient(app)

def test_rate_limiter_and_security_headers():
    response = client.get("/api/v1/targets/")
    assert response.status_code == 200
    assert response.headers.get("X-Content-Type-Options") == "nosniff"
    assert response.headers.get("Strict-Transport-Security") is not None
    assert response.headers.get("Server") == "SiteCure-Protected-Server"

def test_cache_engine():
    scan_cache.set("test_key", {"data": "cached_value"}, ttl=60)
    cached = scan_cache.get("test_key")
    assert cached == {"data": "cached_value"}
