import pytest
import asyncio
from fastapi.testclient import TestClient
from app.main import app
from app.scanner.dast_engine import DASTEngine
from app.scanner.sast_engine import SASTEngine

client = TestClient(app)

def test_api_root():
    response = client.get("/")
    assert response.status_code == 200
    assert response.json()["status"] == "online"

def test_create_and_list_target():
    response = client.post(
        "/api/v1/targets/",
        json={
            "name": "Internal Test App",
            "target_url": "http://127.0.0.1:8000",
            "asset_type": "web",
            "environment": "internal",
            "description": "Local test target"
        }
    )
    assert response.status_code == 201
    data = response.json()
    assert data["name"] == "Internal Test App"
    target_id = data["id"]

    # List targets
    list_res = client.get("/api/v1/targets/")
    assert list_res.status_code == 200
    assert len(list_res.json()) >= 1

def test_sast_engine_local_scan(tmp_path):
    # Create a temporary file with a secret leak pattern
    vulnerable_file = tmp_path / "config.py"
    vulnerable_file.write_text('AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"\n')

    engine = SASTEngine(str(tmp_path))
    findings = asyncio.run(engine.run_scan())

    assert len(findings) >= 1
    assert "Exposed AWS Secret Access Key" in findings[0]["title"]
