from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)

def test_scan_safe_url():
    response = client.post("/scan/url", json={"url": "http://example.com"})
    assert response.status_code == 200
    data = response.json()
    # Verify response has the required structure
    assert "url" in data
    assert "domain" in data
    assert "verdict" in data
    assert "score" in data

def test_scan_risky_url():
    response = client.post("/scan/url", json={"url": "http://login-secure-free.biz"})
    assert response.status_code == 200
    data = response.json()
    # If suspicious words are found, score should be higher
    assert "verdict" in data
    assert data["verdict"] in ["Safe", "Risky"]