"""Tests for the agent HTTP endpoint and regression of the existing API surface."""
from fastapi.testclient import TestClient

from backend.app import app

client = TestClient(app)

AGENT_REQUIRED = {"url", "normalized_url", "prediction", "label", "confidence",
                  "confidence_semantics", "risk_level", "explanation", "signals",
                  "training_distribution_gaps", "recommendation", "advisories",
                  "disclaimer", "research_notice", "website_visited", "model", "agent"}


def test_existing_endpoints_still_work():
    assert client.get("/").status_code == 200
    root = client.get("/").json()
    assert root["status"] == "ready"
    health = client.get("/api/health").json()
    assert health["model_loaded"] is True
    info = client.get("/api/model_info").json()
    assert info["features"] == 38 and info["records"] > 0
    assert info["model"] == "Decision Tree"


def test_predict_contract_is_unchanged():
    body = client.post("/api/predict", json={"url": "https://www.example.com/"}).json()
    for key in ("url", "normalized_url", "prediction", "label", "confidence",
                "model", "technical_class", "features", "analysis"):
        assert key in body
    assert body["label"] in (0, 1)
    assert len(body["features"]) == 38


def test_agent_endpoint_returns_200_and_full_contract():
    response = client.post("/api/agent/analyze", json={"url": "https://www.example.com/"})
    assert response.status_code == 200
    body = response.json()
    assert AGENT_REQUIRED <= set(body)
    assert body["label"] in (0, 1)
    assert 0.0 <= body["confidence"] <= 1.0
    assert isinstance(body["explanation"], list) and body["explanation"]
    assert body["website_visited"] is False
    assert body["model"]["feature_count"] == 38


def test_agent_endpoint_handles_both_schemes():
    for url in ("http://www.example.com/", "https://www.example.com/"):
        assert client.post("/api/agent/analyze", json={"url": url}).status_code == 200


def test_agent_endpoint_rejects_invalid_input_with_422():
    for payload in ({"url": ""}, {"url": "not a url"}, {"url": "ftp://example.com/"},
                    {"url": "javascript:alert(1)"}, {"url": "http://"},
                    {"url": "a" * 2049}, {"url": "https://example.com/\nmalicious"}):
        assert client.post("/api/agent/analyze", json=payload).status_code == 422
    assert client.post("/api/agent/analyze", content="not json",
                       headers={"Content-Type": "application/json"}).status_code == 422


def test_agent_and_predict_agree_on_the_label():
    for url in ("https://www.example.com/", "https://example.com/",
                "http://192.0.2.5:8080/login?next=%2Fadmin"):
        agent = client.post("/api/agent/analyze", json={"url": url}).json()
        raw = client.post("/api/predict", json={"url": url}).json()
        assert agent["label"] == raw["label"]
        assert agent["confidence"] == raw["confidence"]
        assert agent["normalized_url"] == raw["normalized_url"]


def test_known_limitation_is_surfaced_by_the_api():
    body = client.post("/api/agent/analyze", json={"url": "https://example.com/"}).json()
    assert body["training_distribution_gaps"], "apex URL must report a training-distribution gap"
    assert "apex" in " ".join(body["training_distribution_gaps"]).lower()
    assert "apex" in body["research_notice"].lower()
