"""Tests for the deterministic PhishGuard agent layer."""
import pytest

from backend.agent import AGENT_NAME, analyze_url
from backend.agent.explanation import (CONFIDENCE_SEMANTICS, DISCLAIMER,
                                       RESEARCH_NOTICE, build_signals,
                                       distribution_gaps, risk_level)
from backend.prediction import validate_url_text
from src.feature_schema import normalize_url

PHISHING_SHAPED = "http://192.0.2.5:8080/login?next=%2Fadmin"
PLAIN_WWW = "https://www.example.com/"
APEX = "https://example.com/"

REQUIRED_FIELDS = {"url", "normalized_url", "prediction", "label", "confidence",
                   "confidence_semantics", "risk_level", "explanation", "signals",
                   "recommendation", "advisories", "disclaimer", "research_notice",
                   "website_visited", "model", "agent"}


def analyze(url):
    return analyze_url(url).model_dump()


# --------------------------------------------------------------------------
# Validation parity with the existing prediction endpoint
# --------------------------------------------------------------------------

@pytest.mark.parametrize("bad", [
    "",                                   # empty
    "   ",                                # whitespace only
    "not a url",                          # malformed
    "ftp://example.com/x",                # unsupported scheme
    "javascript:alert(1)",                # script scheme
    "http://",                            # no host
    "https://example.com/" + "a" * 3000,  # oversized
    "https://exa mple.com/",              # invalid hostname
])
def test_invalid_inputs_are_rejected(bad):
    with pytest.raises(ValueError):
        validate_url_text(bad)
    with pytest.raises(ValueError):
        analyze_url(bad)


def test_http_and_https_are_both_accepted():
    for url in ("http://www.example.com/", "https://www.example.com/"):
        assert validate_url_text(url) == url
        assert analyze(url)["label"] in (0, 1)


def test_oversized_limit_is_2048():
    validate_url_text("https://example.com/" + "a" * (2048 - len("https://example.com/")))
    with pytest.raises(ValueError, match="2048"):
        validate_url_text("https://example.com/" + "a" * 2049)


# --------------------------------------------------------------------------
# Response contract
# --------------------------------------------------------------------------

def test_response_schema_is_complete():
    body = analyze(PHISHING_SHAPED)
    assert REQUIRED_FIELDS <= set(body)
    assert isinstance(body["explanation"], list) and body["explanation"]
    assert all(isinstance(line, str) and line for line in body["explanation"])
    assert isinstance(body["signals"], list)
    assert isinstance(body["recommendation"], str) and body["recommendation"]
    assert isinstance(body["advisories"], list)
    assert 0.0 <= body["confidence"] <= 1.0
    assert body["label"] in (0, 1)
    assert body["prediction"] in ("Legitimate", "Potential Phishing")
    assert body["risk_level"] in {"high", "elevated", "moderate", "low", "low-to-moderate", "uncertain"}


def test_label_convention_matches_model_metadata():
    import json
    from pathlib import Path
    meta = json.loads(Path("models/model_metadata.json").read_text(encoding="utf-8"))
    mapping = {int(k): v for k, v in meta["label_mapping"].items()}
    assert mapping == {1: "Legitimate", 0: "Potential Phishing"}
    for url in (PLAIN_WWW, APEX, PHISHING_SHAPED):
        body = analyze(url)
        assert body["prediction"] == mapping[body["label"]]


def test_confidence_semantics_are_stated_not_overclaimed():
    body = analyze(PLAIN_WWW)
    assert body["confidence_semantics"] == CONFIDENCE_SEMANTICS
    assert "not a calibrated probability" in body["confidence_semantics"].lower()


def test_agent_identity_and_website_never_visited():
    body = analyze(PLAIN_WWW)
    assert body["agent"].startswith(AGENT_NAME)
    assert body["website_visited"] is False


def test_model_block_is_grounded_in_metadata():
    body = analyze(PLAIN_WWW)
    assert body["model"]["feature_count"] == 38
    assert body["model"]["name"] == "Decision Tree"
    assert "PhiUSIIL" in body["model"]["trained_on"]


# --------------------------------------------------------------------------
# Explanation quality and honesty
# --------------------------------------------------------------------------

def test_explanation_never_claims_the_site_was_inspected():
    """Bans affirmative claims. Hedged or negated phrasing is allowed and required."""
    banned = (
        "we visited", "we scanned", "we opened", "we fetched", "we downloaded",
        "we loaded", "the page contains", "the site contains", "contains malware",
        "website is safe", "site is completely safe", "is definitely malicious",
        "definitely malicious", "confirmed malicious", "guaranteed safe",
        "100% safe", "100% protection", "cannot be fooled",
    )
    for url in (PLAIN_WWW, APEX, PHISHING_SHAPED):
        text = " ".join(analyze(url)["explanation"]).lower()
        for phrase in banned:
            assert phrase not in text, f"{url}: explanation contains {phrase!r}"


def test_explanation_always_carries_hedged_language():
    for url in (PLAIN_WWW, APEX, PHISHING_SHAPED):
        body = analyze(url)
        joined = " ".join(body["explanation"]).lower()
        assert "url-level characteristics" in joined
        assert "not evidence that the site itself is malicious" in joined \
            or "not a confirmation that the site is safe" in joined


def test_legitimate_verdict_is_hedged_not_a_safety_guarantee():
    body = analyze(PLAIN_WWW)
    if body["label"] == 1:
        joined = " ".join(body["explanation"]).lower()
        assert "no phishing indicators were detected strongly enough" in joined
        assert "not a confirmation that the site is safe" in joined


def test_signals_are_only_emitted_when_present():
    """A plain HTTPS www root URL must produce no risk signals at all."""
    clean = {"IsHTTPS": 1, "has_port": 0, "IsDomainIP": 0, "has_punycode": 0,
             "has_url_shortener": 0, "num_encoded_chars": 0, "num_suspicious_keywords": 0,
             "HasObfuscation": 0, "num_at": 0, "URLLength": 24, "path_length": 1,
             "query_length": 0, "fragment_length": 0, "NoOfSubDomain": 1,
             "max_repeat_ratio": 0.05}
    assert build_signals(clean, PLAIN_WWW) == []
    # The same features with HTTPS removed must now report exactly the HTTPS signal.
    assert [s["code"] for s in build_signals({**clean, "IsHTTPS": 0}, PLAIN_WWW)] == ["no_https"]


def test_signals_detect_the_expected_phishing_shapes():
    body = analyze(PHISHING_SHAPED)
    codes = {signal["code"] for signal in body["signals"]}
    assert {"ip_host", "no_https", "custom_port", "encoded_chars",
            "suspicious_keywords", "query_string"} <= codes


def test_training_distribution_gap_flagging():
    assert any("HTTP" in gap for gap in distribution_gaps(
        {**{k: 0 for k in ("IsHTTPS",)}, "IsHTTPS": 0}, "http://example.com/"))
    apex_gaps = analyze(APEX)["training_distribution_gaps"]
    assert any("apex" in gap.lower() for gap in apex_gaps)
    assert analyze(PLAIN_WWW)["training_distribution_gaps"] == []


def test_recommendation_is_actionable_for_each_verdict():
    risky = analyze(PHISHING_SHAPED)
    assert "Do not enter passwords" in risky["recommendation"]
    safe = analyze(PLAIN_WWW)
    if safe["label"] == 1:
        assert "confirm the destination" in safe["recommendation"]


def test_disclaimer_and_research_notice_present():
    body = analyze(PLAIN_WWW)
    assert body["disclaimer"] == DISCLAIMER
    assert "never visited" in body["disclaimer"].lower()
    assert body["research_notice"] == RESEARCH_NOTICE
    assert "apex" in body["research_notice"].lower()


def test_normalized_url_is_the_scored_form():
    body = analyze("  WWW.Example.COM  ")
    assert body["url"].strip() == "WWW.Example.COM"
    assert body["normalized_url"] == normalize_url("WWW.Example.COM")


def test_risk_level_bands():
    assert risk_level(0, 0.99) == "high"
    assert risk_level(0, 0.75) == "elevated"
    assert risk_level(0, 0.10) == "moderate"
    assert risk_level(1, 0.99) == "low"
    assert risk_level(1, 0.80) == "low-to-moderate"
    assert risk_level(1, 0.10) == "uncertain"
