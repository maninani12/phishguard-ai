"""PhishGuard agent: a deterministic, offline security-assessment layer.

Pipeline:

    URL text -> validation -> PhishGuard model prediction
             -> rule-based explanation -> safety guidance -> structured response

Design constraints held deliberately:

* **No external LLM.** No API key, no cloud service, no local model server.
  Every sentence is produced by deterministic rules over measured features.
* **No network access of any kind.** The submitted URL is only ever parsed as
  text. This module does not import ``requests``, ``urllib.request``,
  ``httpx``, ``socket``, ``subprocess`` or any browser automation library, and
  it never opens a connection to the submitted host.
* **No invented reasoning.** An observation is emitted only when the feature
  that justifies it is actually present, and the agent never claims knowledge
  about the website itself.
"""
from backend.prediction import load_assets, run_prediction
from .explanation import (CONFIDENCE_SEMANTICS, DISCLAIMER, PREDICTION_LEGITIMATE,
                          PREDICTION_PHISHING, RESEARCH_NOTICE, build_explanation,
                          build_recommendation, build_signals, distribution_gaps,
                          risk_level)
from .schemas import AgentResponse

AGENT_NAME = "phishguard-agent"
AGENT_VERSION = "1.0"


def _label_names(meta: dict) -> dict:
    """Read the label convention from the shipped metadata instead of assuming it."""
    mapping = meta.get("label_mapping") or {}
    if not mapping:
        raise RuntimeError("Model metadata is missing label_mapping; refusing to guess the label convention.")
    return {int(k): str(v) for k, v in mapping.items()}


def analyze_url(url: str) -> AgentResponse:
    """Run the full agent assessment for one submitted URL."""
    prediction = run_prediction(url)
    meta = load_assets()[1]
    names = _label_names(meta)

    label = prediction["label"]
    if label not in names:
        raise RuntimeError(f"Model produced label {label}, which is absent from the documented label mapping.")

    confidence = prediction["confidence"]
    normalized = prediction["normalized_url"]
    features = prediction["features"]

    signals = build_signals(features, normalized)
    gaps = distribution_gaps(features, normalized)
    explanation = build_explanation(label, confidence, signals, gaps)
    recommendation, advisories = build_recommendation(label, gaps)

    return AgentResponse(
        url=prediction["submitted_url"],
        normalized_url=normalized,
        prediction=names[label],
        label=label,
        confidence=confidence,
        confidence_semantics=CONFIDENCE_SEMANTICS,
        risk_level=risk_level(label, confidence),
        explanation=explanation,
        signals=signals,
        training_distribution_gaps=gaps,
        recommendation=recommendation,
        advisories=advisories,
        disclaimer=DISCLAIMER,
        research_notice=RESEARCH_NOTICE,
        website_visited=False,
        model={
            "name": meta["model"],
            "feature_count": meta["feature_count"],
            "label_mapping": names,
            "trained_on": meta["dataset"],
        },
        agent=f"{AGENT_NAME}/{AGENT_VERSION}",
    )


__all__ = ["analyze_url", "AGENT_NAME", "AGENT_VERSION",
           "PREDICTION_LEGITIMATE", "PREDICTION_PHISHING"]
