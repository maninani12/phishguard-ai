"""Single source of truth for model loading, URL validation, and inference.

Both ``/api/predict`` and the agent endpoint call :func:`run_prediction`, so the
agent cannot drift from the existing verified prediction behaviour and the model
is loaded exactly once per process.

SAFETY: this module performs **no network I/O of any kind**. The submitted URL
is treated purely as text. Nothing here opens a socket, resolves a hostname,
follows a redirect, or downloads content.
"""
import json
import re
from functools import lru_cache
from pathlib import Path

import joblib
import pandas as pd

from src.feature_schema import FEATURES, extract_url_features, normalize_url

ROOT = Path(__file__).resolve().parents[1]
MAX_URL_LENGTH = 2048
_CONTROL_CHARS = re.compile(r"[\x00-\x1f\x7f]")
_SCHEME_PREFIX = re.compile(r"^[A-Za-z][A-Za-z0-9+.-]*:")
_HTTP_SCHEME = re.compile(r"^https?://", re.IGNORECASE)


@lru_cache(maxsize=1)
def load_assets():
    """Load the verified pipeline and its metadata. Cached for the process lifetime."""
    model_path = ROOT / "models" / "phishguard_pipeline.joblib"
    meta_path = ROOT / "models" / "model_metadata.json"
    if not model_path.exists() or not meta_path.exists():
        raise RuntimeError("Model is not trained. Run python -m src.train first.")
    return joblib.load(model_path), json.loads(meta_path.read_text(encoding="utf-8"))


def validate_url_text(value: str) -> str:
    """Validate a submitted URL string. Raises ValueError with a user-safe message.

    Rules are identical for the raw prediction endpoint and the agent endpoint:
    non-empty, at most 2048 characters, no control characters, HTTP/HTTPS only,
    and parseable by the project's normalizer.
    """
    if not isinstance(value, str):
        raise ValueError("URL must be a string")
    value = value.strip()
    if not value:
        raise ValueError("URL cannot be empty")
    if len(value) > MAX_URL_LENGTH:
        raise ValueError(f"URL exceeds the {MAX_URL_LENGTH} character limit")
    if _CONTROL_CHARS.search(value):
        raise ValueError("URL contains control characters")
    if _SCHEME_PREFIX.match(value) and not _HTTP_SCHEME.match(value):
        raise ValueError("Only HTTP and HTTPS URLs are supported")
    try:
        normalize_url(value)
    except Exception as exc:
        raise ValueError(f"Malformed URL: {exc}") from exc
    return value


def predict_frame(pipeline, features: dict) -> dict:
    """Run the fitted pipeline over a single feature dict. No I/O."""
    frame = pd.DataFrame([{key: features[key] for key in FEATURES}], columns=FEATURES)
    label = int(pipeline.predict(frame)[0])
    probs = pipeline.predict_proba(frame)[0]
    classes = list(pipeline.named_steps["model"].classes_)
    return {"label": label,
            "confidence": float(probs[classes.index(label)]),
            "predicted_class_score": float(probs[classes.index(label)])}


def run_prediction(url: str) -> dict:
    """Validate, normalize, featurize and score one URL. Returns the raw prediction record.

    ``confidence`` is the classifier's score for the class it predicted. It is
    **not** a calibrated probability that a URL is malicious.
    """
    cleaned = validate_url_text(url)
    pipeline, meta = load_assets()
    normalized = normalize_url(cleaned)
    features = extract_url_features(normalized)
    scored = predict_frame(pipeline, features)
    label = scored["label"]
    return {
        "submitted_url": cleaned,
        "normalized_url": normalized,
        "label": label,
        "confidence": scored["confidence"],
        "features": features,
        "model_name": meta["model"],
        "feature_count": meta["feature_count"],
    }
