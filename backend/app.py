"""FastAPI service. Submitted URLs are parsed as strings and are never fetched.

SAFETY: this service makes no outbound request to any submitted URL. It performs
URL string parsing and local model inference only. There is no HTTP client, no
socket, no DNS resolution, no redirect following and no browser automation
anywhere in the request path.
"""
import json
from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, field_validator

from backend.agent import analyze_url
from backend.prediction import load_assets, run_prediction, validate_url_text
from src.feature_schema import FEATURES

ROOT = Path(__file__).resolve().parents[1]
app = FastAPI(
    title="PhishGuard API",
    description=("URL-only static phishing classification and agent assessment. "
                 "Submitted URLs are never visited, fetched or rendered."),
    version="1.1",
)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["https://maninani12.github.io", "http://localhost:5173", "http://127.0.0.1:5173"],
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type"],
)


class PredictRequest(BaseModel):
    url: str

    @field_validator("url")
    @classmethod
    def valid_url(cls, value):
        return validate_url_text(value)


@app.get("/")
def root():
    return {
        "name": "PhishGuard",
        "title": "AI-Based Phishing URL Detection Using Machine Learning",
        "status": "ready",
        "kind": "research / demonstration system",
        "analysis": "URL-only static analysis; submitted websites are never requested.",
        "agent_endpoint": "POST /api/agent/analyze",
        "prediction_endpoint": "POST /api/predict",
    }


@app.get("/api/health")
def health():
    try:
        _, meta = load_assets()
        return {"status": "healthy", "model_loaded": True, "model": meta["model"]}
    except Exception as exc:
        raise HTTPException(status_code=503, detail=str(exc))


@app.get("/api/model_info")
def model_info():
    try:
        _, meta = load_assets()
    except Exception as exc:
        raise HTTPException(status_code=503, detail=str(exc))
    metrics = meta["metrics"]
    return {
        "dataset": meta["dataset"],
        "records": meta["dataset_records_clean"],
        "raw_records": meta["dataset_records_raw"],
        "class_distribution": meta["class_distribution_clean"],
        "features": meta["feature_count"],
        "feature_list": meta["features"],
        "model": meta["model"],
        "accuracy": metrics["accuracy"],
        "precision": metrics["precision"],
        "recall": metrics["recall"],
        "f1": metrics["f1"],
        "false_positives": metrics["false_positives"],
        "false_negatives": metrics["false_negatives"],
        "domain_aware": meta["domain_aware_metrics"],
        "training_date_utc": meta["training_date_utc"],
    }


@app.post("/api/predict")
def predict(payload: PredictRequest):
    """Raw model prediction. Unchanged response contract."""
    try:
        result = run_prediction(payload.url)
        label = result["label"]
        return {
            "url": payload.url,
            "normalized_url": result["normalized_url"],
            "prediction": "Legitimate" if label == 1 else "Potential Phishing",
            "label": label,
            "confidence": result["confidence"],
            "model": result["model_name"],
            "technical_class": "Legitimate URL" if label == 1 else "Potential Phishing URL",
            "features": result["features"],
            "analysis": "ML-Based Prediction",
        }
    except HTTPException:
        raise
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Prediction failed: {exc}") from exc


@app.post("/api/agent/analyze", response_model=None)
def agent_analyze(payload: PredictRequest):
    """Agent assessment: prediction plus evidence-based explanation and guidance.

    Uses the same validated prediction pipeline as /api/predict; it adds no
    network capability of any kind.
    """
    try:
        return analyze_url(payload.url).model_dump()
    except HTTPException:
        raise
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Agent analysis failed: {exc}") from exc
