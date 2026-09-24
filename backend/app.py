"""FastAPI service. Submitted URLs are parsed as strings and are never fetched."""
import json,re
from pathlib import Path
from functools import lru_cache
import joblib
import pandas as pd
from fastapi import FastAPI,HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel,field_validator
from src.feature_schema import FEATURES,extract_url_features,normalize_url

ROOT=Path(__file__).resolve().parents[1]
app=FastAPI(title="PhishGuard API",description="URL-only static phishing classification. Submitted URLs are never visited.",version="1.0")
app.add_middleware(CORSMiddleware,allow_origins=["https://maninani12.github.io","http://localhost:5173","http://127.0.0.1:5173"],allow_methods=["GET","POST"],allow_headers=["Content-Type"])

@lru_cache(maxsize=1)
def load_assets():
    model_path=ROOT/"models"/"phishguard_pipeline.joblib"; meta_path=ROOT/"models"/"model_metadata.json"
    if not model_path.exists() or not meta_path.exists(): raise RuntimeError("Model is not trained. Run python -m src.train first.")
    return joblib.load(model_path),json.loads(meta_path.read_text(encoding="utf-8"))

class PredictRequest(BaseModel):
    url:str
    @field_validator("url")
    @classmethod
    def valid_url(cls,value):
        value=value.strip()
        if not value: raise ValueError("URL cannot be empty")
        if len(value)>2048: raise ValueError("URL exceeds the 2048 character limit")
        if any(ord(c)<32 or ord(c)==127 for c in value): raise ValueError("URL contains control characters")
        if re.match(r"^[A-Za-z][A-Za-z0-9+.-]*:",value) and not re.match(r"^https?://",value,re.I): raise ValueError("Only HTTP and HTTPS URLs are supported")
        try: normalize_url(value)
        except Exception as exc: raise ValueError(f"Malformed URL: {exc}") from exc
        return value

@app.get("/")
def root(): return {"name":"PhishGuard","title":"AI-Based Phishing URL Detection Using Machine Learning","status":"ready","analysis":"URL-only static analysis; submitted websites are never requested."}

@app.get("/api/health")
def health():
    try: _,meta=load_assets(); return {"status":"healthy","model_loaded":True,"model":meta["model"]}
    except Exception as exc: raise HTTPException(status_code=503,detail=str(exc))

@app.get("/api/model_info")
def model_info():
    try: _,meta=load_assets()
    except Exception as exc: raise HTTPException(status_code=503,detail=str(exc))
    metrics=meta["metrics"]
    return {"dataset":meta["dataset"],"records":meta["dataset_records_clean"],"raw_records":meta["dataset_records_raw"],"class_distribution":meta["class_distribution_clean"],"features":meta["feature_count"],"feature_list":meta["features"],"model":meta["model"],"accuracy":metrics["accuracy"],"precision":metrics["precision"],"recall":metrics["recall"],"f1":metrics["f1"],"false_positives":metrics["false_positives"],"false_negatives":metrics["false_negatives"],"domain_aware":meta["domain_aware_metrics"],"training_date_utc":meta["training_date_utc"]}

@app.post("/api/predict")
def predict(payload:PredictRequest):
    try:
        pipeline,meta=load_assets(); normalized=normalize_url(payload.url)
        features=extract_url_features(normalized)
        frame=pd.DataFrame([{k:features[k] for k in FEATURES}],columns=FEATURES)
        label=int(pipeline.predict(frame)[0]); probs=pipeline.predict_proba(frame)[0]
        classes=list(pipeline.named_steps["model"].classes_); confidence=float(probs[classes.index(label)])
        return {"url":payload.url,"normalized_url":normalized,"prediction":"Legitimate" if label==1 else "Potential Phishing","label":label,"confidence":confidence,"model":meta["model"],"technical_class":"Legitimate URL" if label==1 else "Potential Phishing URL","features":features,"analysis":"ML-Based Prediction"}
    except HTTPException: raise
    except Exception as exc: raise HTTPException(status_code=500,detail=f"Prediction failed: {exc}") from exc
