"""Controlled baseline experiment — canonical dataset ONLY.

No candidate dataset is read, integrated, or sampled by this script
(PhreshPhish, EdgePhish-5G, PhishVN, PhishBD, LegitPhish, URL-Phish are all
untouched). Diagnostic examples are canonical rows only; every diagnostic
category that canonical cannot supply is reported as measured-unavailable
rather than filled from a non-approved source.

Writes ONLY under models/experiments/. Never modifies:
  models/phishguard_pipeline.joblib, models/model_metadata.json,
  results/, docs/, data/, frontend/, backend/

Evaluations:
  PRIMARY EVALUATION  - stratified URL-level 80/20, random_state=42
  DOMAIN-AWARE EVALUATION - registrable-domain grouped, PSL-aware
                           (GroupShuffleSplit 20%, random_state=42,
                            groups from src/domain_split.py; overlap must be 0)
"""
import hashlib
import ipaddress
import json
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (accuracy_score, confusion_matrix, f1_score,
                             precision_score, recall_score)
from sklearn.model_selection import GroupShuffleSplit, train_test_split
from sklearn.tree import DecisionTreeClassifier

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from src.data_loader import DATASET, clean_url_labels, load_datasets  # noqa: E402
from src.data_preprocessing import make_pipeline  # noqa: E402
from src.domain_split import (groups_for_urls,  # noqa: E402
                              registrable_domain_from_host,
                              verify_group_overlap)
from src.evaluate import score_model  # noqa: E402
from src.feature_schema import FEATURES, extract_url_features, normalize_url  # noqa: E402
from src.train import build_features  # noqa: E402

EXP_DIR = ROOT / "models" / "experiments"
CANONICAL = ROOT / "data" / "raw" / "PhiUSIIL_Phishing_URL_Dataset.csv"
PROD_PIPE = ROOT / "models" / "phishguard_pipeline.joblib"
PROD_META = ROOT / "models" / "model_metadata.json"

FORBIDDEN = ["PhreshPhish", "EdgePhish-5G", "PhishVN", "PhishBD",
             "LegitPhish", "URL-Phish", "ISCX", "PhishStorm"]


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def is_ip_host(norm):
    try:
        ipaddress.ip_address((urlsplit(norm).hostname or "").strip("[]"))
        return True
    except ValueError:
        return False


def has_port(norm):
    try:
        return urlsplit(norm).port is not None
    except ValueError:
        return False


def is_punycode(norm):
    return any(part.startswith("xn--") for part in (urlsplit(norm).hostname or "").split("."))


def shape(norm):
    host = urlsplit(norm).hostname or ""
    reg = registrable_domain_from_host(host)
    www = host.startswith("www.")
    apex = bool(host) and host == reg and not www
    sub = bool(host) and host != reg and not www
    root = urlsplit(norm).path in ("", "/") and not urlsplit(norm).query
    return {"www": www, "apex": apex, "sub": sub, "root": root}


def metrics_for(name, y_true, y_pred):
    cm = confusion_matrix(y_true, y_pred, labels=[0, 1])
    return {"model": name,
            "accuracy": float(accuracy_score(y_true, y_pred)),
            "precision": float(precision_score(y_true, y_pred, pos_label=0, zero_division=0)),
            "recall": float(recall_score(y_true, y_pred, pos_label=0, zero_division=0)),
            "f1": float(f1_score(y_true, y_pred, pos_label=0, zero_division=0)),
            "false_positives": int(cm[1, 0]), "false_negatives": int(cm[0, 1]),
            "positive_class": "Potential Phishing (0)",
            "confusion_matrix": {"labels": ["Phishing (0)", "Legitimate (1)"],
                                 "matrix": cm.tolist()}}


def coverage(df):
    """Full canonical scan: per-class structural counts (measured, not assumed)."""
    stats = {0: Counter(), 1: Counter()}
    for url, label in zip(df["URL"].astype(str), df["label"].astype(int)):
        c = stats[label]
        c["rows"] += 1
        try:
            norm = normalize_url(url)
        except Exception:
            c["invalid_url"] += 1
            continue
        c["valid_url"] += 1
        p = urlsplit(norm)
        s = shape(norm)
        c["http" if p.scheme == "http" else "https" if p.scheme == "https" else "other_scheme"] += 1
        if s["apex"] and s["root"]:
            c["apex_root"] += 1
        elif s["apex"]:
            c["apex_with_path"] += 1
        if s["www"]:
            c["www"] += 1
        if s["sub"]:
            c["other_subdomain"] += 1
        if s["root"]:
            c["root_path"] += 1
        if p.query:
            c["query"] += 1
        if is_ip_host(norm):
            c["ip_host"] += 1
        if "%" in norm:
            c["percent_encoded"] += 1
        if has_port(norm):
            c["explicit_port"] += 1
        if is_punycode(norm):
            c["punycode"] += 1
    return {str(k): dict(v) for k, v in stats.items()}


def pick(df, label, predicate, limit):
    out = []
    for url, lab in zip(df["URL"].astype(str), df["label"].astype(int)):
        if lab != label:
            continue
        try:
            norm = normalize_url(url)
        except Exception:
            continue
        if predicate(norm):
            out.append({"url": url, "normalized": norm, "source_label": lab,
                        "source": "canonical CSV (PhiUSIIL, UCI 967), label %d" % lab})
            if len(out) >= limit:
                break
    return out


def main():
    started = datetime.now(timezone.utc).isoformat()
    prod_pipe_hash_before = sha256(PROD_PIPE)
    prod_meta_hash_before = sha256(PROD_META)

    raw = load_datasets([DATASET])
    assert len(raw) == 235795, "canonical raw row count changed: %d" % len(raw)
    data, clean = clean_url_labels(raw)
    assert len(data) == 234894, "canonical clean row count changed: %d" % len(data)

    urls = data.normalized_url.tolist()
    X = build_features(urls)
    y = data.label_numeric.to_numpy()

    # ---- PRIMARY EVALUATION: stratified URL-level 80/20 ----
    idx = np.arange(len(y))
    tr, te = train_test_split(idx, test_size=0.2, random_state=42, stratify=y)
    assert set(data.normalized_url.iloc[tr]).isdisjoint(set(data.normalized_url.iloc[te]))

    ctors = [
        ("Logistic Regression",
         lambda: LogisticRegression(max_iter=500, class_weight=None, solver="lbfgs")),
        ("Decision Tree",
         lambda: DecisionTreeClassifier(random_state=42, min_samples_leaf=3, class_weight=None)),
        ("Random Forest",
         lambda: RandomForestClassifier(n_estimators=60, max_depth=24, min_samples_leaf=3,
                                        max_features="sqrt", n_jobs=-1, random_state=42,
                                        class_weight=None)),
    ]

    primary, primary_pipes = {}, {}
    for name, ctor in ctors:
        print("PRIMARY  %s" % name, flush=True)
        pipe = make_pipeline(ctor())
        pipe.fit(X.iloc[tr], y[tr])
        primary[name] = score_model(name, pipe, X.iloc[tr], y[tr], X.iloc[te], y[te])
        primary_pipes[name] = pipe

    # ---- DOMAIN-AWARE EVALUATION: registrable-domain grouped, PSL-aware ----
    groups = groups_for_urls(urls)
    gs = GroupShuffleSplit(n_splits=1, test_size=0.2, random_state=42)
    gtr, gte = next(gs.split(X, y, groups=groups))
    ov = verify_group_overlap([urls[i] for i in gtr], [urls[i] for i in gte])
    if ov["overlap_count"] != 0:
        print(json.dumps({"EXPERIMENT_FAILED": "registrable-domain overlap is non-zero",
                          "overlap": ov}, indent=2))
        sys.exit(1)

    domain = {}
    for name, ctor in ctors:
        print("DOMAIN   %s" % name, flush=True)
        pipe = make_pipeline(ctor())
        pipe.fit(X.iloc[gtr], y[gtr])
        domain[name] = {**metrics_for(name, y[gte], pipe.predict(X.iloc[gte])),
                        "train_rows": int(len(gtr)), "test_rows": int(len(gte)),
                        "train_groups": ov["train_groups"], "test_groups": ov["test_groups"]}

    # ---- DIAGNOSTIC / ROBUSTNESS TEST (canonical rows only) ----
    cdf = pd.read_csv(CANONICAL, usecols=["URL", "label"], low_memory=False)
    cov = coverage(cdf)
    items = []
    items += [dict(i, category="legitimate www") for i in
              pick(cdf, 1, lambda n: shape(n)["www"], 3)]
    items += [dict(i, category="suspicious IP URL") for i in
              pick(cdf, 0, lambda n: is_ip_host(n), 1)]
    items += [dict(i, category="suspicious login-pattern URL") for i in
              pick(cdf, 0, lambda n: "login" in n.lower() and shape(n)["root"] is False, 1)]
    items += [dict(i, category="suspicious verification-pattern URL") for i in
              pick(cdf, 0, lambda n: "verify" in n.lower() and shape(n)["root"] is False, 1)]
    items += [dict(i, category="suspicious percent-encoded URL") for i in
              pick(cdf, 0, lambda n: "%" in n, 1)]
    items += [dict(i, category="suspicious explicit-port URL") for i in
              pick(cdf, 0, lambda n: has_port(n), 1)]
    items += [dict(i, category="suspicious punycode URL") for i in
              pick(cdf, 0, lambda n: is_punycode(n), 1)]
    items += [dict(i, category="suspicious apex-root URL") for i in
              pick(cdf, 0, lambda n: shape(n)["apex"] and shape(n)["root"], 2)]

    prod = joblib.load(PROD_PIPE)
    for it in items:
        feats = extract_url_features(it["normalized"])
        frame = pd.DataFrame([[feats[k] for k in FEATURES]], columns=FEATURES)
        pl, pp = int(prod.predict(frame)[0]), prod.predict_proba(frame)[0]
        it["production_model"] = {"label": pl, "confidence": float(max(pp))}
        it["experimental_models"] = {}
        for name, pipe in primary_pipes.items():
            el, ep = int(pipe.predict(frame)[0]), pipe.predict_proba(frame)[0]
            it["experimental_models"][name] = {"label": el, "confidence": float(max(ep))}
        it["matches_source_label"] = {
            "production": (pl == it["source_label"]),
            **{n: (v["label"] == it["source_label"]) for n, v in it["experimental_models"].items()}}
        it["features"] = feats

    unavailable = [
        {"category": "legitimate apex-root URL",
         "available_in_canonical": bool(cov["1"].get("apex_root", 0)),
         "measured_rows": cov["1"].get("apex_root", 0),
         "reason": "canonical label-1 rows are 100% HTTPS + www + root-path; zero apex-root legitimate rows exist, and no non-approved dataset may be used to supply them."},
        {"category": "legitimate apex with path",
         "available_in_canonical": bool(cov["1"].get("apex_with_path", 0)),
         "measured_rows": cov["1"].get("apex_with_path", 0),
         "reason": "zero legitimate apex rows of any path shape in canonical."},
        {"category": "legitimate non-www subdomain",
         "available_in_canonical": bool(cov["1"].get("other_subdomain", 0)),
         "measured_rows": cov["1"].get("other_subdomain", 0),
         "reason": "zero legitimate non-www subdomain rows in canonical."},
    ]

    EXP_DIR.mkdir(parents=True, exist_ok=True)
    for name, pipe in primary_pipes.items():
        joblib.dump(pipe, EXP_DIR / (name.lower().replace(" ", "_") + "_primary.joblib"), compress=3)

    guard = {"joblib_sha256_before": prod_pipe_hash_before,
             "joblib_sha256_after": sha256(PROD_PIPE),
             "metadata_sha256_before": prod_meta_hash_before,
             "metadata_sha256_after": sha256(PROD_META)}
    if guard["joblib_sha256_before"] != guard["joblib_sha256_after"] or \
       guard["metadata_sha256_before"] != guard["metadata_sha256_after"]:
        print(json.dumps({"EXPERIMENT_FAILED": "production artifact changed"}, indent=2))
        sys.exit(1)

    report = {
        "experiment": "controlled baseline, canonical dataset only (no candidate datasets read)",
        "candidate_datasets_used": [],
        "candidate_datasets_forbidden_and_untouched": FORBIDDEN,
        "started_utc": started, "finished_utc": datetime.now(timezone.utc).isoformat(),
        "canonical": {"file": "data/raw/PhiUSIIL_Phishing_URL_Dataset.csv",
                      "raw_rows": int(len(raw)), "clean_rows": int(len(data)),
                      "cleaning": clean, "label_mapping": {1: "Legitimate", 0: "Phishing"},
                      "class_counts_raw": {"1": 134850, "0": 100945}},
        "representation_audit_by_class": cov,
        "primary_split": {"label": "PRIMARY EVALUATION - STRATIFIED URL-LEVEL 80/20",
                          "train_rows": int(len(tr)), "test_rows": int(len(te)),
                          "random_state": 42},
        "primary_metrics": primary,
        "domain_split": {"label": "DOMAIN-AWARE EVALUATION - REGISTRABLE-DOMAIN GROUPED, PSL-AWARE",
                         "method": "GroupShuffleSplit test_size=0.2, random_state=42, groups from src/domain_split.py (tldextract, PSL private domains included)",
                         "train_rows": int(len(gtr)), "test_rows": int(len(gte)),
                         "train_groups": ov["train_groups"], "test_groups": ov["test_groups"],
                         "overlap_count": ov["overlap_count"],
                         "overlap_pct_of_union": ov["overlap_pct_of_union"],
                         "overlap_pct_of_test": ov["overlap_pct_of_test"]},
        "domain_metrics": domain,
        "diagnostic": {
            "label": "DIAGNOSTIC / ROBUSTNESS TEST - not an official benchmark",
            "ground_truth": "canonical source labels only; source labels are dataset labels, not current-safety verdicts",
            "candidate_datasets_used": [],
            "unavailable_categories": unavailable,
            "items": items},
        "production_artifact_guard": guard,
    }
    (EXP_DIR / "baseline_experiment_metrics.json").write_text(
        json.dumps(report, indent=2, default=str), encoding="utf-8")
    print(json.dumps({
        "primary": {k: {m: v[m] for m in ("accuracy", "precision", "recall", "f1",
                                          "false_positives", "false_negatives")} for k, v in primary.items()},
        "domain": {k: {m: v[m] for m in ("accuracy", "precision", "recall", "f1",
                                        "false_positives", "false_negatives")} for k, v in domain.items()},
        "domain_split": report["domain_split"],
        "guard": guard,
    }, indent=2), flush=True)


if __name__ == "__main__":
    main()
