"""Phase 10 - error analysis on the canonical primary held-out split.

Trains the production classifier configuration on the primary stratified
80/20 split (random_state=42) and characterises the false positives and
false negatives structurally. No individual domain is patched, whitelisted
or special-cased; only aggregate patterns are reported.

Writes only to models/experiments/.
"""
import json
import sys
from pathlib import Path
from urllib.parse import urlsplit

import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.tree import DecisionTreeClassifier

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from src.data_loader import DATASET, clean_url_labels, load_datasets  # noqa: E402
from src.data_preprocessing import make_pipeline  # noqa: E402
from src.domain_split import registrable_domain_from_host  # noqa: E402
from src.feature_schema import SHORTENERS  # noqa: E402
from src.train import build_features  # noqa: E402

EXP = ROOT / "models" / "experiments"
SAMPLE = 15


def shape(row):
    q = urlsplit(row.normalized_url)
    host = q.hostname or ""
    reg = registrable_domain_from_host(host)
    is_www = host.startswith("www.")
    is_apex = bool(host) and host == reg and not is_www
    is_root = q.path in ("", "/") and not q.query
    return {"scheme": q.scheme, "is_www": is_www, "is_apex": is_apex,
            "is_subdomain": bool(host) and host != reg and not is_www,
            "is_root_path": is_root, "has_query": bool(q.query),
            "has_port": q.port is not None, "has_https": q.scheme == "https"}


def profile(df, X, name):
    out = {"count": int(len(df))}
    sh = pd.DataFrame([shape(row) for _, row in df.iterrows()], index=df.index)
    for key in ("has_https", "is_www", "is_apex", "is_subdomain", "is_root_path", "has_query", "has_port"):
        out["pct_" + key] = round(float(sh[key].mean()) * 100, 2)
    for feat in ("URLLength", "DomainLength", "NoOfSubDomain", "path_length",
                 "query_length", "num_suspicious_keywords", "num_encoded_chars",
                 "url_entropy", "IsDomainIP", "has_punycode"):
        col = X.loc[df.index, feat].astype(float)
        out["mean_" + feat] = round(float(col.mean()), 3)
        out["median_" + feat] = round(float(col.median()), 3)
    out["pct_shortener_host"] = round(float(
        df.normalized_url.map(lambda u: (urlsplit(u).hostname or "") in SHORTENERS).mean()) * 100, 2)
    out["pct_suspicious_keyword_url"] = round(float(
        df.normalized_url.str.lower().str.contains("login|verify|account|secure|update|password|signin|bank|confirm|wallet|support|recover|auth|billing").mean()) * 100, 2)
    return out


def main():
    raw = load_datasets([DATASET])
    data, _ = clean_url_labels(raw)
    urls = data.normalized_url.tolist()
    X = build_features(urls)
    y = data.label_numeric.to_numpy()
    idx = np.arange(len(y))
    tr, te = train_test_split(idx, test_size=0.2, random_state=42, stratify=y)

    pipe = make_pipeline(DecisionTreeClassifier(random_state=42, min_samples_leaf=3, class_weight=None))
    pipe.fit(X.iloc[tr], y[tr])
    pred = pipe.predict(X.iloc[te])

    test = data.iloc[te].copy().reset_index(drop=True)
    Xte = X.iloc[te].reset_index(drop=True)
    yte = y[te]
    pred = np.asarray(pred)
    test["_pred"] = pred

    fp = test[(yte == 1) & (pred == 0)]   # legitimate called phishing
    fn = test[(yte == 0) & (pred == 1)]   # phishing called legitimate
    tp_phish = test[(yte == 0) & (pred == 0)]
    tp_legit = test[(yte == 1) & (pred == 1)]

    out = {
        "label": "ERROR ANALYSIS - canonical primary held-out split, Decision Tree (production configuration)",
        "split": {"train_rows": int(len(tr)), "test_rows": int(len(te)), "random_state": 42},
        "counts": {"false_positives": int(len(fp)), "false_negatives": int(len(fn)),
                   "true_positive_phishing": int(len(tp_phish)), "true_positive_legitimate": int(len(tp_legit))},
        "false_positive_profile": profile(fp, Xte.loc[fp.index], "fp"),
        "false_negative_profile": profile(fn, Xte.loc[fn.index], "fn"),
        "reference_correct_legitimate_profile": profile(tp_legit, Xte.loc[tp_legit.index], "legit"),
        "reference_correct_phishing_profile": profile(tp_phish, Xte.loc[tp_phish.index], "phish"),
        "false_positive_examples": fp.normalized_url.head(SAMPLE).tolist(),
        "false_negative_examples": fn.normalized_url.head(SAMPLE).tolist(),
        "note": "Examples are listed for pattern inspection only. No domain is patched, whitelisted or special-cased anywhere in the project.",
    }
    (EXP / "error_analysis.json").write_text(json.dumps(out, indent=2), encoding="utf-8")
    print(json.dumps({"counts": out["counts"],
                      "false_positive_profile": out["false_positive_profile"],
                      "false_negative_profile": out["false_negative_profile"]}, indent=2))
    print("\nFP examples:", out["false_positive_examples"][:6])
    print("FN examples:", out["false_negative_examples"][:6])
    print("\nwrote", EXP / "error_analysis.json")


if __name__ == "__main__":
    main()
