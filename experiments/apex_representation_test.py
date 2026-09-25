"""Phase 9 - apex representation diagnostic (DIAGNOSTIC, NOT A BENCHMARK).

Measures whether the model has learned the canonical corpus's
HTTPS + www + root-path bias, using labeled apex / www / subdomain examples
that the canonical training set structurally cannot contain.

LABEL MAPPING WARNING
PhishTrap uses 0 = legitimate, 1 = phishing.
PhishGuard uses 0 = phishing,   1 = legitimate.
The two conventions are INVERTED. Every row is remapped explicitly below
(project_label = 1 - phishtrap_label) and the remapping is asserted.

PhishTrap is used for MEASUREMENT ONLY. It is not approved for training,
model selection, or deployment: its legitimate rows are the Tranco top-10K
list, which inherits a non-commercial (Cloudflare Radar CC BY-NC 4.0)
upstream component.

Writes only to models/experiments/.
"""
import json
import sys
from pathlib import Path
from urllib.parse import urlsplit

import joblib
import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from src.domain_split import registrable_domain_from_host  # noqa: E402
from src.feature_schema import FEATURES, extract_url_features, normalize_url  # noqa: E402

EXP = ROOT / "models" / "experiments"
CAND = ROOT / "data" / "candidates" / "PhishTrap" / "phishtrap_full.csv"
PROD = ROOT / "models" / "phishguard_pipeline.joblib"
PER_CATEGORY = 2000


def categorise(norm):
    """Structural shape only. Never embeds a class assumption."""
    q = urlsplit(norm)
    host = q.hostname or ""
    reg = registrable_domain_from_host(host)
    is_www = host.startswith("www.")
    is_apex = bool(host) and host == reg and not is_www
    is_root = q.path in ("", "/") and not q.query
    scheme = q.scheme
    if is_www:
        shape = "www"
    elif is_apex and is_root:
        shape = "apex-root"
    elif is_apex:
        shape = "apex-with-path"
    elif host != reg:
        shape = "subdomain"
    else:
        shape = "other"
    return "%s|%s%s" % (shape, scheme, "|query" if q.query else "")


def main():
    df = pd.read_csv(CAND, usecols=["url", "label"], low_memory=False)
    buckets = {}
    remap_checked = set()
    for url, label in zip(df["url"].astype(str), df["label"].astype(int)):
        project_label = 1 - label          # invert: phishtrap 0=legit -> project 1=legit
        assert project_label in (0, 1)
        remap_checked.add((label, project_label))
        try:
            norm = normalize_url(url)
        except Exception:
            continue
        buckets.setdefault((categorise(norm), project_label), []).append(norm)

    assert remap_checked == {(0, 1), (1, 0)}, remap_checked

    models = {"production (Decision Tree, shipped)": joblib.load(PROD)}
    for name, fname in (("experiment Logistic Regression", "logistic_regression_primary.joblib"),
                        ("experiment Decision Tree", "decision_tree_primary.joblib"),
                        ("experiment Random Forest", "random_forest_primary.joblib")):
        p = EXP / fname
        if p.exists():
            models[name] = joblib.load(p)

    results = {}
    for (shape, project_label) in sorted(buckets):
        population = buckets[(shape, project_label)]
        sample = population[:PER_CATEGORY]
        cls = "legitimate" if project_label == 1 else "phishing"
        key = "%s  [%s]" % (shape, cls)
        n = len(sample)
        counts = {m: 0 for m in models}
        for norm in sample:
            feats = extract_url_features(norm)
            frame = pd.DataFrame([[feats[k] for k in FEATURES]], columns=FEATURES)
            for m, pp in models.items():
                if int(pp.predict(frame)[0]) == project_label:
                    counts[m] += 1
        results[key] = {"n": n, "population_in_file": len(population),
                        "truncated_sample": len(population) > n,
                        "phishtrap_label": 1 - project_label,
                        "project_label": project_label,
                        "class": cls,
                        "correct_vs_source_label": {
                            m: {"correct": c, "accuracy": round(c / n, 6)} for m, c in counts.items()}}

    out = {"label": "DIAGNOSTIC / ROBUSTNESS TEST - NOT AN OFFICIAL BENCHMARK",
           "purpose": "detect whether the model learned the canonical HTTPS + www + root-path bias",
           "ground_truth": "PhishTrap source labels, diagnostic use only",
           "label_mapping": "PhishTrap 0=legitimate / 1=phishing is INVERTED vs PhishGuard 0=phishing / 1=legitimate; remapped as project = 1 - phishtrap",
           "confound_warning": "Every PhishTrap legitimate row is a constructed http:// URL (9973 http, 0 https), so 'apex' and 'HTTP' effects cannot be fully separated with this source alone.",
           "canonical_training_data_contains": "zero legitimate apex-root, apex-with-path, or non-www subdomain rows",
           "sample_cap_per_category": PER_CATEGORY,
           "categories": results}
    # ---- Causal probe: is the scheme the decisive variable? ----
    # SYNTHETIC COUNTERFACTUAL, NOT GROUND TRUTH. The same legitimate apex/subdomain
    # hosts are re-scored after a mechanical http:// -> https:// rewrite. The host and
    # path are unchanged, so any change in prediction is attributable to the scheme
    # feature the model learned from the canonical corpus.
    probe_models = {"production (Decision Tree, shipped)": models["production (Decision Tree, shipped)"]}
    probe = {}
    for (shape, project_label) in sorted(buckets):
        if project_label != 1 or "http" not in shape:
            continue
        population = [u for u in buckets[(shape, project_label)]][:PER_CATEGORY]
        https_forms = []
        for u in population:
            if u.startswith("http://"):
                https_forms.append("https://" + u[len("http://"):])
        n = len(https_forms)
        if not n:
            continue
        before_ok = after_ok = 0
        for orig, https in zip(population, https_forms):
            pipe = probe_models["production (Decision Tree, shipped)"]
            f1 = extract_url_features(orig)
            f2 = extract_url_features(https)
            fr1 = pd.DataFrame([[f1[k] for k in FEATURES]], columns=FEATURES)
            fr2 = pd.DataFrame([[f2[k] for k in FEATURES]], columns=FEATURES)
            if int(pipe.predict(fr1)[0]) == project_label:
                before_ok += 1
            if int(pipe.predict(fr2)[0]) == project_label:
                after_ok += 1
        probe[shape] = {"n": n,
                        "correct_as_http": before_ok,
                        "correct_after_https_rewrite": after_ok,
                        "accuracy_as_http": round(before_ok / n, 6),
                        "accuracy_after_https_rewrite": round(after_ok / n, 6)}
    out["counterfactual_scheme_probe"] = {
        "label": "SYNTHETIC COUNTERFACTUAL PROBE - NOT GROUND TRUTH, NOT A BENCHMARK",
        "method": "identical host and path, only the scheme rewritten http->https; production pipeline unchanged",
        "purpose": "test whether HTTPS is the decisive learned feature rather than the apex/www shape itself",
        "results": probe}

    (EXP / "apex_representation_test.json").write_text(json.dumps(out, indent=2), encoding="utf-8")
    for k, v in results.items():
        print("%-34s n=%-5d %-10s %s" % (
            k, v["n"], v["class"],
            {m: a["accuracy"] for m, a in v["correct_vs_source_label"].items()}))
    print("\n-- counterfactual http->https rewrite (synthetic, production model) --")
    for k, v in probe.items():
        print("%-30s n=%-5d http_acc=%.4f  https_acc=%.4f" % (
            k, v["n"], v["accuracy_as_http"], v["accuracy_after_https_rewrite"]))
    print("\nwrote", EXP / "apex_representation_test.json")


if __name__ == "__main__":
    main()
