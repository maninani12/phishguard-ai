# Controlled baseline model experiment (canonical only)

**Date (UTC):** 2026-09-25
**Script:** `experiments/baseline_experiment.py`
**Machine-readable results:** `models/experiments/baseline_experiment_metrics.json`
**Status:** EXPERIMENTAL. The production model was **not** replaced. The apex representation problem is **not** solved.

## Scope and guards (verified inside the run)

- Training data: `data/raw/PhiUSIIL_Phishing_URL_Dataset.csv` **only** (235,795 raw / 234,894 cleaned; unchanged).
- Candidate datasets read, integrated, or sampled: **none**. PhreshPhish, EdgePhish-5G, PhishVN, PhishBD, LegitPhish, URL-Phish, ISCX-URL2016 and PhishStorm are untouched by this script.
- Production artifacts preserved, enforced by assertion in the script:
  - `models/phishguard_pipeline.joblib` SHA-256 `882b1f5d…d724df1` before **and** after.
  - `models/model_metadata.json` SHA-256 `c1f239c4…672d2c` before **and** after.
- All experimental output is written to `models/experiments/` only. `results/`, `docs/`, `data/`, `frontend/`, `backend/` are not written by the script.
- Reused unchanged from the project: `normalize_url`, `clean_url_labels`, the 38-feature schema, `make_pipeline`, `build_features`, `GroupShuffleSplit`, `random_state=42`.

## PRIMARY EVALUATION — STRATIFIED URL-LEVEL 80/20

187,915 train / 46,979 test rows, `random_state=42`, stratified on the label.

| Model | Accuracy | Precision | Recall | F1 | FP | FN |
|---|---:|---:|---:|---:|---:|---:|
| Logistic Regression | 0.972094 | 0.986927 | 0.947024 | 0.966564 | 251 | 1060 |
| Decision Tree | 0.979948 | 0.984155 | 0.968514 | 0.976272 | 312 | 630 |
| Random Forest | 0.978160 | 0.984879 | 0.963516 | 0.974080 | 296 | 730 |

Confusion matrices are stored per model in the run JSON. These values reproduce the previously verified canonical metrics exactly, which confirms a clean baseline after the PSL integration (the integration changed only the domain-aware path).

## DOMAIN-AWARE EVALUATION — REGISTRABLE-DOMAIN GROUPED, PSL-AWARE

`GroupShuffleSplit`, `test_size=0.2`, `random_state=42`, groups from `src/domain_split.py` (`tldextract`, PSL ICANN+PRIVATE included). Each model was refit on this split's training side, mirroring `src/train.py`.

| Property | Value |
|---|---:|
| Train rows | 187,391 |
| Test rows | 47,503 |
| Train registrable-domain groups | 157,840 |
| Test registrable-domain groups | 39,460 |
| **Registrable-domain overlap** | **0** |
| **Overlap percentage** | **0.00%** |

Overlap is asserted to be zero; a non-zero overlap aborts the run. It did not abort.

| Model | Accuracy | Precision | Recall | F1 | FP | FN |
|---|---:|---:|---:|---:|---:|---:|
| Logistic Regression | 0.973117 | 0.986987 | 0.949811 | 0.968042 | 255 | 1022 |
| Decision Tree | 0.979201 | 0.983819 | 0.967392 | 0.975536 | 324 | 664 |
| Random Forest | 0.979054 | 0.985316 | 0.965526 | 0.975321 | 293 | 702 |

## Combined comparison (no ranking, no winner)

| Model | Primary Acc | Primary Prec | Primary Rec | Primary F1 | Primary FP | Primary FN | Domain Acc | Domain Prec | Domain Rec | Domain F1 | Domain FP | Domain FN |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| Logistic Regression | 0.972094 | 0.986927 | 0.947024 | 0.966564 | 251 | 1060 | 0.973117 | 0.986987 | 0.949811 | 0.968042 | 255 | 1022 |
| Decision Tree | 0.979948 | 0.984155 | 0.968514 | 0.976272 | 312 | 630 | 0.979201 | 0.983819 | 0.967392 | 0.975536 | 324 | 664 |
| Random Forest | 0.978160 | 0.984879 | 0.963516 | 0.974080 | 296 | 730 | 0.979054 | 0.985316 | 0.965526 | 0.975321 | 293 | 702 |

Factual tradeoffs, stated without ranking:

- Logistic Regression has the fewest false positives on both splits (251 / 255) and the highest precision, but the most false negatives (1,060 / 1,022) and the lowest recall.
- Decision Tree has the fewest false negatives (630 / 664) and the highest recall, F1 and accuracy on both splits, but the most false positives (312 / 324).
- Random Forest falls between the other two on every error count on both splits.
- Domain-aware figures sit within roughly 0.0007–0.002 of the primary figures for all three models. This split is still drawn from the same canonical collection, so the small gap indicates the hostname/registrable-domain distinction was not the dominant error source here; it does **not** demonstrate out-of-distribution generalization.
- A decision between these models requires an explicit false-alarm versus missed-phish cost policy, which this experiment does not assume and does not resolve.

## Representation audit by class (measured, canonical only)

| Measure | Phishing (label 0) | Legitimate (label 1) |
|---|---:|---:|
| Rows | 100,945 | 134,850 |
| Valid URLs | 100,945 | 134,850 |
| HTTP | 51,749 | 0 |
| HTTPS | 49,196 | 134,850 |
| `www` host | 41,744 | 134,850 |
| Apex-root (PSL, non-www) | 21,301 | **0** |
| Apex with path | 14,521 | **0** |
| Non-www subdomain | 23,379 | **0** |
| Root path | 72,456 | 134,850 |
| Query present | 6,079 | 0 |
| IP host | present | 0 |
| Percent-encoded | present | 0 |
| Explicit port | present | 0 |
| Punycode | present | 0 |

The legitimate class is degenerate: every row is HTTPS, `www`, root-path, no query. Every phishing shape is present; no legitimate counterpart exists.

## DIAGNOSTIC / ROBUSTNESS TEST — not an official benchmark

Ground truth is the **canonical source label only** (dataset labels, not current-safety verdicts). No candidate dataset contributed rows, and no domain is hard-coded — categories are selected by structural predicate over the canonical file.

Eleven canonical rows were scored by the frozen production pipeline and by the three experimental primary pipelines. All eleven agree with their canonical source label under the production model (11/11).

| Category | n | Production vs source label | Experimental models |
|---|---:|---|---|
| Legitimate `www` | 3 | 3/3 | LR, DT, RF all 3/3 |
| Suspicious IP URL | 1 | 1/1 | all 1/1 |
| Suspicious login-pattern URL | 1 | 1/1 | all 1/1 |
| Suspicious verification-pattern URL | 1 | 1/1 | all 1/1 |
| Suspicious percent-encoded URL | 1 | 1/1 | all 1/1 |
| Suspicious explicit-port URL | 1 | 1/1 | all 1/1 |
| Suspicious punycode URL | 1 | 1/1 | all 1/1 |
| Suspicious apex-root URL | 2 | 2/2 | DT 2/2; LR 1/2; RF 1/2 |

The single cross-model difference is on `https://service-mitld.firebaseapp.com/` (source label 0): Decision Tree predicts 0, Logistic Regression and Random Forest predict 1. On a two-item subgroup this is anecdotal and supports no selection conclusion.

### Diagnostic categories that could not be populated

| Requested category | Available in canonical | Measured rows | Reason |
|---|---|---:|---|
| Legitimate apex-root URL | No | 0 | All legitimate rows are `www`; no non-approved dataset may be used to supply them |
| Legitimate apex with path | No | 0 | Zero legitimate apex rows of any path shape |
| Legitimate non-www subdomain | No | 0 | Zero legitimate non-www subdomain rows |

These three categories are reported as **unavailable**, not as passes. The apex representation gap is therefore reproduced as a measured absence of training signal; this experiment does not fix it and makes no claim that it is fixed.

## Artifacts

- `models/experiments/baseline_experiment_metrics.json` — splits, primary and domain metrics, confusion matrices, representation audit, diagnostic, production-artifact hashes.
- `models/experiments/logistic_regression_primary.joblib`
- `models/experiments/decision_tree_primary.joblib`
- `models/experiments/random_forest_primary.joblib`

These are experimental artifacts and are not referenced by the backend.
