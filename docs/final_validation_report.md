# Final validation report

**Date (UTC):** 2026-09-25
**Project:** PhishGuard AI — URL-only phishing URL classifier
**Workflow status:** complete through model selection, artifact verification, backend, frontend, security, and deployment gating. No production model replacement was performed, and no deployment was performed.

## 1. Datasets

| Dataset | Role | License status | Rows used |
|---|---|---|---:|
| UCI PhiUSIIL (ID 967) | **canonical, sole training source** | CLEAR FOR INTENDED USE (CC BY 4.0, any purpose with credit) | 235,795 raw / 234,894 clean |
| PhishTrap | apex diagnostic only | REQUIRES TERMS REVIEW (MIT card; Tranco CC BY-NC 4.0 upstream) | 19,948 measured |
| PhreshPhish | research-only audit | research-only wording | 0 (not used) |
| EdgePhish-5G | audited, not integrated | NOT CLEARLY COMPATIBLE (OpenPhish non-commercial) | 0 (not used) |
| PhishVN, PhishBD_2026, LegitPhish, URL-Phish, ISCX-URL2016, PhishStorm | not obtained | unavailable / unspecified | 0 (not used) |

Canonical SHA-256 `a236549cd369cd80bd478ff8e1779cbf44c58d5c3f79f7a51a1adbed7d06d1c6` — unchanged.

## 2. Representation: the central unresolved defect

The canonical legitimate class is fully degenerate: **134,850 of 134,850** rows are HTTPS + `www` + root path, with zero queries, zero apex-root, zero apex-with-path, and zero non-www subdomains. Phishing covers all of those shapes.

Measured consequence (`docs/apex_representation_test.md`, diagnostic only):

- **0 of 4,163 legitimate URLs** classified correctly.
- Decomposed by a synthetic scheme-rewrite probe into **two independent biases**:
  - *scheme*: `www` goes 0% → 97.3% correct when only `http` is rewritten to `https`;
  - *apex*: apex-root reaches only 7.3% even after that rewrite, versus 81% for subdomains.

Fixing the scheme alone would not fix the apex problem. The blocker is the absence
of license-clear training data with those shapes, documented in
`docs/dataset_research.md` as a structural gap in the public data ecosystem.

## 3. Model metrics (canonical only)

Primary, stratified URL-level 80/20, seed 42:

| Model | Accuracy | Precision | Recall | F1 | FP | FN |
|---|---:|---:|---:|---:|---:|---:|
| Logistic Regression | 0.972094 | 0.986927 | 0.947024 | 0.966564 | 251 | 1060 |
| Decision Tree | 0.979948 | 0.984155 | 0.968514 | 0.976272 | 312 | 630 |
| Random Forest | 0.978160 | 0.984879 | 0.963516 | 0.974080 | 296 | 730 |

Domain-aware, registrable-domain grouped, PSL-aware (overlap **0**, 0.00%):

| Model | Accuracy | Precision | Recall | F1 | FP | FN |
|---|---:|---:|---:|---:|---:|---:|
| Logistic Regression | 0.973117 | 0.986987 | 0.949811 | 0.968042 | 255 | 1022 |
| Decision Tree | 0.979201 | 0.983819 | 0.967392 | 0.975536 | 324 | 664 |
| Random Forest | 0.979054 | 0.985316 | 0.965526 | 0.975321 | 293 | 702 |

## 4. Cost scenarios and model selection

Decision Tree has the lowest expected cost in all four documented scenarios on
both splits. Sensitivity is reported, not hidden: Logistic Regression becomes
cost-preferred above an FP:FN cost ratio of about 7.05 (primary) / 5.19
(domain-aware), and Random Forest above about 1.23 on the domain-aware split.

**Model selection is conditional on the chosen operational cost ratio.** No
owner-approved business cost policy exists, so no unconditional claim is made.

**Selected: Decision Tree — no artifact replacement performed.** The shipped model
is already a `DecisionTreeClassifier(min_samples_leaf=3, random_state=42)` trained
on the full cleaned corpus, so replacing it with a primary-split experimental
pipeline would be a downgrade in training data. The artifact was verified instead
and left byte-identical.

**Canonical model status statement:** Decision Tree is the currently shipped model
and remains the lowest-cost candidate under the analyzed technical scenarios,
subject to the operational FP/FN cost ratio. It is not a universally best model;
Logistic Regression becomes cost-preferred above an FP:FN ratio of about 7.05
(primary) / 5.19 (domain-aware), and Random Forest above about 1.23 on the
domain-aware split.

## 5. Error analysis

- **312 false positives** are structurally identical to correct legitimate URLs
  (100% HTTPS + `www` + root) and differ mainly by length: 35.2 vs 28.2 characters,
  domains 26.2 vs 19.2. They are flagged for looking long, not for looking risky.
- **630 false negatives** are 100% HTTPS, 98.7% root path, and carry no suspicious
  signal at all (0% IP, 0% punycode, 0% encoding, 0% shortener, 0.3% query), and
  concentrate on apex (36.4%) and subdomain (44.9%) hosts that the corpus only ever
  shows as phishing.

No domain was patched, whitelisted, or special-cased.

## 6. Artifact verification

| Check | Result |
|---|---|
| Pipeline steps | `['preprocess', 'model']` |
| Classifier | `DecisionTreeClassifier`, `min_samples_leaf=3`, `random_state=42` |
| Metadata matches artifact | yes |
| Feature count / order vs metadata and `feature_schema.json` | 38, identical |
| Transformed dimension | 545 |
| Classes | `[0, 1]` |
| Verification failures | none |

Recorded metadata gaps (not artifact defects): `model_metadata.json` has no
`dataset_sources` block, and its `domain_aware_metrics` has no `grouping` key —
those figures are **LEGACY HOSTNAME-GROUPED RESULTS** and are not comparable with
the registrable-domain numbers above. A future training run writes both fields.

## 7. Backend

Live on `127.0.0.1:8013`. `GET /` ready; `GET /api/health` `model_loaded=true`;
`GET /api/model_info` Decision Tree / 38 features; `POST /api/predict` verified
across 11 cases:

| Input | Result |
|---|---|
| `https://example.com/` (legit apex) | Potential Phishing, conf 1.0 |
| `http://example.com/` (legit apex, http) | Potential Phishing, conf 1.0 |
| `https://www.example.com/` | Legitimate, conf 0.9970 |
| `https://www.example.com/account/settings` | Potential Phishing |
| `https://www.example.com/search?q=test&page=2` | Potential Phishing |
| `http://203.0.113.10/` | Potential Phishing |
| `https://www.example.com:8443/login?next=%2Fadmin` | Potential Phishing |
| `not a url` | 422 malformed |
| empty | 422 empty |
| `ftp://example.com/x` | 422 unsupported scheme |
| >2048 chars | 422 too long |

The three legitimate apex/path/query cases reproduce the representation defect
through the shipped API. The API never fetches a submitted URL.

## 8. Frontend

`npm run build` succeeds (Vite 6.4.3; main 25.6 kB, motion 119.6 kB, three 960.6 kB
/ 264.8 kB gzip — chunk-size advisory only). The production bundle contains the
`/api/health`, `/api/model_info`, `/api/predict` calls and the "API not connected"
path, so prediction, loading, error, unavailable-API, confidence and result
rendering are all present. No redesign.

Fixed this phase: `frontend/.env.example` pointed at port 8010 while the code's dev
default and the documented backend port are 8013. The example now matches the code
and documents the start command.

## 9. Security

- No `requests`, `urllib.request`, `urlopen`, `httpx` client, Selenium, Playwright,
  `subprocess`, `os.system`, `eval`, or `exec` anywhere in application source. The
  only `fetch()` is the frontend calling the configured PhishGuard API; the
  submitted host is sent as JSON to that local endpoint and is never requested.
- No SSRF surface: the backend parses URL text only.
- CORS restricted to `https://maninani12.github.io`, `http://localhost:5173`,
  `http://127.0.0.1:5173`; methods GET/POST; headers Content-Type only.
- Input validation: scheme allow-list, 2048-char cap, control-character rejection,
  normalizer-based malformed rejection, all returning 422.
- No secrets in tracked files. The only tracked env file is `frontend/.env.example`,
  which contains a localhost URL and no credential. `VITE_API_BASE_URL` is public
  build-time configuration by design.

## 10. Tests

`python -m pytest -q` → **19 passed** (1 third-party Starlette deprecation warning).
`git diff --check` → clean apart from LF/CRLF advisories. Frontend build passes.
Backend smoke tests pass. No test was skipped or disabled to obtain a pass.

## 11. Deployment

**DEPLOYMENT NOT PERFORMED.** Two independent reasons:

1. **Dataset terms.** The only sources that supply legitimate apex-root coverage
   are unusable for a public deployment: PhreshPhish is research-only by its own
   card, EdgePhish-5G inherits OpenPhish's non-commercial terms, PhishTrap inherits
   Cloudflare Radar's CC BY-NC 4.0 through Tranco, and PhishStorm's license is
   unspecified. No apex-fixing model may be deployed.
2. **Project readiness.** Independently of licensing, the shipped model misclassifies
   legitimate apex, subdomain and HTTP URLs at a 0-of-4,163 rate in the available
   diagnostic. Publishing it as a public safety tool would be misleading.

The canonical-only model is license-clear (CC BY 4.0, attribution required) and
technically deployable, so licensing alone would not block it. It is not
recommended for public release on quality grounds, and no deployment target or
credentials were provided in this session, so no external deployment action was
taken.

## 12. Production readiness

**NOT READY.** The blocker is data, not code:

- no license-clear dataset supplies legitimate non-`www` apex, subdomain, HTTP or
  query URLs, so the model cannot be retrained into a correct state;
- the defect is measured, not suspected (0/4,163 legitimate diagnostic URLs);
- model selection is conditional on an owner-set cost ratio that does not exist yet.

Engineering status is otherwise complete and verified: pipeline, PSL evaluation,
cost analysis, error analysis, artifact verification, backend, frontend, security
and tests all pass.

## 13. Artifact hashes

| Artifact | SHA-256 |
|---|---|
| `models/phishguard_pipeline.joblib` | `882b1f5de934cb0a190f0f9461ea744b1e96cb42e9a3f539a60279662d724df1` |
| `models/model_metadata.json` | `c1f239c40b57aac009092e6d77cfaecef3207f4d7c852601118f20a000672d2c` |
| `data/raw/PhiUSIIL_Phishing_URL_Dataset.csv` | `a236549cd369cd80bd478ff8e1779cbf44c58d5c3f79f7a51a1adbed7d06d1c6` |

All three are unchanged from the start of this phase.
