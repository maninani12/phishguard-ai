# PhishGuard AI

**Phishing URL Detection Research & Demonstration System** — an AI agent that inspects the *structure* of a URL with a locally trained model, then explains what it found and what you should do next.

> **Research / demonstration notice.** PhishGuard analyzes URL-level characteristics only. The submitted website is never visited, fetched or rendered. The model is trained on the UCI PhiUSIIL corpus, whose legitimate class contains only HTTPS, `www`-prefixed, root-path URLs. Legitimate apex, non-`www` subdomain, HTTP and query-string URLs are **absent from the training data**, so verdicts on those shapes are unreliable and tend to over-report phishing. A prediction is a statistical classification, not a guarantee of safety or maliciousness.

---

## 1. Problem

Phishing URLs imitate brands people already trust. The link looks familiar, the page loads, and the credential form appears. Conventional defenses check reputation lists, which are slow to update and easy to evade, or they load the page in a sandbox, which is expensive and can itself be dangerous.

There is a narrower question that is cheap, fast and safe to answer: **does this string of text look like the phishing URLs we have seen before?**

## 2. Solution

PhishGuard answers that question and nothing more. You paste a URL. A deterministic agent:

1. validates the URL string (scheme, length, syntax),
2. scores it with a scikit-learn model trained on 38 URL-derived features,
3. converts the measured features into a plain-language explanation,
4. returns concrete, safety-first guidance.

The site behind the URL is never contacted. There is no crawler, no sandbox, no headless browser, no reputation feed, and no external AI service.

## 3. Why it matters

- **Zero exposure.** The submitted host is never requested, so a PhishGuard user cannot be silently redirected, tracked, or attacked by the page they are inspecting.
- **Explainable.** Every sentence in the assessment traces back to a feature that was computed from the URL text.
- **Fast and offline.** Inference is a single local model call. No API key, no cloud AI, no rate limit, no cost.
- **Honest about its limits.** The system reports when a URL's shape is unrepresented in its training data instead of pretending confidence it does not have.

## 4. Architecture

```text
        Browser (React + Vite, static, GitHub Pages)
                          |
                          |  JSON over HTTPS  (only network call in the app)
                          v
        FastAPI  /api/agent/analyze   /api/predict   /api/model_info   /api/health
                          |
                          v
        PhishGuard Agent  (deterministic, offline, no LLM)
        validate -> predict -> explain -> advise
                          |
                          v
        src.feature_schema  ->  38 URL-only features
                          |
                          v
        sklearn Pipeline  (impute + scale + one-hot TLD  ->  DecisionTreeClassifier)
                          |
                          v
        Read-only scoring. No socket is ever opened to the submitted host.
```

## 5. Agent workflow

| Stage | What happens | Guarantee |
|---|---|---|
| **Validate** | Trim, reject empty, enforce the 2048-character limit, reject control characters, allow only `http`/`https`, parse with the project normalizer | Bad input returns HTTP 422 before any scoring |
| **Predict** | Extract 38 features, run the fitted pipeline, read the predicted class score | Same pipeline as the raw endpoint; model is loaded once per process |
| **Explain** | Emit observations only for features that are actually present | No invented reasons, no claim about the website |
| **Advise** | Return a primary recommendation plus safe-handling advisories | Never says a site is "safe" or "malicious" |
| **Flag gaps** | Report URL shapes that are absent from the legitimate training class | Surfaces the dataset's blind spot instead of hiding it |

The agent is a plain Python module (`backend/agent/`). It contains **no** external LLM client, no API key, no model server, and no network code.

## 6. ML model

| Property | Value |
|---|---|
| Classifier | `DecisionTreeClassifier(min_samples_leaf=3, random_state=42)` |
| Training data | UCI PhiUSIIL Phishing URL Dataset (ID 967), 234,894 cleaned records |
| Features | 38 URL-only features, 545 transformed dimensions |
| Classes | `0 = Potential Phishing`, `1 = Legitimate` |
| Primary split | Stratified URL-level 80/20, `random_state=42` |
| Domain-aware split | Registrable-domain grouped (PSL-aware, `tldextract`), overlap 0 |
| Primary metrics | accuracy 0.9799, precision 0.9842, recall 0.9685, F1 0.9763 |
| Artifact | `models/phishguard_pipeline.joblib`, SHA-256 `882b1f5d…d724df1` |

Logistic Regression and Random Forest were trained and compared under a documented error-cost analysis. **Model selection is conditional on the operational false-positive / false-negative cost ratio**; see `docs/model_selection_policy.md` and `docs/model_selection_report.md`. Decision Tree is the currently shipped model and is the lowest-cost candidate under the analyzed scenarios — it is not a universally best model.

## 7. Feature schema

`URLLength, DomainLength, TLDLength, TLD, NoOfSubDomain, HasObfuscation, NoOfObfuscatedChar, ObfuscationRatio, NoOfLettersInURL, LetterRatioInURL, NoOfDegitsInURL, DegitRatioInURL, NoOfEqualsInURL, NoOfQMarkInURL, NoOfAmpersandInURL, NoOfOtherSpecialCharsInURL, SpacialCharRatioInURL, IsDomainIP, IsHTTPS, num_dots, num_hyphens, num_underscores, num_slashes, num_at, num_hashes, num_percent, num_colons, num_semicolons, url_entropy, path_length, query_length, fragment_length, has_port, has_punycode, has_url_shortener, num_encoded_chars, max_repeat_ratio, num_suspicious_keywords`

Extraction is defined once in `src/feature_schema.py` and is identical at training and inference. It performs no I/O. Webpage-derived columns in the source dataset are never used.

## 8. API endpoints

Base URL: local `http://127.0.0.1:8013`, or your deployed Render URL.

| Method | Path | Purpose |
|---|---|---|
| `GET` | `/` | Service identity and endpoint index |
| `GET` | `/api/health` | Model load status (Render health check) |
| `GET` | `/api/model_info` | Dataset, classifier, feature list, held-out metrics |
| `POST` | `/api/predict` | Raw model prediction plus all 38 feature values |
| `POST` | `/api/agent/analyze` | **Agent assessment**: verdict, score, risk band, explanation, signals, gaps, recommendation |

`POST /api/agent/analyze` request:

```json
{ "url": "https://example.com/login" }
```

`POST /api/agent/analyze` response (abridged):

```json
{
  "url": "https://example.com/login",
  "normalized_url": "https://example.com/login",
  "prediction": "Potential Phishing",
  "label": 0,
  "confidence": 0.997,
  "confidence_semantics": "Classifier score for the class it predicted ... not a calibrated probability ...",
  "risk_level": "high",
  "explanation": ["The model classified this URL as Potential Phishing ...", "..."],
  "signals": [{ "code": "suspicious_keywords", "label": "Phishing-related keywords", "value": 1, "observation": "..." }],
  "training_distribution_gaps": ["A bare apex host with no www prefix"],
  "recommendation": "Do not enter passwords, card details, codes or other personal information ...",
  "advisories": ["..."],
  "disclaimer": "PhishGuard analyzes URL-level characteristics only ...",
  "research_notice": "Research / demonstration system ...",
  "website_visited": false,
  "model": { "name": "Decision Tree", "feature_count": 38, "label_mapping": {"1": "Legitimate", "0": "Potential Phishing"}, "trained_on": "..." },
  "agent": "phishguard-agent/1.0"
}
```

`confidence` is the classifier's score for the class it predicted. It is **not** a calibrated probability that a URL is malicious.

Validation rules (identical for both POST endpoints): non-empty, at most 2048 characters, no control characters, `http`/`https` only, must parse. Violations return HTTP 422.

## 9. Security model

- The submitted URL is **never** requested. There is no HTTP client, socket, DNS resolution, redirect follower, HTML downloader, JavaScript runtime or browser automation in the request path. This is enforced by tests that parse the request-path source and fail on any network or code-execution import.
- The only outbound request in the entire application is the browser calling the configured PhishGuard API.
- CORS is restricted to `https://maninani12.github.io`, `http://localhost:5173`, `http://127.0.0.1:5173`; methods `GET`/`POST`; header `Content-Type`.
- No secrets, API keys or credentials are committed. `VITE_API_BASE_URL` is public build-time configuration.
- The model artifact is read-only at runtime; nothing is retrained on start-up.

## 10. Local setup

Requires Python 3.11+ and Node.js 20+.

```powershell
cd C:\Users\manik\OneDrive\Desktop\PhishGuard

python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt

Set-Location frontend
npm install
Set-Location ..

# Terminal 1 - backend
python -m uvicorn backend.app:app --host 127.0.0.1 --port 8013

# Terminal 2 - frontend
Set-Location frontend
npm run dev
```

Open <http://127.0.0.1:5173>. The dev frontend defaults to `http://127.0.0.1:8013`; override it by copying `frontend/.env.example` to `frontend/.env.local`.

Run the tests:

```powershell
python -m pytest -q
```

Retraining is **not** required to run the app, and is not part of deployment. If you ever retrain deliberately:

```powershell
python -m src.train
```

## 11. Deployment

Two independent pieces. GitHub Pages cannot execute Python, so the API must be hosted separately.

### Backend on Render

`render.yaml` is already configured: Python web service, `pip install -r requirements.txt`,
`uvicorn backend.app:app --host 0.0.0.0 --port $PORT`, health check `/api/health`. The model
artifact is committed, so the service starts from the verified pipeline and **no secrets are
required**.

```powershell
git push                       # after you have committed and reviewed
```

Then in the Render dashboard: **New → Blueprint** → select this repository → apply. Copy the
resulting service URL, for example `https://phishguard-api.onrender.com`.

Verify the deployment:

```powershell
curl https://phishguard-api.onrender.com/api/health
curl -X POST https://phishguard-api.onrender.com/api/agent/analyze `
     -H "Content-Type: application/json" `
     -d '{\"url\":\"https://www.example.com/\"}'
```

### Frontend on GitHub Pages

Set one repository variable — **Settings → Secrets and variables → Actions → Variables**:

| Name | Value |
|---|---|
| `VITE_API_BASE_URL` | `https://phishguard-api.onrender.com` (no trailing `/api`, no trailing slash) |

`.github/workflows/deploy-pages.yml` builds `frontend/dist` on every push to `main` and passes
that variable into the Vite build. The bundle uses the base path `/phishguard-ai/`.

In **Settings → Pages**, set **Source** to **GitHub Actions**.

Verify:

```powershell
# asset paths must sit under the Pages base path
Select-String -Path frontend\dist\index.html -Pattern '/phishguard-ai/'
```

### Deployment safety check

The production bundle refuses to use a loopback API base. If `VITE_API_BASE_URL` is missing or
points at `localhost`/`127.0.0.1` in a production build, the app reports **API NOT CONFIGURED**
rather than silently calling a local machine. This is enforced by
`tests/test_frontend_deployment.py`.

## 12. Known limitations

This is a research and demonstration system. The limitations are measured, not speculative.

- **The training data is structurally biased.** All 134,850 legitimate rows are HTTPS + `www` + root path with no query. There are **zero** legitimate apex-root, apex-with-path, non-`www` subdomain, or HTTP examples.
- **Measured consequence:** a diagnostic run over 4,163 legitimate URLs from a separate source classified **0** of them correctly. The failure decomposes into two independent biases — a scheme bias (HTTPS is treated as near-decisive evidence of legitimacy) and an apex bias (a bare apex host stays wrong even over HTTPS).
- **The domain-aware metrics do not measure this.** The registrable-domain split is drawn from the same corpus, so its accuracy (0.9792) reflects the corpus's own distribution and materially overstates real-world performance.
- **No licensed dataset has been cleared** that supplies the missing shapes. See `docs/dataset_research.md` for the candidates evaluated and why each was rejected.
- **Source labels are not ground truth.** They are dataset labels, not present-day safety verdicts.
- **A classification is not a verdict.** False positives and false negatives both occur.

## 13. Dataset and license

| Item | Detail |
|---|---|
| Training dataset | UCI Machine Learning Repository, dataset 967, *PhiUSIIL Phishing URL (Website)* |
| Authors | A. Prasad, S. Chandra (2024) |
| License | **CC BY 4.0** — reuse and adaptation for any purpose with attribution |
| SHA-256 | `a236549cd369cd80bd478ff8e1779cbf44c58d5c3f79f7a51a1adbed7d06d1c6` |

Datasets evaluated and **not** used for training: PhreshPhish (research-only wording),
EdgePhish-5G (upstream OpenPhish non-commercial terms), PhishVN v4, PhishBD 2026, LegitPhish,
URL-Phish, ISCX-URL2016, PhishStorm, and PhishTrap (diagnostic measurement only; license
unresolved). Rationale in `docs/dataset_research.md`.

## 14. Repository layout

```text
backend/
  app.py              FastAPI routes
  prediction.py       model loading, URL validation, inference (shared core)
  agent/
    agent.py          agent orchestration
    explanation.py    deterministic explanation + safety guidance
    schemas.py        Pydantic response contract
src/
  feature_schema.py   normalization + the 38 features (single source of truth)
  domain_split.py     PSL-aware registrable-domain grouping
  data_loader.py      multi-dataset loading and cleaning
  train.py            training entry point
models/               verified pipeline, metadata, feature schema
frontend/             React + Vite single-page app
tests/                97 tests: agent, API, security, data limitations, deployment config
docs/                 evaluation, error analysis, dataset research, demo material
```

## 15. References

- Prasad, A. & Chandra, S. (2024). *PhiUSIIL Phishing URL (Website) Dataset*. UCI Machine Learning Repository. <https://archive.ics.uci.edu/dataset/967/phiusiil+phishing+url+dataset>
- Prasad, A. & Chandra, S. (2024). PhiUSIIL: A diverse security profile empowered phishing URL detection framework. *Computers & Security*. <https://doi.org/10.1016/j.cose.2023.103545>
- Project documentation: `docs/model_selection_report.md`, `docs/apex_representation_test.md`, `docs/error_analysis.md`, `docs/dataset_research.md`, `docs/hackathon_demo.md`
