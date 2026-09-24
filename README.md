# PhishGuard

**AI-Based Phishing URL Detection Using Machine Learning** — Edunet Foundation Mini Project, Learning Block-1.

PhishGuard classifies a submitted URL as **Legitimate** or **Potential Phishing** using a locally trained scikit-learn model and features extracted only from the URL string. It never requests, opens, crawls, renders, or inspects the destination website. No paid service, external AI, or hosted inference is used.

## Problem and objectives

Phishing URLs can imitate familiar services while embedding unusual hosts, paths, or encoded text. This project demonstrates an auditable URL-only classifier, a reproducible dataset-to-model pipeline, and a local web interface that shows the prediction probability and extracted features. A probability is a model output, not a security guarantee.

## Scope and architecture

```text
PhiUSIIL CSV ──> URL cleaning/deduplication ──> one URL feature extractor
                                                   │
                     stratified / domain holdout ──┤
                                                   v
         sklearn preprocessing + LR / Decision Tree / Random Forest
                         │                         │
              joblib pipeline + reports       FastAPI JSON API
                                                     │
                                       React/Vite local interface
```

The training pipeline ignores the dataset's webpage-derived variables. The preprocessing pipeline learns numeric scaling and TLD encoding only from each training fold. Exact normalized URL duplicates are removed before splitting. Random evaluation is stratified 80/20 with seed 42; a second hostname-disjoint split is reported separately.

## Dataset

The project downloads the **PhiUSIIL Phishing URL Dataset** from the [UCI Machine Learning Repository, dataset 967](https://archive.ics.uci.edu/dataset/967/phiusiil+phishing+url+dataset). UCI describes 235,795 instances, 54 variables, and documents labels 1 = legitimate and 0 = phishing. The downloaded CSV, file hash, actual columns, missing values, duplicates, and labels are recorded in `results/dataset_audit.json` and `.md`. Raw feature columns from the dataset are never used as model inputs.

## URL normalization and features

`src/feature_schema.py` contains the single `normalize_url()` and authoritative `extract_url_features(url)` functions used by training and prediction. Host/scheme are lowercased; a missing scheme is interpreted as HTTP for parsing; default ports are removed; an empty path becomes `/`. Subdomains, paths, query parameters, fragments, and suspicious characters are preserved. Extraction performs no I/O.

Thirty-eight URL-only features are used: URLLength, DomainLength, TLDLength, TLD, NoOfSubDomain, HasObfuscation, NoOfObfuscatedChar, ObfuscationRatio, NoOfLettersInURL, LetterRatioInURL, NoOfDegitsInURL, DegitRatioInURL, NoOfEqualsInURL, NoOfQMarkInURL, NoOfAmpersandInURL, NoOfOtherSpecialCharsInURL, SpacialCharRatioInURL, IsDomainIP, IsHTTPS, num_dots, num_hyphens, num_underscores, num_slashes, num_at, num_hashes, num_percent, num_colons, num_semicolons, url_entropy, path_length, query_length, fragment_length, has_port, has_punycode, has_url_shortener, num_encoded_chars, max_repeat_ratio, num_suspicious_keywords.

No per-site reputation or external corpus statistics are needed. `CharContinuationRate`, `TLDLegitimateProb`, and `URLCharProb` are excluded because reliable implementation would require dataset-specific learned statistics or source features whose URL-only definitions are not established here. `URLSimilarityIndex` and all webpage fields are excluded.

The excluded source columns are `FILENAME`, `Domain`, `URLSimilarityIndex`, `CharContinuationRate`, `TLDLegitimateProb`, `URLCharProb`, `LineOfCode`, `LargestLineLength`, `HasTitle`, `Title`, `DomainTitleMatchScore`, `URLTitleMatchScore`, `HasFavicon`, `Robots`, `IsResponsive`, `NoOfURLRedirect`, `NoOfSelfRedirect`, `HasDescription`, `NoOfPopup`, `NoOfiFrame`, `HasExternalFormSubmit`, `HasSocialNet`, `HasSubmitButton`, `HasHiddenFields`, `HasPasswordField`, `Bank`, `Pay`, `Crypto`, `HasCopyrightInfo`, `NoOfImage`, `NoOfCSS`, `NoOfJS`, `NoOfSelfRef`, `NoOfEmptyRef`, and `NoOfExternalRef`. The latter group requires page content, page behavior, redirects, or extracted webpage resources. `Domain` and `FILENAME` are not used because host features are rebuilt from `URL` and the filename has no URL-only prediction value.

## Models and evaluation

The training run compares Logistic Regression, Decision Tree, and Random Forest using accuracy, phishing precision, phishing recall, phishing F1, training score, test score, train/test gap, false positives, and false negatives. The final classifier is selected by held-out phishing precision (phishing F1 and accuracy break ties) to reduce false alarms on legitimate URLs. Metrics and dataset-specific TLD/scheme/hostname analyses are generated in `results/`; see `results/model_metrics.json` and `results/robustness_report.md` for actual run values. A domain-aware evaluation holds out entire hostnames and reports its difference from the random split.

## Installation and run (Windows)

Install Python 3.11+ and Node.js 20+ first. From the project directory:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
Set-Location frontend
npm install
Set-Location ..
python -m src.train
```

Then use `run_windows.bat` to start the backend and frontend in separate windows. Or manually:

```powershell
# Terminal 1, from PhishGuard
python -m uvicorn backend.app:app --host 127.0.0.1 --port 8010

# Terminal 2, from PhishGuard\frontend
npm run dev
```

Open http://127.0.0.1:5173. The API is on http://127.0.0.1:8010.

To retrain, run `python -m src.train`. This reads only `data/raw/PhiUSIIL_Phishing_URL_Dataset.csv` and writes the production pipeline and evaluation artifacts. The expected first-run training duration depends on CPU and available memory.

## API

- `GET /` — project and URL-only scope.
- `GET /api/health` — model load status.
- `GET /api/model_info` — dataset, selected classifier, feature count and held-out metrics.
- `POST /api/predict` — accepts `{"url":"https://example.com/path"}` and returns the actual model label, class probability, model name, normalized URL, and all feature values.

Only HTTP and HTTPS schemes are accepted. Empty, malformed, control-character, and over-2,048-character inputs return validation errors. The API contains no URL-fetching client.

## Deployment

The frontend and API are deployed separately. GitHub Pages serves static files and does not execute Python or FastAPI, so URL predictions require a separately hosted API service. The checked-in model pipeline is used as-is at API startup; deployment does not retrain it. The dataset is excluded from Git and is not needed by the running service.

### Frontend: GitHub Pages

The Vite build uses `/phishguard-ai/` as its base path and the Actions workflow publishes only `frontend/dist` to the project site:

<https://maninani12.github.io/phishguard-ai/>

In the GitHub repository, open **Settings → Pages** and set **Build and deployment → Source** to **GitHub Actions**. The Pages workflow can build and deploy while the backend URL is not yet known. In that state, the site loads and clearly reports that the API is not connected; live URL analysis remains unavailable. After deploying FastAPI and obtaining its actual base URL, open **Settings → Secrets and variables → Actions → Variables**, create a repository variable named `VITE_API_BASE_URL`, and set it to that base URL without `/api`. This is public frontend configuration, not a secret. Rerun the Pages workflow or push a new commit on `main` so the production bundle includes the configured API URL.

For local development, copy `frontend/.env.example` to `frontend/.env.local`; its default points to `http://127.0.0.1:8010`. The frontend uses `VITE_API_BASE_URL` consistently for `/api/health`, `/api/model_info`, and `/api/predict`.

### Backend: FastAPI hosting service

`render.yaml` prepares a Render web service using the repository root, the existing model under `models/`, and the start command `uvicorn backend.app:app --host 0.0.0.0 --port $PORT`. To deploy, connect `maninani12/phishguard-ai` in Render, select **New → Blueprint**, and apply the `render.yaml` configuration on `main`. After Render finishes deploying, copy the service's actual HTTPS URL into the GitHub Actions repository variable `VITE_API_BASE_URL`, then rerun the Pages workflow or push a new commit to `main`.

The FastAPI CORS policy allows `https://maninani12.github.io` and the local Vite origins `http://localhost:5173` and `http://127.0.0.1:5173`. CORS origins contain no Pages path. The backend is not deployed merely by adding this configuration. Until a hosting service has been deployed and its actual URL has been added as the `VITE_API_BASE_URL` Actions repository variable, GitHub Pages has no live prediction API.

## Frontend and 3D UI

React + Vite + Tailwind CSS, Lucide React, Framer Motion, Three.js, React Three Fiber, and Drei. The shield visualization uses a low-detail shield, points, wireframe geometry, orbital rings, gentle movement, and pointer response. The interface includes a WebGL fallback, responsive layout, and reduced-motion styling. Analyzer loading reflects the real API call; model metrics are fetched dynamically.

## Testing

After training, run:

```powershell
pytest -q
Set-Location frontend
npm run build
```

The API tests cover homepage, model health and info, predictions, empty/malformed/oversized input, unsafe schemes, IP hosts, ports, query strings, and encoded text. The final validation also starts a fresh backend process and sends real HTTP requests.

## Limitations

PhishGuard analyzes URL-derived features only. It does not visit or inspect the submitted website. Predictions may contain false positives and false negatives. HTTPS, `.com`, and `.in` are classifier signals, not guarantees of legitimacy. Dataset labels and collection patterns can be stale or biased; the hostname-disjoint results make that limitation visible. A classification is not a substitute for browser protections or security review.

## Future scope

Evaluate temporal and cross-source datasets, calibrate probabilities on separate validation data, assess drift, and add model cards and explainability. Any future enrichment must preserve a clear consent and privacy boundary and must not silently fetch submitted URLs.

## References

- Prasad, A. & Chandra, S. (2024). *PhiUSIIL Phishing URL (Website) Dataset*. UCI Machine Learning Repository, dataset 967. https://doi.org/10.1016/j.cose.2023.103545.
- Scikit-learn documentation: https://scikit-learn.org/stable/.
- FastAPI documentation: https://fastapi.tiangolo.com/.
