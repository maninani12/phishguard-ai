# Final validation report

Generated from PhishGuard's final training and fresh-process verification run.

## Dataset and model

- Source: UCI PhiUSIIL Phishing URL Dataset (ID 967).
- Records: 235,795 raw; 234,894 after cleaning.
- Clean labels: 134,849 legitimate (1); 100,045 phishing (0).
- Duplicate normalized URLs removed: 899; conflicting-label URL rows removed: 2.
- Selected model: Logistic Regression, highest phishing precision on the stratified held-out set.

| Model | Accuracy | Phishing precision | Phishing recall | Phishing F1 | False positives | False negatives |
|---|---:|---:|---:|---:|---:|---:|
| Logistic Regression | 97.21% | 98.69% | 94.70% | 96.66% | 251 | 1,060 |
| Decision Tree | 97.99% | 98.42% | 96.85% | 97.63% | 312 | 630 |
| Random Forest | 97.82% | 98.49% | 96.35% | 97.41% | 296 | 730 |

Random stratified confusion matrix, actual rows/predicted columns in order phishing 0, legitimate 1: `[[18949,1060],[251,26719]]`.
Random split hostname overlap: 1,972 hostnames. Domain-aware test: 47,437 rows, 0 hostname overlap, accuracy 97.19%, phishing precision 98.76%, recall 94.67%, F1 96.67%.

## Fresh backend and frontend checks

- Backend was restarted as a new Uvicorn process on port 8010; `/api/health` reported healthy and loaded Logistic Regression. `/api/model_info` returned live values.
- Frontend production build succeeded. The Vite development server also started in a fresh process and connected to the API; the page displayed model metrics, a URL prediction, and extracted features.
- Browser prediction for `https://google.com` displayed **Legitimate**, 97.2% model confidence, and 38 actual extracted features. The browser never navigated to the submitted URL; only the local API received it.
- Invalid URL was rejected by the API and surfaced as a readable validation message in the frontend.
- Automated API suite: 3 passed. It covers homepage, health, model information, URL prediction, empty/malformed/overlong/unsafe inputs, IP URL, port, query and encoded characters.
- The frontend production build completed successfully. Its Three.js vendor chunk is about 961 KB minified (265 KB gzip).

## Actual prediction checks

| Input type | URL | Model output | Confidence |
|---|---|---|---:|
| requested | `https://google.com` | Legitimate (label 1) | 97.2% |
| requested | `https://youtube.com` | Legitimate (label 1) | 96.1% |
| requested | `https://chatgpt.com` | Legitimate (label 1) | 95.8% |
| requested | `https://github.com` | Legitimate (label 1) | 95.9% |
| dot_in_example | `https://example.in` | Legitimate (label 1) | 93.4% |
| held_out_legitimate | `https://www.mpg-av.de/` | Legitimate (label 1) | 99.5% |
| held_out_phishing | `https://springdalemarket.com/` | Legitimate (label 1) | 76.5% |
| ip_url | `http://203.0.113.10/` | Potential Phishing (label 0) | 100.0% |
| port_query_encoded_url | `https://example.com:8443/login?next=%2Faccount&token=%2525` | Potential Phishing (label 0) | 100.0% |
| suspicious_url | `http://198.51.100.27:8080/secure-account/verify/login?continue=%2Fwallet%3Fref%3D%40` | Potential Phishing (label 0) | 100.0% |

The four requested brand-like URLs and `https://example.in` were classified as legitimate without per-domain rules. The held-out legitimate sample was correct. The held-out phishing sample `https://springdalemarket.com/` was misclassified as legitimate; this is one observed false negative and is consistent with the measured recall tradeoff. IP, custom-port/query/encoded, and suspicious examples were classified as potential phishing in these spot checks. These individual predictions do not establish real-world safety.

## Dataset-bias findings

- Scheme counts by class (0 phishing, 1 legitimate): `{"0": {"http": 51502, "https": 48543}, "1": {"http": 0, "https": 134849}}`. All 134,849 legitimate records use HTTPS; phishing records include 51,502 HTTP and 48,543 HTTPS URLs.
- www/non-www counts by class: `{"0": {"false": 58435, "true": 41610}, "1": {"false": 0, "true": 134849}}`. All 134,849 legitimate records have a `www.` hostname. The held-out set has 6,599 non-`www` root URLs and all are labeled phishing in this dataset.
- `.com` and `.in` are present in both classes. Per-TLD counts, URL length/path/query distributions, and held-out subgroup results are in `results/robustness_report.json`.
- Logistic Regression reduced false positives and classified short bare HTTPS hosts more permissively than the tree models, without a whitelist or HTTPS/TLD override. Missing legitimate non-`www` training examples remain a dataset limitation.

## Security audit

- No application code calls `requests.get/post`, `urllib.request`, Selenium, Playwright, subprocess, `os.system`, `eval`, or `exec`.
- `httpx` appears only as a test dependency used by FastAPI/Starlette TestClient for local in-process tests; no submitted URL is sent through it.
- The frontend calls only the configured local PhishGuard API. `normalize_url` and `extract_url_features` parse URL text; no prediction code requests or visits submitted hosts.
- No `google.com`, `youtube.com`, `chatgpt.com`, or `github.com` hostname special cases exist in prediction source. HTTPS and TLD are model features; no deterministic safe rule is present.

## Run commands

From the project directory, install dependencies with `run_windows.bat` option 1, train with option 2, then start both apps with option 5. Open `http://127.0.0.1:5173`. The API uses `http://127.0.0.1:8010` because another unrelated service already occupies port 8000.
