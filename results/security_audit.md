# Security and override audit

Audit scope: application and test source in `src/`, `backend/`, `frontend/src/`, and `tests/`.

## Submitted URL handling

- `normalize_url()` uses Python URL parsing and string operations; `extract_url_features()` calculates lexical measurements. Neither function opens a socket or makes a request.
- The only frontend `fetch()` targets the configured local PhishGuard API (`/api/model_info` or `/api/predict`). The submitted host is included only as JSON input to that local endpoint.
- Backend prediction transforms the URL into the authoritative feature dictionary and calls the saved scikit-learn pipeline.
- No calls to `requests.get/post`, `urllib.request`, Selenium, Playwright, subprocess, `os.system`, `eval`, or `exec` were found in application or test source.
- The text `httpx` occurs only in `requirements.txt` for Starlette's local in-process test client; application code does not import or use it to contact submitted URLs.

## Hard-coded prediction check

- No `google.com`, `youtube.com`, `chatgpt.com`, or `github.com` occurrences exist in prediction source.
- HTTPS is extracted as the `IsHTTPS` feature. `.com` and `.in` are represented through the learned TLD encoder. No direct scheme/TLD safe rule, hostname whitelist, branded-host override, or special-case confidence exists.

The predictions recorded in `final_api_checks.json` were made by the selected trained model.
