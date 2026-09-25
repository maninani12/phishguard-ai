# PhishGuard AI — hackathon demo material

**One line:** A deterministic AI agent that inspects a URL's *structure*, explains its reasoning, and tells you what to do — without ever opening the link.

---

## 1. Problem

Phishing links imitate brands people already trust. The hostname looks familiar, the page loads, and a credential form appears. Standard defenses either rely on reputation feeds that are slow to update and easy to evade, or load the page in a sandbox — which is expensive and can itself expose the defender.

There is a cheaper question available: **does this text look like the phishing URLs we have already seen?**

## 2. Solution

The user pastes a URL. A local agent validates it, scores it with a scikit-learn model trained on 38 URL-derived features, converts the measured features into plain language, and returns safety-first guidance.

The destination website is **never** visited. No crawler, no sandbox, no headless browser, no reputation feed, no external LLM.

## 3. Why phishing detection matters

- Phishing is the most common initial access vector for credential theft and fraud.
- Users cannot reliably inspect URLs themselves; the attacker's advantage is that the visible part of the link is the part they control.
- A detector that helps a user judge a link *before* clicking changes the outcome, rather than cleaning up afterwards.
- Judging a URL as text is inherently low-risk, which is what makes it practical to ship.

## 4. Architecture

```text
Browser (React + Vite, static, GitHub Pages)
        |  JSON over HTTPS — the only network call in the app
        v
FastAPI  /api/agent/analyze · /api/predict · /api/model_info · /api/health
        v
PhishGuard Agent (deterministic, offline, no LLM)
   validate -> predict -> explain -> advise
        v
38 URL-only features -> sklearn Pipeline -> DecisionTreeClassifier
```

## 5. Agent workflow

| Stage | Behaviour | Guarantee |
|---|---|---|
| Validate | Trim, 2048-char cap, no control chars, `http`/`https` only, must parse | 422 before any scoring |
| Predict | Extract 38 features, run the fitted pipeline | Same pipeline as `/api/predict`; model loaded once |
| Explain | Emit observations only for features actually present | No invented reasons |
| Advise | Primary recommendation + advisories | Never claims a site is "safe" or "malicious" |
| Flag gaps | Report URL shapes absent from the legitimate class | Surfaces the blind spot instead of hiding it |

## 6. ML model

- **Classifier:** `DecisionTreeClassifier(min_samples_leaf=3, random_state=42)`
- **Data:** UCI PhiUSIIL (ID 967), 234,894 cleaned records, CC BY 4.0
- **Features:** 38 URL-only features → 545 transformed dimensions
- **Classes:** `0 = Potential Phishing`, `1 = Legitimate`
- **Primary split:** stratified URL-level 80/20, seed 42 → accuracy 0.9799, F1 0.9763
- **Domain-aware split:** registrable-domain grouped, PSL-aware, **overlap 0** → accuracy 0.9792
- **Comparison:** Logistic Regression and Random Forest were evaluated under a documented FP/FN cost analysis. Decision Tree is the lowest-cost candidate under the analyzed scenarios and is the shipped model; **selection remains conditional on the operational cost ratio**, which is a business decision.

## 7. Security design

The strongest claim in this project is a negative one: **we never touch the submitted site.**

- No HTTP client, socket, DNS resolution, redirect follower, HTML downloader, JavaScript runtime or browser automation anywhere in the request path — enforced by tests that parse the source and fail on any such import.
- The only outbound request in the whole application is the browser calling our own API.
- Input validation: scheme allow-list, 2048-character cap, control-character rejection, normalizer-based rejection. All failures return 422.
- CORS restricted to three known origins; `GET`/`POST`; `Content-Type` only.
- No secrets or API keys. `VITE_API_BASE_URL` is public build configuration.
- The production bundle refuses a loopback API base, so a misconfigured deploy fails visibly instead of silently calling a laptop.

## 8. Demo flow (2–3 minutes)

### Setup before you present
```powershell
# Terminal 1
python -m uvicorn backend.app:app --host 127.0.0.1 --port 8013
# Terminal 2
cd frontend; npm run dev
```
Open <http://127.0.0.1:5173> and confirm the badge reads **SYSTEM ONLINE**.

### Beat 1 — the normal case (~30s)
Paste `https://www.example.com/` → **Analyze URL**.

> "Verdict: LEGITIMATE, low risk, model score 99.7%. No phishing indicators were detected strongly enough by the model. This is not a confirmation that the site is safe. Recommendation: still confirm the destination before submitting anything sensitive."

**Say:** "It found no phishing tokens — and notice it refuses to call the site safe."

### Beat 2 — the obvious phishing case (~30s)
Paste `http://192.0.2.5:8080/login?next=%2Fadmin` → Analyze.

> "Verdict: POTENTIAL PHISHING, high risk. Seven signals: raw IP host, no HTTPS, non-default port, percent-encoding, the keyword *login*, an `@`-style obfuscation character, and a query string. Recommendation: do not enter passwords, card details or codes on this URL until you have independently verified the site."

**Say:** "Every one of those lines maps to a specific measured feature. Click *Show the 38 extracted features* to prove it."

### Beat 3 — the honest failure (~45s)
Paste `https://example.com/` → Analyze.

> "Verdict: POTENTIAL PHISHING — and the agent flags its own blind spot: *a bare apex host with no www prefix* is underrepresented in the training data, so this verdict is less reliable."

**Say:** "This is a real site shape our training data never showed as legitimate. The system tells you when it does not know, instead of pretending."

### Beat 4 — the security claim (~30s)
Open DevTools → Network. Analyze a URL. Point out the only request is to `127.0.0.1:8013/api/agent/analyze` (or your deployed API). There is no request to the analysed host.

**Say:** "We never fetched the page. Open DevTools and confirm it."

### Beat 5 — the model is real (~20s)
Scroll to **Model snapshot**: live dataset name, 234,894 cleaned records, 38 features, held-out accuracy, false positives and false negatives.

**Say:** "These numbers come from a held-out split, and a registrable-domain-disjoint split with zero domain overlap."

## 9. Limitations (state these before you are asked)

1. **Training data is structurally biased.** Every one of the 134,850 legitimate rows is HTTPS + `www` + root path. There are zero legitimate apex, non-`www` subdomain, HTTP or query URLs.
2. **Measured, not theoretical.** A diagnostic over 4,163 legitimate URLs from another source classified **0** of them correctly. Two independent causes: a scheme bias and an apex bias.
3. **The 97.9% accuracy is not a real-world figure.** It is measured on the same distribution the model was trained on. The domain-aware split shares that distribution, which is why it does not expose the problem either.
4. **We did not fix it by patching the model.** Changing the classifier does not help when the training data has no examples of the shape. Fixing it requires license-clear data with those URL shapes; every public candidate we evaluated was research-only, non-commercial upstream, license-unspecified, or access-gated. See `docs/dataset_research.md`.
5. **Source labels are not ground truth**, and a classification is not a verdict.

## 10. Future improvements

1. **Obtain license-clear data** covering legitimate apex, subdomain, HTTP and query URLs, then retrain and re-measure. This is the single highest-value improvement.
2. **Calibrate** the model score on a held-out realistic base rate, so `confidence` becomes a defensible probability.
3. **Temporal evaluation** — phishing patterns drift; measure on a time-partitioned split.
4. **Abstention** — return "I don't know" when the URL shape is outside the training distribution, instead of forcing a binary verdict.
5. **Explainability upgrades** — per-feature contribution attribution (e.g. SHAP-style) so the agent can say *which* feature drove the decision.
6. **Subdomain intelligence** — the project's weakest area (45% of false negatives sit on subdomains); a public-suffix-aware reputation layer is the obvious candidate.
7. **Browser extension** for in-page warnings, which is where the real protective value is.

## 11. Deployment architecture

```text
      GitHub Pages (static React bundle, base path /phishguard-ai/)
                        |  fetch(VITE_API_BASE_URL + /api/...)
                        v
      Render (FastAPI, uvicorn, model loaded read-only from models/)
                        |
                        v
              sklearn inference, entirely local
```

- Backend: `render.yaml` → `uvicorn backend.app:app --host 0.0.0.0 --port $PORT`, health check `/api/health`. No secrets required; nothing is retrained.
- Frontend: `.github/workflows/deploy-pages.yml` builds on push to `main` with `VITE_API_BASE_URL` from an Actions repository variable.
- Contract between them: one JSON endpoint, `POST /api/agent/analyze`.

## 12. Anticipated judge questions

**"What is your accuracy on real phishing?"**
97.99% accuracy and 96.85% phishing recall on a held-out split of our training corpus. I will not present that as real-world accuracy, and here is the measured evidence of why: 0 of 4,163 legitimate URLs from an independent source were classified correctly. The corpus is the limitation, not the classifier.

**"Why doesn't it just visit the site?"**
Because fetching a page you are trying to assess is itself an attack surface — it exposes the defender to redirects, drive-by content and tracking, and it is slow and expensive. Judging the text keeps the user's device untouched, which is the property that makes this deployable at all.

**"Is it using an LLM?"**
No. The agent is deterministic Python over measured features. No API key, no external service, no cost. That is why every sentence in the explanation can be traced to a specific feature, and why the whole thing runs offline.

**"Isn't 100% of the risk just the dataset?"**
For the accuracy number, yes — and we measured and published that rather than hiding it. The engineering around it is what makes the failure legible: the agent detects an out-of-distribution URL shape and tells the user its verdict is unreliable. A model that is quietly wrong is worse than one that admits its limits.

**"How do I know it isn't fetching URLs?"**
The test suite parses the request-path source and fails if any network or code-execution module is imported. It also asserts CORS origins, the input limits and the absence of secrets. In the browser, DevTools shows the only request is to our own API.
