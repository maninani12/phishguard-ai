# Error analysis

**Date (UTC):** 2026-09-25
**Data:** canonical UCI PhiUSIIL only. No candidate, external, or research-only dataset.
**Script:** `experiments/error_analysis_experiment.py` → `models/experiments/error_analysis.json`
**Scope:** Decision Tree, the shipped configuration, on the primary stratified 80/20 held-out split (seed 42).

No individual domain is patched, whitelisted, or special-cased anywhere. The
examples below exist for pattern inspection only.

## Confusion counts

| | Predicted phishing (0) | Predicted legitimate (1) |
|---|---:|---:|
| **Actual phishing (0)** | 19,379 | **630 (FN)** |
| **Actual legitimate (1)** | **312 (FP)** | 26,658 |

## Structural profile of each error class

| Metric | FP (legit → phishing) | FN (phish → legit) | Correct legitimate | Correct phishing |
|---|---:|---:|---:|---:|
| count | 312 | 630 | 26,658 | 19,379 |
| % HTTPS | 100.0 | 100.0 | 100.0 | 46.6 |
| % `www` | 100.0 | 18.7 | 100.0 | 42.5 |
| % apex (non-www) | 0.0 | 36.4 | 0.0 | 34.9 |
| % non-www subdomain | 0.0 | 44.9 | 0.0 | 22.6 |
| % root path | 100.0 | 98.7 | 100.0 | 70.8 |
| % with query | 0.0 | 0.3 | 0.0 | 6.4 |
| mean URL length | 35.2 | 33.8 | 28.2 | 46.9 |
| mean domain length | 26.2 | 24.5 | 19.2 | 24.4 |
| mean suspicious keywords | 0.048 | 0.041 | 0.004 | 0.116 |
| mean encoded chars | 0.000 | 0.000 | 0.000 | 0.059 |
| % shortener host | 0.0 | 0.0 | 0.0 | 0.61 |
| % containing suspicious keyword | 4.81 | 3.97 | 0.45 | 9.25 |
| % IP host | 0.0 | 0.0 | 0.0 | (present) |
| % punycode | 0.0 | 0.0 | 0.0 | (present) |

## General pattern 1 — false positives are length-driven, not risk-driven

Every false positive is HTTPS + `www` + root path, i.e. structurally identical to
a correctly classified legitimate URL. The only systematic differences are
**length**: false positives average 35.2 characters versus 28.2 for correct
legitimate URLs, and their domains average 26.2 characters versus 19.2. They carry
essentially no suspicious markers (mean suspicious-keyword count 0.048 versus 0.004
for correct legitimate, no IP, no punycode, no encoding, no query).

Representative false positives: `https://www.tgcom24.mediaset.it/`,
`https://www.questionablecontent.net/`, `https://www.mxt2510.com/`,
`https://www.beausoleil-architects.com/`.

So the model is not reacting to evidence of phishing. It is reacting to a long,
unusual-looking domain on an otherwise perfectly normal HTTPS `www` root URL. The
operational reading: longer, less common legitimate domains are disproportionately
warned about.

## General pattern 2 — false negatives are phishing URLs with no structural tell

The 630 false negatives are 100% HTTPS, 98.7% root path, and carry **no**
suspicious structure at all: 0% IP host, 0% punycode, 0% encoded characters, 0%
shortener, 0.3% query, mean suspicious-keyword count 0.041 (below the 0.116 of
correctly detected phishing). They concentrate on exactly the shapes the corpus
never shows as legitimate: 36.4% apex (non-`www`) and 44.9% non-www subdomain,
versus only 18.7% `www` — while correctly detected phishing is 42.5% `www`.

Representative false negatives: `https://www.blog.bcpekanbaru.online/`,
`https://lokpiii.weebly.com/`, `https://zemerhsahzez.firebaseapp.com/`,
`https://www.aflacxvmlyr.com/`, `https://currenty.boxmode.io/`.

The model has no evidence to work with on these rows. Every channel it does have —
IP, port, encoding, punycode, shortener, suspicious keywords, query — is empty, so
the decision falls back to the host-shape prior, and that prior says apex and
subdomain hosts are phishing because in this corpus they only ever are.

## Interaction with the apex finding

These two patterns and `docs/apex_representation_test.md` are the same defect seen
from three sides. The corpus teaches HTTPS + `www` + root ⇒ legitimate. Everything
else defaults toward phishing. The consequences are:

- legitimate apex/subdomain/HTTP URLs are misclassified as phishing (measured:
  0 of 4,163 legitimate diagnostic URLs correct);
- the residual false positives are legitimate URLs that are merely long;
- the residual false negatives are phishing URLs with no lexical signal.

## What was not done

- No domain, hostname, or pattern was added to any exception list.
- No feature was added or removed in response to these findings.
- No threshold was tuned, and no model was retrained.
- No candidate dataset was consulted; the legitimate apex/subdomain rows that
  would be needed to retrain against this bias are unavailable under usable terms.
- These are dataset-induced error modes. Fixing them requires new training data
  with legitimate non-`www` apex, subdomain, HTTP and query coverage, not code
  changes to the classifier.
