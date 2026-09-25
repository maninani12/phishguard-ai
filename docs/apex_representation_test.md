# Apex representation test

**Date (UTC):** 2026-09-25
**Classification: DIAGNOSTIC / ROBUSTNESS TEST — NOT AN OFFICIAL BENCHMARK.**
**Script:** `experiments/apex_representation_test.py`
**Raw output:** `models/experiments/apex_representation_test.json`

No domain is hard-coded, whitelisted, or special-cased. Examples are selected by
structural predicate over a labeled source file; the pipelines are used exactly as
shipped.

## Why this test exists

The canonical corpus cannot answer the question it most needs to answer. Its
legitimate class is fully degenerate:

| Measure | Phishing (label 0) | Legitimate (label 1) |
|---|---:|---:|
| Rows | 100,945 | 134,850 |
| HTTPS | 49,196 | **134,850 (100%)** |
| `www` host | 41,744 | **134,850 (100%)** |
| Root path | 72,456 | **134,850 (100%)** |
| Apex-root (PSL, non-www) | 21,301 | **0** |
| Apex with path | 14,521 | **0** |
| Non-www subdomain | 23,379 | **0** |
| Query present | 6,079 | **0** |

Every legitimate example in training is HTTPS, `www`, and root-path. The model
therefore cannot learn what a legitimate apex-root, subdomain, HTTP, or
query-bearing URL looks like, because no such example exists.

## Ground truth source and its limits

Ground truth: `data/candidates/PhishTrap/phishtrap_full.csv` (19,948 rows).

**Label mapping warning — the conventions are inverted.** PhishTrap uses
`0 = legitimate, 1 = phishing`; PhishGuard uses `0 = phishing, 1 = legitimate`.
Every row is remapped explicitly as `project_label = 1 - phishtrap_label`, and the
remapping is asserted in code. Mis-reading this would invert every result below.

**Licensing:** PhishTrap is used for **measurement only**. It is **not** approved
for training, model selection, or deployment. Its legitimate class is the Tranco
top-10K list, which inherits a non-commercial upstream component (Cloudflare
Radar, CC BY-NC 4.0) via Tranco, and its phishing class includes OpenPhish rows
whose terms are non-commercial. See `data/candidates/PhishTrap/source_manifest.json`.

**Confound:** every PhishTrap legitimate row is a constructed `http://` URL
(9,973 http, 0 https), so with this source alone the *apex* effect and the *HTTP*
effect cannot be fully separated. The counterfactual probe below separates them.

## Result 1 — accuracy by class and shape

Agreement with the source label (project convention):

| Shape | Scheme | Class | n | Production (shipped) | Exp. LR | Exp. DT | Exp. RF |
|---|---|---|---:|---:|---:|---:|---:|
| apex-root | http | legitimate | 2000 | **0.0000** | 0.0000 | 0.0000 | 0.0000 |
| subdomain | http | legitimate | 1687 | **0.0000** | 0.0000 | 0.0000 | 0.0000 |
| www | http | legitimate | 476 | **0.0000** | 0.0000 | 0.0000 | 0.0000 |
| apex-root | http | phishing | 2000 | 1.0000 | 1.0000 | 1.0000 | 1.0000 |
| subdomain | http | phishing | 2000 | 1.0000 | 0.9965 | 1.0000 | 1.0000 |
| apex-root | https | phishing | 1 | 1.0000 | 1.0000 | 1.0000 | 1.0000 |
| apex-with-path | https | phishing | 3 | 1.0000 | 1.0000 | 1.0000 | 1.0000 |
| apex-with-path | https+query | phishing | 2 | 1.0000 | 1.0000 | 1.0000 | 1.0000 |
| subdomain | https+query | phishing | 5 | 1.0000 | 1.0000 | 1.0000 | 1.0000 |
| subdomain | https | phishing | 1 | 0.0000 | 0.0000 | 0.0000 | 0.0000 |

**0 of 4,163 legitimate URLs were classified correctly.** The model flags
essentially every legitimate URL in this source as phishing, and correctly flags
the phishing URLs. All four pipelines — shipped and experimental — behave
identically here, so this is a property of the training data, not of the
classifier choice.

## Result 2 — counterfactual scheme probe (SYNTHETIC, NOT GROUND TRUTH)

Identical host and path; only the scheme rewritten `http://` -> `https://`.
Production pipeline, unchanged. This is a mechanism probe, not a benchmark.

| Shape | n | Correct as `http` | Correct after `https` rewrite |
|---|---:|---:|---:|
| www | 476 | 0.0000 | **0.9727** |
| subdomain | 1687 | 0.0000 | **0.8103** |
| apex-root | 2000 | 0.0000 | **0.0730** |

This decomposes the failure into **two independent learned biases**:

1. **Scheme bias.** Rewriting only the scheme flips `www` from 0% to 97% correct.
   The model has learned HTTPS as near-decisive evidence of legitimacy, because
   the canonical corpus contains 0 legitimate HTTP URLs and 51,749 phishing ones.
2. **Apex bias, independent of scheme.** Even after the rewrite, apex-root reaches
   only 7.3% correct, versus 81% for subdomains and 97% for `www`. A legitimate
   apex (non-`www`) URL stays wrong even when it is served over HTTPS, because the
   corpus contains 0 legitimate apex-root URLs at any scheme.

Fixing only the scheme would therefore not fix the apex problem. Both gaps trace
to the same root cause: absence of legitimate training examples for those shapes.

## What this test does not establish

- It is not an official benchmark and carries no accuracy claim about real-world
  traffic. The source is a curated convenience sample, not a representative
  prevalence sample.
- PhishTrap's legitimate labels derive from Tranco popularity, not from an
  independent safety judgment, so a "correct" here means agreement with that
  inference.
- Because the legitimate rows are 100% HTTP, the absolute 0% figure overstates how
  a mixed-scheme legitimate population would fare. The probe shows the direction
  and the two mechanisms, not a population-level rate.
- No figure here is used to select, tune, or retrain any model.

## Requirement to fix this

The gap cannot be closed inside the current corpus. Closing it needs a
license-clear labeled source of legitimate non-`www` apex-root, subdomain, HTTP,
and query-bearing URLs. `docs/dataset_research.md` records the current state of
that search: every readily available source is either unlabeled by construction,
research-only, license-unspecified, access-gated, or carries a non-commercial
upstream component.
