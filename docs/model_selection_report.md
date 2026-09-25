# Model selection report

**Date (UTC):** 2026-09-25
**Cost policy applied:** `docs/model_selection_policy.md` (analytical scenarios, **not** owner-approved)
**Training data:** canonical `data/raw/PhiUSIIL_Phishing_URL_Dataset.csv` only
**Model replacement:** NONE. The shipped production artifact is unchanged.

## PRIMARY EVALUATION — STRATIFIED URL-LEVEL 80/20 (187,915 / 46,979, seed 42)

| Model | Accuracy | Precision | Recall | F1 | FP | FN |
|---|---:|---:|---:|---:|---:|---:|
| Logistic Regression | 0.972094 | 0.986927 | 0.947024 | 0.966564 | 251 | 1060 |
| Decision Tree | 0.979948 | 0.984155 | 0.968514 | 0.976272 | 312 | 630 |
| Random Forest | 0.978160 | 0.984879 | 0.963516 | 0.974080 | 296 | 730 |

## DOMAIN-AWARE EVALUATION — REGISTRABLE-DOMAIN GROUPED, PSL-AWARE

`GroupShuffleSplit` 20%, seed 42, groups from `src/domain_split.py`. Train 187,391
rows / 157,840 groups; test 47,503 rows / 39,460 groups; **registrable-domain
overlap 0 (0.00%)**, asserted during the run.

| Model | Accuracy | Precision | Recall | F1 | FP | FN |
|---|---:|---:|---:|---:|---:|---:|
| Logistic Regression | 0.973117 | 0.986987 | 0.949811 | 0.968042 | 255 | 1022 |
| Decision Tree | 0.979201 | 0.983819 | 0.967392 | 0.975536 | 324 | 664 |
| Random Forest | 0.979054 | 0.985316 | 0.965526 | 0.975321 | 293 | 702 |

## COST SCENARIOS

| Scenario (FP:FN) | Logistic Regression | Decision Tree | Random Forest | Lowest |
|---|---:|---:|---:|---|
| **Primary** A (1:1) | 1311 | **942** | 1026 | Decision Tree |
| **Primary** B (1:2) | 2371 | **1572** | 1756 | Decision Tree |
| **Primary** C (1:5) | 5551 | **3462** | 3946 | Decision Tree |
| **Primary** D (2:5) | 5802 | **3774** | 4242 | Decision Tree |
| **Domain-aware** A (1:1) | 1277 | **988** | 995 | Decision Tree |
| **Domain-aware** B (1:2) | 2299 | **1652** | 1697 | Decision Tree |
| **Domain-aware** C (1:5) | 5365 | **3644** | 3803 | Decision Tree |
| **Domain-aware** D (2:5) | 5620 | **3968** | 4096 | Decision Tree |

## Selection

**Selected model: Decision Tree** — conditional on the cost ratio.

Rationale, and the limits of that rationale:

1. Decision Tree has the lowest expected cost in all four documented scenarios on
   both evaluation splits. It also has the highest recall and the fewest false
   negatives in both.
2. **The ordering is sensitive and this is not hidden.** Decision Tree is *not*
   unconditionally best. Logistic Regression has the lowest false-positive count
   and the highest precision in both splits, and it becomes cost-preferred once
   the false-alarm cost exceeds roughly 7.05x the missed-phish cost on the primary
   split, or 5.19x on the domain-aware split. On the domain-aware split Random
   Forest becomes preferred above a ratio of about 1.23. The two splits disagree
   on how fragile the decision is.
3. **Model selection is conditional on the chosen operational cost ratio.** No
   project-owner business cost policy exists, so this report does not assert that
   the owner prefers missed phishes over false alarms. The scenarios above are
   analysis inputs for that decision, not a substitute for it.
4. The comparison rests entirely on the canonical corpus, whose legitimate class
   is degenerate (100% HTTPS + `www` + root path). All three models inherit that
   bias identically, so the cost comparison is internally valid but does not
   describe behaviour on legitimate apex-root, subdomain, HTTP, or query URLs.
   `docs/apex_representation_test.md` measures that failure and it is not captured
   by any FP/FN number in this report.

## Artifact decision

The shipped `models/phishguard_pipeline.joblib` is a
`DecisionTreeClassifier(min_samples_leaf=3, random_state=42)` — the same family
and configuration as the cost-preferred model, and trained on the full cleaned
corpus rather than only the 80% primary split.

**Therefore no replacement was performed.** Replacing it with an experimental
primary-split pipeline would be a downgrade in training data at best and a
gratuitous change of a verified artifact at worst. The artifact was verified
instead (`experiments/verify_artifact.py`, output
`models/experiments/artifact_verification.json`) and left byte-identical.

Production pipeline SHA-256: `882b1f5de934cb0a190f0f9461ea744b1e96cb42e9a3f539a60279662d724df1`
