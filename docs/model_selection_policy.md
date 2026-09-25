# Model selection policy — error-cost analysis

**Date (UTC):** 2026-09-25
**Status:** TECHNICAL ANALYSIS. **This is not a business policy and it is not owner-approved.**

## Why this document exists

Model selection was previously blocked because no explicit false-alarm versus
missed-phishing cost policy existed, and the project refused to pick a model
implicitly from a single metric such as accuracy or F1. This document supplies a
**transparent default technical cost analysis** so that the choice can be made
explicitly and audited, while making clear that the actual cost ratio remains a
business decision for the project owner.

## The two error types

**FALSE POSITIVE (FP)** — a legitimate URL is classified as phishing.
Operational implications: a user is warned about a site that is safe. In a browser
or mail-client integration this produces a false security warning, which drives
users to ignore warnings, may block legitimate business or study sites, and
erodes trust in the tool. FP cost scales with traffic volume, because every
legitimate visit is a candidate for a warning, and it is usually felt by many
users at once.

**FALSE NEGATIVE (FN)** — a phishing URL is classified as legitimate.
Operational implications: a malicious site is presented as safe. The user proceeds
to a credential-harvesting or malware page. Consequences are concentrated,
asymmetric and potentially irreversible: credential theft, financial loss,
account takeover, malware execution. FN cost is incurred per actual attack, but
each incident can be far more damaging than a single false warning.

Neither error is universally more important. The relative weight is a property of
the deployment context, not of the model. This analysis therefore does not assert
a ratio; it quantifies the consequences of several ratios.

## Cost model

For a scenario with false-positive weight `F` and false-negative weight `N`:

```
expected_error_cost = (FP x F) + (FN x N)
```

Rates reported alongside: false-positive rate `FPR = FP / actual_legitimate` and
false-negative rate `FNR = FN / actual_phishing`, both on the positive (phishing)
class convention used by the project.

## Analytical scenarios

These are analytical scenarios, **not** claimed business requirements.

| Scenario | FP cost | FN cost | Reading |
|---|---:|---:|---|
| A | 1 | 1 | Errors weighted equally; pure error count |
| B | 1 | 2 | A missed phish counts double |
| C | 1 | 5 | A missed phish counts five times |
| D | 2 | 5 | A false alarm also costs extra |

## Results — canonical primary split (stratified 80/20, seed 42, 46,979 rows)

| Model | FP | FN | FPR | FNR | A (1:1) | B (1:2) | C (1:5) | D (2:5) |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| Logistic Regression | 251 | 1060 | 0.009307 | 0.052976 | 1311 | 2371 | 5551 | 5802 |
| Decision Tree | 312 | 630 | 0.011568 | 0.031486 | **942** | **1572** | **3462** | **3774** |
| Random Forest | 296 | 730 | 0.010975 | 0.036484 | 1026 | 1756 | 3946 | 4242 |

## Results — domain-aware split (registrable-domain grouped, PSL-aware, seed 42, 47,503 rows)

| Model | FP | FN | FPR | FNR | A (1:1) | B (1:2) | C (1:5) | D (2:5) |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| Logistic Regression | 255 | 1022 | 0.009396 | 0.050189 | 1277 | 2299 | 5365 | 5620 |
| Decision Tree | 324 | 664 | 0.011938 | 0.032608 | **988** | **1652** | **3644** | **3968** |
| Random Forest | 293 | 702 | 0.010796 | 0.034474 | 995 | 1697 | 3803 | 4096 |

Raw output: `models/experiments/cost_scenarios.json`, produced by
`experiments/cost_analysis.py`.

## Sensitivity — where the ordering changes

Decision Tree has the lowest expected cost in all four scenarios on both splits.
That result is **not** unconditional. Solving for the FP/FN cost ratio `r = F/N`
at which a different model becomes cheaper:

| Comparison | Primary split | Domain-aware split |
|---|---:|---:|
| Random Forest cheaper than Decision Tree when | r > 6.25 | r > 1.23 |
| Logistic Regression cheaper than Decision Tree when | r > 7.05 | r > 5.19 |

Consequences, stated explicitly:

- On the **domain-aware** split the ordering is genuinely fragile. If a false
  alarm is more than about 1.2x the cost of a missed phish, Random Forest becomes
  cheaper than Decision Tree. Between roughly 1.23 and 5.19, Random Forest is the
  cost-preferred model.
- On the **primary** split the crossover is far away (6.25 to 7.05), i.e. only
  reachable if a false alarm is worth more than about six missed phishes.
- The two splits therefore disagree about the sensitivity of the decision. This
  disagreement is a direct consequence of the domain-aware split producing
  somewhat different error counts, and it is reported rather than smoothed over.

**Model selection is conditional on the chosen operational cost ratio.**

## What this document does not do

- It does not declare a business cost ratio.
- It does not rank models by accuracy, and it does not treat F1 as decisive.
- It does not use any external, candidate, or research-only dataset. All figures
  come from the canonical UCI PhiUSIIL corpus only.
- It does not consider the representation failure documented in
  `docs/apex_representation_test.md`, which affects all three models equally and
  is not expressible as a per-row cost on this corpus, because the corpus contains
  no legitimate examples of the affected shapes.
