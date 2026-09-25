# Model evaluation — PhishGuard (canonical-only; PhreshPhish and EdgePhish-5G audit-only)

**Date (UTC):** 2026-09-25
**Status:** No new training was performed. PhreshPhish was audited only and was NOT integrated. EdgePhish-5G was downloaded and row-verified this phase but is STOPPED from production training by upstream OpenPhish non-commercial terms. All metrics below are the existing canonical-only artifact.

## 1. Dataset sources

- Training source (only): `data/raw/PhiUSIIL_Phishing_URL_Dataset.csv` (UCI ID 967). NOT modified.
  - Raw: 235,795 rows (134,850 label 1 legitimate; 100,945 label 0 phishing).
  - After `clean_url_labels`: 234,894 rows (134,849 label 1; 100,045 label 0).
  - Cleaning: 0 missing/empty/invalid URLs, 0 invalid labels, 1 conflicting normalized-URL group removed (2 rows), 899 duplicate normalized URLs removed.
- Candidate source (audit-only, NOT training): `data/candidates/PhreshPhish/phreshphish_url_label_audit.csv`.
  - Verified in this session: 666,315 rows, 9 columns (`url,label,target,date,lang,lang_score,source_split,source_shard,source_row`), labels `benign` 367,989 / `phish` 298,326, splits test 168,060 / train 498,255, 0 empty URLs.
  - After `clean_url_labels`: 666,270 rows (367,987 label 1; 298,283 label 0); 1 invalid URL removed, 1 conflicting group removed (2 rows), 42 duplicate normalized URLs removed.
  - Provenance: Hugging Face `phreshphish/phreshphish`, source revision `eabec4b7a66324b79cc8a0ad856d1731dc26fe1a`, 77 Parquet shards totaling 36,576,373,578 bytes; projection SHA-256 `ac08bfd0e6c03874f83f5d682266952bb365b8546af12282fae967bca2333cee`, 83,790,252 bytes. HTML column omitted; no destination URL visited.
  - Partial file `phreshphish_url_label_audit.csv.partial` (34,815,907 bytes) exists but was explicitly excluded from all counts and was not used for training.
- Other candidates (PhishVN v4, PhishBD_2026, LegitPhish, URL-Phish v2, ISCX-URL2016, PhishStorm): no row-level files obtained; no rows invented. See `docs/candidate_dataset_audit.md`.

## 2. PhreshPhish licensing restriction

- Dataset card (verified live 2026-09-25): “released under CC BY 4.0 license and should only be used for anti-phishing research.”
- Intended PhishGuard deployment per README: public GitHub Pages frontend (`https://maninani12.github.io/phishguard-ai/`) plus separately hosted Render FastAPI backend — a general public web service, not confined to research.
- Verdict: use of PhreshPhish for training a publicly deployed model is NOT clearly permitted. Per Phase 5B/18 gates: **STOP BEFORE TRAINING. PRODUCTION DEPLOYMENT BLOCKED BY DATASET TERMS if PhreshPhish were integrated.** No integration, merge, or retraining was performed in this session.

## 3. Normalized overlap and conflicts (recomputed with project functions)

Using `src.feature_schema.normalize_url` and `src.data_loader.clean_url_labels` on both datasets:

- Cleaned normalized-URL overlap: **1,579**.
- By PhreshPhish label: 152 label 0, 1,427 label 1.
- Conflicting labels: **8**. No label was adjudicated; no merge was performed. The project cleaner policy (remove conflicting normalized-URL groups) was NOT applied across sources because no cross-source merge was performed.

| Normalized URL | PhreshPhish label | Canonical label | PhreshPhish raw URL | Canonical raw URL | PhreshPhish provenance |
|---|---|---:|---|---|---|
| `https://www.brooklinen.com/` | 0 (phish, target `at&t`) | 1 | `https://www.brooklinen.com/` | `https://www.brooklinen.com` | train/0052.parquet row 4261, 2024-07-10 |
| `http://www.coinbase.com/` | 1 (benign) | 0 | `www.coinbase.com/` (no scheme; normalizer treats as http) | `http://www.coinbase.com` | train/0042.parquet row 2940, 2024-09-12 |
| `https://www.bundestag.de/` | 0 (phish, target `at&t`) | 1 | `https://www.bundestag.de/` | `https://www.bundestag.de` | train/0033.parquet row 5624, 2025-01-30 |
| `https://www.poncevacay.com/` | 0 (phish, target `mobilbahis`) | 1 | `https://www.poncevacay.com` | `https://www.poncevacay.com` | test/0001.parquet row 246, 2025-11-01 |
| `https://www.tawk.to/` | 0 (phish, target `holiganbet`) | 1 | `https://www.tawk.to/` | `https://www.tawk.to` | train/0027.parquet row 3544, 2024-10-06 |
| `https://www.unesco.gov.ph/` | 0 (phish, target `other`) | 1 | `https://www.unesco.gov.ph` | `https://www.unesco.gov.ph` | test/0009.parquet row 5337, 2025-09-19 |
| `https://www.los40.com.gt/` | 0 (phish, target `other`) | 1 | `https://www.los40.com.gt/` | `https://www.los40.com.gt` | train/0023.parquet row 5994, 2024-07-10 |
| `https://www.southpointfinancial.com/` | 0 (phish, target `westnet`) | 1 | `https://www.southpointfinancial.com` | `https://www.southpointfinancial.com` | test/0019.parquet row 3384, 2025-10-23 |

Cause assessment: identical normalized URLs, so these are genuine source-label disagreements, not path/query semantics (trailing-slash differences are collapsed by the documented normalizer). The coinbase case additionally involves a missing-scheme raw string on the PhreshPhish side. Whether any side is stale, feed-specific, or time-dependent **cannot be established** from URL strings alone; no independent re-labeling was performed.

## 4. Feature schema (unchanged)

38 URL-only features, identical at training and inference (`src/feature_schema.py:FEATURES`): URLLength, DomainLength, TLDLength, TLD, NoOfSubDomain, HasObfuscation, NoOfObfuscatedChar, ObfuscationRatio, NoOfLettersInURL, LetterRatioInURL, NoOfDegitsInURL, DegitRatioInURL, NoOfEqualsInURL, NoOfQMarkInURL, NoOfAmpersandInURL, NoOfOtherSpecialCharsInURL, SpacialCharRatioInURL, IsDomainIP, IsHTTPS, num_dots, num_hyphens, num_underscores, num_slashes, num_at, num_hashes, num_percent, num_colons, num_semicolons, url_entropy, path_length, query_length, fragment_length, has_port, has_punycode, has_url_shortener, num_encoded_chars, max_repeat_ratio, num_suspicious_keywords. No source, provenance, content, title, reputation, or whitelist features.

## 5. Model comparison (existing artifact, verified)

From `results/model_metrics.json` (matches prompt’s verified metrics):

| Model | Accuracy | Precision | Recall | F1 | FP | FN |
|---|---:|---:|---:|---:|---:|---:|
| Logistic Regression | 0.972094 | 0.986927 | 0.947024 | 0.966564 | 251 | 1060 |
| Decision Tree | 0.979948 | 0.984155 | 0.968514 | 0.976272 | 312 | 630 |
| Random Forest | 0.978160 | 0.984879 | 0.963516 | 0.974080 | 296 | 730 |

Serialized artifact verified: `DecisionTreeClassifier(min_samples_leaf=3, random_state=42)`, pipeline steps `['preprocess','model']`, metadata model “Decision Tree”, 38 features in correct order. Selection rule in current `src/train.py` is highest held-out phishing F1, then accuracy, then precision. Per-metric comparison: Decision Tree has the highest F1 and recall but more false positives (312) than Logistic Regression (251); Logistic Regression has the highest precision but 1,060 false negatives. Accuracy alone was not used and no single metric decides the choice.

**Canonical model status statement:** Decision Tree is the currently shipped model and remains the lowest-cost candidate under the analyzed technical scenarios, subject to the operational FP/FN cost ratio. It is not a universally best model; the cost-scenario sensitivity is documented in `docs/model_selection_report.md`.

## 6. Domain-aware evaluation

`src/train.py` now groups its domain-aware holdout by registrable domain via `src/domain_split.py` (integrated without retraining). The figures stored in `models/model_metadata.json` (train 187,457 / test 47,437 rows, 0 hostname overlap, accuracy 0.979341, F1 0.975818) were produced under the old full-hostname grouping and are therefore LEGACY HOSTNAME-GROUPED RESULTS; they must not be compared silently with future registrable-domain figures. PSL-aware evaluation was implemented this phase WITHOUT retraining: `src/domain_split.py` on `tldextract>=5.0` (private PSL domains included; no manual TLD parsing). Evaluation-only check on the 234,894 cleaned canonical rows: 197,300 registrable groups; GroupShuffleSplit (20%, seed 42) -> train 187,391 rows / 157,840 groups, test 47,503 rows / 39,460 groups, overlap **0 (0.00%)**. 8 tests in `tests/test_domain_split.py` cover `example.com`/`example.co.uk` grouping, private-suffix tenant separation, ports/case, IPs, and zero-overlap splitting. Switching future training to these groups is intended but deliberately not done here.

## 7. External evaluation

No external test set was used for training influence in this session because no training occurred. PhreshPhish was NOT used as an external benchmark here; doing so after inspecting its labels for model selection would risk contamination. A future external pathway must apply the frozen pipeline directly with no influence on features, hyperparameters, thresholds, or selection.

## 8. Robustness (existing)

`results/robustness_report.md` held-out groups (canonical-only): HTTP 100% accuracy but only phishing examples; non-www-root 6,599 rows all phishing-labeled (no legitimate non-www examples); IP/punycode/shortener/port groups have only phishing examples. This session’s live smoke test confirmed the gap: `https://example.com/` (legitimate apex) → “Potential Phishing” (conf 1.0), while `https://www.example.com/` → “Legitimate”. See `docs/error_analysis.md`.

## 9. Limitations

- Canonical legitimate class has zero non-www apex training signal (all legitimate use HTTPS + www + root path); generalization to legitimate apex-root cannot be established from internal metrics.
- PhreshPhish would add 7,962 benign apex-root rows but is blocked by research-only terms; count alone does not guarantee generalization.
- EdgePhish-5G contributes a verified 2,487 legitimate apex-root rows but is blocked by upstream OpenPhish non-commercial terms; see `docs/dataset_research.md`.
- 8 cross-source label conflicts are unresolved.
- PhreshPhish 76-row test-class discrepancy (card sums to 168,136 vs 168,060 extracted) is unresolved.
- Source labels are not current-safety verdicts.
