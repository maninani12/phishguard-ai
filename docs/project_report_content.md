# PhishGuard — Project Report Content

## 1. Introduction
PhishGuard demonstrates URL-only machine-learning classification of phishing risk as a local web application.

## 2. Problem Statement
Phishing URLs can imitate known brands. The project measures URL string characteristics without contacting the destination.

## 3. Objectives
Train and compare interpretable baseline classifiers, expose a local prediction API, display model outputs and features, and document generalization limits.

## 4. Project Scope
Input is one HTTP/HTTPS URL string. Website content, redirects, DNS, WHOIS, reputation services, and remote APIs are out of scope.

## 5. Proposed System / Methodology
The same URL normalizer and extractor are used at training and inference. Numeric scaling and TLD encoding are fitted within each training pipeline only.

## 6. Dataset Description
UCI PhiUSIIL Phishing URL Dataset (ID 967); raw records: 235,795; cleaned records: 234,894; SHA-256: `a236549cd369cd80bd478ff8e1779cbf44c58d5c3f79f7a51a1adbed7d06d1c6`. Clean class counts: `{'1': 134849, '0': 100045}`. UCI label mapping verified: 1 = legitimate, 0 = phishing.

## 7. Data Preprocessing
Removed empty/missing URLs, invalid URL strings, missing or non-binary labels, ambiguous normalized URLs carrying conflicting labels, and duplicate normalized URLs. Audit counts: `{'input_rows': 235795, 'missing_url_removed': 0, 'missing_label_removed': 0, 'empty_url_removed': 0, 'invalid_url_removed': 0, 'invalid_or_inconsistent_label_removed': 0, 'conflicting_label_urls_removed': 2, 'duplicate_normalized_url_removed': 899, 'clean_rows': 234894}`. Normalized URL duplicates are removed before splitting.

## 8. AI/ML Model Selection
Logistic Regression, Decision Tree and Random Forest were compared. Selection rule: highest stratified held-out phishing precision (to limit false alarms), then phishing F1, then accuracy.

## 9. Model Development
The final feature set has 38 URL-only features: `['URLLength', 'DomainLength', 'TLDLength', 'TLD', 'NoOfSubDomain', 'HasObfuscation', 'NoOfObfuscatedChar', 'ObfuscationRatio', 'NoOfLettersInURL', 'LetterRatioInURL', 'NoOfDegitsInURL', 'DegitRatioInURL', 'NoOfEqualsInURL', 'NoOfQMarkInURL', 'NoOfAmpersandInURL', 'NoOfOtherSpecialCharsInURL', 'SpacialCharRatioInURL', 'IsDomainIP', 'IsHTTPS', 'num_dots', 'num_hyphens', 'num_underscores', 'num_slashes', 'num_at', 'num_hashes', 'num_percent', 'num_colons', 'num_semicolons', 'url_entropy', 'path_length', 'query_length', 'fragment_length', 'has_port', 'has_punycode', 'has_url_shortener', 'num_encoded_chars', 'max_repeat_ratio', 'num_suspicious_keywords']`. Excluded fields include webpage contents/metadata, link counts, redirects, `URLSimilarityIndex`, and unreproducible derived dataset statistics. TLD one-hot encoding and numeric imputation/scaling are pipeline stages.

## 10. Model Training and Evaluation
Random stratified split: 187,915 train / 46,979 test, random state 42. Hostname overlap is 1,972 for this random split. Separate hostname-disjoint evaluation: 187,457 train / 47,437 test, overlap 0.

## 11. Results and Analysis
Selected model: **Logistic Regression**. Accuracy 0.9721; phishing precision 0.9869; phishing recall 0.9470; phishing F1 0.9666; training score 0.9718; test score 0.9721; gap -0.0003; false positives 251; false negatives 1,060. Confusion matrix (actual rows, predicted columns; class order 0 phishing, 1 legitimate): `[[18949, 1060], [251, 26719]]`. Domain-aware accuracy 0.9719, phishing precision 0.9876, phishing recall 0.9467, F1 0.9667, false positives 243, false negatives 1,089. See generated comparison and robustness reports for all model and URL subgroup metrics.

## 12. System Architecture / Workflow
CSV → URL cleaning/deduplication → authoritative URL extraction → training-only preprocessing → stratified model comparison and hostname holdout → saved pipeline → FastAPI → React/Vite.

## 13. Implementation
Python, pandas, NumPy, scikit-learn, joblib, FastAPI and Uvicorn implement data preparation, training and inference. FastAPI accepts JSON and does not use a network client for submitted URLs.

## 14. UI/Application
The responsive dark interface provides an analyzer, probability and class, actual extracted features, live model information, workflow, and a Three.js shield visualization. Reduced-motion and WebGL fallback paths are provided.

## 15. Challenges and Limitations
The source dataset contains webpage-level predictors that would violate the URL-only requirement; these are deliberately ignored. The audit found a clear structure bias: every legitimate record is HTTPS and has a `www.` hostname, while phishing records include both schemes and non-`www` hosts. Counts by scheme, `www` presence, and TLD are recorded in `results/robustness_report.json`; `.com` and `.in` are present in both classes. The held-out set contains 6,599 non-`www` root URLs, all labeled phishing, so the dataset cannot establish how unseen legitimate bare domains should classify. Logistic Regression was selected by measured held-out phishing precision and classified the four requested bare HTTPS `.com` examples as legitimate without a hostname override; those predictions are not independent ground-truth validation. Random URL splits can share hostnames, so hostname-disjoint metrics are reported separately. Predictions can be wrong, and dataset-level class patterns may not match current traffic.

## 16. Conclusion
The implementation trains and evaluates a local model on URL-derived features only. Its output is a statistical classification and not a safety verdict.

## 17. Future Scope
Assess newer independent corpora, temporal drift, probability calibration and subgroup fairness; consider explanation tools that remain strictly URL-only.

## 18. References
- Prasad, A. & Chandra, S. (2024). *PhiUSIIL Phishing URL (Website) Dataset*. UCI Machine Learning Repository, ID 967. https://archive.ics.uci.edu/dataset/967/phiusiil+phishing+url+dataset
- Prasad, A. & Chandra, S. (2024). PhiUSIIL: A diverse security profile empowered phishing URL detection framework based on similarity index and incremental learning. *Computers & Security*. https://doi.org/10.1016/j.cose.2023.103545
- Actual metrics are machine generated in `results/model_metrics.json`; dataset audit in `results/dataset_audit.json`; subgroup and hostname evaluation in `results/robustness_report.json`.
