# Robustness and generalization report

Selected model: **Decision Tree** (highest held-out phishing F1; accuracy and precision break ties).

## Split comparison

Random stratified: 187,915 train / 46,979 test; 1,972 hostnames overlap.
Domain-aware: 187,457 train / 47,437 test; 0 hostnames overlap; accuracy 0.9793, phishing precision 0.9831, phishing recall 0.9686, F1 0.9758.

The source has a strong structure bias: legitimate records are all HTTPS and all use a `www.` hostname; phishing records include HTTP and non-`www` hosts. The model still uses HTTPS and TLD as learned signals, with no deterministic scheme, TLD, or hostname override. This dataset does not provide labeled legitimate non-`www` URLs for a direct held-out quality estimate of that subgroup.

## Held-out URL group performance

Class counts use label 0 = phishing and label 1 = legitimate. Empty classes in a group mean the dataset provides no held-out examples for that class.

| Group | Count | Phishing | Legitimate | Accuracy | Precision | Recall | F1 |
|---|---:|---:|---:|---:|---:|---:|---:|
| bare_root_urls | 41,321 | 14,351 | 26,970 | 0.9773964812081024 | 0.9777793604444128 | 0.9566580726081806 | 0.9671034094111017 |
| non_www_root_urls | 6,599 | 6,599 | 0 | 0.9233217154114259 | 1.0 | 0.9233217154114259 | 0.9601323668452568 |
| www_domains | 35,329 | 8,359 | 26,970 | 0.9878286959721475 | 0.9635215713784637 | 0.9858834788850341 | 0.9745742667928098 |
| domains_with_paths | 5,440 | 5,440 | 0 | 0.9988970588235294 | 1.0 | 0.9988970588235294 | 0.9994482251241493 |
| HTTPS | 36,630 | 9,660 | 26,970 | 0.9742833742833743 | 0.9666024405908799 | 0.9347826086956522 | 0.9504262709188507 |
| HTTP | 10,349 | 10,349 | 0 | 1.0 | 1.0 | 1.0 | 1.0 |
| .com | 22,495 | 8,773 | 13,722 | 0.9704378750833519 | 0.9762687969924813 | 0.9472244386184886 | 0.961527335840324 |
| .in | 284 | 115 | 169 | 0.9859154929577465 | 0.9911504424778761 | 0.9739130434782609 | 0.9824561403508771 |
| IP_based | 132 | 132 | 0 | 1.0 | 1.0 | 1.0 | 1.0 |
| suspicious_long | 449 | 449 | 0 | 1.0 | 1.0 | 1.0 | 1.0 |
| obfuscated | 484 | 484 | 0 | 0.9979338842975206 | 1.0 | 0.9979338842975206 | 0.9989658738366081 |
| punycode | 35 | 35 | 0 | 1.0 | 1.0 | 1.0 | 1.0 |
| shortener | 118 | 118 | 0 | 1.0 | 1.0 | 1.0 | 1.0 |
| ports | 5 | 5 | 0 | 1.0 | 1.0 | 1.0 | 1.0 |
| suspicious_query | 414 | 414 | 0 | 1.0 | 1.0 | 1.0 | 1.0 |

## Cleaning

Input rows 235,795; kept 234,894; normalized duplicate URLs removed 899; conflicting-label URLs removed 2; invalid URLs removed 0; invalid/missing labels removed 0.

Data-derived TLD, scheme, `www`/non-`www`, path, query, and URL-length distributions are recorded in `results/robustness_report.json`. The model contains no hostname whitelist or scheme/TLD override.
