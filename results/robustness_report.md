# Robustness and generalization report

Selected model: **Logistic Regression** (highest held-out phishing precision; phishing F1 and accuracy break ties).

## Split comparison

Random stratified: 187,915 train / 46,979 test; 1,972 hostnames overlap.
Domain-aware: 187,457 train / 47,437 test; 0 hostnames overlap; accuracy 0.9719, phishing precision 0.9876, phishing recall 0.9467, F1 0.9667.

The source has a strong structure bias: legitimate records are all HTTPS and all use a `www.` hostname; phishing records include HTTP and non-`www` hosts. The model still uses HTTPS and TLD as learned signals, with no deterministic scheme, TLD, or hostname override. This dataset does not provide labeled legitimate non-`www` URLs for a direct held-out quality estimate of that subgroup.

## Held-out URL group performance

Class counts use label 0 = phishing and label 1 = legitimate. Empty classes in a group mean the dataset provides no held-out examples for that class.

| Group | Count | Phishing | Legitimate | Accuracy | Precision | Recall | F1 |
|---|---:|---:|---:|---:|---:|---:|---:|
| bare_root_urls | 41,321 | 14,351 | 26,970 | 0.9690714164710438 | 0.9815101289134438 | 0.9284370427147934 | 0.9542361956599584 |
| non_www_root_urls | 6,599 | 6,599 | 0 | 0.8643733899075617 | 1.0 | 0.8643733899075617 | 0.9272535154027473 |
| www_domains | 35,329 | 8,359 | 26,970 | 0.9888759942257069 | 0.9703589985829003 | 0.9830123220480919 | 0.9766446781957568 |
| domains_with_paths | 5,440 | 5,440 | 0 | 0.9939338235294117 | 1.0 | 0.9939338235294117 | 0.9969576841523001 |
| HTTPS | 36,630 | 9,660 | 26,970 | 0.9642096642096643 | 0.9716416224155463 | 0.8902691511387164 | 0.9291772459618605 |
| HTTP | 10,349 | 10,349 | 0 | 1.0 | 1.0 | 1.0 | 1.0 |
| .com | 22,495 | 8,773 | 13,722 | 0.958390753500778 | 0.9833477241889725 | 0.9086971389490482 | 0.9445497630331754 |
| .in | 284 | 115 | 169 | 0.9859154929577465 | 1.0 | 0.9652173913043478 | 0.9823008849557522 |
| IP_based | 132 | 132 | 0 | 1.0 | 1.0 | 1.0 | 1.0 |
| suspicious_long | 449 | 449 | 0 | 1.0 | 1.0 | 1.0 | 1.0 |
| obfuscated | 484 | 484 | 0 | 1.0 | 1.0 | 1.0 | 1.0 |
| punycode | 35 | 35 | 0 | 1.0 | 1.0 | 1.0 | 1.0 |
| shortener | 118 | 118 | 0 | 1.0 | 1.0 | 1.0 | 1.0 |
| ports | 5 | 5 | 0 | 1.0 | 1.0 | 1.0 | 1.0 |
| suspicious_query | 414 | 414 | 0 | 1.0 | 1.0 | 1.0 | 1.0 |

## Cleaning

Input rows 235,795; kept 234,894; normalized duplicate URLs removed 899; conflicting-label URLs removed 2; invalid URLs removed 0; invalid/missing labels removed 0.

Data-derived TLD, scheme, `www`/non-`www`, path, query, and URL-length distributions are recorded in `results/robustness_report.json`. The model contains no hostname whitelist or scheme/TLD override.
