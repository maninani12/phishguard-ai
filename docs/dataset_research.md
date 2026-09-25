# Production-compatible dataset research

**Date (UTC):** 2026-09-25
**Constraint:** PhreshPhish MUST NOT be used for production training (research-only terms). This phase searches for production-compatible data WITHOUT integrating PhreshPhish. No training was run. No model was replaced. The canonical dataset is unchanged.

## Verdict summary

| Dataset | License status | Row-verified | Outcome |
|---|---|---|---|
| PhiUSIIL (canonical, UCI 967) | CLEAR FOR INTENDED USE (CC BY 4.0, any purpose with credit) | Yes (prior phases) | Current training source; attribution required |
| EdgePhish-5G (Zenodo 19371661) | NOT CLEARLY COMPATIBLE (record CC BY 4.0, but upstream OpenPhish bars commercial/detection use) | Yes (340,000 rows, this phase) | STOP from production training despite 2,487 legit apex-root rows |
| PhishTank (verified feed) | REQUIRES TERMS REVIEW (Data stated OK for commercial use, but CC BY-SA 2.5 scope unclear; key needed for routine use) | No (phishing-only; cannot fix legit gap) | Not downloaded; deferred |
| Majestic Million (domain list) | REQUIRES TERMS REVIEW + label STOP (CC BY 3.0 permissive, but domains only, no labels; popularity != legitimate) | No (disqualified from docs) | STOP from integration |
| Tranco (domain ranking) | REQUIRES TERMS REVIEW (Cloudflare CC BY-NC upstream component; domains only) | No (disqualified from docs) | STOP from integration |
| URLhaus (abuse.ch) | NOT CLEARLY COMPATIBLE for deployment (commercial API paid; community fair-use) + label STOP (malware, not phishing) | No (disqualified from docs) | STOP from integration |
| Ozcelik Phishing URL Features (Kaggle 2026) | Face-value CC BY 4.0, but UNAVAILABLE (login required; no bypass attempted) | No | UNAVAILABLE |
| PhishVN v4 / PhishBD_2026 / LegitPhish / URL-Phish v2 (Mendeley) | Declared CC BY 4.0, but UNAVAILABLE (401, no bypass) + upstream/provenance review outstanding | No | UNAVAILABLE |
| ISCX-URL2016 | License unspecified; UNAVAILABLE (form error, identifying details requested, none submitted) | No | UNAVAILABLE |
| PhishStorm (Aalto, original) | LICENSE UNSPECIFIED | No | STOP (Innovatiana mirror ODbL claim is not authoritative) |
| OpenPhish (direct feed) | NOT CLEARLY COMPATIBLE (non-commercial only; no commercial detection/product use without consent) | No | Not pursued |
| PhishTrap (HF `saidutta69/PhishTrap`, rev `31585632`) | REQUIRES TERMS REVIEW — MIT card, but legitimate class is the Tranco top-10K and inherits Cloudflare Radar **CC BY-NC 4.0**; phishing class includes OpenPhish rows | **Yes (19,948 rows, this phase)** | STOP from production training. **Diagnostic use only** — supplied the 7,810 legitimate apex-root rows that made the apex test possible |
| PhishBench-External / D4V (Mendeley 10.17632/2ctjcnm9kn) | Face-value CC BY 4.0, but legitimate class is Tranco-derived (same NC upstream concern) | No | UNAVAILABLE (file API 404 / error 400; no bypass attempted) |
| Verified Phishing & Legitimate URL Dataset 2026 (IEEE DataPort 10.21227/0hy1-z117) | LICENSE UNSPECIFIED on the record | No | UNAVAILABLE (paid institutional subscription required) |
| vonpower/PhishingDataset, 999Roti/phishing-dataset, Mitake HF mirror | Unspecified / share-alike / no provenance statement | No | STOP (license or provenance insufficient) |

**Bottom line: no CLEAR production-compatible dataset with verified legitimate apex-root coverage was found. Per the gate checklist: STOP. Do not train.**

### Why the blocker is structural, not a search failure

The second research pass established *why* the gap persists. Legitimate apex-root
URLs are, by definition, bare registered domains — and every large, readily
available source of bare domains is a **popularity ranking, not a safety label**:

| Source of bare legitimate domains | Problem |
|---|---|
| Tranco | Aggregates Cloudflare Radar under **CC BY-NC 4.0** (non-commercial) and CrUX CC BY-SA 4.0 |
| Majestic Million | CC BY 3.0 and permissive, but ranks popularity, not safety; no labels |
| Cisco Umbrella / retired Alexa | Free redistribution terms unclear; Alexa retired |
| Common Crawl derived lists | Crawl membership is not a legitimacy judgment |
| ROR / .edu / .gov lists | "high-authority institution" is an assumption, and coverage is narrow |

Every labeled benign corpus that *does* exist is blocked for a different reason:
PhreshPhish is research-only by its own card; EdgePhish-5G inherits OpenPhish's
non-commercial terms; PhishStorm's license is unspecified; ISCX-URL2016 has no
dataset-specific license and an identity-gated form; the Mendeley and Kaggle sets
are access-gated.

The result is a structural gap: **the public data ecosystem offers either
license-clear labels with degenerate URL shapes (PhiUSIIL), or realistic URL shapes
with unusable license terms.** PhishTrap demonstrates the trade-off precisely — it
is the only openly downloadable source found that supplies 7,810 legitimate
apex-root rows, and it is unusable for production for exactly the licensing reason
the others are.

## Candidate records

### 1. PhiUSIIL Phishing URL Dataset (canonical)

- Official source: https://archive.ics.uci.edu/dataset/967/phiusiil+phishing+url+dataset (UCI ML Repository, ID 967)
- Download source: same UCI record (already in `data/raw/`)
- Publisher: Prasad & Chandra, Babasaheb Bhimrao Ambedkar University
- License: CC BY 4.0, "sharing and adaptation for any purpose, provided appropriate credit" (verified live 2026-09-25; no research-only restriction)
- Usage restrictions: attribution required; none blocking public deployment found
- Label semantics: 1 = legitimate, 0 = phishing (documented; verified binary)
- Total records: 235,795 (134,850 legit / 100,945 phish); cleaned 234,894
- Legitimate apex-root coverage: **0** (known representation gap)
- HTTP/HTTPS: legit all-HTTPS; phish mixed
- www/non-www: legit all-www; phish mixed
- Root/path, query, subdomain: documented in robustness reports
- Provenance: peer-reviewed (Computers & Security 2024); webpage-derived columns ignored by URL-only pipeline
- Known limitations: zero legit non-www apex training signal; `https://example.com/` currently predicts phishing
- Status: **CLEAR FOR INTENDED USE** (keep attribution in README/metadata)

### 2. EdgePhish-5G (downloaded and row-verified this phase)

- Official source: https://doi.org/10.5281/zenodo.19371661 (Zenodo record 19371661)
- Download source: same record, `balanced_urls.csv` via open files API (no auth, no bypass); stored at `data/candidates/EdgePhish5G/balanced_urls.csv` + `source_manifest.json`
- Publisher: Hassan Saeed AlBattra (Misr University for Science and Technology)
- License: record label CC BY 4.0; upstream declared: PhishTank, OpenPhish, a Kaggle dataset, Alexa Top Sites, Common Crawl
- Usage restrictions: **OpenPhish Terms of Use** (verified): personal/academic/independent/personal research only; commercial purposes including detection, threat intel, product development, automation, customer protection organizatonally barred without prior written consent; Community Feed non-commercial only. This taints derived phishing rows.
- Label semantics: string `legitimate`/`phishing`, self-describing; project mapping legitimate->1, phishing->0. Columns `['label','url']` (project loader expects `URL,label`; adapter needed if ever approved — not now)
- Total records: **340,000** (170,000 / 170,000), 0 empty URLs; SHA-256 `8a864a7f…c3d4d`, 30,777,577 bytes
- Invalid (project normalizer): 17 phishing, 0 legitimate; unique normalized 339,680; duplicate rows 303; internal conflict groups 0
- Legitimate apex-root coverage: **2,487** (PSL ICANN+PRIVATE, non-www, root path); phishing apex-root 3,117
- HTTP/HTTPS: legit http 56,785 / https 113,215; phish http 166,205 / https 3,684 (+111 missing scheme)
- www/non-www: legit www 122,399; phish www 47,256
- Root/path: legit root-path 4,915; phish 11,456. Query: legit 29,752; phish 37,468. Apex-with-path: legit 44,227; phish 67,054
- Provenance: Zenodo open record, GitHub derivation noted, 314 downloads at check; 5G slice columns are heuristic proxies (not used here)
- Known limitations: upstream OpenPhish restriction; Alexa retired; Kaggle/Crawl vintage unclear; 17 invalid URLs; 303 dups
- Status: **NOT CLEARLY COMPATIBLE** — STOP from production training

### 3. PhishTank verified feed (not downloaded)

- Official source: https://www.phishtank.com/ ; data: http://data.phishtank.com/data/online-valid.csv (hourly; key for routine/automated use, few/day without)
- Publisher: OpenDNS/Cisco (PhishTank, incl. Threat Intelligence Group)
- License: Terms state Data (incl. API info) available for commercial use without charge; page also carries a CC BY-SA 2.5 notice of unclear scope over "the work"
- Usage restrictions: rate limits; app key for automation (registration needs email — not submitted here)
- Label semantics: verified-online phishing only; no legitimate class
- Coverage fields: phishing-only, so apex/www/scheme distributions cannot fix the legitimate gap; legitimate counts N/A
- Status: **REQUIRES TERMS REVIEW** (sharealike scope + key regime). Single limited download deferred to avoid rate-limit gray areas; phishing-only makes it non-decisive for this phase.

### 4. Majestic Million (domain list; not a labeled URL dataset)

- Official source: https://majestic.com/reports/majestic-million ; CSV: http://downloads.majestic.com/majestic_million.csv (free, max ~1/day)
- Publisher: Majestic
- License: CC BY 3.0 per publisher blog (share/adapt with credit)
- Label semantics: NONE — popularity ranking of domains, no URL labels. "Popular implies legitimate" is an assumption, not verification; lists can contain compromised domains
- Status: **REQUIRES TERMS REVIEW + label STOP**. Not downloaded (disqualified from authoritative schema; full fetch adds no labels).

### 5. Tranco ranking (domain list)

- Official source: https://tranco-list.eu/
- License/terms: research-oriented service; underlying inputs include Cloudflare Radar under **CC BY-NC 4.0** (non-commercial) — incompatible with general deployment absent review
- Label semantics: NONE (domains only; constructed `https://domain/` URLs are synthetic, not observed)
- Status: **REQUIRES TERMS REVIEW + label STOP**. Not downloaded as training data.

### 6. URLhaus (abuse.ch)

- Official source: https://urlhaus.abuse.ch/about/ ; API: https://urlhaus.abuse.ch/api/
- License/terms: community API free under fair use; commercial/for-profit use may require paid Spamhaus commercial API
- Label semantics: **malware URLs, not phishing** — label mapping cannot be established for a phishing classifier
- Status: **NOT CLEARLY COMPATIBLE + label STOP**. Not downloaded.

### 7. Ozcelik et al. Phishing URL Features Dataset (Kaggle, 2026)

- Official source: https://www.kaggle.com/datasets/elifzelik/phishing-url-features-dataset
- Publisher: Ozcelik, ElSilk, Osmanoglu (2026), DOI 10.34740/kaggle/dsv/15339081
- License: CC BY 4.0 (face value from record snippet)
- Label semantics: source snippet reports `0` = legitimate, `1` = phishing — **reversed** vs PhishGuard convention; must be explicitly remapped if ever approved
- Records (source-claimed): 579,920 (339,074 legit / 240,846 phish); raw-URL column presence unconfirmed (page JS-gated; not verified)
- Download: login-gated; no bypass attempted
- Status: **UNAVAILABLE** (plus mapping + column verification outstanding)

### 8. Mendeley candidates (carried forward)

PhishVN v4, PhishBD_2026, LegitPhish, URL-Phish v2: declared CC BY 4.0; no-auth file retrieval 401; no bypass; upstream/provenance gaps (withheld feeds, malware-vs-phishing ambiguity, constructed `http://` baselines, tier noise) per `docs/candidate_dataset_audit.md`. Status: **UNAVAILABLE** (each needs authorized fetch + full row/label/license review).

### 9. ISCX-URL2016 / PhishStorm (carried forward)

- ISCX: five-class (benign/spam/phishing/malware/defacement), form error + identifying details requested (none submitted); no dataset-specific license found. **UNAVAILABLE**.
- PhishStorm original (Aalto): license **UNSPECIFIED**; file 403. Third-party ODbL mirror claims are not authoritative. **STOP**.

### 10. PhishTrap (downloaded and row-verified this phase; DIAGNOSTIC ONLY)

- Official source: https://huggingface.co/datasets/saidutta69/PhishTrap (revision `3158563225c7fb600ca30c9af3183c20cbfb9ada`)
- Download source: same, `data/phishtrap_full.csv` via open HTTPS resolve. No authentication, no access-control bypass.
- Publisher: `saidutta69`; build pipeline `github.com/instax-dutta/PhishTrap`
- License: **REQUIRES TERMS REVIEW.** Card declares MIT for the compilation and the pipeline is MIT, but the card does not cover upstream data rights:
  - legitimate class = Tranco top-10K, which aggregates Cloudflare Radar under **CC BY-NC 4.0** (non-commercial) and CrUX under CC BY-SA 4.0;
  - phishing class = Phishing.Database (MIT) 9,962 rows, PhishStats 9 rows, **OpenPhish 3 rows** (non-commercial for detection/product use).
  - Conclusion: the MIT card covers the compilation, not the underlying data. Not cleared for a public deployment.
- Label semantics: numeric, and **inverted relative to PhishGuard** — `0 = legitimate`, `1 = phishing`. Verified against the card and by row inspection (apex domains such as `higgsfield.ai` carry label 0). Any use must remap as `project = 1 - phishtrap`; the apex test script asserts this.
- Total records: **19,948** (`legitimate` 9,974 / `phishing` 9,974), 0 invalid URLs, 19,947 unique normalized, 1 duplicate row, **0 conflicting label groups**.
- **Legitimate apex-root coverage: 7,810** — the coverage the canonical corpus lacks. Legitimate: 9,973 http / 0 https, 7,810 apex-root, 1,687 non-www subdomain, 476 `www`, 0 queries, 0 apex-with-path.
- Phishing: 5,994 apex-root, 3,974 non-www subdomain, 9 with query, 12 https.
- Provenance: documented pipeline, source column retained per row (`tranco`, `phishing_database`, `phishstats`, `openphish`).
- Known limitations: every legitimate row is a **constructed `http://` URL**, so the class is scheme-degenerate and would inject a fresh HTTP-is-legitimate bias if trained on; legitimate labels are a popularity inference, not a safety judgment.
- Status: **NOT CLEARLY COMPATIBLE for production training.** Used **only** as a diagnostic measurement source in `docs/apex_representation_test.md`, where it produced the project's most important finding: 0 of 4,163 legitimate URLs classified correctly, decomposable into an independent scheme bias and an independent apex bias.

### 11. PhishBench-External / D4V (Mendeley, not obtained)

- Official source: https://data.mendeley.com/datasets/2ctjcnm9kn/1 — CC BY 4.0, 1,000 URLs (500 legitimate from Tranco, 500 phishing from PhishTank), compiled July 2025, explicitly designed as an external test set.
- Access: `api.data.mendeley.com` and the public files API both returned errors (404 / `{"error":400}`) for unauthenticated requests. No credentials were used and no restriction was bypassed.
- License caveat: even if obtained, the legitimate class is Tranco-derived and inherits the same CC BY-NC 4.0 upstream component.
- Status: **UNAVAILABLE.**

### 12. Verified Phishing & Legitimate URL Dataset 2026 (IEEE DataPort, not obtained)

- Official source: https://ieee-dataport.org/documents/phishing-urldataset — DOI 10.21227/0hy1-z117, Jadhav & Chandre, created 2026-08-08. Phishing from PhishTank; legitimate from Majestic Million, Cisco Umbrella, Tranco, Common Crawl, and official government/education/finance/health sites. Labels `0 = Legitimate, 1 = Phishing` (inverted vs PhishGuard).
- Access: the record states a subscription is required and renders "LOGIN TO ACCESS DATASET FILES". Not logged in; nothing submitted.
- License: no license statement is present on the record. Not treated as permissive.
- Status: **UNAVAILABLE + LICENSE UNSPECIFIED.** Note that its legitimate class is also ranking-derived and therefore carries the same popularity-is-not-safety caveat.

## Method notes

- No access controls bypassed; no credentials used; no personal details submitted; no restricted files fetched.
- EdgePhish is the only new row-level file; it lives in `data/candidates/EdgePhish5G/` (never `data/raw/`); canonical CSV untouched.
- Structure counts use `normalize_url` + stdlib parsing; apex uses PSL ICANN+PRIVATE via `tldextract` (same definition as the PhreshPhish audit).
- Labels were never invented or remapped silently; reversed/conflicting mappings are documented as integration blockers.
