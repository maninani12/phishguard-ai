# Candidate Dataset Acquisition & Verification Audit

**Audit date:** 2026-09-25  
**Scope:** source review and read-only URL/label audit; no dataset integration, training, model change, deployment, commit, or push.

## Executive result

Only **PhreshPhish** was obtained as a complete URL/label audit projection. Its 666,315 source rows were read from the public Hugging Face Parquet viewer/API, projecting out the large HTML payload; the original 36.6 GB Parquet collection was not downloaded. The audit CSV is at [`data/candidates/PhreshPhish/phreshphish_url_label_audit.csv`](../data/candidates/PhreshPhish/phreshphish_url_label_audit.csv), with an extraction manifest and summary beside it. An interrupted first pass remains preserved as `phreshphish_url_label_audit.csv.partial`; it is incomplete and was not used for counts.

PhreshPhish contains **7,962 source-labeled benign apex/non-www root URLs** and **74,613 source-labeled phish apex/non-www root URLs** under the Public Suffix List definition below. These are dataset labels, not an independent assessment of whether any URL is currently safe or malicious. The dataset card says CC BY 4.0 and “should only be used for anti-phishing research”; its use in a deployed product therefore requires license/terms review. No candidate is approved or selected for training.

For the six other candidates, official documentation was reviewed, but no underlying data file was available to this audit. Their row-level counts, structures, apex examples, duplicates, and overlaps are therefore **NOT AVAILABLE / UNVERIFIED**, not inferred from documentation. Mendeley pages list download controls, but unauthenticated file retrieval returned 401 through the documented file API. No credentials, access-control workaround, or personal details were used. ISCX's official download form returned an error and asks for identifying details; no personal information was submitted. PhishStorm's license is unspecified, so its file was not obtained.

## Method and definitions

- No candidate URL was opened, visited, resolved, or requested. Only dataset/source pages and the public PhreshPhish Parquet dataset itself were read.
- Source-reported metadata and locally measured rows are kept distinct. “Actual” below means read from an obtained dataset file; it is not a ground-truth re-labeling exercise.
- For PhreshPhish, `benign` is mapped to project label `1` (legitimate) and `phish` to project label `0` (phishing). Samples below preserve the publisher's string class label.
- Apex means the parsed hostname is exactly the registrable domain under the Public Suffix List's ICANN **and PRIVATE** sections, and does not start with `www.`. Apex root means its path is empty or `/`; apex with path means a non-root path. This treats tenant domains under PRIVATE suffixes as registrable domains. Rows with no registrable-domain result and IP hosts are counted separately.
- URL structure counts use source URLs without contacting their destinations. Path, scheme, query, fragment, explicit port, percent-encoding, punycode, URL/domain lengths, and subdomain count were parsed from the URL text. The audit's “suspicious keyword” indicator is only a lexical audit heuristic; it is not a dataset label, a current project feature, or a verdict.
- PhreshPhish comparisons use the current project functions `src.feature_schema.normalize_url` and `src.data_loader.clean_url_labels` on both candidate and canonical rows. They are comparisons only; no merge was performed.

## Candidate decision table

“Downloaded” refers to an actual local candidate data file/projection, not the presence of a public record page. Dataset descriptions below are source claims unless marked as measured.

| Dataset | Downloaded | Labels verified | Provenance verified | License verified | Legit apex root found | Actual rows verified | Further review |
|---|---|---|---|---|---|---|---|
| PhishVN v4 | NOT AVAILABLE (no-auth file retrieval unavailable) | VERIFIED at source-description/tier level; no local rows | VERIFIED at source-description level | VERIFIED declared CC BY 4.0 for open files; review upstream/source and gated-file terms | UNVERIFIED | NOT AVAILABLE | REQUIRES REVIEW |
| PhishBD_2026 | NOT AVAILABLE (no-auth file retrieval unavailable) | LABEL MAPPING UNVERIFIED | VERIFIED at source-description level; four feed names withheld | VERIFIED declared CC BY 4.0; underlying source/partner restrictions need review | UNVERIFIED | NOT AVAILABLE | REQUIRES REVIEW |
| PhreshPhish | VERIFIED URL/label projection, all rows | VERIFIED (`benign` / `phish`) | VERIFIED to dataset card/paper and source fields | REQUIRES REVIEW (research-only use statement) | VERIFIED in actual rows | VERIFIED (666,315) | REQUIRES REVIEW |
| LegitPhish | NOT AVAILABLE (no-auth file retrieval unavailable) | VERIFIED as described by source; no local rows | REQUIRES REVIEW (source descriptions differ) | VERIFIED declared CC BY 4.0; upstream provenance needs review | UNVERIFIED | NOT AVAILABLE | REQUIRES REVIEW |
| URL-Phish v2 | NOT AVAILABLE (no-auth file retrieval unavailable) | VERIFIED in official record (0 benign, 1 phishing) | VERIFIED at source-description level | VERIFIED declared CC BY 4.0 | UNVERIFIED | NOT AVAILABLE | REQUIRES REVIEW |
| ISCX-URL2016 | NOT AVAILABLE (official download form error / identifying details requested) | VERIFIED class names; file-level encoding unavailable | VERIFIED at institutional source-description level | REQUIRES REVIEW (no dataset-specific license statement found) | UNVERIFIED; source says domain-only benign URLs were removed | NOT AVAILABLE | REQUIRES REVIEW |
| PhishStorm | NOT AVAILABLE (license unspecified; no file obtained) | VERIFIED in official record (0 legitimate, 1 phishing) | VERIFIED at source-description level | REQUIRES REVIEW (unspecified) | UNVERIFIED | NOT AVAILABLE | REQUIRES REVIEW |

## Dataset-by-dataset findings

### 1. PhishVN v4

- **Official source / publisher:** [Mendeley Data record, version 4](https://data.mendeley.com/datasets/b97hxbxtpd/4), contributed by Thai Nguyen Vu and associated with the University of Transport and Communications. Author documentation: [PhishVN repository](https://github.com/vuthainguyen1602/phishvn), especially its [datasheet](https://raw.githubusercontent.com/vuthainguyen1602/phishvn/master/docs/datasheet.md), [source notes](https://raw.githubusercontent.com/vuthainguyen1602/phishvn/master/docs/data_sources.md), and [schema](https://raw.githubusercontent.com/vuthainguyen1602/phishvn/master/docs/schema.md).
- **Download source:** Mendeley record lists `dataset_url.csv`, split CSVs, documentation, and a Download All control. The documented [Mendeley file API](https://data.mendeley.com/api/docs/) required OAuth for file retrieval; the unauthenticated request used for this audit returned 401. No data file was obtained and no restriction was bypassed. The page's Download All control means this is a local access limitation, not proof that an account-based/manual download is impossible.
- **Reported size:** 53,116 rows: 18,997 verified-core records (2,587 NCSC-feed phishing and 16,410 legitimate) plus a separately tagged 34,119-row bronze phishing expansion. Source-reported gold=9,593 and silver=9,404 sum to the 18,997 core; bronze=34,119. Do not collapse the tiers without preserving them.
- **Label semantics / audit:** Source describes phishing-feed and legitimate classes plus confidence tiers. Its published completed annotator audit reports Cohen's kappa 0.609 for four-way abuse type and 0.725 for abuse-vs-legitimate; estimated positive-arm label noise 12.1% (95% CI 7.1–20.0%), concentrated in bronze, and 4.0% in benign rows. The source says its positive class is broader than credential phishing: only 42.5% of defensible positive labels are credential phishing. These are publisher-reported results, not independently recomputed here.
- **Provenance / coverage:** NCSC `Tin Nhiem Mang`, ChongLuaDao, OpenPhish, certified trusted-organization registry, `.vn` Tranco, and global Tranco are described. Gold/silver/bronze have different confidence and collection meanings; the bronze expansion includes community/feed-derived items and has materially higher reported label uncertainty. Source says `is_https` is a collection artefact; source documentation advises excluding it from modeling. It reports raw URL records and lexical features, so the URL field appears compatible with a URL-only extractor, but no actual file was inspected here.
- **Actual row/structure audit:** NOT AVAILABLE. Valid/invalid/missing URLs, actual class counts by tier, actual legitimate apex-root examples, duplicate/overlap counts, and URL-structure distributions were not measured.
- **License / deployment:** Mendeley declares CC BY 4.0 for the open files. Captured HTML/screenshots are a separate gated tier under a research-only data-use agreement. Confirm attribution and upstream-source terms before any integration or commercial deployment.

### 2. PhishBD_2026

- **Official source / publisher:** [Mendeley Data record](https://data.mendeley.com/datasets/8d6zsfwc7z/1), from authors affiliated with Notre Dame University Bangladesh, Bangladesh University of Professionals, and Daffodil International University.
- **Download source:** Mendeley record is the original source and describes a CSV; no file was obtained through the unauthenticated API attempt (401). No authentication or access-control workaround was attempted.
- **Reported size / format:** 131,167 URLs (91,817 phishing; 39,350 legitimate), with a raw URL, binary label, and 73 engineered features; the record describes a 75-column CSV and URL-level deduplication.
- **Label semantics:** **LABEL MAPPING UNVERIFIED.** The official record gives class counts but does not state what numeric label 0 and label 1 mean. Do not infer the bit mapping.
- **Provenance:** Phishing data is described as four unnamed threat-intelligence feeds plus an incident spreadsheet from a Bangladeshi financial institution; feed providers are withheld under a confidentiality agreement. Legitimate sources include Tranco, ISCX, Majestic Million, and manually verified Bangladeshi sites. These are the source's statements; underlying records were unavailable for inspection.
- **Constructed HTTP root-style records:** The official method says the legitimate baseline started with the top 10,000 Tranco domains prefixed with `http://`, then used the same parsing/features. This documents a constructed scheme prefix, not independently observed HTTP visits. Because the CSV was not available, the final surviving exact strings, labels attached to them, final per-class HTTP/HTTPS distribution, and apex-root counts could not be verified. No claim is made that those are observed HTTP URLs.
- **Actual row/structure audit:** NOT AVAILABLE. All URL-level validity, duplicates, class-specific structures, apex examples, overlap, and split details remain unmeasured.
- **License / deployment:** Mendeley declares CC BY 4.0. The unnamed-feed and partner incident-data terms cannot be inspected from the public record; obtain source-rights clarification before integration or deployment.

### 3. PhreshPhish

- **Official source / publisher:** [Hugging Face dataset record](https://huggingface.co/datasets/phreshphish/phreshphish), [paper](https://arxiv.org/abs/2507.10854), and the [public Parquet viewer API](https://datasets-server.huggingface.co/parquet?dataset=phreshphish%2Fphreshphish). The Parquet source revision recorded in the local manifest is `eabec4b7a66324b79cc8a0ad856d1731dc26fe1a`.
- **Acquisition:** Complete 666,315-row URL/label projection; not the full HTML-bearing source. CSV: `data/candidates/PhreshPhish/phreshphish_url_label_audit.csv`; UTF-8, comma-separated, 9 columns: `url`, `label`, `target`, `date`, `lang`, `lang_score`, `source_split`, `source_shard`, `source_row`. `url` is the URL field and `label` is `benign` / `phish`. Export size 83,790,252 bytes; SHA-256 `ac08bfd0e6c03874f83f5d682266952bb365b8546af12282fae967bca2333cee`. The source has 77 Parquet shards totaling 36,576,373,578 bytes; HTML and source `sha256` columns were omitted from the audit projection. No destination website was contacted.
- **Label mapping / provenance:** `benign`→project legitimate `1`; `phish`→project phishing `0`. The paper describes phishing sources including PhishTank, APWG eCrime Exchange, and Netcraft; benign sources include anonymized browsing telemetry and Google search results. It is an HTML/URL-pair dataset, but the raw URL makes URL-only feature extraction technically possible without fetching sites. Source provenance and collection are summarized in the [paper](https://arxiv.org/abs/2507.10854).
- **Reported vs measured split totals:**

  | Split/class | Source page reports | Extracted Parquet rows |
  |---|---:|---:|
  | Train benign | 276,729 | 276,729 |
  | Train phish | 221,526 | 221,526 |
  | Test benign | 91,260 | 91,260 |
  | Test phish | 76,876 | 76,800 |
  | Total | 666,315 | 666,315 |

  The source page's test class counts sum to 168,136, exceeding its stated 168,060 test rows by 76. Extracted shard counts sum to 168,060, with 76 fewer phish rows than the page reports. This discrepancy is unresolved and is retained explicitly.

- **Actual row and label totals:** 666,315 rows: 367,989 `benign` and 298,326 `phish`. No missing URL rows; 367,989 benign URLs parse validly, while 298,325 phishing URLs parse validly and one does not.
- **Cleaning / duplicates:** 0 exact raw duplicate rows. There are 666,271 valid normalized unique URLs before the project's conflict/deduplication cleaner. URL normalization finds 43 duplicate groups/rows and one conflicting-label group. The project's existing cleaner removes one invalid URL, both rows in the conflicting group, and 42 repeated normalized rows, leaving 666,270 unique cleaned rows: 367,987 label `1` and 298,283 label `0`.
- **Apex-critical result:** 7,962 benign apex-root rows (2.1637% of benign class) and 74,613 phish apex-root rows (25.0106% of phish class). Benign apex with non-root path: 56,187. Phish apex with non-root path: 89,548. Apex here uses PSL ICANN+PRIVATE registrable-domain parsing and excludes `www`; examples and exact rows appear in [`candidate_dataset_samples.md`](candidate_dataset_samples.md). These are only source labels.
- **Canonical overlap:** after applying the project normalizer and cleaner to both datasets, 1,579 normalized URLs overlap the canonical dataset: 152 candidate label-0 rows and 1,427 label-1 rows. Eight overlapping normalized URLs have opposite labels. Examples: `https://www.brooklinen.com/` (candidate 0 / canonical 1), `http://www.coinbase.com/` (candidate 1 / canonical 0), and `https://www.unesco.gov.ph/` (candidate 0 / canonical 1). These differences demonstrate a concrete label/provenance review need; this is not an integration or label adjudication.
- **License / deployment:** Dataset card declares CC BY 4.0 and says the dataset should only be used for anti-phishing research. Audit-only review was within this task's purpose; suitability for commercial or production use is **REQUIRES REVIEW**. Do not treat this as deployment approval.

### 4. LegitPhish

- **Official source / publisher:** [Mendeley Data record, version 2](https://data.mendeley.com/datasets/hx4m73v2sf/2); related [Data in Brief paper](https://pmc.ncbi.nlm.nih.gov/articles/PMC12538017/).
- **Download source:** Mendeley record; file not obtained using unauthenticated file retrieval (401), and no authentication bypass was attempted.
- **Reported size / labels:** 101,219 claimed rows; source describes 63,678 phishing (`0`) and 37,540 legitimate (`1`), totaling 101,218—one fewer than the stated total. Raw `URL` is documented, alongside engineered columns.
- **Provenance / limitations:** Mendeley description refers to URLHaus and other repositories/threat sources for phishing and reputable websites such as Wikipedia/Stack Overflow for legitimate URLs. The paper/record descriptions are not fully consistent about the phishing source and “manual verification.” URLHaus is a malware URL feed, which is not itself equivalent to a phishing-specific label. These claims need source-level clarification; no actual rows were available to reconcile them.
- **Actual row/structure audit:** NOT AVAILABLE. URL validity, structure, apex-root examples, duplicates, overlaps, and actual file counts remain unverified.
- **License / deployment:** Mendeley declares CC BY 4.0. Upstream data rights and labeling methodology require review before reuse.

### 5. URL-Phish v2

- **Official source / publisher:** [Mendeley Data record, version 2](https://data.mendeley.com/datasets/65z9twcx3r/2), contributed by authors affiliated with the Posts and Telecommunications Institute of Technology.
- **Download source:** Mendeley record describes CSV; file not obtained with unauthenticated file retrieval (401). No access restriction was bypassed.
- **Reported size / labels:** 116,600 unique URLs: 100,000 benign (`0`) and 16,600 phishing (`1`)—the reverse of the current PhishGuard label convention. Raw fields `url`, `dom`, `tld`; 22 engineered numeric features and label (26 columns total). The official record identifies ROR as a benign source and PhishTank as a phishing source.
- **Actual row/structure audit:** NOT AVAILABLE. Published counts and bit mapping are verified only from source documentation; local row-level totals, apex-root coverage, URL structures, duplicates, and overlaps are unverified.
- **License / deployment:** Mendeley declares CC BY 4.0. Review source attribution and any upstream-data terms; the label reversal must be explicitly handled if later approved.

### 6. ISCX-URL2016

- **Official source / publisher:** [University of New Brunswick Canadian Institute for Cybersecurity dataset page](https://www.unb.ca/cic/datasets/url-2016.html); official [download form](https://cicresearch.ca/CICDataset/ISCX-URL-2016/) and [UNB dataset FAQ](https://www.unb.ca/cic/datasets/).
- **Reported classes / approximate size:** over 35,300 benign; around 12,000 spam; around 10,000 phishing; over 11,500 malware; over 45,450 defacement. These are rounded/minimum counts from the source page, not an exact locally measured total. It is a five-category dataset, not a documented binary label-bit file in the source page.
- **Structure finding:** UNB says benign URLs were crawled from Alexa top websites, deduplicated, and “domain only” URLs removed before VirusTotal screening. This published construction suggests the benign class is not suitable evidence for bare apex-root URLs. It does not establish actual row-level URL structures.
- **Access / license:** Official form returned “Server error. Please try again later” and asks for name, email, organization, job title, and country. No identifying information was submitted. UNB's general FAQ allows redistribution/republication with citation, but the dataset page did not state a dataset-specific license; obtain license clarification before reuse.
- **Actual row/structure audit:** NOT AVAILABLE. No file, label-bit mapping, apex examples, row counts, or overlaps were measured.

### 7. PhishStorm

- **Official source / publisher:** [Aalto University research portal record](https://research.aalto.fi/en/datasets/phishstorm-phishing-legitimate-url-dataset/), dataset creator Samuel Marchal.
- **Download source / reported size:** Portal lists `urlset.csv.zip` (3.24 MB); the linked [official file URL](https://research.aalto.fi/files/16859732/urlset.csv.zip) returned HTTP 403 when checked. The record reports 96,018 URLs, exactly 48,009 legitimate and 48,009 phishing, with a `domain` field that the portal explains actually contains the URL and a `label` field.
- **Label mapping:** Source documents `0 = legitimate`, `1 = phishing` (reverse of PhishGuard's current mapping).
- **Access / license:** The portal marks the dataset license “Unspecified.” Since the task allows obtaining data only where terms permit it, no file was downloaded. License and permitted reuse require clarification.
- **Actual row/structure audit:** NOT AVAILABLE. Published counts/semantics are documented, but row validity, actual apex-root examples, URL structures, duplicate rate, and overlap are unverified.

## Structure audit for the obtained PhreshPhish URL/label projection

Counts below are row counts; percentages are within the source-labeled class (including the one invalid phishing URL in the class denominator, so a few phishing categories total 99.9997%). For structural columns, values are extracted from URL text only.

### Hostname structure

| Class | Rows | Apex root | Apex, non-root path | `www` host | Other subdomain | IP host | Registrable-domain unknown |
|---|---:|---:|---:|---:|---:|---:|---:|
| benign | 367,989 | 7,962 (2.1637%) | 56,187 (15.2687%) | 213,332 (57.9724%) | 90,489 (24.5901%) | 0 (0%) | 19 (0.0052%) |
| phish | 298,326 | 74,613 (25.0106%) | 89,548 (30.0168%) | 21,191 (7.1033%) | 111,592 (37.4061%) | 796 (0.2668%) | 585 (0.1961%) |

### Scheme, path, and query

| Class | HTTP | HTTPS | Missing scheme | Root path | Non-root path | No query | Query present |
|---|---:|---:|---:|---:|---:|---:|---:|
| benign | 2,212 (0.6011%) | 360,036 (97.8388%) | 5,741 (1.5601%) | 27,423 (7.4521%) | 340,566 (92.5479%) | 367,921 (99.9815%) | 68 (0.0185%) |
| phish | 41,072 (13.7675%) | 257,253 (86.2322%) | 0 (0%) | 151,593 (50.8145%) | 146,732 (49.1851%) | 263,576 (88.352%) | 34,749 (11.648%) |

No other URL schemes were counted. The single invalid phishing URL is excluded from parse-derived fields.

### Other URL characteristics

| Class | No fragment / fragment | Explicit port | Percent-encoded chars present | Punycode present | Audit keyword heuristic present |
|---|---:|---:|---:|---:|---:|
| benign | 367,988 / 1 (0.0003% fragment) | 0 | 4,508 (1.225%) | 61 (0.0166%) | 22,742 (6.1801%) |
| phish | 296,724 / 1,601 (0.5367% fragment) | 1,051 (0.3523%) | 11,517 (3.8605%) | 626 (0.2098%) | 45,592 (15.2826%) |

| Class | URL length mean / median / p90 / max | Domain length mean / median / p90 / max | Subdomain count mean / median / p90 / max |
|---|---|---|---|
| benign | 60.5656 / 55 / 95 / 1,414 | 17.5222 / 17 / 24 / 92 | 0.8548 / 1 / 1 / 5 |
| phish | 55.3669 / 39 / 88 / 25,523 | 24.5539 / 23 / 37 / 114 | 0.4905 / 0 / 1 / 13 |

These are descriptive differences, not evidence that any one structure causes a label or that a URL is malicious. The class labels have their source-specific provenance and limitations.

## URL-only pipeline compatibility and overlap

The PhreshPhish projection includes a raw `url` and string `label`, so it can be mechanically passed through the existing URL-only feature extractor after an explicit, approved label mapping. Its extra provenance, split, language, target, and date fields must remain excluded from features. This is a compatibility observation only, not approval to integrate. Other candidates' documentation identifies raw URL fields for PhishVN, PhishBD_2026, LegitPhish, and URL-Phish; their actual files were unavailable, so their column and normalization details have not been confirmed. The ISCX file schema was likewise not inspected.

Only PhreshPhish could be compared against another actual candidate file (there were no other downloaded candidates), so candidate-to-candidate overlap is otherwise NOT AVAILABLE. The Phresh-vs-canonical comparison found 1,579 normalized unique URL overlaps after cleaning both sources and eight opposite-label overlap URLs. Do not combine these datasets without reviewing conflicts and preventing source duplicates/conflicts from contaminating train/test evaluation.

## Recommended next review steps (no selection)

1. For each Mendeley candidate, obtain its original file through an authorized, ordinary source download and preserve source version/checksum; do not work around OAuth or account checks.
2. Resolve PhishBD's numeric label mapping and document its feed/provider/partner rights; specifically audit the final CSV's `http://`-prefixed legitimate baseline rows against source provenance.
3. For PhishVN, inspect gold, silver, and bronze separately; preserve tier and upstream provenance. Review the author's completed annotation audit and upstream terms before any non-research deployment.
4. For PhreshPhish, resolve the 76-row split class-count discrepancy with the publisher, and get written clarity on research-only wording before production use.
5. For every candidate that is later approved, compute normalized URL and registrable-domain overlap and label conflicts against all already-approved data before any model evaluation; hold a separate external evaluation split by domain and time.
6. Do not treat this audit as model training, an endorsement, a license opinion, or a current-URL safety assessment.

## End state

- **Datasets obtained:** PhreshPhish URL/label projection only.
- **Datasets not obtained:** PhishVN v4, PhishBD_2026, LegitPhish, URL-Phish v2, ISCX-URL2016, PhishStorm.
- **Verified legitimate apex-root examples:** present in PhreshPhish; source-labeled benign count 7,962; sample rows in the companion report.
- **Canonical dataset changed:** NO.
- **Model changed:** NO.
- **Training performed:** NO.
- **Backend/frontend/deployment changed:** NO.
- **Dataset integration performed:** NO.
- **Commit/push performed:** NO.

## Addendum 2026-09-25 — production-safe research phase (no training)

PSL-aware evaluation was implemented (`src/domain_split.py` + `tldextract>=5.0`; private PSL domains included); canonical check gives 197,300 registrable groups and a GroupShuffleSplit (20%, seed 42) with train 187,391 rows / 157,840 groups, test 47,503 rows / 39,460 groups, overlap 0. `src/train.py` now uses this splitter for its domain-aware holdout (code integration only; no retraining; previously generated hostname-grouped reports are LEGACY HOSTNAME-GROUPED RESULTS).

EdgePhish-5G (`balanced_urls.csv`, Zenodo 19371661, CC BY 4.0 record) was downloaded openly into `data/candidates/EdgePhish5G/` (30,777,577 bytes, SHA-256 `8a864a7f…c3d4d`) and row-verified: 340,000 rows (`legitimate` 170,000 / `phishing` 170,000, header `label,url`), 17 invalid phishing URLs, 339,680 unique normalized URLs, 303 duplicate rows, 0 internal conflict groups, legitimate apex-root 2,487 and phishing apex-root 3,117 (PSL ICANN+PRIVATE). It is STOPPED from production training because upstream OpenPhish terms bar commercial/detection/product use (non-commercial only). Full candidate table, license verdicts (canonical CLEAR; EdgePhish NOT CLEARLY COMPATIBLE; PhishTank/Majestic/Tranco/URLhaus REQUIRES REVIEW or label-STOP; Kaggle/Mendeley/ISCX UNAVAILABLE; PhishStorm LICENSE UNSPECIFIED), and the gate checklist live in `docs/dataset_research.md` and `docs/production_dataset_requirements.md`. PhreshPhish files are preserved untouched; the 1,579 overlaps / 8 conflicts remain unresolved source disagreements and were never used to edit the canonical dataset. No training, commit, push, or deployment resulted from this phase.
