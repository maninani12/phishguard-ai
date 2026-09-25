# Candidate Dataset URL Samples

**Audit date:** 2026-09-25  
**Safety note:** The examples below are copied from actual PhreshPhish audit-projection rows, all from its `test` split. URLs are rendered as non-clickable code. No destination was visited. `benign` and `phish` are the source's labels; they do not establish that a URL is currently safe or malicious.

## PhreshPhish

Source file: `data/candidates/PhreshPhish/phreshphish_url_label_audit.csv`  
Source: [official dataset page](https://huggingface.co/datasets/phreshphish/phreshphish) and [paper](https://arxiv.org/abs/2507.10854).  
The extracted projection contains all 666,315 URL/label rows. The `target`, `date`, language, and provenance fields were retained for auditability; they are not labels of current safety.

### 1. Legitimate apex root

Definition: hostname is a registrable domain under the ICANN+PRIVATE Public Suffix List, no `www`, and path is empty or `/`.

| Dataset label | URL | Split |
|---|---|---|
| benign | `https://elbow.co.uk/` | test |
| benign | `https://mynavi-ms.jp/` | test |
| benign | `https://schoolcafek12.com/` | test |
| benign | `https://roanoketexas.com/` | test |
| benign | `https://brattysisters.com/` | test |

Measured source-labeled benign root-apex count: **7,962**.

### 2. Legitimate apex with a non-root path

| Dataset label | URL | Split |
|---|---|---|
| benign | `https://calculatodo.com/en/count-days-between-dates` | test |
| benign | `https://punktum.dk/en/customer-service` | test |
| benign | `https://porch.com/checkout/start` | test |

### 3. Legitimate `www` host

| Dataset label | URL | Split |
|---|---|---|
| benign | `https://www.kenhub.com/en/library/anatomy/dorsal-root-ganglion` | test |
| benign | `https://www.berncoclerk.gov/` | test |
| benign | `https://www.postoffice.co.za/Questions/Postalrates.pdf` | test |

### 4. Legitimate other subdomain

| Dataset label | URL | Split |
|---|---|---|
| benign | `https://my.lafarmbureau.com/insurance/home` | test |
| benign | `https://en.wikipedia.org/wiki/History_of_mathematics` | test |
| benign | `https://player.vimeo.com/video/884176531` | test |

### 5. Phish-labeled apex root

Under the PSL definition above, hosting tenants such as `*.pages.dev` are registrable domains because `pages.dev` is a PRIVATE suffix; these sample hostnames have no additional subdomain above the registrable domain.

| Dataset label | URL | Split |
|---|---|---|
| phish | `https://treser-bridge.pages.dev` | test |
| phish | `https://yrytfhgftyrdttt.pages.dev` | test |
| phish | `https://support-phantomwallet.pages.dev` | test |
| phish | `https://begin--strt.pages.dev` | test |
| phish | `https://app-ledger-cloud-sso.typedream.app` | test |

Measured source-labeled phish root-apex count: **74,613**.

### 6. Phish-labeled URL with a path

| Dataset label | URL | Split |
|---|---|---|
| phish | `http://coolfocus.info/google.php` | test |
| phish | `https://ficovenexpress.com/rhoudes/daddddy/h0tmail` | test |
| phish | `https://cypostatu.click/index.html` | test |

### 7. Phish-labeled URL with a query

| Dataset label | URL | Split |
|---|---|---|
| phish | `https://jiu-jitsuinbridport.blogspot.pt/?m=1` | test |
| phish | `https://wi-guy-in-tx.blogspot.com.tr/?m=1` | test |
| phish | `https://livegilfcams.blogspot.si/?m=1` | test |

### 8. Phish-labeled subdomain

| Dataset label | URL | Split |
|---|---|---|
| phish | `https://www1.cmetricsfluence.robinhood-crypto.online/` | test |
| phish | `http://trezr-bridg-begin.tem3.io` | test |
| phish | `http://imap4d-indica.kleinanzegien.de` | test |

## Candidates without obtainable row-level files

No actual URL examples are provided for the following candidates because no dataset rows were obtained in this audit. Source-reported class descriptions do not substitute for actual rows, so apex-root coverage remains **UNVERIFIED**.

| Dataset | Source record | Sample status |
|---|---|---|
| PhishVN v4 | [Mendeley Data](https://data.mendeley.com/datasets/b97hxbxtpd/4) | NOT AVAILABLE — no row file obtained; no examples fabricated |
| PhishBD_2026 | [Mendeley Data](https://data.mendeley.com/datasets/8d6zsfwc7z/1) | NOT AVAILABLE — no row file obtained; no examples fabricated |
| LegitPhish | [Mendeley Data](https://data.mendeley.com/datasets/hx4m73v2sf/2) | NOT AVAILABLE — no row file obtained; no examples fabricated |
| URL-Phish v2 | [Mendeley Data](https://data.mendeley.com/datasets/65z9twcx3r/2) | NOT AVAILABLE — no row file obtained; no examples fabricated |
| ISCX-URL2016 | [UNB/CIC dataset page](https://www.unb.ca/cic/datasets/url-2016.html) | NOT AVAILABLE — official form failed; no examples fabricated |
| PhishStorm | [Aalto University record](https://research.aalto.fi/en/datasets/phishstorm-phishing-legitimate-url-dataset/) | NOT AVAILABLE — license is unspecified; no examples fabricated |

## Interpretation limits

- The source label is reported exactly as present; `phish` is not an independent statement that the URL is currently malicious, and `benign` is not a guarantee of present-day safety.
- These examples are not model predictions, labels were not changed, and no URL was requested.
- Summary counts, parsing definitions, provenance, and canonical overlap are documented in [`candidate_dataset_audit.md`](candidate_dataset_audit.md).
