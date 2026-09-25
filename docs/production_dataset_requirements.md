# Production dataset requirements (gates for any future training)

**Date (UTC):** 2026-09-25
**Rule:** no dataset enters `data/raw/` or the training pipeline until EVERY box below is checked with evidence. PhreshPhish is permanently excluded from production training under its current research-only terms; EdgePhish-5G is excluded under upstream OpenPhish non-commercial terms.

## Gate checklist (all required)

- [ ] PSL-aware evaluation implemented — DONE (this phase: `src/domain_split.py` + `tldextract`, 8 tests pass, canonical overlap 0; see below). No retraining was triggered by it.
- [ ] Tests pass (`python -m pytest -q`, `git diff --check`)
- [ ] At least one external candidate has verified labels (string or numeric mapping proven from original docs AND cross-checked against actual rows; reversed mappings explicitly handled)
- [ ] Provenance verified (original repository/institution/author record; version/revision; hash; download source; no mirror-only evidence)
- [ ] License/usage terms verified CLEAR FOR INTENDED USE (public GitHub Pages + hosted API): permissive license with no research-only / non-commercial / no-derivatives / sharealike conflict, including UPSTREAM feed terms for derived datasets
- [ ] Legitimate apex-root coverage verified from actual rows (PSL ICANN+PRIVATE, non-www, root path), not from documentation claims
- [ ] Structural coverage audited by source and class (apex/www, HTTP/HTTPS, root/path, query, subdomains, ports, punycode, encoded chars, length)
- [ ] Dataset integration policy established: column mapping to `URL,label` (0 = phishing, 1 = legitimate), `clean_url_labels` conflict rule (drop conflicting normalized-URL groups, report counts), per-source accounting, registrable-domain-disjoint splits, frozen-pipeline external evaluation

## Current gate state

| Gate | State |
|---|---|
| PSL-aware evaluation | IMPLEMENTED, canonical overlap 0 (train 157,840 groups / test 39,460 groups) |
| Tests | See final report (this phase) |
| Verified-labels external candidate | NONE CLEAR (EdgePhish labels verified but license-blocked) |
| Provenance | EdgePhish proven; others incomplete or mirror-only |
| License CLEAR | NONE except canonical itself |
| Legit apex-root verified | EdgePhish 2,487 rows verified BUT license-blocked; no CLEAR source |
| Structural audit | EdgePhish done; others docs-only or unavailable |
| Integration policy | Documented here; not executed (correctly — gates unmet) |

## PSL evaluation reference

- Dependency: `tldextract>=5.0` (maintained, PSL-backed, private domains included) in `requirements.txt`
- Module: `src/domain_split.py` (`registrable_domain_from_host`, `registrable_domain_for_url`, `groups_for_urls`, `verify_group_overlap`); IP/single-label fallback to hostname itself
- Canonical result (evaluation-only, no training): 234,894 cleaned rows -> 197,300 registrable groups; GroupShuffleSplit(20%, seed 42) -> train 187,391 rows / 157,840 groups, test 47,503 rows / 39,460 groups, overlap **0 (0.00%)**
- `src/train.py` now uses `src/domain_split.py` groups for its domain-aware holdout (integrated without retraining; previously generated hostname-grouped reports are LEGACY HOSTNAME-GROUPED RESULTS)

## Conflict policy (unchanged)

- PhreshPhish 1,579 overlaps / 8 conflicts remain unresolved source disagreements; they are never used to edit the canonical dataset.
- The eight URLs are listed in `docs/model_evaluation.md` and the prior audit; no adjudication by guessing.
- `clean_url_labels` keeps its remove-conflicting-groups behavior with per-source reporting for any future approved merge.

## If no suitable dataset is verified

STOP. Do not train on PhreshPhish or EdgePhish-5G. That is the current outcome.
