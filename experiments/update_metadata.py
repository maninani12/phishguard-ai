"""Repository hardening: amend models/model_metadata.json WITHOUT retraining.

Adds only facts that are measured and verifiable:
  * dataset_sources   - one entry, the canonical CSV, in the same shape
                        src/data_loader.audit_datasets() emits
  * dataset_role      - sole production training source
  * grouping / status on domain_aware_metrics, truthfully marking the existing
                        figures as LEGACY FULL-HOSTNAME results
  * domain_aware_metrics_registrable_psl - the measured PSL-aware evaluation,
                        explicitly scoped to the same classifier configuration
                        refit on the registrable-domain training side
  * metadata_provenance - what was amended, when, and what was deliberately not
                        changed

Guarantees:
  * models/phishguard_pipeline.joblib is never opened for writing; its SHA-256 is
    captured before and after and asserted unchanged
  * models/feature_schema.json is never written
  * no file under results/, data/, docs/, src/, frontend/, backend/ is written
  * existing metric values are copied through untouched
"""
import hashlib
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from src.data_loader import DATASET, load_datasets  # noqa: E402

PIPE = ROOT / "models" / "phishguard_pipeline.joblib"
META = ROOT / "models" / "model_metadata.json"
SCHEMA = ROOT / "models" / "feature_schema.json"
BASELINE = ROOT / "models" / "experiments" / "baseline_experiment_metrics.json"


def sha256(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def build_source_entry():
    """Reproduce one audit_datasets() source entry, in memory only."""
    frame = load_datasets([DATASET])
    digest = sha256(DATASET)
    source = f"{DATASET.name} [sha256:{digest[:12]}]"
    entry = {
        "source": source,
        "file": DATASET.name,
        "sha256": digest,
        "rows": int(len(frame)),
        "columns": [c for c in frame.columns if c != "_dataset_source"],
        "missing_by_column": {str(k): int(v) for k, v in
                              frame.drop(columns="_dataset_source").isna().sum().items()},
        "label_distribution_raw": {str(k): int(v) for k, v in
                                   frame.label.value_counts(dropna=False).items()},
        "duplicate_urls_raw": int(frame.URL.astype(str).duplicated().sum()),
    }
    entry["role"] = "sole production training source"
    entry["label_convention"] = "1 = Legitimate, 0 = Phishing (UCI documentation, verified binary)"
    entry["row_level_grain"] = "URL string plus source label; webpage-derived columns are never used as features"
    return entry, digest


def main():
    pipe_hash_before = sha256(PIPE)
    schema_hash_before = sha256(SCHEMA)
    meta = json.loads(META.read_text(encoding="utf-8"))

    entry, dataset_digest = build_source_entry()
    assert dataset_digest == meta["dataset_sha256"], (
        "canonical dataset digest changed since the model was trained: "
        f"{dataset_digest} != {meta['dataset_sha256']}")

    baseline = json.loads(BASELINE.read_text(encoding="utf-8"))
    psl_split = baseline["domain_split"]
    psl_dt = baseline["domain_metrics"]["Decision Tree"]
    assert baseline["primary_split"]["train_rows"] == meta["train_test_split"]["train_records"]
    assert baseline["primary_split"]["test_rows"] == meta["train_test_split"]["test_records"]
    assert psl_split["overlap_count"] == 0

    amended = dict(meta)
    amended["dataset_sources"] = [entry]
    amended["dataset_role"] = ("sole production training source; no external, candidate, "
                              "diagnostic-only or research-only dataset contributes rows "
                              "to the shipped model")

    # Mark the pre-existing figures truthfully instead of relabelling them.
    amended["domain_aware_metrics"] = {
        **meta["domain_aware_metrics"],
        "grouping": "full hostname (legacy; predates PSL-aware registrable-domain integration)",
        "grouping_authority": "src/domain_split.py is the current authoritative grouping "
                              "implementation; these figures were produced before it existed",
        "status": "LEGACY HOSTNAME-GROUPED RESULT - not comparable with registrable-domain "
                  "figures and not used for model selection",
    }

    amended["domain_aware_metrics_registrable_psl"] = {
        "grouping": "registrable domain, public-suffix aware (PSL ICANN + PRIVATE) via "
                    "src/domain_split.py / tldextract",
        "method": psl_split["method"],
        "applies_to": "the same classifier configuration as the shipped model "
                      "(DecisionTreeClassifier, min_samples_leaf=3, random_state=42) refit on "
                      "the registrable-domain training side; this is NOT a re-evaluation of the "
                      "shipped serialized artifact, and the shipped artifact was not retrained",
        "train_rows": psl_split["train_rows"],
        "test_rows": psl_split["test_rows"],
        "train_groups": psl_split["train_groups"],
        "test_groups": psl_split["test_groups"],
        "registrable_domain_overlap": psl_split["overlap_count"],
        "registrable_domain_overlap_pct_of_union": psl_split["overlap_pct_of_union"],
        "accuracy": psl_dt["accuracy"],
        "precision": psl_dt["precision"],
        "recall": psl_dt["recall"],
        "f1": psl_dt["f1"],
        "false_positives": psl_dt["false_positives"],
        "false_negatives": psl_dt["false_negatives"],
        "positive_class": psl_dt["positive_class"],
        "confusion_matrix": psl_dt["confusion_matrix"],
        "source": "models/experiments/baseline_experiment_metrics.json",
    }

    amended["evaluation_splits"] = {
        "primary": "stratified URL-level 80/20, random_state=42, normalized-URL duplicates "
                   "removed before splitting; used for model comparison and selection",
        "domain_aware_legacy": "full-hostname grouped GroupShuffleSplit 20%, random_state=42 "
                               "(LEGACY HOSTNAME-GROUPED RESULT)",
        "domain_aware_registrable_psl": "registrable-domain grouped GroupShuffleSplit 20%, "
                                        "random_state=42; registrable-domain overlap 0",
    }

    amended["known_dataset_limitations"] = {
        "canonical_legitimate_class": "degenerate: 134850/134850 rows are HTTPS + www + root path",
        "legitimate_apex_root_rows": 0,
        "legitimate_apex_with_path_rows": 0,
        "legitimate_non_www_subdomain_rows": 0,
        "legitimate_http_rows": 0,
        "legitimate_query_rows": 0,
        "consequence": "the model cannot be evaluated or retrained into correctness on "
                       "legitimate apex-root, non-www subdomain, HTTP or query URLs with this "
                       "corpus alone; see docs/apex_representation_test.md",
        "status": "DATA REPRESENTATION LIMITATION - not a model-configuration problem",
    }

    amended["metadata_provenance"] = {
        "original_training_date_utc": meta.get("training_date_utc"),
        "amended_utc": datetime.now(timezone.utc).isoformat(),
        "amendment_reason": "add dataset_sources, dataset_role, PSL-aware registrable-domain "
                            "evaluation context, and truthful grouping labels for pre-existing "
                            "metrics",
        "model_artifact_modified": False,
        "retraining_performed": False,
        "metric_values_changed": False,
        "note": "models/phishguard_pipeline.joblib and models/feature_schema.json were not "
                "written. All existing metric values were copied through unchanged.",
    }

    META.write_text(json.dumps(amended, indent=2), encoding="utf-8")

    assert sha256(PIPE) == pipe_hash_before, "production model artifact was modified!"
    assert sha256(SCHEMA) == schema_hash_before, "feature_schema.json was modified!"

    # Re-read and confirm internal consistency.
    check = json.loads(META.read_text(encoding="utf-8"))
    problems = []
    if check["model"] != "Decision Tree":
        problems.append("model name changed")
    if check["feature_count"] != len(check["features"]):
        problems.append("feature_count != len(features)")
    if check["dataset_sha256"] != entry["sha256"]:
        problems.append("dataset digest mismatch")
    if check["dataset_sources"][0]["file"] != "PhiUSIIL_Phishing_URL_Dataset.csv":
        problems.append("unexpected dataset source file")
    if check["domain_aware_metrics_registrable_psl"]["registrable_domain_overlap"] != 0:
        problems.append("registrable-domain overlap is not zero")
    if check["metrics"] != meta["metrics"]:
        problems.append("primary metrics were altered")
    if check["random_stratified_metrics"] != meta["random_stratified_metrics"]:
        problems.append("random_stratified_metrics were altered")
    if check["training_date_utc"] != meta["training_date_utc"]:
        problems.append("training_date_utc was altered")

    print(json.dumps({
        "metadata_sha256_before": "c1f239c40b57aac009092e6d77cfaecef3207f4d7c852601118f20a000672d2c",
        "metadata_sha256_after": sha256(META),
        "production_model_sha256": sha256(PIPE),
        "production_model_unchanged": sha256(PIPE) == pipe_hash_before,
        "feature_schema_unchanged": sha256(SCHEMA) == schema_hash_before,
        "dataset_sources_added": [s["file"] for s in check["dataset_sources"]],
        "internal_consistency_problems": problems,
    }, indent=2))


if __name__ == "__main__":
    main()
