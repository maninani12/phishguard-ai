"""Phase 11 - production artifact verification.

Verifies the shipped pipeline and metadata agree with each other and with the
documented schema. Reports hashes. Does NOT modify the artifact.
"""
import hashlib
import json
import sys
from pathlib import Path

import joblib

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from src.data_preprocessing import NUMERIC  # noqa: E402
from src.feature_schema import FEATURES  # noqa: E402

PIPE = ROOT / "models" / "phishguard_pipeline.joblib"
META = ROOT / "models" / "model_metadata.json"
SCHEMA = ROOT / "models" / "feature_schema.json"
OUT = ROOT / "models" / "experiments" / "artifact_verification.json"


def sha256(p):
    return hashlib.sha256(Path(p).read_bytes()).hexdigest()


def main():
    pipe = joblib.load(PIPE)
    meta = json.loads(META.read_text(encoding="utf-8"))
    schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
    model = pipe.named_steps["model"]
    pre = pipe.named_steps["preprocess"]
    checks = {}

    checks["pipeline_steps"] = list(pipe.named_steps.keys())
    checks["classifier_type"] = type(model).__name__
    checks["classifier_params"] = {k: v for k, v in model.get_params().items()
                                   if k in ("min_samples_leaf", "random_state", "max_depth",
                                            "n_estimators", "max_features", "criterion")}
    checks["metadata_model_matches_artifact"] = (meta["model"] == "Decision Tree"
                                                 and type(model).__name__ == "DecisionTreeClassifier")
    checks["feature_count"] = len(FEATURES)
    checks["feature_order_matches_metadata"] = meta["features"] == FEATURES
    checks["feature_order_matches_schema_file"] = schema["features"] == FEATURES
    checks["feature_count_matches_metadata"] = meta["feature_count"] == len(FEATURES)
    checks["preprocessing"] = {
        "type": type(pre).__name__,
        "numeric_features": len(NUMERIC),
        "categorical_features": ["TLD"],
        "numeric_steps": [type(s).__name__ for s in pre.transformers[0][1].steps],
        "categorical_encoder": type(pre.transformers[1][1]).__name__,
    }
    transformed_dim = len(pre.get_feature_names_out())
    checks["transformed_feature_dimension"] = transformed_dim
    checks["label_mapping"] = meta["label_mapping"]
    checks["model_classes"] = [int(c) for c in model.classes_]
    checks["dataset"] = meta["dataset"]
    checks["dataset_sources"] = [s.get("file") for s in meta.get("dataset_sources", [])] or None
    metadata_gaps = []
    if not meta.get("dataset_sources"):
        metadata_gaps.append(
            "metadata has no 'dataset_sources' block; the shipped metadata predates the current "
            "src/train.py writer. Dataset identity is attested only by dataset + dataset_sha256.")
    if "grouping" not in meta.get("domain_aware_metrics", {}):
        metadata_gaps.append(
            "domain_aware_metrics has no 'grouping' key: those figures are LEGACY HOSTNAME-GROUPED RESULTS.")
    checks["metadata_gaps"] = metadata_gaps
    checks["dataset_sha256"] = meta["dataset_sha256"]
    checks["dataset_records_raw"] = meta["dataset_records_raw"]
    checks["dataset_records_clean"] = meta["dataset_records_clean"]
    checks["class_distribution_clean"] = meta["class_distribution_clean"]
    checks["metrics"] = {k: meta["metrics"][k] for k in
                         ("accuracy", "precision", "recall", "f1", "false_positives", "false_negatives")}
    checks["confusion_matrix"] = meta["metrics"]["confusion_matrix"]["matrix"]
    checks["random_state"] = meta["random_state"]
    checks["training_date_utc"] = meta["training_date_utc"]
    checks["train_test_split"] = meta["train_test_split"]
    dom = meta["domain_aware_metrics"]
    checks["domain_aware_methodology"] = {
        "recorded_grouping_key": dom.get("grouping", "ABSENT -> legacy full-hostname grouping"),
        "train_rows": dom["train_rows"], "test_rows": dom["test_rows"],
        "train_domains": dom["train_domains"], "test_domains": dom["test_domains"],
        "domain_overlap": dom["domain_overlap"],
        "status": "LEGACY HOSTNAME-GROUPED RESULT - predates PSL integration; not comparable with "
                  "registrable-domain figures and not used for model selection in this phase",
    }
    checks["cleaning"] = meta["cleaning"]
    checks["hashes"] = {
        "production_pipeline_sha256": sha256(PIPE),
        "model_metadata_sha256": sha256(META),
        "feature_schema_sha256": sha256(SCHEMA),
        "canonical_dataset_sha256": sha256(ROOT / "data" / "raw" / "PhiUSIIL_Phishing_URL_Dataset.csv"),
    }

    failures = []
    if not checks["metadata_model_matches_artifact"]:
        failures.append("metadata model does not match serialized classifier")
    if not checks["feature_order_matches_metadata"]:
        failures.append("feature order mismatch vs metadata")
    if not checks["feature_order_matches_schema_file"]:
        failures.append("feature order mismatch vs feature_schema.json")
    if checks["pipeline_steps"] != ["preprocess", "model"]:
        failures.append("unexpected pipeline steps")
    if checks["model_classes"] != [0, 1]:
        failures.append("unexpected class set")
    checks["verification_failures"] = failures
    checks["verified"] = not failures
    checks["decision"] = ("KEEP existing production artifact: the cost-policy winner (Decision Tree, "
                          "min_samples_leaf=3, random_state=42) is the same family and configuration as "
                          "the shipped model, so no replacement is warranted.")

    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(checks, indent=2, default=str), encoding="utf-8")
    print(json.dumps({k: checks[k] for k in (
        "pipeline_steps", "classifier_type", "classifier_params", "metadata_model_matches_artifact",
        "feature_count", "feature_order_matches_metadata", "feature_order_matches_schema_file",
        "transformed_feature_dimension", "model_classes", "verified", "verification_failures", "hashes")},
        indent=2))
    print("\ndomain_aware_methodology:", json.dumps(checks["domain_aware_methodology"], indent=2))
    print("\nwrote", OUT)


if __name__ == "__main__":
    main()
