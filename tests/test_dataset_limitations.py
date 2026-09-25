"""Regression tests that pin the documented data limitations and artifact identity.

These tests preserve what is TRUE about the project today. They deliberately do
not assert that the model should classify arbitrary internet domains as
legitimate, and they do not manufacture any desired outcome: the canonical
corpus contains zero legitimate examples of the affected shapes, so the only
honest assertion is that the absence is real and must not be forgotten.
"""
import hashlib
import json
import re
from pathlib import Path
from urllib.parse import urlsplit

import pandas as pd
import pytest

from src.data_loader import DATASET
from src.domain_split import groups_for_urls, verify_group_overlap
from src.feature_schema import FEATURES, extract_url_features, normalize_url

ROOT = Path(__file__).resolve().parents[1]
CANONICAL = ROOT / "data" / "raw" / "PhiUSIIL_Phishing_URL_Dataset.csv"
PROD_PIPE = ROOT / "models" / "phishguard_pipeline.joblib"
PROD_META = ROOT / "models" / "model_metadata.json"
SCHEMA = ROOT / "models" / "feature_schema.json"

# Golden digests. These pin the shipped artifact and the training corpus.
# A change here is intentional and must be made consciously, never as a side
# effect of running the test suite or a training job.
CANONICAL_SHA256 = "a236549cd369cd80bd478ff8e1779cbf44c58d5c3f79f7a51a1adbed7d06d1c6"
PRODUCTION_MODEL_SHA256 = "882b1f5de934cb0a190f0f9461ea744b1e96cb42e9a3f539a60279662d724df1"

WWW_AT_HOST = re.compile(r"(?i)(?://|^)www\.")


def sha256(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


@pytest.fixture(scope="module")
def canonical():
    return pd.read_csv(CANONICAL, usecols=["URL", "label"], low_memory=False)


@pytest.fixture(scope="module")
def legitimate(canonical):
    frame = canonical[canonical["label"] == 1].copy()
    frame["URL"] = frame["URL"].astype(str)
    return frame


@pytest.fixture(scope="module")
def non_www_legitimate_candidates(legitimate):
    """Superset of legitimate rows whose host is not `www.`, found without full parsing.

    The prefilter can only over-approximate, so a non-empty result is then fully
    parsed. An empty result is a proof that no legitimate row has a non-www host.
    """
    return legitimate[~legitimate["URL"].str.contains(WWW_AT_HOST, na=False)]


# --------------------------------------------------------------------------
# Canonical dataset limitations (documented facts, not desired outcomes)
# --------------------------------------------------------------------------

def test_canonical_dataset_digest_is_unchanged():
    assert sha256(CANONICAL) == CANONICAL_SHA256


def test_canonical_row_and_class_counts(canonical):
    assert len(canonical) == 235795
    counts = canonical["label"].value_counts().to_dict()
    assert counts == {1: 134850, 0: 100945}


def test_legitimate_class_has_no_www_host_at_all(legitimate):
    """Every legitimate URL sits behind a `www.` host. This is the root of the bias."""
    matched = legitimate["URL"].str.contains(WWW_AT_HOST, na=False)
    assert int(matched.sum()) == len(legitimate)
    assert len(legitimate) == 134850


def test_legitimate_class_has_no_http_rows(legitimate):
    lowered = legitimate["URL"].str.lower()
    assert int(lowered.str.startswith("http://").sum()) == 0
    assert int(lowered.str.startswith("https://").sum()) == 134850


def test_legitimate_class_has_no_query_rows(legitimate):
    assert int(legitimate["URL"].str.contains("?", regex=False, na=False).sum()) == 0


def test_legitimate_class_has_no_apex_root_apex_path_or_subdomain_coverage(
        non_www_legitimate_candidates):
    """The documented gap: zero legitimate non-www representations of any shape.

    Asserts the ABSENCE of coverage, which is the measured fact. It does not
    assert how the model should behave on such URLs.
    """
    assert len(non_www_legitimate_candidates) == 0
    counts = {"apex_root": 0, "apex_with_path": 0, "non_www_subdomain": 0}
    for raw in non_www_legitimate_candidates["URL"]:
        norm = normalize_url(raw)
        host = urlsplit(norm).hostname or ""
        is_www = host.startswith("www.")
        if is_www or not host:
            continue
        parts = host.split(".")
        registrable = ".".join(parts[-2:]) if len(parts) >= 2 else host
        if host == registrable:
            key = "apex_root" if urlsplit(norm).path in ("", "/") else "apex_with_path"
        else:
            key = "non_www_subdomain"
        counts[key] += 1
    assert counts == {"apex_root": 0, "apex_with_path": 0, "non_www_subdomain": 0}


def test_phishing_class_does_cover_the_shapes_legitimate_lacks(canonical):
    """Confirms the asymmetry rather than a uniform corpus."""
    phishing = canonical[canonical["label"] == 0].copy()
    phishing["URL"] = phishing["URL"].astype(str)
    non_www = phishing[~phishing["URL"].str.contains(WWW_AT_HOST, na=False)]
    assert len(non_www) > 0
    assert int(phishing["URL"].str.lower().str.startswith("http://").sum()) > 0
    assert int(phishing["URL"].str.contains("?", regex=False, na=False).sum()) > 0


# --------------------------------------------------------------------------
# Feature schema
# --------------------------------------------------------------------------

def test_feature_schema_is_38_features_and_matches_everywhere():
    assert len(FEATURES) == 38
    schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
    assert schema["feature_count"] == 38
    assert schema["features"] == FEATURES
    meta = json.loads(PROD_META.read_text(encoding="utf-8"))
    assert meta["feature_count"] == 38
    assert meta["features"] == FEATURES


def test_feature_extraction_never_performs_io():
    feats = extract_url_features("https://www.example.com/a?b=c")
    assert set(feats) == set(FEATURES)
    assert feats["IsHTTPS"] == 1


# --------------------------------------------------------------------------
# Production artifact identity
# --------------------------------------------------------------------------

def test_production_model_digest_is_unchanged():
    assert sha256(PROD_PIPE) == PRODUCTION_MODEL_SHA256, (
        "the shipped pipeline changed; model replacement must be an explicit, "
        "separately verified decision, never a side effect")


def test_production_model_class_and_parameters():
    joblib = pytest.importorskip("joblib")
    pipe = joblib.load(PROD_PIPE)
    assert list(pipe.named_steps.keys()) == ["preprocess", "model"]
    model = pipe.named_steps["model"]
    assert type(model).__name__ == "DecisionTreeClassifier"
    assert model.get_params()["min_samples_leaf"] == 3
    assert model.get_params()["random_state"] == 42
    assert [int(c) for c in model.classes_] == [0, 1]


def test_production_metadata_is_internally_consistent():
    meta = json.loads(PROD_META.read_text(encoding="utf-8"))
    assert meta["model"] == "Decision Tree"
    assert meta["feature_count"] == len(meta["features"])
    assert meta["metrics"] == meta["random_stratified_metrics"]
    assert meta["dataset_sha256"] == CANONICAL_SHA256
    assert meta["dataset_records_raw"] == 235795
    assert meta["dataset_records_clean"] == 234894
    assert meta["class_distribution_clean"] == {"1": 134849, "0": 100045}
    assert meta["label_mapping"] == {"1": "Legitimate", "0": "Potential Phishing"}


def test_production_metadata_names_only_the_canonical_training_source():
    meta = json.loads(PROD_META.read_text(encoding="utf-8"))
    sources = meta["dataset_sources"]
    assert [s["file"] for s in sources] == ["PhiUSIIL_Phishing_URL_Dataset.csv"]
    assert sources[0]["sha256"] == CANONICAL_SHA256
    assert sources[0]["role"] == "sole production training source"


def test_production_metadata_records_the_representation_limitation():
    meta = json.loads(PROD_META.read_text(encoding="utf-8"))
    limits = meta["known_dataset_limitations"]
    assert limits["legitimate_apex_root_rows"] == 0
    assert limits["legitimate_non_www_subdomain_rows"] == 0
    assert limits["legitimate_http_rows"] == 0
    assert "DATA REPRESENTATION LIMITATION" in limits["status"]


def test_metadata_marks_legacy_hostname_grouping_and_records_psl_evaluation():
    meta = json.loads(PROD_META.read_text(encoding="utf-8"))
    legacy = meta["domain_aware_metrics"]
    assert "LEGACY HOSTNAME-GROUPED RESULT" in legacy["status"]
    psl = meta["domain_aware_metrics_registrable_psl"]
    assert psl["registrable_domain_overlap"] == 0
    assert "registrable" in psl["grouping"].lower()
    assert "NOT a re-evaluation of the shipped serialized artifact" in psl["applies_to"]


def test_metadata_amendment_did_not_claim_retraining():
    meta = json.loads(PROD_META.read_text(encoding="utf-8"))
    prov = meta["metadata_provenance"]
    assert prov["model_artifact_modified"] is False
    assert prov["retraining_performed"] is False
    assert prov["metric_values_changed"] is False


# --------------------------------------------------------------------------
# No candidate / diagnostic data may reach production training
# --------------------------------------------------------------------------

def test_no_application_module_references_candidate_datasets():
    """PhishTrap, PhreshPhish, EdgePhish-5G and friends must stay out of src/ and backend/."""
    needles = ("candidates", "PhishTrap", "PhreshPhish", "EdgePhish", "phishtrap", "phreshphish")
    for folder in ("src", "backend"):
        for path in (ROOT / folder).rglob("*.py"):
            text = path.read_text(encoding="utf-8")
            for needle in needles:
                assert needle not in text, f"{path} references {needle}"


def test_training_entrypoint_defaults_to_canonical_only():
    from src import train

    assert train.DATASET == DATASET
    source = (ROOT / "src" / "train.py").read_text(encoding="utf-8")
    assert "dataset_paths or [DATASET]" in source
    assert "candidates" not in source


def test_phishtrap_manifest_is_marked_diagnostic_only_and_unresolved():
    manifest = ROOT / "data" / "candidates" / "PhishTrap" / "source_manifest.json"
    data = json.loads(manifest.read_text(encoding="utf-8"))
    assert data["license_status"] == "REQUIRES TERMS REVIEW"
    assert data["training_use"].startswith("NOT APPROVED")
    assert data["diagnostic_use"].startswith("APPROVED FOR DIAGNOSTIC ONLY")
    assert "non-commercial" in " ".join(data["license_notes"]).lower()


# --------------------------------------------------------------------------
# PSL-aware split integrity
# --------------------------------------------------------------------------

def test_registrable_domain_split_has_zero_overlap():
    urls = [
        "https://example.com/", "https://www.example.com/p", "https://login.example.com/a",
        "https://example.co.uk/", "https://www.example.co.uk/x", "https://shop.example.co.uk/y",
        "https://other.test/", "https://www.other.test/y", "https://a.pages.dev/",
        "https://b.pages.dev/", "http://203.0.113.10/t", "http://203.0.113.10:8080/other",
    ]
    groups = groups_for_urls(urls)
    assert groups[0] == groups[1] == groups[2] == "example.com"
    assert groups[3] == groups[4] == groups[5] == "example.co.uk"
    assert groups[10] == groups[11] == "203.0.113.10"
    report = verify_group_overlap(urls[:6], urls[6:])
    assert report["overlap_count"] == 0
    assert report["overlap_pct_of_union"] == 0.0
