import pandas as pd
import pytest

from src.data_loader import clean_url_labels, load_datasets
from src.feature_schema import FEATURES


def _write_csv(path, rows):
    pd.DataFrame(rows).to_csv(path, index=False)
    return path


def test_multiple_labeled_csvs_are_cleaned_together_with_provenance(tmp_path):
    first = _write_csv(
        tmp_path / "first.csv",
        [
            {"URL": "https://www.good.test/", "label": 1, "source_note": "ignored"},
            {"URL": "https://conflict.test/", "label": 1, "extra_feature": 987},
            {"URL": "https://duplicate.test", "label": 1, "extra_feature": 123},
            {"URL": "", "label": 1},
            {"URL": "https://bad-label.test/", "label": "unknown"},
            {"URL": "not a valid host", "label": 0},
        ],
    )
    second = _write_csv(
        tmp_path / "second.csv",
        [
            {"URL": "https://phishing.test/", "label": 0},
            {"URL": "https://conflict.test", "label": 0},
            {"URL": "https://duplicate.test/", "label": 1},
            {"URL": "https://other.test/path?q=x", "label": 0},
        ],
    )

    raw = load_datasets([first, second])
    cleaned, counts = clean_url_labels(raw)

    assert len(raw) == 10
    assert counts["conflicting_label_url_count"] == 1
    assert counts["conflicting_label_urls_removed"] == 2
    assert counts["duplicate_normalized_url_removed"] == 1
    # pandas reads a blank CSV cell as missing, so it is counted in this stage.
    assert counts["missing_url_removed"] == 1
    assert counts["invalid_url_removed"] == 1
    assert counts["invalid_or_inconsistent_label_removed"] == 1
    assert counts["clean_rows"] == 4
    assert set(cleaned["label_numeric"]) == {0, 1}
    assert cleaned["normalized_url"].is_unique
    assert set(cleaned["_dataset_source"]) == {item["source"] for item in raw.attrs["dataset_manifest"]}
    assert counts["per_source"][raw.attrs["dataset_manifest"][0]["source"]]["clean_rows"] == 2
    assert counts["per_source"][raw.attrs["dataset_manifest"][1]["source"]]["clean_rows"] == 2

    # Additional CSV columns and provenance remain outside the URL feature schema.
    assert "source_note" not in cleaned.columns
    assert "extra_feature" not in cleaned.columns
    assert "_dataset_source" not in FEATURES


def test_cleaner_rejects_missing_required_columns():
    with pytest.raises(ValueError, match="URL"):
        clean_url_labels(pd.DataFrame({"link": ["https://example.test"], "label": [1]}))


def test_load_datasets_rejects_empty_input(tmp_path):
    with pytest.raises(ValueError, match="At least one"):
        load_datasets([])
