"""Dataset loading and URL-only audit helpers."""
from pathlib import Path
import hashlib
import json
import pandas as pd
from .feature_schema import normalize_url

ROOT = Path(__file__).resolve().parents[1]
DATASET = ROOT / "data" / "raw" / "PhiUSIIL_Phishing_URL_Dataset.csv"

def load_dataset(path=DATASET):
    df = pd.read_csv(path, low_memory=False)
    required = {"URL", "label"}
    if not required.issubset(df.columns):
        raise ValueError(f"Dataset missing required columns: {sorted(required - set(df.columns))}")
    return df

def load_datasets(paths):
    """Load and combine labeled URL CSVs, tagging each row with source provenance.

    CSVs must use the project's label convention (0 = phishing, 1 = legitimate).
    Other source columns are retained only in the raw frame for auditing; the
    cleaner below selects URL and label (plus this private provenance field).
    """
    paths = list(paths or [])
    if not paths:
        raise ValueError("At least one training dataset path is required")

    frames = []
    manifest = []
    seen_sources = set()
    for path in paths:
        path = Path(path)
        frame = load_dataset(path)
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        source = f"{path.name} [sha256:{digest[:12]}]"
        if source in seen_sources:
            raise ValueError(f"The same dataset was supplied more than once: {path.name}")
        seen_sources.add(source)
        frame["_dataset_source"] = source
        frames.append(frame)
        manifest.append({
            "source": source,
            "file": path.name,
            "sha256": digest,
            "rows": int(len(frame)),
            "columns": [column for column in frame.columns if column != "_dataset_source"],
            "missing_by_column": {str(k): int(v) for k, v in frame.drop(columns="_dataset_source").isna().sum().items()},
            "label_distribution_raw": {str(k): int(v) for k, v in frame.label.value_counts(dropna=False).items()},
            "duplicate_urls_raw": int(frame.URL.astype(str).duplicated().sum()),
        })

    combined = pd.concat(frames, ignore_index=True, sort=False)
    combined.attrs["dataset_manifest"] = manifest
    return combined

def audit_dataset(df, path=DATASET):
    out = ROOT / "results"
    out.mkdir(exist_ok=True)
    stats = {"source": "UCI PhiUSIIL Phishing URL Dataset (ID 967)", "file": str(path),
             "sha256": hashlib.sha256(Path(path).read_bytes()).hexdigest(), "rows": int(len(df)),
             "columns": list(df.columns), "missing_by_column": {k: int(v) for k,v in df.isna().sum().items()},
             "duplicate_rows": int(df.duplicated().sum()), "data_types": {k:str(v) for k,v in df.dtypes.items()},
             "label_column": "label", "label_distribution_raw": {str(k):int(v) for k,v in df.label.value_counts(dropna=False).items()},
             "url_column": "URL", "duplicate_urls_raw": int(df.URL.astype(str).duplicated().sum())}
    stats["label_mapping_verified_from_UCI_documentation_and_binary_values"] = {"1":"Legitimate","0":"Phishing"}
    (out/"dataset_audit.json").write_text(json.dumps(stats,indent=2),encoding="utf-8")
    md = ["# Dataset audit", "", f"- Source: {stats['source']}", f"- Rows: {len(df):,}", f"- SHA-256: `{stats['sha256']}`", f"- Label distribution: `{stats['label_distribution_raw']}`", f"- Duplicate rows: {stats['duplicate_rows']:,}", f"- Duplicate raw URLs: {stats['duplicate_urls_raw']:,}", "- Label mapping: 1 = legitimate; 0 = phishing (confirmed against UCI documentation and checked for binary values).", "", "## Missing values", "", "| Column | Missing |", "|---|---:|"]
    md += [f"| {k} | {v:,} |" for k,v in stats["missing_by_column"].items()]
    (out/"dataset_audit.md").write_text("\n".join(md)+"\n",encoding="utf-8")
    return stats

def audit_datasets(df):
    """Write a raw-data audit for one or more inputs loaded by load_datasets."""
    manifest = df.attrs.get("dataset_manifest")
    if not manifest:
        raise ValueError("Dataset provenance is missing; load inputs with load_datasets()")
    source_hashes = [item["sha256"] for item in manifest]
    combined_hash = hashlib.sha256("\n".join(source_hashes).encode("ascii")).hexdigest()
    raw_columns = sorted({column for item in manifest for column in item["columns"]})
    audit_frame = df.drop(columns="_dataset_source", errors="ignore")
    stats = {
        "sources": manifest,
        "sha256": combined_hash,
        "rows": int(len(df)),
        "columns": raw_columns,
        "missing_by_column": {
            column: int(sum(item["missing_by_column"].get(column, 0) for item in manifest))
            for column in raw_columns
        },
        "duplicate_rows": int(audit_frame.duplicated().sum()),
        "label_column": "label",
        "label_distribution_raw": {str(k): int(v) for k, v in df.label.value_counts(dropna=False).items()},
        "url_column": "URL",
        "duplicate_urls_raw": int(df.URL.astype(str).duplicated().sum()),
    }
    out = ROOT / "results"
    out.mkdir(exist_ok=True)
    (out / "dataset_audit.json").write_text(json.dumps(stats, indent=2), encoding="utf-8")
    md = ["# Dataset collection audit", "", f"- Combined source digest: `{combined_hash}`", f"- Raw rows: {len(df):,}", f"- Duplicate raw URLs across inputs: {stats['duplicate_urls_raw']:,}", "- Label convention required: 0 = phishing; 1 = legitimate.", "", "## Sources", "", "| File | Rows | SHA-256 |", "|---|---:|---|"]
    md += [f"| {item['file']} | {item['rows']:,} | `{item['sha256']}` |" for item in manifest]
    md += ["", "## Raw label counts", "", "| Label | Rows |", "|---:|---:|"]
    md += [f"| {label} | {count:,} |" for label, count in stats["label_distribution_raw"].items()]
    (out / "dataset_audit.md").write_text("\n".join(md) + "\n", encoding="utf-8")
    return stats

def clean_url_labels(df):
    required = {"URL", "label"}
    if not required.issubset(df.columns):
        raise ValueError(f"Dataset missing required columns: {sorted(required - set(df.columns))}")
    has_source = "_dataset_source" in df.columns
    columns = ["URL", "label"] + (["_dataset_source"] if has_source else [])
    work = df[columns].copy()
    counts = {"input_rows": int(len(work))}
    per_source = {}

    def account_removed(stage, rows):
        if has_source and len(rows):
            for source, count in rows["_dataset_source"].value_counts(dropna=False).items():
                per_source.setdefault(str(source), {})[stage] = int(count)

    missing_url = work.URL.isna()
    account_removed("missing_url_removed", work.loc[missing_url])
    counts["missing_url_removed"] = int(missing_url.sum())
    work = work.loc[~missing_url].copy()

    missing_label = work.label.isna()
    account_removed("missing_label_removed", work.loc[missing_label])
    counts["missing_label_removed"] = int(missing_label.sum())
    work = work.loc[~missing_label].copy()

    work["URL"] = work.URL.astype(str).str.strip()
    empty_url = work.URL.eq("")
    account_removed("empty_url_removed", work.loc[empty_url])
    counts["empty_url_removed"] = int(empty_url.sum())
    work = work.loc[~empty_url].copy()

    normalized = []
    valid = []
    for url in work.URL:
        try:
            normalized.append(normalize_url(url))
            valid.append(True)
        except Exception:
            normalized.append("")
            valid.append(False)
    work["normalized_url"] = normalized
    invalid_url = ~pd.Series(valid, index=work.index)
    account_removed("invalid_url_removed", work.loc[invalid_url])
    counts["invalid_url_removed"] = int(invalid_url.sum())
    work = work.loc[~invalid_url].copy()

    work["label_numeric"] = pd.to_numeric(work.label, errors="coerce")
    invalid_label = ~work.label_numeric.isin([0, 1])
    account_removed("invalid_or_inconsistent_label_removed", work.loc[invalid_label])
    counts["invalid_or_inconsistent_label_removed"] = int(invalid_label.sum())
    work = work.loc[~invalid_label].copy()
    work["label_numeric"] = work.label_numeric.astype(int)

    label_counts = work.groupby("normalized_url").label_numeric.nunique()
    ambiguous = set(label_counts[label_counts > 1].index)
    conflict_rows = work.normalized_url.isin(ambiguous)
    account_removed("conflicting_label_rows_removed", work.loc[conflict_rows])
    counts["conflicting_label_url_count"] = int(len(ambiguous))
    counts["conflicting_label_urls_removed"] = int(conflict_rows.sum())
    work = work.loc[~conflict_rows].copy()

    duplicate_rows = work.duplicated(subset=["normalized_url"], keep="first")
    account_removed("duplicate_normalized_url_removed", work.loc[duplicate_rows])
    counts["duplicate_normalized_url_removed"] = int(duplicate_rows.sum())
    work = work.loc[~duplicate_rows].copy()
    counts["clean_rows"] = int(len(work))
    if has_source:
        final_counts = work["_dataset_source"].value_counts().to_dict()
        source_names = set(per_source) | set(df["_dataset_source"].astype(str))
        counts["per_source"] = {
            source: {
                "input_rows": int((df["_dataset_source"].astype(str) == source).sum()),
                **per_source.get(source, {}),
                "clean_rows": int(final_counts.get(source, 0)),
            }
            for source in sorted(source_names)
        }
    return work.reset_index(drop=True), counts
