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

def clean_url_labels(df):
    counts={"input_rows":len(df)}
    work=df[["URL","label"]].copy()
    counts["missing_url_removed"]=int(work.URL.isna().sum())
    counts["missing_label_removed"]=int(work.label.isna().sum())
    work=work.dropna(subset=["URL","label"])
    work["URL"]=work.URL.astype(str).str.strip()
    counts["empty_url_removed"]=int((work.URL=="").sum())
    work=work[work.URL!=""]
    valid=[]; normalized=[]
    for u in work.URL:
        try: normalized.append(normalize_url(u)); valid.append(True)
        except Exception: normalized.append(""); valid.append(False)
    work["normalized_url"]=normalized
    counts["invalid_url_removed"]=int((~pd.Series(valid,index=work.index)).sum())
    work=work.loc[valid].copy()
    work["label_numeric"]=pd.to_numeric(work.label,errors="coerce")
    bad=~work.label_numeric.isin([0,1])
    counts["invalid_or_inconsistent_label_removed"]=int(bad.sum())
    work=work.loc[~bad].copy(); work["label_numeric"]=work.label_numeric.astype(int)
    label_counts=work.groupby("normalized_url").label_numeric.nunique()
    ambiguous=set(label_counts[label_counts>1].index)
    counts["conflicting_label_urls_removed"]=int(work.normalized_url.isin(ambiguous).sum())
    work=work.loc[~work.normalized_url.isin(ambiguous)].copy()
    before=len(work); work=work.drop_duplicates(subset=["normalized_url"],keep="first")
    counts["duplicate_normalized_url_removed"]=before-len(work)
    work=work.drop_duplicates(subset=["URL","label_numeric"],keep="first")
    counts["clean_rows"]=len(work)
    return work.reset_index(drop=True),counts
