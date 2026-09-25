"""Train and compare URL-only classifiers on labeled URL CSV inputs."""
import argparse,json,sys,joblib,copy
from pathlib import Path
from datetime import datetime,timezone
import numpy as np
import pandas as pd
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from sklearn.linear_model import LogisticRegression
from sklearn.tree import DecisionTreeClassifier
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split,GroupShuffleSplit
from sklearn.metrics import accuracy_score,precision_score,recall_score,f1_score,confusion_matrix
from .data_loader import DATASET,load_datasets,audit_datasets,clean_url_labels
from .feature_schema import FEATURES,extract_url_features
from .domain_split import groups_for_urls,verify_group_overlap
from .evaluate import score_model,save_comparison
from .data_preprocessing import make_pipeline

ROOT=Path(__file__).resolve().parents[1]
def build_features(urls):
    records=[extract_url_features(u) for u in urls]
    return pd.DataFrame.from_records(records,columns=FEATURES)

def main(dataset_paths=None):
    dataset_paths = list(dataset_paths or [DATASET])
    raw=load_datasets(dataset_paths); audit=audit_datasets(raw)
    dataset_description = ", ".join(item["file"] for item in audit["sources"])
    labels=set(pd.to_numeric(raw.label,errors="coerce").dropna().unique())
    if labels!={0,1}: raise ValueError(f"Unexpected labels: {labels}")
    data,clean=clean_url_labels(raw)
    # URL-only corpus audit and feature extraction. Normalized duplicates are removed first.
    # Splits. PRIMARY: stratified 80/20 URL-level split (random_state=42) for model comparison.
    # DOMAIN-AWARE: registrable-domain grouped GroupShuffleSplit (20%, random_state=42) for
    # generalization evaluation only. Grouping is PSL-aware via src/domain_split.py (single
    # authoritative implementation; no manual TLD parsing here).
    X=build_features(data.normalized_url.tolist()); y=data.label_numeric.to_numpy(); registrable_groups=groups_for_urls(data.normalized_url.tolist())
    idx=np.arange(len(y)); tr,te=train_test_split(idx,test_size=.2,random_state=42,stratify=y)
    # Explicit audit: normalized URLs cannot cross the split.
    assert set(data.normalized_url.iloc[tr]).isdisjoint(set(data.normalized_url.iloc[te]))
    models=[("Logistic Regression",LogisticRegression(max_iter=500,class_weight=None,solver="lbfgs")),
            ("Decision Tree",DecisionTreeClassifier(random_state=42,min_samples_leaf=3,class_weight=None)),
            ("Random Forest",RandomForestClassifier(n_estimators=60,max_depth=24,min_samples_leaf=3,max_features="sqrt",n_jobs=-1,random_state=42,class_weight=None))]
    results=[]; fitted=[]
    for name,model in models:
        print(f"Training {name}...",flush=True)
        pipe=make_pipeline(model); pipe.fit(X.iloc[tr],y[tr]); results.append(score_model(name,pipe,X.iloc[tr],y[tr],X.iloc[te],y[te])); fitted.append(pipe)
    # Select on held-out phishing F1; use accuracy and precision as tie-breakers.
    best_i=max(range(len(results)),key=lambda i:(results[i]["f1"],results[i]["accuracy"],results[i]["precision"]))
    best,bestpipe=results[best_i],fitted[best_i]
    out=ROOT/"results"; out.mkdir(exist_ok=True); save_comparison(results,best,X.iloc[te],y[te])
    # Domain-aware holdout (registrable-domain grouped, PSL-aware via src/domain_split.py).
    # Preprocessing is fitted only on this split's training side. No registrable domain
    # may appear on both sides (verified by assertion below).
    gs=GroupShuffleSplit(n_splits=1,test_size=.2,random_state=42); gtr,gte=next(gs.split(X,y,groups=registrable_groups))
    _train_reg_groups=set(np.array(registrable_groups)[gtr]); _test_reg_groups=set(np.array(registrable_groups)[gte])
    assert _train_reg_groups.isdisjoint(_test_reg_groups), "registrable-domain overlap between domain-aware train/test"
    assert verify_group_overlap([data.normalized_url.iloc[i] for i in gtr],[data.normalized_url.iloc[i] for i in gte])["overlap_count"]==0
    domain_pipe=make_pipeline(copy.deepcopy(models[best_i][1])); domain_pipe.fit(X.iloc[gtr],y[gtr]); dp=domain_pipe.predict(X.iloc[gte]); dcm=confusion_matrix(y[gte],dp,labels=[0,1])
    domain_metrics={"grouping":"registrable-domain (PSL-aware via tldextract; src/domain_split.py)","train_rows":len(gtr),"test_rows":len(gte),"train_domains":len(_train_reg_groups),"test_domains":len(_test_reg_groups),
      "domain_overlap":0,"registrable_domain_overlap_pct":0.0,"accuracy":accuracy_score(y[gte],dp),"precision":precision_score(y[gte],dp,pos_label=0,zero_division=0),"recall":recall_score(y[gte],dp,pos_label=0,zero_division=0),"f1":f1_score(y[gte],dp,pos_label=0,zero_division=0),"false_positives":int(dcm[1,0]),"false_negatives":int(dcm[0,1]),"positive_class":"Potential Phishing (0)","confusion_matrix":dcm.tolist()}
    # Structure slices on random held-out data; each URL receives the same authoritative extractor.
    categories={"bare_root_urls":lambda f:(f.path_length==1)&(f.query_length==0)&(f.num_slashes<=3),"non_www_root_urls":lambda f:True,
      "www_domains":lambda f:True,"domains_with_paths":lambda f:f.path_length>1,"HTTPS":lambda f:True,"HTTP":lambda f:True,
      ".com":lambda f:f.TLD=="com",".in":lambda f:f.TLD=="in","IP_based":lambda f:f.IsDomainIP==1,
      "suspicious_long":lambda f:f.URLLength>=150,"obfuscated":lambda f:f.HasObfuscation==1,"punycode":lambda f:f.has_punycode==1,
      "shortener":lambda f:f.has_url_shortener==1,"ports":lambda f:f.has_port==1,"suspicious_query":lambda f:(f.query_length>0)&(f.num_suspicious_keywords>0)}
    # held-out labeled groups are reported as measured; www/http/https use original normalized URL strings.
    from urllib.parse import urlsplit
    testF=X.iloc[te].reset_index(drop=True); testY=y[te]; pred=bestpipe.predict(testF); testurls=data.normalized_url.iloc[te].reset_index(drop=True)
    robustness=[]
    for name,fn in categories.items():
        if name=="www_domains": mask=testurls.map(lambda u:(urlsplit(u).hostname or "").startswith("www."))
        elif name=="bare_root_urls": mask=testurls.map(lambda u:urlsplit(u).path in ("", "/") and not urlsplit(u).query)
        elif name=="non_www_root_urls": mask=testurls.map(lambda u:(not (urlsplit(u).hostname or "").startswith("www.")) and urlsplit(u).path in ("", "/") and not urlsplit(u).query)
        elif name=="HTTPS": mask=testurls.map(lambda u:urlsplit(u).scheme=="https")
        elif name=="HTTP": mask=testurls.map(lambda u:urlsplit(u).scheme=="http")
        else: mask=fn(testF)
        sel=np.asarray(mask,dtype=bool); n=int(sel.sum())
        robustness.append({"group":name,"held_out_count":n,"accuracy":float(accuracy_score(testY[sel],pred[sel])) if n else None,
          "precision":float(precision_score(testY[sel],pred[sel],pos_label=0,zero_division=0)) if n else None,"recall":float(recall_score(testY[sel],pred[sel],pos_label=0,zero_division=0)) if n else None,
          "f1":float(f1_score(testY[sel],pred[sel],pos_label=0,zero_division=0)) if n else None,"class_distribution":{str(k):int(v) for k,v in pd.Series(testY[sel]).value_counts().items()}})
    domain_audit={"unique_urls":len(data),"unique_domains":len(set(registrable_groups)),"random_train_domains":len(set(np.array(registrable_groups)[tr])),"random_test_domains":len(set(np.array(registrable_groups)[te])),"random_domain_overlap":len(set(np.array(registrable_groups)[tr])&set(np.array(registrable_groups)[te]))}
    bias={"url_prefix_www_vs_other":data.assign(www=[(urlsplit(u).hostname or "").startswith("www.") for u in data.normalized_url]).groupby(["www","label_numeric"]).size().unstack(fill_value=0).to_dict(),
      "scheme_by_label":data.assign(scheme=[urlsplit(u).scheme for u in data.normalized_url]).groupby(["scheme","label_numeric"]).size().unstack(fill_value=0).to_dict(),
      "bare_vs_path_by_label":data.assign(has_path=[len(urlsplit(u).path.strip("/"))>0 for u in data.normalized_url]).groupby(["has_path","label_numeric"]).size().unstack(fill_value=0).to_dict(),
      "com_in_by_label":data.assign(tld=X.TLD.values).loc[lambda d:d.tld.isin(["com","in"])].groupby(["tld","label_numeric"]).size().unstack(fill_value=0).to_dict(),
      "top_tlds_by_label":data.assign(tld=X.TLD.values).groupby(["tld","label_numeric"]).size().unstack(fill_value=0).sort_values(1,ascending=False).head(25).to_dict(),
      "top_tld_counts":{str(k):int(v) for k,v in X.TLD.value_counts().head(30).items()},
      "url_length_quantiles_by_label":{str(label):{str(q):float(np.quantile(X.URLLength.to_numpy()[y==label],q)) for q in [0,.25,.5,.75,.9,.95,.99,1]} for label in [0,1]},
      "path_length_quantiles_by_label":{str(label):{str(q):float(np.quantile(X.path_length.to_numpy()[y==label],q)) for q in [0,.25,.5,.75,.9,.95,.99,1]} for label in [0,1]},
      "query_length_quantiles_by_label":{str(label):{str(q):float(np.quantile(X.query_length.to_numpy()[y==label],q)) for q in [0,.25,.5,.75,.9,.95,.99,1]} for label in [0,1]}}
    cleaning={**clean,"duplicate_rows_in_raw":audit["duplicate_rows"],"raw_duplicate_urls":audit["duplicate_urls_raw"],"duplicates_removed_by_normalized_url":clean["duplicate_normalized_url_removed"],"invalid_label_rows_removed":clean["invalid_or_inconsistent_label_removed"]}
    report={"random_state":42,"random_stratified":{"train_rows":len(tr),"test_rows":len(te),"train_domains":domain_audit["random_train_domains"],"test_domains":domain_audit["random_test_domains"],"domain_overlap":domain_audit["random_domain_overlap"],"models":results,"selected_model":best["model"]},"domain_aware":domain_metrics,"domain_audit":domain_audit,"robustness_groups":robustness,"bias_analysis":bias,"cleaning":cleaning}
    (out/"robustness_report.json").write_text(json.dumps(report,indent=2,default=str),encoding="utf-8")
    md=["# Robustness and generalization report","",f"Selected model: **{best['model']}** (highest held-out phishing F1; accuracy and precision break ties).","", "## Split comparison","",f"Primary evaluation (stratified URL-level 80/20, random_state=42): {len(tr):,} train / {len(te):,} test; {domain_audit['random_domain_overlap']:,} registrable domains overlap (random split is not domain-disjoint).",f"Domain-aware evaluation (registrable-domain grouped GroupShuffleSplit, 20%, random_state=42; PSL-aware via tldextract): {len(gtr):,} train / {len(gte):,} test; {domain_metrics['domain_overlap']} registrable-domain overlap; accuracy {domain_metrics['accuracy']:.4f}, phishing precision {domain_metrics['precision']:.4f}, phishing recall {domain_metrics['recall']:.4f}, F1 {domain_metrics['f1']:.4f}.","","The source has a strong structure bias: legitimate records are all HTTPS and all use a `www.` hostname; phishing records include HTTP and non-`www` hosts. The model still uses HTTPS and TLD as learned signals, with no deterministic scheme, TLD, or hostname override. This dataset does not provide labeled legitimate non-`www` URLs for a direct held-out quality estimate of that subgroup.","","## Held-out URL group performance","","Class counts use label 0 = phishing and label 1 = legitimate. Empty classes in a group mean the dataset provides no held-out examples for that class.","","| Group | Count | Phishing | Legitimate | Accuracy | Precision | Recall | F1 |","|---|---:|---:|---:|---:|---:|---:|---:|"]
    for q in robustness: md.append(f"| {q['group']} | {q['held_out_count']:,} | {q['class_distribution'].get('0',0):,} | {q['class_distribution'].get('1',0):,} | {q['accuracy'] if q['accuracy'] is not None else 'n/a'} | {q['precision'] if q['precision'] is not None else 'n/a'} | {q['recall'] if q['recall'] is not None else 'n/a'} | {q['f1'] if q['f1'] is not None else 'n/a'} |")
    md += ["","## Cleaning","",f"Input rows {clean['input_rows']:,}; kept {clean['clean_rows']:,}; normalized duplicate URLs removed {clean['duplicate_normalized_url_removed']:,}; conflicting-label URLs removed {clean.get('conflicting_label_urls_removed',0):,}; invalid URLs removed {clean['invalid_url_removed']:,}; invalid/missing labels removed {clean['invalid_or_inconsistent_label_removed']+clean['missing_label_removed']:,}.","","Data-derived TLD, scheme, `www`/non-`www`, path, query, and URL-length distributions are recorded in `results/robustness_report.json`. The model contains no hostname whitelist or scheme/TLD override."]
    (out/"robustness_report.md").write_text("\n".join(md)+"\n",encoding="utf-8")
    # Save final trained pipeline and feature schema.
    modelsdir=ROOT/"models"; modelsdir.mkdir(exist_ok=True); joblib.dump(bestpipe,modelsdir/"phishguard_pipeline.joblib",compress=3)
    # Feature importance from final estimator; one-hot TLD importance is aggregated into its source feature.
    model=bestpipe.named_steps["model"]
    try:
        if hasattr(model,"feature_importances_"): imp=model.feature_importances_
        else: imp=np.mean(np.abs(model.coef_),axis=0)
        transformed=bestpipe.named_steps["preprocess"].get_feature_names_out()
        aggregate={f:0.0 for f in FEATURES}
        for nm,val in zip(transformed,imp):
            source=nm.split("__",1)[-1]; key="TLD" if source.startswith("TLD_") else source
            if key in aggregate: aggregate[key]+=float(val)
        order=sorted(aggregate.items(),key=lambda kv:kv[1],reverse=True)[:20]
        fig,ax=plt.subplots(figsize=(9,7)); ax.barh([x[0] for x in order[::-1]],[x[1] for x in order[::-1]],color="#14b8a6"); ax.set_title(f"{best['model']} feature importance (aggregated)"); fig.tight_layout(); fig.savefig(out/"feature_importance.png",dpi=160); plt.close(fig)
    except Exception: pass
    schema={"version":"1.0","feature_count":len(FEATURES),"features":FEATURES,"numeric_features":[x for x in FEATURES if x!="TLD"],"categorical_features":["TLD"],"url_normalization":"lowercase scheme and hostname; remove trailing hostname dot; drop default ports; add / for empty path; preserve subdomains/path/query/fragment; missing scheme treated as http for parsing"}
    (modelsdir/"feature_schema.json").write_text(json.dumps(schema,indent=2),encoding="utf-8")
    meta={"dataset":dataset_description,"dataset_sources":audit["sources"],"dataset_sha256":audit["sha256"],"dataset_records_raw":len(raw),"dataset_records_clean":len(data),"class_distribution_clean":{str(k):int(v) for k,v in data.label_numeric.value_counts().items()},"label_mapping":{"1":"Legitimate","0":"Potential Phishing"},"model":best["model"],"feature_count":len(FEATURES),"features":FEATURES,"metrics":best,"random_stratified_metrics":best,"domain_aware_metrics":domain_metrics,"train_test_split":{"test_size":0.2,"stratified":True,"train_records":len(tr),"test_records":len(te),"random_state":42},"random_state":42,"training_date_utc":datetime.now(timezone.utc).isoformat(),"pipeline_version":"1.0","cleaning":clean}
    (modelsdir/"model_metadata.json").write_text(json.dumps(meta,indent=2),encoding="utf-8")
    (ROOT/"docs").mkdir(exist_ok=True)
    mdreport=f"""# PhishGuard — Project Report Content

## 1. Introduction
PhishGuard demonstrates URL-only machine-learning classification of phishing risk as a local web application.

## 2. Problem Statement
Phishing URLs can imitate known brands. The project measures URL string characteristics without contacting the destination.

## 3. Objectives
Train and compare interpretable baseline classifiers, expose a local prediction API, display model outputs and features, and document generalization limits.

## 4. Project Scope
Input is one HTTP/HTTPS URL string. Website content, redirects, DNS, WHOIS, reputation services, and remote APIs are out of scope.

## 5. Proposed System / Methodology
The same URL normalizer and extractor are used at training and inference. Numeric scaling and TLD encoding are fitted within each training pipeline only.

## 6. Dataset Description
Training source files: `{dataset_description}`; raw records: {len(raw):,}; cleaned records: {len(data):,}; combined source digest: `{audit['sha256']}`. Per-source hashes and row counts are recorded in `models/model_metadata.json` and `results/dataset_audit.json`. Clean class counts: `{meta['class_distribution_clean']}`. Required label convention: 1 = legitimate, 0 = phishing; verify each source's label semantics before training.

## 7. Data Preprocessing
Removed empty/missing URLs, invalid URL strings, missing or non-binary labels, ambiguous normalized URLs carrying conflicting labels, and duplicate normalized URLs. Audit counts: `{clean}`. Normalized URL duplicates are removed before splitting.

## 8. AI/ML Model Selection
Logistic Regression, Decision Tree and Random Forest were compared. Selection rule: highest stratified held-out phishing F1, then accuracy, then precision.

## 9. Model Development
The final feature set has {len(FEATURES)} URL-only features: `{FEATURES}`. Excluded fields include webpage contents/metadata, link counts, redirects, `URLSimilarityIndex`, and unreproducible derived dataset statistics. TLD one-hot encoding and numeric imputation/scaling are pipeline stages.

## 10. Model Training and Evaluation
Primary evaluation: stratified URL-level split (80/20, random state 42): {len(tr):,} train / {len(te):,} test. Registrable-domain overlap on this random split is {domain_audit['random_domain_overlap']:,} (the primary split is not domain-disjoint). Domain-aware evaluation: registrable-domain grouped split (PSL-aware via tldextract, GroupShuffleSplit 20%, random state 42): {len(gtr):,} train / {len(gte):,} test, registrable-domain overlap {domain_metrics['domain_overlap']}.

## 11. Results and Analysis
Selected model: **{best['model']}**. Accuracy {best['accuracy']:.4f}; phishing precision {best['precision']:.4f}; phishing recall {best['recall']:.4f}; phishing F1 {best['f1']:.4f}; training score {best['training_score']:.4f}; test score {best['testing_score']:.4f}; gap {best['train_test_gap']:.4f}; false positives {best['false_positives']:,}; false negatives {best['false_negatives']:,}. Confusion matrix (actual rows, predicted columns; class order 0 phishing, 1 legitimate): `{best['confusion_matrix']['matrix']}`. Domain-aware accuracy {domain_metrics['accuracy']:.4f}, phishing precision {domain_metrics['precision']:.4f}, phishing recall {domain_metrics['recall']:.4f}, F1 {domain_metrics['f1']:.4f}, false positives {domain_metrics['false_positives']:,}, false negatives {domain_metrics['false_negatives']:,}. See generated comparison and robustness reports for all model and URL subgroup metrics.

## 12. System Architecture / Workflow
CSV → URL cleaning/deduplication → authoritative URL extraction → training-only preprocessing → primary stratified comparison plus registrable-domain holdout → saved pipeline → FastAPI → React/Vite.

## 13. Implementation
Python, pandas, NumPy, scikit-learn, joblib, FastAPI and Uvicorn implement data preparation, training and inference. FastAPI accepts JSON and does not use a network client for submitted URLs.

## 14. UI/Application
The responsive dark interface provides an analyzer, probability and class, actual extracted features, live model information, workflow, and a Three.js shield visualization. Reduced-motion and WebGL fallback paths are provided.

## 15. Challenges and Limitations
Only URL-derived fields are used; webpage content, redirects, DNS, WHOIS, and remote reputation are outside this system. Dataset structure counts by label are recorded in `results/robustness_report.json`, including scheme, `www`/non-`www`, path, query, and TLD distributions. These dataset measurements do not establish performance on structures or domains missing from the labeled sources. The selected model is chosen by measured held-out phishing F1, with accuracy and precision as tie-breakers; predictions remain statistical results and not ground-truth validation. Random URL splits can share registrable domains, so registrable-domain-disjoint metrics are reported separately. Predictions can be wrong, and dataset-level class patterns may not match current traffic.

## 16. Conclusion
The implementation trains and evaluates a local model on URL-derived features only. Its output is a statistical classification and not a safety verdict.

## 17. Future Scope
Assess newer independent corpora, temporal drift, probability calibration and subgroup fairness; consider explanation tools that remain strictly URL-only.

## 18. References
- Prasad, A. & Chandra, S. (2024). *PhiUSIIL Phishing URL (Website) Dataset*. UCI Machine Learning Repository, ID 967. https://archive.ics.uci.edu/dataset/967/phiusiil+phishing+url+dataset
- Prasad, A. & Chandra, S. (2024). PhiUSIIL: A diverse security profile empowered phishing URL detection framework based on similarity index and incremental learning. *Computers & Security*. https://doi.org/10.1016/j.cose.2023.103545
- Actual metrics are machine generated in `results/model_metrics.json`; dataset audit in `results/dataset_audit.json`; subgroup and registrable-domain evaluation in `results/robustness_report.json`. Previously generated reports that used full-hostname grouping are LEGACY HOSTNAME-GROUPED RESULTS and must not be compared silently with registrable-domain figures.
"""
    (ROOT/"docs"/"project_report_content.md").write_text(mdreport,encoding="utf-8")
    print(json.dumps({"selected_model":best["model"],"metrics":best,"domain_aware":domain_metrics,"cleaning":clean,"features":len(FEATURES)},indent=2),flush=True)
if __name__=="__main__":
    parser = argparse.ArgumentParser(description="Train PhishGuard from one or more labeled URL CSVs")
    parser.add_argument("--dataset", action="append", dest="dataset_paths", metavar="CSV",
                        help="training CSV with URL,label columns; repeat for multiple training sources")
    args = parser.parse_args()
    main(args.dataset_paths)
