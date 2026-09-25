"""Error-cost scenario analysis over the completed baseline experiment.

Reads models/experiments/baseline_experiment_metrics.json (canonical-only
baseline) and computes, per model and per evaluation split:
  precision, recall, F1, FP, FN, FPR, FNR, and expected error cost under
  several analytical cost scenarios. Also solves for the FP/FN cost ratio
  crossover points where the ordering of the three models changes.

These scenarios are TECHNICAL ANALYSIS ONLY. They are not a business policy
and are not owner-approved.
"""
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RUN = ROOT / "models" / "experiments" / "baseline_experiment_metrics.json"
OUT = ROOT / "models" / "experiments" / "cost_scenarios.json"

SCENARIOS = [
    ("A", 1, 1, "equal weights"),
    ("B", 1, 2, "missed phish twice as costly as a false alarm"),
    ("C", 1, 5, "missed phish five times as costly as a false alarm"),
    ("D", 2, 5, "false alarm twice as costly, missed phish five times as costly"),
]


def rates(block):
    cm = block["confusion_matrix"]["matrix"]
    fn, tp = cm[0][1], cm[0][0]      # actual phishing (0)
    fp, tn = cm[1][0], cm[1][1]      # actual legitimate (1)
    actual_pos, actual_neg = fn + tp, fp + tn
    return {
        "accuracy": block["accuracy"],
        "precision": block["precision"],
        "recall": block["recall"],
        "f1": block["f1"],
        "false_positives": fp,
        "false_negatives": fn,
        "actual_phishing": actual_pos,
        "actual_legitimate": actual_neg,
        "false_positive_rate": fp / actual_neg if actual_neg else None,
        "false_negative_rate": fn / actual_pos if actual_pos else None,
    }


def crossover(a_fp, a_fn, b_fp, b_fn):
    """FP/FN cost ratio above which model b becomes cheaper than model a.

    cost_b < cost_a  <=>  (b_fp-a_fp)*F < (a_fn-b_fn)*N  <=>  F/N > (a_fn-b_fn)/(b_fp-a_fp)
    Returns None when the ratio is negative, i.e. b is never cheaper for any
    non-negative cost weighting.
    """
    num = a_fn - b_fn
    den = b_fp - a_fp
    if den == 0:
        return None
    ratio = num / den
    return ratio if ratio > 0 else None


def main():
    run = json.loads(RUN.read_text(encoding="utf-8"))
    out = {"source_run": str(RUN.relative_to(ROOT)),
           "disclaimer": "Analytical cost scenarios only. Not an owner-approved business policy.",
           "primary_split": run["primary_split"], "domain_split": run["domain_split"],
           "splits": {}}

    for split_key, source in (("primary", run["primary_metrics"]),
                              ("domain_aware", run["domain_metrics"])):
        models = {}
        for name, block in source.items():
            r = rates(block)
            costs = {}
            for tag, fpw, fnw, desc in SCENARIOS:
                costs[tag] = {"fp_cost": fpw, "fn_cost": fnw, "description": desc,
                              "expected_error_cost": fpw * r["false_positives"] + fnw * r["false_negatives"]}
            models[name] = {**r, "cost_scenarios": costs}
        out["splits"][split_key] = models

    # Sensitivity: where does the preferred model change?
    for split_key, all_models in out["splits"].items():
        models = {n: v for n, v in all_models.items() if "cost_scenarios" in v}
        lr, dt, rf = models["Logistic Regression"], models["Decision Tree"], models["Random Forest"]
        out["splits"][split_key]["crossover_fp_over_fn_cost_ratio"] = {
            "Random Forest cheaper than Decision Tree when FP/FN cost ratio >": crossover(
                dt["false_positives"], dt["false_negatives"], rf["false_positives"], rf["false_negatives"]),
            "Logistic Regression cheaper than Decision Tree when FP/FN cost ratio >": crossover(
                dt["false_positives"], dt["false_negatives"], lr["false_positives"], lr["false_negatives"]),
        }
        winners = {}
        for tag, fpw, fnw, _ in SCENARIOS:
            scored = {n: fpw * m["false_positives"] + fnw * m["false_negatives"] for n, m in models.items()}
            winners[tag] = {"costs": scored, "lowest": min(scored, key=scored.get)}
        out["splits"][split_key]["scenario_winners"] = winners

    OUT.write_text(json.dumps(out, indent=2, default=str), encoding="utf-8")

    for split_key, models in out["splits"].items():
        print("== %s ==" % split_key.upper())
        for name, m in models.items():
            if "cost_scenarios" not in m:
                continue
            print("  %s  FP=%d FN=%d FPR=%.6f FNR=%.6f  costs=%s" % (
                name, m["false_positives"], m["false_negatives"],
                m["false_positive_rate"], m["false_negative_rate"],
                {t: m["cost_scenarios"][t]["expected_error_cost"] for t, *_ in SCENARIOS}))
        print("  winners:", {k: v["lowest"] for k, v in models["scenario_winners"].items()})
        print("  crossovers:", json.dumps(models["crossover_fp_over_fn_cost_ratio"], indent=None))
    print("\nwrote", OUT)


if __name__ == "__main__":
    main()
