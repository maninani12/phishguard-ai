"""Metric and report generation."""
import json
from pathlib import Path
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.metrics import accuracy_score,precision_score,recall_score,f1_score,confusion_matrix

ROOT=Path(__file__).resolve().parents[1]
def score_model(name,estimator,X_train,y_train,X_test,y_test):
    pred=estimator.predict(X_test); train_score=estimator.score(X_train,y_train)
    cm=confusion_matrix(y_test,pred,labels=[0,1])
    return {"model":name,"accuracy":accuracy_score(y_test,pred),"precision":precision_score(y_test,pred,pos_label=0,zero_division=0),
            "recall":recall_score(y_test,pred,pos_label=0,zero_division=0),"f1":f1_score(y_test,pred,pos_label=0,zero_division=0),
            "training_score":train_score,"testing_score":estimator.score(X_test,y_test),"train_test_gap":train_score-estimator.score(X_test,y_test),
            "false_positives":int(cm[1,0]),"false_negatives":int(cm[0,1]),"positive_class":"Potential Phishing (0)","confusion_matrix":{"labels":["Phishing (0)","Legitimate (1)"],"matrix":cm.tolist()}}
def save_comparison(results,final,X_test,y_test,feature_names=None):
    out=ROOT/"results"; out.mkdir(exist_ok=True)
    (out/"model_metrics.json").write_text(json.dumps({"models":results,"selected_model":final["model"]},indent=2),encoding="utf-8")
    fig,ax=plt.subplots(figsize=(9,5)); names=[x["model"] for x in results]
    for metric in ["accuracy","precision","recall","f1"]: ax.plot(names,[x[metric] for x in results],marker="o",label=metric.title())
    ax.set_ylim(0,1); ax.set_title("Held-out model comparison"); ax.legend(); ax.grid(alpha=.2); fig.tight_layout(); fig.savefig(out/"model_comparison.png",dpi=160); plt.close(fig)
    fig,ax=plt.subplots(figsize=(5,4)); cm=final["confusion_matrix"]["matrix"]; sns.heatmap(cm,annot=True,fmt="d",cmap="Blues",xticklabels=["Phishing","Legitimate"],yticklabels=["Phishing","Legitimate"],ax=ax); ax.set(xlabel="Predicted",ylabel="Actual",title="Confusion matrix"); fig.tight_layout(); fig.savefig(out/"confusion_matrix.png",dpi=160); plt.close(fig)
    return out
