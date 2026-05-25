import os
import sys
import numpy as np
import pandas as pd
from pymongo import MongoClient
from datetime import datetime
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score,
    f1_score, roc_auc_score, confusion_matrix
)
import joblib
import torch
import torch.nn as nn

# ── Config ─────────────────────────────────────────
DATASET_PATH = r"D:\rajasri\xai_itd_dlp\dataset"
MODELS_DIR   = r"D:\rajasri\xai_itd_dlp\ml\models"
MONGO_URI    = "mongodb://localhost:27017/"
DB_NAME      = "xai_itd_dlp"

FEATURE_COLS = [
    "logon_count","logoff_count","after_hrs_logon","unique_pcs",
    "session_duration_min","login_hour_mean",
    "usb_connect_count","usb_after_hrs",
    "file_access_count","file_copy_count","file_delete_count",
    "file_to_removable","file_from_removable","file_risk_ratio",
    "email_count","email_after_hrs","email_attach_total",
    "email_size_mean","email_bcc_count",
    "phone_detected_count","face_missing_count","blocked_action_count"
]

SEQ_LEN = 7

client = MongoClient(MONGO_URI)
db = client[DB_NAME]

# ==================================================
# FAST FEATURE ENGINEERING
# ==================================================
def build_cert_labeled_features_fast():
    print("  Loading CERT CSVs...")

    dfs = {}
    for name in ["logon", "device", "file", "email"]:
        df = pd.read_csv(os.path.join(DATASET_PATH, f"clean_{name}.csv"))

        df["date"] = pd.to_datetime(df["date"], errors="coerce")
        df["hour"] = df["date"].dt.hour
        df["day"]  = df["date"].dt.date
        df["after_hrs"] = (~df["hour"].between(9, 17)).astype(int)

        dfs[name] = df
        print(f"  {name}: {len(df):,}")

    # LOGON
    logon = dfs["logon"]
    logon_feat = logon.groupby(["user","day"]).agg(
        logon_count=("activity", lambda x: (x=="Logon").sum()),
        logoff_count=("activity", lambda x: (x=="Logoff").sum()),
        after_hrs_logon=("after_hrs","max"),
        unique_pcs=("pc","nunique"),
        login_hour_mean=("hour","mean"),
        first=("date","min"),
        last=("date","max")
    ).reset_index()

    logon_feat["session_duration_min"] = (
        (logon_feat["last"] - logon_feat["first"])
        .dt.total_seconds()/60
    ).fillna(0)

    # DEVICE
    device_feat = dfs["device"].groupby(["user","day"]).agg(
        usb_connect_count=("activity", lambda x: (x=="Connect").sum()),
        usb_after_hrs=("after_hrs","max")
    ).reset_index()

    # FILE
    file_feat = dfs["file"].groupby(["user","day"]).agg(
        file_access_count=("activity","count"),
        file_copy_count=("activity", lambda x: (x=="file copy").sum()),
        file_delete_count=("activity", lambda x: (x=="file delete").sum()),
        file_to_removable=("to_removable_media","max"),
        file_from_removable=("from_removable_media","max")
    ).reset_index()

    file_feat["file_risk_ratio"] = (
        (file_feat["file_copy_count"] + file_feat["file_delete_count"]) /
        file_feat["file_access_count"].replace(0,1)
    )

    # EMAIL
    email_feat = dfs["email"].groupby(["user","day"]).agg(
        email_count=("activity","count"),
        email_after_hrs=("after_hrs","max"),
        email_attach_total=("attachments","sum"),
        email_size_mean=("size","mean"),
        email_bcc_count=("bcc", lambda x: x.notna().sum())
    ).reset_index()

    # MERGE
    df = logon_feat.merge(device_feat, on=["user","day"], how="left") \
                   .merge(file_feat, on=["user","day"], how="left") \
                   .merge(email_feat, on=["user","day"], how="left") \
                   .fillna(0)

    # Add missing cols
    df["phone_detected_count"] = 0
    df["face_missing_count"]   = 0
    df["blocked_action_count"] = 0

    # LABELS
    y = (
        ((df["file_to_removable"]>0)&(df["after_hrs_logon"]>0)) |
        ((df["usb_after_hrs"]>0)&(df["file_access_count"]>5)) |
        ((df["email_after_hrs"]>0)&(df["email_attach_total"]>0)&(df["usb_connect_count"]>0)) |
        ((df["file_risk_ratio"]>0.5)&(df["file_to_removable"]>0))
    ).astype(int).values

    print(f"  Samples: {len(df)} | Malicious: {y.sum()}")
    return df, y


# ==================================================
# MODEL
# ==================================================
class BiLSTMAutoencoder(nn.Module):
    def __init__(self, input_size, hidden_size=64, num_layers=2):
        super().__init__()
        self.encoder = nn.LSTM(input_size, hidden_size, num_layers=2,
                               batch_first=True, bidirectional=True)
        self.decoder = nn.LSTM(hidden_size*2, hidden_size, num_layers=2,
                               batch_first=True)
        self.fc = nn.Linear(hidden_size, input_size)

    def forward(self, x):
        enc,_ = self.encoder(x)
        dec,_ = self.decoder(enc)
        return self.fc(dec)


def load_models():
    print("  Loading models...")
    iso = joblib.load(os.path.join(MODELS_DIR,"isolation_forest.pkl"))
    lof = joblib.load(os.path.join(MODELS_DIR,"dblof.pkl"))
    scaler = joblib.load(os.path.join(MODELS_DIR,"scaler.pkl"))
    seq_scaler = joblib.load(os.path.join(MODELS_DIR,"seq_scaler.pkl"))

    bilstm = None
    path = os.path.join(MODELS_DIR,"bilstm.pt")
    if os.path.exists(path):
        bilstm = BiLSTMAutoencoder(len(FEATURE_COLS))
        bilstm.load_state_dict(torch.load(path,map_location="cpu"))
        bilstm.eval()

    return iso, lof, bilstm, scaler, seq_scaler


# ==================================================
# SCORING
# ==================================================
def score_iso(iso, X):
    return np.clip((iso.score_samples(X)-0.1)/(-0.8),0,1)

def score_lof(lof, X):
    return np.clip((lof.score_samples(X)+0.5)/(-2.5),0,1)

def score_bilstm_fast(bilstm, seq_scaler, X):
    if bilstm is None:
        return np.zeros(len(X))

    seqs=[]
    for i in range(len(X)):
        seq = X[max(0,i-SEQ_LEN+1):i+1]
        if len(seq)<SEQ_LEN:
            seq=np.vstack([np.zeros((SEQ_LEN-len(seq),X.shape[1])),seq])
        seqs.append(seq)

    seqs=np.array(seqs)
    seqs=seq_scaler.transform(seqs.reshape(-1,X.shape[1])).reshape(seqs.shape)

    scores=[]
    for i in range(0,len(seqs),256):
        batch=torch.FloatTensor(seqs[i:i+256])
        with torch.no_grad():
            recon=bilstm(batch)
        err=((recon-batch)**2).mean((1,2)).numpy()
        scores.extend(np.clip(err/0.3,0,1))

    return np.array(scores)


def score_rules(df):
    s=np.zeros(len(df))
    s+=(df["after_hrs_logon"]>0)*0.15
    s+=(df["usb_connect_count"]>3)*0.2
    s+=(df["file_to_removable"]>0)*0.2
    return np.clip(s,0,1)


def score_dev(X):
    z=np.abs((X-X.mean(0))/(X.std(0)+1e-9))
    return np.clip(z.mean(1)/3,0,1)


# ==================================================
# EVALUATION
# ==================================================
def evaluate(y, scores, name):
    pred=(scores>=0.4).astype(int)
    return {
        "model":name,
        "accuracy":round(accuracy_score(y,pred)*100,2),
        "precision":round(precision_score(y,pred,zero_division=0)*100,2),
        "recall":round(recall_score(y,pred,zero_division=0)*100,2),
        "f1":round(f1_score(y,pred,zero_division=0)*100,2),
        "auc":round(roc_auc_score(y,scores)*100,2)
    }


# ==================================================
# MAIN
# ==================================================
if __name__=="__main__":
    print("\n=== FAST ENSEMBLE EVAL ===\n")

    df,y = build_cert_labeled_features_fast()
    X = df[FEATURE_COLS].values

    iso,lof,bilstm,scaler,seq_scaler = load_models()
    Xs = scaler.transform(X)

    print("  Scoring models...")

    iso_s = score_iso(iso,Xs)
    lof_s = score_lof(lof,Xs)
    bil_s = score_bilstm_fast(bilstm,seq_scaler,X)
    rule_s= score_rules(df)
    dev_s = score_dev(Xs)

    ensemble = (
        iso_s*0.2 + lof_s*0.2 + bil_s*0.2 +
        dev_s*0.2 + rule_s*0.2
    )

    results=[
        evaluate(y,iso_s,"ISO"),
        evaluate(y,lof_s,"LOF"),
        evaluate(y,bil_s,"BiLSTM"),
        evaluate(y,ensemble,"ENSEMBLE")
    ]

    print("\nRESULTS:")
    for r in results:
        print(r)

    db["evaluation_results"].drop()
    db["evaluation_results"].insert_one({
        "time":datetime.utcnow(),
        "results":results
    })

    print("\nSaved to MongoDB ✓")
    client.close()