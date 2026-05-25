"""
Task 2 - Anomaly Detection & Risk Scoring (Full Ensemble)
File : D:/rajasri/xai_itd_dlp/ml/detect_anomaly.py

Models used:
  1. Isolation Forest     — global point anomaly detection
  2. DBLOF (LOF)          — local density-based anomaly detection
  3. Bi-LSTM              — temporal sequence analysis (7-day window)
  4. GCN                  — graph-based relationship modeling
  5. Z-Score deviation    — personal baseline deviation
  6. Rule-based           — hard policy violation triggers

Final risk score = weighted ensemble of all six signals (0-100)
"""

import os
import sys
import numpy as np
import pandas as pd
from pymongo import MongoClient
from datetime import datetime
from sklearn.ensemble import IsolationForest
from sklearn.neighbors import LocalOutlierFactor
from sklearn.preprocessing import StandardScaler, MinMaxScaler
import joblib
import torch
import torch.nn as nn
import networkx as nx

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# ── Config ───────────────────────────────────────────────────────────────────
# Portable path — works on Render (Linux) and Windows localhost
MODELS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "models")

try:
    from config import MONGO_URI, DB_NAME
except Exception:
    MONGO_URI = "mongodb://localhost:27017/"
    DB_NAME   = "xai_itd_dlp"

os.makedirs(MODELS_DIR, exist_ok=True)

client = MongoClient(MONGO_URI)
db     = client[DB_NAME]

FEATURE_COLS = [
    "logon_count", "logoff_count", "after_hrs_logon", "unique_pcs",
    "session_duration_min", "login_hour_mean",
    "usb_connect_count", "usb_after_hrs",
    "file_access_count", "file_copy_count", "file_delete_count",
    "file_to_removable", "file_from_removable", "file_risk_ratio",
    "email_count", "email_after_hrs", "email_attach_total",
    "email_size_mean", "email_bcc_count",
    "phone_detected_count", "face_missing_count", "blocked_action_count"
]

SEQ_LEN = 7


# =============================================================================
# MODEL 1 — Isolation Forest
# =============================================================================

def train_isolation_forest(X_scaled):
    print("  Training Isolation Forest...")
    iso = IsolationForest(n_estimators=200, contamination=0.05, random_state=42, n_jobs=-1)
    iso.fit(X_scaled)
    joblib.dump(iso, os.path.join(MODELS_DIR, "isolation_forest.pkl"))
    print("  Isolation Forest saved.")
    return iso


def score_isolation_forest(iso, scaler, feature_vector):
    X        = np.array(feature_vector).reshape(1, -1)
    X_scaled = scaler.transform(X)
    raw      = iso.score_samples(X_scaled)[0]
    norm     = (raw - 0.1) / (-0.7 - 0.1)
    return round(float(np.clip(norm, 0, 1)) * 100, 2)


# =============================================================================
# MODEL 2 — DBLOF (Local Outlier Factor)
# =============================================================================

def train_dblof(X_scaled):
    print("  Training DBLOF (Local Outlier Factor)...")
    lof = LocalOutlierFactor(n_neighbors=20, contamination=0.05, novelty=True, n_jobs=-1)
    lof.fit(X_scaled)
    joblib.dump(lof, os.path.join(MODELS_DIR, "dblof.pkl"))
    print("  DBLOF saved.")
    return lof


def score_dblof(lof, scaler, feature_vector):
    X        = np.array(feature_vector).reshape(1, -1)
    X_scaled = scaler.transform(X)
    raw      = lof.score_samples(X_scaled)[0]
    norm     = (raw - (-0.5)) / ((-3.0) - (-0.5))
    return round(float(np.clip(norm, 0, 1)) * 100, 2)


# =============================================================================
# MODEL 3 — Bi-LSTM Autoencoder
# =============================================================================

class BiLSTMAutoencoder(nn.Module):
    def __init__(self, input_size, hidden_size=64, num_layers=2):
        super(BiLSTMAutoencoder, self).__init__()
        self.encoder = nn.LSTM(input_size, hidden_size, num_layers=num_layers,
                               batch_first=True, bidirectional=True, dropout=0.2)
        self.decoder = nn.LSTM(hidden_size * 2, hidden_size, num_layers=num_layers,
                               batch_first=True, dropout=0.2)
        self.output_layer = nn.Linear(hidden_size, input_size)

    def forward(self, x):
        enc_out, _ = self.encoder(x)
        dec_out, _ = self.decoder(enc_out)
        return self.output_layer(dec_out)


def build_sequences(df, user_col="user", day_col="day"):
    sequences = []
    for user, grp in df.groupby(user_col):
        grp_sorted = grp.sort_values(day_col)
        vals = grp_sorted[FEATURE_COLS].fillna(0).values
        if len(vals) < SEQ_LEN:
            pad  = np.zeros((SEQ_LEN - len(vals), len(FEATURE_COLS)))
            vals = np.vstack([pad, vals])
            sequences.append(vals)
        else:
            for i in range(len(vals) - SEQ_LEN + 1):
                sequences.append(vals[i:i+SEQ_LEN])
    return np.array(sequences, dtype=np.float32)


def train_bilstm(cert_df, seq_scaler):
    print("  Building sequences for Bi-LSTM...")
    seqs = build_sequences(cert_df, user_col="user", day_col="day")
    if len(seqs) == 0:
        print("  [WARN] No sequences — skipping Bi-LSTM")
        return None

    orig_shape  = seqs.shape
    seqs_scaled = seq_scaler.transform(seqs.reshape(-1, len(FEATURE_COLS))).reshape(orig_shape)
    seqs_tensor = torch.FloatTensor(seqs_scaled)

    print(f"  Training Bi-LSTM on {len(seqs_tensor)} sequences...")
    model     = BiLSTMAutoencoder(input_size=len(FEATURE_COLS))
    optimizer = torch.optim.Adam(model.parameters(), lr=1e-3)
    criterion = nn.MSELoss()
    loader    = torch.utils.data.DataLoader(
        torch.utils.data.TensorDataset(seqs_tensor), batch_size=64, shuffle=True)

    model.train()
    for epoch in range(15):
        total_loss = 0
        for (batch,) in loader:
            optimizer.zero_grad()
            loss = criterion(model(batch), batch)
            loss.backward()
            optimizer.step()
            total_loss += loss.item()
        if (epoch + 1) % 5 == 0:
            print(f"    Epoch {epoch+1}/15  loss={total_loss/len(loader):.4f}")

    torch.save(model.state_dict(), os.path.join(MODELS_DIR, "bilstm.pt"))
    print("  Bi-LSTM saved.")
    return model


def load_bilstm():
    path = os.path.join(MODELS_DIR, "bilstm.pt")
    if not os.path.exists(path):
        return None
    model = BiLSTMAutoencoder(input_size=len(FEATURE_COLS))
    model.load_state_dict(torch.load(path, map_location="cpu"))
    model.eval()
    return model


def score_bilstm(model, seq_scaler, user_history_df):
    if model is None:
        return 0.0
    vals = user_history_df[FEATURE_COLS].fillna(0).values[-SEQ_LEN:]
    if len(vals) < SEQ_LEN:
        pad  = np.zeros((SEQ_LEN - len(vals), len(FEATURE_COLS)))
        vals = np.vstack([pad, vals])
    vals_scaled = seq_scaler.transform(vals).astype(np.float32)
    tensor      = torch.FloatTensor(vals_scaled).unsqueeze(0)
    with torch.no_grad():
        reconstructed = model(tensor)
    error = nn.MSELoss()(reconstructed, tensor).item()
    return round(min(error / 0.3, 1.0) * 100, 2)


# =============================================================================
# MODEL 4 — GCN
# =============================================================================

class GCNLayer(nn.Module):
    def __init__(self, in_features, out_features):
        super(GCNLayer, self).__init__()
        self.W    = nn.Linear(in_features, out_features, bias=False)
        self.relu = nn.ReLU()

    def forward(self, H, A_norm):
        return self.relu(self.W(torch.mm(A_norm, H)))


class GCNAnomalyDetector(nn.Module):
    def __init__(self, in_features, hidden=32, out_features=16):
        super(GCNAnomalyDetector, self).__init__()
        self.layer1  = GCNLayer(in_features, hidden)
        self.layer2  = GCNLayer(hidden, out_features)
        self.decoder = nn.Linear(out_features, in_features)

    def forward(self, X, A_norm):
        h2 = self.layer2(self.layer1(X, A_norm), A_norm)
        return self.decoder(h2), h2


def build_behavior_graph(profiles_df):
    G = nx.Graph()
    user_features = {}
    for email, grp in profiles_df.groupby("user_email"):
        feat = grp[FEATURE_COLS].fillna(0).mean().values
        user_features[email] = feat
        G.add_node(email, features=feat)

    emails = list(user_features.keys())
    for i in range(len(emails)):
        for j in range(i+1, len(emails)):
            fi, fj = user_features[emails[i]], user_features[emails[j]]
            ni, nj = np.linalg.norm(fi), np.linalg.norm(fj)
            if ni > 0 and nj > 0:
                sim = np.dot(fi, fj) / (ni * nj)
                if sim > 0.5:
                    G.add_edge(emails[i], emails[j], weight=float(sim))

    for node in G.nodes():
        G.add_edge(node, node)
    return G, user_features


def graph_to_tensors(G, user_features, node_order):
    n         = len(node_order)
    node_idx  = {node: i for i, node in enumerate(node_order)}
    X         = np.array([user_features[n] for n in node_order], dtype=np.float32)
    A         = np.zeros((n, n), dtype=np.float32)
    for u, v, data in G.edges(data=True):
        if u in node_idx and v in node_idx:
            i, j    = node_idx[u], node_idx[v]
            w       = data.get("weight", 1.0)
            A[i, j] = w
            A[j, i] = w
    D_inv = np.linalg.pinv(np.diag(A.sum(axis=1)))
    return torch.FloatTensor(X), torch.FloatTensor(D_inv @ A)


def train_gcn(profiles_df, cert_df=None):
    print("  Building behavior graph for GCN...")
    if cert_df is not None and len(cert_df) > 0:
        cert_sample = cert_df.groupby("user")[FEATURE_COLS].mean().reset_index()
        cert_sample["user_email"] = cert_sample["user"]
        combined = pd.concat([
            profiles_df[["user_email"] + FEATURE_COLS],
            cert_sample[["user_email"] + FEATURE_COLS]
        ], ignore_index=True)
    else:
        combined = profiles_df[["user_email"] + FEATURE_COLS]

    G, user_features = build_behavior_graph(combined)
    node_order       = list(G.nodes())

    if len(node_order) < 2:
        print("  [WARN] Not enough nodes for GCN — skipping")
        return None, None, None

    X_tensor, A_tensor = graph_to_tensors(G, user_features, node_order)
    model     = GCNAnomalyDetector(in_features=X_tensor.shape[1])
    optimizer = torch.optim.Adam(model.parameters(), lr=1e-3)
    criterion = nn.MSELoss()

    print(f"  Training GCN on {len(node_order)} nodes, {G.number_of_edges()} edges...")
    model.train()
    for epoch in range(100):
        optimizer.zero_grad()
        reconstructed, _ = model(X_tensor, A_tensor)
        loss = criterion(reconstructed, X_tensor)
        loss.backward()
        optimizer.step()
        if (epoch + 1) % 25 == 0:
            print(f"    Epoch {epoch+1}/100  loss={loss.item():.4f}")

    torch.save({
        "state_dict":    model.state_dict(),
        "node_order":    node_order,
        "user_features": {k: v.tolist() for k, v in user_features.items()},
        "in_features":   X_tensor.shape[1]
    }, os.path.join(MODELS_DIR, "gcn.pt"))
    print("  GCN saved.")
    return model, node_order, user_features


def load_gcn():
    path = os.path.join(MODELS_DIR, "gcn.pt")
    if not os.path.exists(path):
        return None, None, None
    ckpt = torch.load(path, map_location="cpu")
    model = GCNAnomalyDetector(in_features=ckpt["in_features"])
    model.load_state_dict(ckpt["state_dict"])
    model.eval()
    return model, ckpt["node_order"], {k: np.array(v) for k, v in ckpt["user_features"].items()}


def score_gcn(model, node_order, user_features, email, today_features):
    if model is None or not node_order:
        return 0.0

    updated = dict(user_features)
    updated[email] = np.array(today_features, dtype=np.float32)

    rows = [{"user_email": u, **{c: v for c, v in zip(FEATURE_COLS, f)}}
            for u, f in updated.items()]
    G, uf = build_behavior_graph(pd.DataFrame(rows))
    valid_order = [n for n in node_order if n in uf]
    if not valid_order:
        return 0.0

    X_tensor, A_tensor = graph_to_tensors(G, uf, valid_order)
    with torch.no_grad():
        reconstructed, _ = model(X_tensor, A_tensor)

    errors = nn.MSELoss(reduction='none')(reconstructed, X_tensor).mean(dim=1)
    idx    = valid_order.index(email) if email in valid_order else 0
    return round(min(errors[idx].item() / 1.0, 1.0) * 100, 2)


# =============================================================================
# SCORING HELPERS
# =============================================================================

def is_zero_activity(feat_dict):
    return all(float(feat_dict.get(k, 0)) == 0 for k in [
        "logon_count", "file_access_count", "email_count",
        "usb_connect_count", "phone_detected_count",
        "blocked_action_count", "face_missing_count"
    ])


def get_deviation_score(feat_dict, baseline):
    if not baseline:
        return 0.0

    # New employee fix — less than 3 days history or all stds are zero
    # Use absolute risk scoring instead of personal deviation
    profile_days = baseline.get("profile_days", 0)
    all_std_zero = all(
        baseline.get(f"{col}_std", 0) == 0
        for col in FEATURE_COLS
    )

    if profile_days < 3 or all_std_zero:
        risky_sum = (
            float(feat_dict.get("phone_detected_count", 0)) * 10 +
            float(feat_dict.get("blocked_action_count", 0)) * 8  +
            float(feat_dict.get("after_hrs_logon", 0))      * 15 +
            float(feat_dict.get("usb_connect_count", 0))    * 10 +
            float(feat_dict.get("file_to_removable", 0))    * 20
        )
        return round(min(risky_sum, 100), 2)

    devs = []
    for col in FEATURE_COLS:
        val = feat_dict.get(col, 0)
        m   = baseline.get(f"{col}_mean", 0)
        s   = baseline.get(f"{col}_std",  0)
        devs.append(min(abs((val - m) / s), 3.0) if s and s > 0 else 0.0)
    return round((np.mean(devs) / 3.0) * 100, 2)


def get_rule_score(feat_dict):
    score = 0
    if feat_dict.get("after_hrs_logon", 0):          score += 15
    if feat_dict.get("usb_connect_count", 0) > 3:    score += 20
    if feat_dict.get("usb_after_hrs", 0):             score += 15
    if feat_dict.get("file_to_removable", 0) > 0:    score += 20
    if feat_dict.get("file_risk_ratio", 0) > 0.5:    score += 15
    # Scaled: each blocked action adds 4 points, capped at 30
    if feat_dict.get("blocked_action_count", 0) > 2:
        score += min(int(feat_dict.get("blocked_action_count", 0)) * 4, 30)
    # Scaled: each phone detection adds 5 points, capped at 30
    score += min(int(feat_dict.get("phone_detected_count", 0)) * 5, 30)
    if feat_dict.get("face_missing_count", 0) > 2:    score += 10
    if feat_dict.get("email_bcc_count", 0) > 5:       score += 10
    return min(score, 100)


def combine_scores(iso_s, dblof_s, bilstm_s, gcn_s, deviation_s, rule_s):
    return round(min(
        iso_s * 0.20 + dblof_s * 0.20 + bilstm_s * 0.20 +
        gcn_s * 0.15 + deviation_s * 0.15 + rule_s * 0.10,
        100
    ), 2)


def risk_label(score):
    if score < 40: return "LOW"
    if score < 70: return "MEDIUM"
    if score < 90: return "HIGH"
    return "CRITICAL"


# =============================================================================
# TRAIN ALL + LOAD ALL
# =============================================================================

def train_all_models():
    print("\n  Loading CERT features...")
    cert_docs = list(db["cert_features"].find({}, {"_id": 0}))
    if not cert_docs:
        print("  [ERR] cert_features empty. Run analyze_behavior.py first.")
        return None

    cert_df = pd.DataFrame(cert_docs)
    X       = cert_df[[c for c in FEATURE_COLS if c in cert_df.columns]].fillna(0).values

    print("  Fitting scalers...")
    scaler     = StandardScaler()
    seq_scaler = MinMaxScaler()
    X_scaled   = scaler.fit_transform(X)
    seq_scaler.fit(X)
    joblib.dump(scaler,     os.path.join(MODELS_DIR, "scaler.pkl"))
    joblib.dump(seq_scaler, os.path.join(MODELS_DIR, "seq_scaler.pkl"))

    iso  = train_isolation_forest(X_scaled)
    lof  = train_dblof(X_scaled)
    lstm = train_bilstm(cert_df, seq_scaler)

    profiles_df = pd.DataFrame(list(db["behavior_profiles"].find({}, {"_id": 0})))
    gcn_model, node_order, user_features = train_gcn(profiles_df, cert_df)

    return {
        "iso": iso, "lof": lof, "lstm": lstm,
        "gcn": gcn_model, "node_order": node_order, "user_features": user_features,
        "scaler": scaler, "seq_scaler": seq_scaler
    }


def load_models():
    paths = [os.path.join(MODELS_DIR, f)
             for f in ["isolation_forest.pkl", "dblof.pkl", "scaler.pkl", "seq_scaler.pkl"]]
    if not all(os.path.exists(p) for p in paths):
        return None

    print("  Loading saved models from disk...")
    iso        = joblib.load(os.path.join(MODELS_DIR, "isolation_forest.pkl"))
    lof        = joblib.load(os.path.join(MODELS_DIR, "dblof.pkl"))
    scaler     = joblib.load(os.path.join(MODELS_DIR, "scaler.pkl"))
    seq_scaler = joblib.load(os.path.join(MODELS_DIR, "seq_scaler.pkl"))
    lstm       = load_bilstm()
    gcn_model, node_order, user_features = load_gcn()

    return {
        "iso": iso, "lof": lof, "lstm": lstm,
        "gcn": gcn_model, "node_order": node_order, "user_features": user_features,
        "scaler": scaler, "seq_scaler": seq_scaler
    }


# =============================================================================
# SCORE ALL EMPLOYEES
# =============================================================================

def score_all_employees(models):
    profiles = list(db["behavior_profiles"].find({}, {"_id": 0}))
    if not profiles:
        print("  [WARN] No behavior profiles. Run analyze_behavior.py first.")
        return

    baselines   = {b["user_email"]: b for b in db["user_baselines"].find({}, {"_id": 0})}
    profiles_df = pd.DataFrame(profiles)

    print(f"  Scoring {len(profiles)} records with 6-model ensemble...")
    threat_records = []
    skipped_zero   = 0

    for p in profiles:
        email = p.get("user_email")
        day   = p.get("day")

        if is_zero_activity(p):
            skipped_zero += 1
            threat_records.append({
                "user_email": email, "day": day,
                "risk_score": 0.0, "risk_label": "LOW",
                "iso_score": 0.0, "dblof_score": 0.0,
                "bilstm_score": 0.0, "gcn_score": 0.0,
                "deviation_score": 0.0, "rule_score": 0.0,
                "top_features": [], "note": "no_activity",
                "scored_at": datetime.utcnow()
            })
            continue

        feat_vec = [float(p.get(c, 0)) for c in FEATURE_COLS]

        iso_score      = score_isolation_forest(models["iso"], models["scaler"], feat_vec)
        dblof_score    = score_dblof(models["lof"], models["scaler"], feat_vec)
        user_hist      = profiles_df[profiles_df["user_email"] == email].sort_values("day")
        bilstm_score   = score_bilstm(models["lstm"], models["seq_scaler"], user_hist)
        gcn_score      = score_gcn(models["gcn"], models.get("node_order"),
                                   models.get("user_features"), email, feat_vec)
        deviation_score = get_deviation_score(p, baselines.get(email, {}))
        rule_score      = get_rule_score(p)
        final_score     = combine_scores(iso_score, dblof_score, bilstm_score,
                                         gcn_score, deviation_score, rule_score)
        label = risk_label(final_score)

        bl      = baselines.get(email, {})
        contribs = sorted([
            (col, round(abs((p.get(col,0) - bl.get(f"{col}_mean",0)) /
                            max(bl.get(f"{col}_std", 0), 1e-9)), 2))
            for col in FEATURE_COLS
        ], key=lambda x: x[1], reverse=True)[:3]

        threat_records.append({
            "user_email":      email, "day": day,
            "risk_score":      final_score, "risk_label": label,
            "iso_score":       iso_score, "dblof_score": dblof_score,
            "bilstm_score":    bilstm_score, "gcn_score": gcn_score,
            "deviation_score": deviation_score, "rule_score": rule_score,
            "top_features":    [{"feature": f, "z_score": z} for f, z in contribs],
            "scored_at":       datetime.utcnow()
        })

    # Use upsert per (user_email, day) instead of drop+insert
    # This preserves any realtime scores written between scans
    for rec in threat_records:
        db["threat_scores"].replace_one(
            {"user_email": rec["user_email"], "day": rec["day"]},
            rec,
            upsert=True
        )

    print(f"  Saved {len(threat_records)} records → threat_scores")
    print(f"  ({skipped_zero} zero-activity → auto LOW/0)")

    df = pd.DataFrame(threat_records)
    print("\n  Risk distribution:")
    print(df["risk_label"].value_counts().to_string())
    print("\n  Score breakdown per employee:")
    for email, grp in df.groupby("user_email"):
        r = grp.sort_values("day").iloc[-1]
        note = " ← no_activity" if r.get("note") == "no_activity" else ""
        print(f"    {email:35s} FINAL={r['risk_score']:5.1f}[{r['risk_label']}] "
              f"ISO={r['iso_score']:4.1f} DBLOF={r['dblof_score']:4.1f} "
              f"LSTM={r['bilstm_score']:4.1f} GCN={r['gcn_score']:4.1f}{note}")


# =============================================================================
# MAIN
# =============================================================================

if __name__ == "__main__":
    print("\n=== Task 2: Ensemble (IF + DBLOF + Bi-LSTM + GCN + Z-Score + Rules) ===\n")

    print("[1/3] Loading models...")
    models = load_models()
    if models is None:
        print("  No saved models — training now (10-20 min first run)...")
        models = train_all_models()
        if models is None:
            client.close(); exit(1)

    print("\n[2/3] Scoring all employees...")
    score_all_employees(models)

    print("\n[3/3] Complete.")
    client.close()