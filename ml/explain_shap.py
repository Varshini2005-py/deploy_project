"""
Module 3 — Step 1
File : D:/rajasri/xai_itd_dlp/ml/explain_shap.py

What this does:
  - Loads the trained Isolation Forest + scaler from ml/models/ using joblib
    (same as detect_anomaly.py — avoids pickle version mismatch)
  - Fetches each real employee's latest feature vector from behavior_profiles
  - Computes SHAP values using TreeExplainer with tree_path_dependent
    (no background dataset needed — runs in milliseconds per employee)
  - Saves results to MongoDB collection: shap_explanations

Called by:
  scheduler.py — after detect_anomaly step (Step 4 in the pipeline)

Academic reference:
  Lundberg & Lee (2017) — A Unified Approach to Interpreting Model Predictions
  SHAP formula:
    phi_i = sum over S not containing i of
    [ |S|!(|F|-|S|-1)! / |F|! ] * [ f(S U {i}) - f(S) ]
"""

import os
import sys
import numpy as np
import joblib
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from models.user import db

shap_col          = db["shap_explanations"]
profiles_col      = db["behavior_profiles"]
threat_scores_col = db["threat_scores"]

ML_DIR     = os.path.dirname(os.path.abspath(__file__))
MODELS_DIR = os.path.join(ML_DIR, "models")

ISO_PATH    = os.path.join(MODELS_DIR, "isolation_forest.pkl")
SCALER_PATH = os.path.join(MODELS_DIR, "scaler.pkl")

FEATURE_COLUMNS = [
    "logon_count", "logoff_count", "after_hrs_logon", "unique_pcs",
    "session_duration_min", "login_hour_mean",
    "usb_connect_count", "usb_after_hrs",
    "file_access_count", "file_copy_count", "file_delete_count",
    "file_to_removable", "file_from_removable", "file_risk_ratio",
    "email_count", "email_after_hrs", "email_attach_total",
    "email_size_mean", "email_bcc_count",
    "phone_detected_count", "face_missing_count", "blocked_action_count"
]


# =============================================================================
# LOAD MODELS — using joblib exactly like detect_anomaly.py
# =============================================================================

def load_iso_and_scaler():
    """
    Load only Isolation Forest + StandardScaler using joblib.
    Returns (iso, scaler) or (None, None).

    Note: detect_anomaly.load_models() returns a full dict with all 6 models.
    We only need iso + scaler for SHAP TreeExplainer, so we load them directly.
    """
    if not os.path.exists(ISO_PATH):
        print(f"[SHAP] isolation_forest.pkl not found at {ISO_PATH}")
        return None, None
    if not os.path.exists(SCALER_PATH):
        print(f"[SHAP] scaler.pkl not found at {SCALER_PATH}")
        return None, None
    try:
        iso    = joblib.load(ISO_PATH)
        scaler = joblib.load(SCALER_PATH)
        print("[SHAP] Isolation Forest + scaler loaded via joblib")
        return iso, scaler
    except Exception as e:
        print(f"[SHAP ERROR] joblib load failed: {e}")
        return None, None


# =============================================================================
# FETCH EMPLOYEE FEATURE VECTORS
# =============================================================================

def get_latest_profiles():
    """
    Fetch each employee's most recent feature vector from behavior_profiles.
    """
    pipeline = [
        {"$sort": {"day": -1}},
        {"$group": {
            "_id":      "$user_email",
            "day":      {"$first": "$day"},
            "features": {"$first": "$$ROOT"}
        }}
    ]
    results  = list(profiles_col.aggregate(pipeline))
    profiles = []
    for r in results:
        email    = r["_id"]
        day      = r["day"]
        doc      = r["features"]
        feat_vec = {col: float(doc.get(col, 0.0)) for col in FEATURE_COLUMNS}
        profiles.append({"user_email": email, "day": day, "features": feat_vec})

    print(f"[SHAP] Found {len(profiles)} employee profile(s)")
    return profiles


# =============================================================================
# FETCH RISK LABEL
# =============================================================================

def get_risk_info(email):
    doc = threat_scores_col.find_one(
        {"user_email": email},
        sort=[("scored_at", -1)]
    )
    if doc:
        return doc.get("risk_label", "UNKNOWN"), float(doc.get("risk_score", 0.0))
    return "UNKNOWN", 0.0


# =============================================================================
# COMPUTE SHAP VALUES
# =============================================================================

def compute_shap_for_employee(iso_model, scaler, profile):
    """
    Compute SHAP values using TreeExplainer with tree_path_dependent mode.
    - No background data needed
    - Runs in milliseconds
    - Correct mode for IsolationForest (tree ensemble)
    """
    try:
        import shap
    except ImportError:
        print("[SHAP ERROR] shap not installed. Run: pip install shap")
        return None

    email    = profile["user_email"]
    feat_vec = profile["features"]

    raw = np.array(
        [[feat_vec[col] for col in FEATURE_COLUMNS]],
        dtype=np.float64
    )

    try:
        scaled = scaler.transform(raw)
    except Exception as e:
        print(f"[SHAP ERROR] scaler.transform failed for {email}: {e}")
        return None

    try:
        explainer = shap.TreeExplainer(
            iso_model,
            feature_perturbation="tree_path_dependent"
        )
        shap_vals  = explainer.shap_values(scaled)   # shape (1, 22)
        base_value = float(np.array(explainer.expected_value).flat[0])
    except Exception as e:
        print(f"[SHAP ERROR] TreeExplainer failed for {email}: {e}")
        return None

    shap_row = shap_vals[0]
    raw_row  = raw[0]

    attributions = []
    for i, col in enumerate(FEATURE_COLUMNS):
        attributions.append({
            "feature":       col,
            "shap_value":    round(float(shap_row[i]), 6),
            "feature_value": round(float(raw_row[i]), 4)
        })

    # Sort by absolute SHAP value — most impactful first
    attributions.sort(key=lambda x: abs(x["shap_value"]), reverse=True)

    return {
        "shap_values": attributions,
        "base_value":  round(base_value, 6)
    }


# =============================================================================
# SAVE TO MONGODB
# =============================================================================

def save_explanation(email, day, shap_result, risk_label, risk_score):
    doc = {
        "user_email":  email,
        "day":         day,
        "shap_values": shap_result["shap_values"],
        "base_value":  shap_result["base_value"],
        "risk_label":  risk_label,
        "risk_score":  risk_score,
        "scored_at":   datetime.now(timezone.utc)
    }
    shap_col.update_one(
        {"user_email": email, "day": day},
        {"$set": doc},
        upsert=True
    )
    print(f"[SHAP] Saved → {email}  day={day}  risk={risk_label}")


# =============================================================================
# MAIN ENTRY POINT — called by scheduler.py
# =============================================================================

def run_shap_explanations(iso_model=None, scaler=None):
    """
    Compute and save SHAP explanations for all active employees.

    Parameters
    ----------
    iso_model : IsolationForest, optional
        When called from scheduler, pass models_dict["iso"] directly.
    scaler : StandardScaler, optional
        When called from scheduler, pass models_dict["scaler"] directly.
    """
    print("\n[SHAP] ── Starting SHAP explanation run ──")

    # Load from disk if not passed in
    if iso_model is None or scaler is None:
        iso_model, scaler = load_iso_and_scaler()
    if iso_model is None:
        print("[SHAP] Cannot run — models unavailable")
        return False

    profiles = get_latest_profiles()
    if not profiles:
        print("[SHAP] No behavior profiles — skipping")
        return False

    success_count = 0
    for profile in profiles:
        email = profile["user_email"]
        day   = profile["day"]

        print(f"[SHAP] Processing {email}...")

        # Skip zero-activity employees (e.g. isha)
        if all(v == 0.0 for v in profile["features"].values()):
            print(f"[SHAP] Skipping {email} — zero activity")
            continue

        result = compute_shap_for_employee(iso_model, scaler, profile)
        if result is None:
            continue

        risk_label, risk_score = get_risk_info(email)
        save_explanation(email, day, result, risk_label, risk_score)
        success_count += 1

    print(f"[SHAP] ── Done — {success_count}/{len(profiles)} explanations saved ──\n")
    return success_count > 0


# =============================================================================
# HELPERS for xai_api.py
# =============================================================================

def get_latest_explanations():
    """Latest SHAP explanation per employee — used by GET /api/xai/explanations"""
    pipeline = [
        {"$sort": {"scored_at": -1}},
        {"$group": {
            "_id":         "$user_email",
            "user_email":  {"$first": "$user_email"},
            "day":         {"$first": "$day"},
            "shap_values": {"$first": "$shap_values"},
            "base_value":  {"$first": "$base_value"},
            "risk_label":  {"$first": "$risk_label"},
            "risk_score":  {"$first": "$risk_score"},
            "scored_at":   {"$first": "$scored_at"}
        }}
    ]
    results = list(shap_col.aggregate(pipeline))
    for r in results:
        r.pop("_id", None)
        if isinstance(r.get("scored_at"), datetime):
            r["scored_at"] = r["scored_at"].strftime("%Y-%m-%d %H:%M:%S")
    return results


def get_explanation_history(email):
    """30-day SHAP history for one employee — used by GET /api/xai/explanations/<email>"""
    docs = list(shap_col.find(
        {"user_email": email},
        sort=[("scored_at", -1)],
        limit=30
    ))
    for d in docs:
        d.pop("_id", None)
        if isinstance(d.get("scored_at"), datetime):
            d["scored_at"] = d["scored_at"].strftime("%Y-%m-%d %H:%M:%S")
    return docs


# =============================================================================
# STANDALONE TEST
# =============================================================================

if __name__ == "__main__":
    print("=" * 60)
    print("  XAI-ITD-DLP — SHAP Explanation Engine (standalone test)")
    print("=" * 60)

    ok = run_shap_explanations()

    if ok:
        print("\n[TEST] Latest explanations from MongoDB:")
        for exp in get_latest_explanations():
            print(f"\n  {exp['user_email']}  |  {exp['day']}  |  "
                  f"{exp['risk_label']}  |  score={exp['risk_score']}")
            print("  Top 5 features:")
            for feat in exp["shap_values"][:5]:
                arrow = "▲ RISK" if feat["shap_value"] > 0 else "▼ SAFE"
                print(f"    {feat['feature']:30s}  "
                      f"shap={feat['shap_value']:+.4f}  "
                      f"val={feat['feature_value']}  {arrow}")
    else:
        print("\n[TEST] No explanations generated.")
        print("       Ensure behavior_profiles has data and models exist.")