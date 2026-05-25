"""
Task 1 - Employee Behavior Analysis (Fast Vectorized Version)
File : D:/rajasri/xai_itd_dlp/ml/analyze_behavior.py
"""

import os
import pandas as pd
import numpy as np
from pymongo import MongoClient
from datetime import datetime, timedelta

# ── Config ─────────────────────────────────────────────────────────────────
# Portable path — works on Render (Linux) and Windows localhost
DATASET_PATH    = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "dataset")
WORK_HOUR_START = 9
WORK_HOUR_END   = 18

try:
    from config import MONGO_URI, DB_NAME
except Exception:
    MONGO_URI = "mongodb://localhost:27017/"
    DB_NAME   = "xai_itd_dlp"

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


# =============================================================================
# PART A — CERT CSV feature engineering (fully vectorized)
# =============================================================================

def load_csv(name):
    path = os.path.join(DATASET_PATH, f"clean_{name}.csv")
    if not os.path.exists(path):
        print(f"  [WARN] {path} not found — skipping")
        return None
    df = pd.read_csv(path, low_memory=False)
    if "date" in df.columns:
        df["date"]      = pd.to_datetime(df["date"], errors="coerce")
        df["hour"]      = df["date"].dt.hour
        df["day"]       = df["date"].dt.date
        df["after_hrs"] = (~df["hour"].between(WORK_HOUR_START, WORK_HOUR_END - 1)).astype(int)
    print(f"  Loaded clean_{name}.csv  —  {len(df):,} rows")
    return df


def build_cert_features():
    logon  = load_csv("logon")
    device = load_csv("device")
    file_  = load_csv("file")
    email  = load_csv("email")
    psych  = load_csv("psychometric")

    if logon is None:
        print("  [ERR] logon.csv missing — cannot build CERT features.")
        return pd.DataFrame()

    print("  Aggregating logon features...")
    logons  = logon[logon["activity"] == "Logon"]
    logoffs = logon[logon["activity"] == "Logoff"]

    g_all   = logon.groupby(["user","day"])
    g_on    = logons.groupby(["user","day"])
    g_off   = logoffs.groupby(["user","day"])

    feat = pd.DataFrame(index=g_all.groups.keys()).reset_index()
    feat.columns = ["user","day"]

    feat = feat.merge(
        g_all.size().rename("logon_count").reset_index(), on=["user","day"], how="left"
    ).merge(
        g_off.size().rename("logoff_count").reset_index(), on=["user","day"], how="left"
    ).merge(
        g_all["after_hrs"].max().rename("after_hrs_logon").reset_index(), on=["user","day"], how="left"
    ).merge(
        g_all["pc"].nunique().rename("unique_pcs").reset_index(), on=["user","day"], how="left"
    ).merge(
        g_on["hour"].mean().rename("login_hour_mean").reset_index(), on=["user","day"], how="left"
    )

    # Session duration: last logoff - first logon per user/day
    first_on  = logons.groupby(["user","day"])["date"].min().rename("first_on")
    last_off  = logoffs.groupby(["user","day"])["date"].max().rename("last_off")
    sess      = pd.concat([first_on, last_off], axis=1).reset_index()
    sess["session_duration_min"] = (
        (sess["last_off"] - sess["first_on"]).dt.total_seconds() / 60
    ).clip(lower=0)
    feat = feat.merge(sess[["user","day","session_duration_min"]], on=["user","day"], how="left")

    print("  Aggregating device features...")
    if device is not None:
        g_dev = device[device["activity"] == "Connect"].groupby(["user","day"])
        feat = feat.merge(
            g_dev.size().rename("usb_connect_count").reset_index(), on=["user","day"], how="left"
        ).merge(
            device.groupby(["user","day"])["after_hrs"].max().rename("usb_after_hrs").reset_index(),
            on=["user","day"], how="left"
        )
    else:
        feat["usb_connect_count"] = feat["usb_after_hrs"] = 0

    print("  Aggregating file features...")
    if file_ is not None:
        g_fil  = file_.groupby(["user","day"])
        copies  = file_[file_["activity"] == "file copy"].groupby(["user","day"]).size().rename("file_copy_count")
        deletes = file_[file_["activity"] == "file delete"].groupby(["user","day"]).size().rename("file_delete_count")

        feat = feat.merge(
            g_fil.size().rename("file_access_count").reset_index(), on=["user","day"], how="left"
        ).merge(copies.reset_index(), on=["user","day"], how="left"
        ).merge(deletes.reset_index(), on=["user","day"], how="left")

        if "to_removable_media" in file_.columns:
            feat = feat.merge(
                file_.groupby(["user","day"])["to_removable_media"].max().rename("file_to_removable").reset_index(),
                on=["user","day"], how="left"
            )
        else:
            feat["file_to_removable"] = 0

        if "from_removable_media" in file_.columns:
            feat = feat.merge(
                file_.groupby(["user","day"])["from_removable_media"].max().rename("file_from_removable").reset_index(),
                on=["user","day"], how="left"
            )
        else:
            feat["file_from_removable"] = 0
    else:
        for k in ["file_access_count","file_copy_count","file_delete_count",
                  "file_to_removable","file_from_removable"]:
            feat[k] = 0

    print("  Aggregating email features...")
    if email is not None:
        g_eml = email.groupby(["user","day"])
        feat = feat.merge(
            g_eml.size().rename("email_count").reset_index(), on=["user","day"], how="left"
        ).merge(
            g_eml["after_hrs"].max().rename("email_after_hrs").reset_index(), on=["user","day"], how="left"
        )
        if "attachments" in email.columns:
            feat = feat.merge(
                g_eml["attachments"].sum().rename("email_attach_total").reset_index(),
                on=["user","day"], how="left"
            )
        else:
            feat["email_attach_total"] = 0

        if "size" in email.columns:
            feat = feat.merge(
                g_eml["size"].mean().rename("email_size_mean").reset_index(),
                on=["user","day"], how="left"
            )
        else:
            feat["email_size_mean"] = 0

        if "bcc" in email.columns:
            bcc_count = email[email["bcc"].notna() & (email["bcc"].astype(str).str.strip() != "")]\
                .groupby(["user","day"]).size().rename("email_bcc_count")
            feat = feat.merge(bcc_count.reset_index(), on=["user","day"], how="left")
        else:
            feat["email_bcc_count"] = 0
    else:
        for k in ["email_count","email_after_hrs","email_attach_total","email_size_mean","email_bcc_count"]:
            feat[k] = 0

    # Psychometric join
    if psych is not None:
        psych = psych.rename(columns={"user_id": "user"})
        for col in ["O","C","E","A","N"]:
            if col not in psych.columns:
                psych[col] = 50
        feat = feat.merge(psych[["user","O","C","E","A","N"]], on="user", how="left")
        for col in ["O","C","E","A","N"]:
            feat[f"psych_{col}"] = feat[col].fillna(50)
            feat.drop(columns=[col], inplace=True, errors="ignore")
    else:
        for col in ["O","C","E","A","N"]:
            feat[f"psych_{col}"] = 50

    # Real-employee-only fields = 0 for CERT
    feat["phone_detected_count"] = 0
    feat["face_missing_count"]   = 0
    feat["blocked_action_count"] = 0

    # File risk ratio
    feat["file_copy_count"]   = feat.get("file_copy_count", pd.Series(0, index=feat.index)).fillna(0)
    feat["file_delete_count"] = feat.get("file_delete_count", pd.Series(0, index=feat.index)).fillna(0)
    feat["file_access_count"] = feat.get("file_access_count", pd.Series(0, index=feat.index)).fillna(0)
    feat["file_risk_ratio"]   = np.where(
        feat["file_access_count"] > 0,
        (feat["file_copy_count"] + feat["file_delete_count"]) / feat["file_access_count"],
        0
    ).round(4)

    feat = feat.fillna(0)
    feat["day"] = feat["day"].astype(str)

    print(f"  CERT features built: {len(feat):,} user-day records")
    return feat


def save_cert_features(df):
    col = db["cert_features"]
    col.drop()
    if df.empty:
        return
    # Insert in batches to avoid memory spike
    batch = 5000
    for i in range(0, len(df), batch):
        col.insert_many(df.iloc[i:i+batch].replace({np.nan: 0}).to_dict("records"))
    print(f"  Saved {len(df):,} records → cert_features")


# =============================================================================
# PART B — Real employee profiling from MongoDB (unchanged — already fast)
# =============================================================================

def get_all_employees():
    users = db["users"].find({"role": {"$in": ["employee", "manager"]}}, {"email": 1})
    return [u["email"] for u in users]


def build_employee_features(email, day_date):
    day_start = datetime.combine(day_date, datetime.min.time())
    day_end   = day_start + timedelta(days=1)
    feat      = {"user_email": email, "day": str(day_date)}

    logs    = list(db["activity_logs"].find({
        "user_email": email, "timestamp": {"$gte": day_start, "$lt": day_end}
    }))
    logons  = [l for l in logs if "LOGIN"  in l.get("event_type", "")]
    logoffs = [l for l in logs if "LOGOUT" in l.get("event_type", "")]

    feat["logon_count"]      = len(logons)
    feat["logoff_count"]     = len(logoffs)
    feat["after_hrs_logon"]  = 1 if any(
        l["timestamp"].hour < WORK_HOUR_START or l["timestamp"].hour >= WORK_HOUR_END
        for l in logons) else 0
    locations = {l.get("location","") for l in logs if l.get("location","-") != "-"}
    feat["unique_pcs"]       = len(locations)
    if logons and logoffs:
        feat["session_duration_min"] = max(0, (
            max(l["timestamp"] for l in logoffs) -
            min(l["timestamp"] for l in logons)
        ).total_seconds() / 60)
    else:
        feat["session_duration_min"] = 0
    feat["login_hour_mean"] = round(float(np.mean([l["timestamp"].hour for l in logons])), 2) \
                              if logons else 0

    events = list(db["security_events"].find({
        "user_email": email, "timestamp": {"$gte": day_start, "$lt": day_end}
    }))

    def evt(kw):
        return [e for e in events if kw in e.get("action","").upper()]

    usb_evts = evt("USB") + evt("DEVICE")
    feat["usb_connect_count"] = len(usb_evts)
    feat["usb_after_hrs"]     = 1 if any(
        e["timestamp"].hour < WORK_HOUR_START or e["timestamp"].hour >= WORK_HOUR_END
        for e in usb_evts) else 0

    file_evts = evt("FILE") + evt("VIEW")
    feat["file_access_count"]   = len(file_evts)
    feat["file_copy_count"]     = len([e for e in file_evts if "COPY"   in e.get("action","")])
    feat["file_delete_count"]   = len([e for e in file_evts if "DELETE" in e.get("action","")])
    feat["file_to_removable"]   = len([e for e in file_evts if "USB"    in e.get("detail","").upper()])
    feat["file_from_removable"] = 0
    total = feat["file_access_count"]
    feat["file_risk_ratio"] = round(
        (feat["file_copy_count"] + feat["file_delete_count"]) / total, 4
    ) if total > 0 else 0

    email_evts = evt("EMAIL")
    feat["email_count"]        = len(email_evts)
    feat["email_after_hrs"]    = 1 if any(
        e["timestamp"].hour < WORK_HOUR_START or e["timestamp"].hour >= WORK_HOUR_END
        for e in email_evts) else 0
    feat["email_attach_total"] = 0
    feat["email_size_mean"]    = 0
    feat["email_bcc_count"]    = 0

    feat["phone_detected_count"] = len(evt("PHONE"))
    feat["face_missing_count"]   = len(evt("FACE"))
    feat["blocked_action_count"] = len([e for e in events if e.get("blocked") is True])

    for col in ["O","C","E","A","N"]:
        feat[f"psych_{col}"] = 50

    return feat


def build_all_employee_profiles(days_back=30):
    employees = get_all_employees()
    if not employees:
        print("  [WARN] No employees found in users collection.")
        return

    today     = datetime.utcnow().date()
    date_list = [today - timedelta(days=i) for i in range(days_back)]
    records   = []

    for email in employees:
        employee_has_any_activity = False
        today_profile_written = False
        for day in date_list:
            feat = build_employee_features(email, day)
            activity_sum = (
                feat["logon_count"] + feat["file_access_count"] +
                feat["email_count"] + feat["usb_connect_count"] +
                feat["phone_detected_count"] + feat["blocked_action_count"]
            )
            if activity_sum > 0:
                feat["created_at"] = datetime.utcnow()
                records.append(feat)
                employee_has_any_activity = True
                if day == today:
                    today_profile_written = True

        # Always ensure a today profile exists so threat_scores gets a today entry.
        # If the employee had activity on other days but none today, write a zero
        # profile for today so detect_anomaly scores them with today's date.
        if not today_profile_written:
            zero_feat = build_employee_features(email, today)
            zero_feat["created_at"] = datetime.utcnow()
            zero_feat["note"]       = "no_activity_today"
            records.append(zero_feat)
            if not employee_has_any_activity:
                print(f"    [NEW] {email} — no activity found, created zero profile")
            else:
                print(f"    [TODAY] {email} — no activity today, created zero today profile")

    col = db["behavior_profiles"]
    col.drop()
    if records:
        col.insert_many(records)
    print(f"  Saved {len(records)} behavior profile records for "
          f"{len(employees)} employees → behavior_profiles")


def build_user_baseline():
    profiles = pd.DataFrame(list(db["behavior_profiles"].find({}, {"_id": 0})))
    if profiles.empty:
        print("  [WARN] No profiles found — skipping baseline.")
        return

    baselines = []
    for email, grp in profiles.groupby("user_email"):
        bl = {"user_email": email}
        for col in FEATURE_COLS:
            if col in grp.columns:
                bl[f"{col}_mean"] = round(float(grp[col].mean()), 4)
                bl[f"{col}_std"]  = round(float(grp[col].std(skipna=True)), 4)
            else:
                bl[f"{col}_mean"] = 0.0
                bl[f"{col}_std"]  = 0.0
        bl["profile_days"] = len(grp)
        bl["updated_at"]   = datetime.utcnow()
        baselines.append(bl)

    col = db["user_baselines"]
    col.drop()
    col.insert_many(baselines)
    print(f"  Saved baselines for {len(baselines)} employees → user_baselines")


# =============================================================================
# MAIN
# =============================================================================

if __name__ == "__main__":
    print("\n=== Task 1: Employee Behavior Analysis (Fast Version) ===\n")

    print("[1/4] Loading and cleaning CERT CSVs...")
    cert_df = build_cert_features()

    print("\n[2/4] Saving CERT features to MongoDB...")
    save_cert_features(cert_df)

    print("\n[3/4] Building real employee profiles (last 30 days)...")
    build_all_employee_profiles(days_back=30)

    print("\n[4/4] Computing per-user baselines...")
    build_user_baseline()

    print("\n=== Task 1 complete ===")
    print("Collections written:")
    print("  cert_features      — CERT training data  (Task 2 input)")
    print("  behavior_profiles  — real employee daily vectors  (Task 2 input)")
    print("  user_baselines     — per-user mean/std  (Task 2 scoring)")
    client.close()