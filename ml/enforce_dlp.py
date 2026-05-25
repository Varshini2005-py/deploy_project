"""
Task 3 - DLP Enforcement via AI Risk Scores
File : D:/rajasri/xai_itd_dlp/ml/enforce_dlp.py

What this does:
  1. Reads latest threat_scores from MongoDB
  2. Based on risk thresholds writes alerts to ai_alerts collection
  3. Emits real-time Socket.IO events to manager dashboard
  4. CRITICAL scores trigger session lock via existing monitor.py logic

Thresholds:
  0  - 39  -> LOW      : no action
  40 - 69  -> MEDIUM   : warning alert to manager dashboard
  70 - 89  -> HIGH     : high-risk alert + employee flagged
  90 - 100 -> CRITICAL : alert + session lock pushed via Socket.IO
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from pymongo import MongoClient
from datetime import datetime, date

# ── Config ───────────────────────────────────────────────────────────────────
MONGO_URI = "mongodb://localhost:27017/"
DB_NAME   = "xai_itd_dlp"

client = MongoClient(MONGO_URI)
db     = client[DB_NAME]


# =============================================================================
# HELPERS
# =============================================================================

def get_latest_scores():
    """Get the single most recent risk score per employee."""
    pipeline = [
        {"$sort": {"scored_at": -1}},
        {"$group": {
            "_id":          "$user_email",
            "user_email":   {"$first": "$user_email"},
            "day":          {"$first": "$day"},
            "risk_score":   {"$first": "$risk_score"},
            "risk_label":   {"$first": "$risk_label"},
            "anomaly_score":   {"$first": "$anomaly_score"},
            "deviation_score": {"$first": "$deviation_score"},
            "rule_score":      {"$first": "$rule_score"},
            "top_features":    {"$first": "$top_features"},
            "scored_at":       {"$first": "$scored_at"},
            "note":            {"$first": "$note"},
        }}
    ]
    return list(db["threat_scores"].aggregate(pipeline))


def already_alerted_today(user_email, level):
    """Prevent duplicate alerts for same employee+level on same day."""
    today_str = str(date.today())
    existing  = db["ai_alerts"].find_one({
        "user_email": user_email,
        "level":      level,
        "date":       today_str
    })
    return existing is not None


def save_alert(user_email, level, risk_score, top_features, note=""):
    """Write alert to ai_alerts collection — manager dashboard reads from here."""
    today_str = str(date.today())
    alert = {
        "user_email":   user_email,
        "level":        level,           # MEDIUM / HIGH / CRITICAL
        "risk_score":   risk_score,
        "top_features": top_features,
        "note":         note,
        "date":         today_str,
        "created_at":   datetime.utcnow(),
        "acknowledged": False
    }
    db["ai_alerts"].insert_one(alert)
    return alert


def format_top_features(top_features):
    """Human readable explanation of why the score is high."""
    if not top_features:
        return "No specific indicators"
    parts = []
    for f in top_features:
        name  = f.get("feature", "").replace("_", " ").title()
        zscore = f.get("z_score", 0)
        parts.append(f"{name} ({zscore:.1f}σ above normal)")
    return ", ".join(parts)


# =============================================================================
# ENFORCEMENT ACTIONS
# =============================================================================

def enforce_medium(score_doc):
    """Score 40-69: Warning alert to manager dashboard only."""
    email      = score_doc["user_email"]
    score      = score_doc["risk_score"]
    top_feats  = score_doc.get("top_features", [])
    explanation = format_top_features(top_feats)

    if already_alerted_today(email, "MEDIUM"):
        print(f"    [SKIP] {email} — MEDIUM alert already sent today")
        return

    save_alert(email, "MEDIUM", score, top_feats,
               note=f"Behavioral anomaly detected: {explanation}")
    print(f"    [MEDIUM] {email} — score={score} — alert written to DB")
    print(f"             Reason: {explanation}")


def enforce_high(score_doc):
    """Score 70-89: High-risk alert + log security event."""
    email      = score_doc["user_email"]
    score      = score_doc["risk_score"]
    top_feats  = score_doc.get("top_features", [])
    explanation = format_top_features(top_feats)

    if already_alerted_today(email, "HIGH"):
        print(f"    [SKIP] {email} — HIGH alert already sent today")
        return

    save_alert(email, "HIGH", score, top_feats,
               note=f"High-risk behavior detected: {explanation}")

    # Also log to existing security_events so it appears in Module 1 logs
    from models.user import log_security_event
    log_security_event(
        email,
        "AI_HIGH_RISK",
        f"AI Risk Score {score:.1f} — {explanation}",
        "-", "-",
        blocked=False
    )
    print(f"    [HIGH] {email} — score={score} — alert + security event logged")
    print(f"           Reason: {explanation}")


def enforce_critical(score_doc, socketio_instance=None):
    """Score 90+: Alert + real-time Socket.IO push to manager + employee."""
    email      = score_doc["user_email"]
    score      = score_doc["risk_score"]
    top_feats  = score_doc.get("top_features", [])
    explanation = format_top_features(top_feats)

    if already_alerted_today(email, "CRITICAL"):
        print(f"    [SKIP] {email} — CRITICAL alert already sent today")
        return

    save_alert(email, "CRITICAL", score, top_feats,
               note=f"CRITICAL threat detected: {explanation}")

    # Log to security_events
    from models.user import log_security_event
    log_security_event(
        email,
        "AI_CRITICAL_RISK",
        f"AI Risk Score {score:.1f} — {explanation}",
        "-", "-",
        blocked=True
    )

    # Push real-time Socket.IO event to manager dashboard
    if socketio_instance:
        socketio_instance.emit("ai_critical_alert", {
            "user_email":  email,
            "risk_score":  score,
            "risk_label":  "CRITICAL",
            "reason":      explanation,
            "top_features": top_feats,
            "timestamp":   datetime.utcnow().isoformat()
        })
        print(f"    [CRITICAL] {email} — score={score} — Socket.IO alert emitted")
    else:
        print(f"    [CRITICAL] {email} — score={score} — alert saved (no socket instance)")

    print(f"               Reason: {explanation}")


# =============================================================================
# MAIN ENFORCEMENT LOOP
# =============================================================================

def run_enforcement(socketio_instance=None):
    """
    Read latest scores and enforce based on thresholds.
    Called by scheduler.py every hour, or by threat_api.py on demand.
    Pass socketio_instance when calling from app.py context for real-time push.
    """
    print("\n=== Task 3: DLP Enforcement ===\n")

    scores = get_latest_scores()
    if not scores:
        print("  [WARN] No threat scores found. Run detect_anomaly.py first.")
        return []

    print(f"  Processing {len(scores)} employees...\n")

    results = []
    for s in scores:
        email = s.get("user_email", "unknown")
        score = s.get("risk_score", 0)
        label = s.get("risk_label", "LOW")
        note  = s.get("note", "")

        print(f"  {email:35s}  score={score:5.1f}  [{label}]")

        # Skip zero-activity (new/inactive employees)
        if note == "no_activity" or score == 0:
            print(f"    → No activity — skipped")
            results.append({"email": email, "score": score, "action": "none"})
            continue

        if score < 40:
            print(f"    → LOW — no action")
            results.append({"email": email, "score": score, "action": "none"})

        elif score < 70:
            enforce_medium(s)
            results.append({"email": email, "score": score, "action": "medium_alert"})

        elif score < 90:
            enforce_high(s)
            results.append({"email": email, "score": score, "action": "high_alert"})

        else:
            enforce_critical(s, socketio_instance)
            results.append({"email": email, "score": score, "action": "critical_alert"})

    print("\n=== Enforcement complete ===")
    return results


# =============================================================================
# STANDALONE RUN
# =============================================================================

if __name__ == "__main__":
    run_enforcement(socketio_instance=None)
    client.close()