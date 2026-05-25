"""
Task 4 - AI Risk Engine - Flask API Routes
File : D:/rajasri/xai_itd_dlp/routes/threat_api.py

Routes:
  GET  /api/ai/risk-scores          -> latest score per employee
  GET  /api/ai/risk-scores/<email>  -> score history for one employee
  GET  /api/ai/alerts               -> all unacknowledged alerts
  POST /api/ai/alerts/<id>/ack      -> acknowledge an alert
  GET  /api/ai/summary              -> dashboard summary stats
  POST /api/ai/run-scan             -> manually trigger analyze+detect+enforce
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from flask import Blueprint, jsonify, request
from pymongo import MongoClient
from bson  import ObjectId
from datetime import datetime, timedelta
from config import MONGO_URI, DB_NAME

# ── Config ───────────────────────────────────────────────────────────────────

client = MongoClient(MONGO_URI, serverSelectionTimeoutMS=5000, connectTimeoutMS=5000)
db     = client[DB_NAME]

threat_bp = Blueprint("threat_api", __name__)


# ── Auth helper (reuse login_required from app.py) ───────────────────────────
def manager_only(f):
    from functools import wraps
    @wraps(f)
    def decorated(*args, **kwargs):
        from flask import session
        token = request.headers.get("X-Auth-Token") or request.args.get("token")
        # Import active_tokens from app context
        try:
            from app import active_tokens, login_required
        except ImportError:
            pass
        role = session.get("role", "")
        if role != "manager":
            # also allow token-based auth
            try:
                from app import active_tokens
                from models.user import get_user_by_email
                if token and token in active_tokens:
                    email = active_tokens[token]
                    user  = get_user_by_email(email)
                    if user and user.get("role") == "manager":
                        return f(*args, **kwargs)
            except Exception:
                pass
            return jsonify({"error": "Manager access required"}), 403
        return f(*args, **kwargs)
    return decorated


def serialize(doc):
    """Convert MongoDB doc to JSON-safe dict."""
    if doc is None:
        return None
    d = dict(doc)
    d.pop("_id", None)
    for k, v in d.items():
        if isinstance(v, datetime):
            d[k] = v.isoformat()
    return d


# =============================================================================
# ROUTES
# =============================================================================

@threat_bp.route("/api/ai/risk-scores", methods=["GET"])
@manager_only
def get_all_risk_scores():
    """
    Latest risk score per employee.
    Returns array sorted by risk_score descending.
    """
    pipeline = [
        {"$sort": {"scored_at": -1}},
        {"$group": {
            "_id":             "$user_email",
            "user_email":      {"$first": "$user_email"},
            "day":             {"$first": "$day"},
            "risk_score":      {"$first": "$risk_score"},
            "risk_label":      {"$first": "$risk_label"},
            "anomaly_score":   {"$first": "$anomaly_score"},
            "deviation_score": {"$first": "$deviation_score"},
            "rule_score":      {"$first": "$rule_score"},
            "top_features":    {"$first": "$top_features"},
            "scored_at":       {"$first": "$scored_at"},
            "note":            {"$first": "$note"},
        }},
        {"$sort": {"risk_score": -1}}
    ]
    docs = list(db["threat_scores"].aggregate(pipeline))

    # Enrich with employee name
    result = []
    for doc in docs:
        email = doc.get("user_email", "")
        user  = db["users"].find_one({"email": email}, {"name": 1, "_id": 0})
        row   = serialize(doc)
        row["name"] = user.get("name", email) if user else email
        result.append(row)

    return jsonify(result), 200


@threat_bp.route("/api/ai/risk-scores/<path:email>", methods=["GET"])
@manager_only
def get_employee_risk_history(email):
    """
    Risk score history for one employee — last 30 days.
    Used for the employee detail chart on the dashboard.
    """
    days_back = int(request.args.get("days", 30))
    since     = datetime.utcnow() - timedelta(days=days_back)

    docs = list(db["threat_scores"].find(
        {"user_email": email, "scored_at": {"$gte": since}},
        {"_id": 0}
    ).sort("day", 1))

    result = [serialize(d) for d in docs]
    return jsonify(result), 200


@threat_bp.route("/api/ai/alerts", methods=["GET"])
@manager_only
def get_alerts():
    """
    All AI alerts — unacknowledged by default.
    Pass ?all=1 to include acknowledged ones.
    """
    show_all = request.args.get("all", "0") == "1"
    query    = {} if show_all else {"acknowledged": False}

    docs = list(db["ai_alerts"].find(query).sort("created_at", -1).limit(100))
    result = []
    for doc in docs:
        row = serialize(doc)
        row["_id"] = str(doc["_id"])   # keep id for ack endpoint
        # Enrich with employee name
        email = doc.get("user_email", "")
        user  = db["users"].find_one({"email": email}, {"name": 1, "_id": 0})
        row["name"] = user.get("name", email) if user else email
        result.append(row)

    return jsonify(result), 200


@threat_bp.route("/api/ai/alerts/<alert_id>/ack", methods=["POST"])
@manager_only
def acknowledge_alert(alert_id):
    """Mark an alert as acknowledged by the manager."""
    try:
        db["ai_alerts"].update_one(
            {"_id": ObjectId(alert_id)},
            {"$set": {
                "acknowledged":    True,
                "acknowledged_at": datetime.utcnow()
            }}
        )
        return jsonify({"success": True}), 200
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 400


@threat_bp.route("/api/ai/summary", methods=["GET"])
@manager_only
def get_summary():
    """
    Dashboard summary stats:
      - total employees scored
      - count per risk label
      - unacknowledged alert count
      - highest risk employee
    """
    pipeline = [
        {"$sort": {"scored_at": -1}},
        {"$group": {
            "_id":        "$user_email",
            "risk_score": {"$first": "$risk_score"},
            "risk_label": {"$first": "$risk_label"},
            "note":       {"$first": "$note"},
        }}
    ]
    scores = list(db["threat_scores"].aggregate(pipeline))

    label_counts = {"LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0}
    highest      = {"email": None, "score": 0, "label": "LOW"}

    for s in scores:
        label = s.get("risk_label", "LOW")
        label_counts[label] = label_counts.get(label, 0) + 1
        if s.get("risk_score", 0) > highest["score"]:
            highest = {
                "email": s["_id"],
                "score": s["risk_score"],
                "label": label
            }

    unacked = db["ai_alerts"].count_documents({"acknowledged": False})

    # Last scan time
    last_score = db["threat_scores"].find_one(
        {}, {"scored_at": 1, "_id": 0},
        sort=[("scored_at", -1)]
    )
    last_scan = last_score["scored_at"].isoformat() if last_score else None

    return jsonify({
        "total_employees": len(scores),
        "label_counts":    label_counts,
        "unacked_alerts":  unacked,
        "highest_risk":    highest,
        "last_scan":       last_scan
    }), 200


@threat_bp.route("/api/ai/run-scan", methods=["POST"])
@manager_only
def run_scan():
    """
    Manually trigger a full AI scan:
      analyze_behavior -> detect_anomaly -> enforce_dlp
    Runs in background thread so the HTTP response returns immediately.
    """
    import threading

    def _run():
        try:
            print("[AI SCAN] Starting manual scan...")
            ml_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "ml")

            # Step 1: analyze
            import importlib.util
            def load_module(name, path):
                spec   = importlib.util.spec_from_file_location(name, path)
                mod    = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(mod)
                return mod

            analyze = load_module("analyze_behavior",
                                  os.path.join(ml_dir, "analyze_behavior.py"))
            analyze.build_all_employee_profiles(days_back=30)
            analyze.build_user_baseline()
            print("[AI SCAN] Step 1 done — behavior profiles updated")

            # Step 2: detect
            detect = load_module("detect_anomaly",
                                 os.path.join(ml_dir, "detect_anomaly.py"))
            iso, scaler = detect.load_models()
            if iso is None:
                iso, scaler = detect.train_isolation_forest()
            detect.score_all_employees(iso, scaler)
            print("[AI SCAN] Step 2 done — threat scores updated")

            # Step 3: enforce
            enforce = load_module("enforce_dlp",
                                  os.path.join(ml_dir, "enforce_dlp.py"))
            enforce.run_enforcement(socketio_instance=None)
            print("[AI SCAN] Step 3 done — enforcement complete")

        except Exception as e:
            print(f"[AI SCAN ERROR] {e}")
            import traceback
            traceback.print_exc()

    threading.Thread(target=_run, daemon=True).start()

    return jsonify({
        "success": True,
        "message": "AI scan started in background. Refresh scores in ~30 seconds."
    }), 200