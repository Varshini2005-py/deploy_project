"""
routes/meeting_attendance.py — Attendance logging for meetings
"""

from flask import Blueprint, request, jsonify
from datetime import datetime

attendance_bp = Blueprint("meeting_attendance", __name__)


def _col(name):
    from models.user import db as _db
    return _db[name]


def _auth_token():
    from app import active_tokens
    token = request.headers.get("X-Auth-Token") or request.args.get("token", "")
    if not token or token not in active_tokens:
        return None, None
    from models.user import get_user_by_email
    email = active_tokens[token]
    user  = get_user_by_email(email)
    return email, user


# ─── JOIN ─────────────────────────────────────────────────────────────────────

@attendance_bp.route("/api/attendance/join", methods=["POST"])
def log_join():
    email, user = _auth_token()
    if not email:
        return jsonify({"error": "Unauthorized"}), 403

    data    = request.json or {}
    room_id = data.get("room_id")
    if not room_id:
        return jsonify({"error": "room_id required"}), 400

    existing = _col("meeting_attendance").find_one({"room_id": room_id, "user_email": email})
    if existing:
        return jsonify({"success": True, "message": "Already logged"})

    _col("meeting_attendance").insert_one({
        "room_id":       room_id,
        "meeting_title": data.get("meeting_title", ""),
        "user_email":    email,
        "user_name":     user["name"] if user else email,
        "role":          user["role"] if user else "employee",
        "joined_at":     datetime.utcnow(),
        "left_at":       None,
        "duration_minutes": 0,
        "status":        "present"
    })
    return jsonify({"success": True})


# ─── LEAVE ────────────────────────────────────────────────────────────────────

@attendance_bp.route("/api/attendance/leave", methods=["POST"])
def log_leave():
    email, user = _auth_token()
    if not email:
        return jsonify({"error": "Unauthorized"}), 403

    data    = request.json or {}
    room_id = data.get("room_id")
    if not room_id:
        return jsonify({"error": "room_id required"}), 400

    record = _col("meeting_attendance").find_one({"room_id": room_id, "user_email": email})
    if not record:
        return jsonify({"error": "No join record found"}), 404

    joined   = record["joined_at"]
    left     = datetime.utcnow()
    duration = round((left - joined).total_seconds() / 60, 1)

    _col("meeting_attendance").update_one(
        {"room_id": room_id, "user_email": email},
        {"$set": {
            "left_at":          left,
            "duration_minutes": duration,
            "status":           data.get("status", "present")
        }}
    )
    return jsonify({"success": True, "duration_minutes": duration})


# ─── GET ATTENDANCE REPORT FOR ONE MEETING ────────────────────────────────────

@attendance_bp.route("/api/attendance/<room_id>", methods=["GET"])
def get_attendance(room_id):
    email, user = _auth_token()
    if not email:
        return jsonify({"error": "Unauthorized"}), 403

    records = list(_col("meeting_attendance").find({"room_id": room_id}, {"_id": 0}))
    for r in records:
        for k in ("joined_at", "left_at"):
            v = r.get(k)
            if hasattr(v, "strftime"):
                r[k] = v.strftime("%Y-%m-%d %H:%M:%S")

    total   = len(records)
    present = sum(1 for r in records if r["status"] == "present")
    return jsonify({
        "room_id":        room_id,
        "total_invited":  total,
        "present":        present,
        "absent":         total - present,
        "attendance_rate": str(round((present / total) * 100)) + "%" if total else "0%",
        "records":        records
    })


# ─── GET USER ATTENDANCE HISTORY ─────────────────────────────────────────────

@attendance_bp.route("/api/attendance/my-history", methods=["GET"])
def get_my_attendance():
    email, user = _auth_token()
    if not email:
        return jsonify({"error": "Unauthorized"}), 403

    records = list(_col("meeting_attendance").find(
        {"user_email": email}, {"_id": 0}
    ).sort("joined_at", -1))

    for r in records:
        for k in ("joined_at", "left_at"):
            v = r.get(k)
            if hasattr(v, "strftime"):
                r[k] = v.strftime("%Y-%m-%d %H:%M:%S")

    total   = len(records)
    present = sum(1 for r in records if r["status"] == "present")
    return jsonify({
        "user_email":      email,
        "total_meetings":  total,
        "attended":        present,
        "missed":          total - present,
        "attendance_rate": str(round((present / total) * 100)) + "%" if total else "0%",
        "history":         records
    })