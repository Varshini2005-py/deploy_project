"""
routes/meeting_notes.py — Notes, Polls, Action Items, Feedback
"""

from flask import Blueprint, request, jsonify
from bson import ObjectId
from datetime import datetime

notes_bp    = Blueprint("meeting_notes",    __name__)
polls_bp    = Blueprint("meeting_polls",    __name__)
actions_bp  = Blueprint("meeting_actions",  __name__)
feedback_bp = Blueprint("meeting_feedback", __name__)


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


def _s(obj):
    if isinstance(obj, list):
        return [_s(o) for o in obj]
    if isinstance(obj, dict):
        out = {}
        for k, v in obj.items():
            if isinstance(v, ObjectId):
                out[k] = str(v)
            elif isinstance(v, datetime):
                out[k] = v.strftime("%Y-%m-%d %H:%M:%S")
            elif isinstance(v, (dict, list)):
                out[k] = _s(v)
            else:
                out[k] = v
        return out
    return obj


# ══════════════════════════════════════════════════════════════
# NOTES
# ══════════════════════════════════════════════════════════════

@notes_bp.route("/api/notes/<room_id>", methods=["GET"])
def get_notes(room_id):
    email, _ = _auth_token()
    if not email:
        return jsonify({"error": "Unauthorized"}), 403
    note = _col("meeting_notes").find_one({"room_id": room_id})
    if not note:
        return jsonify({"room_id": room_id, "content": "", "last_updated_by": None})
    return jsonify(_s(note))


@notes_bp.route("/api/notes/<room_id>", methods=["POST"])
def save_notes(room_id):
    email, user = _auth_token()
    if not email:
        return jsonify({"error": "Unauthorized"}), 403
    data = request.json or {}
    _col("meeting_notes").update_one(
        {"room_id": room_id},
        {"$set": {
            "room_id":         room_id,
            "content":         data.get("content", ""),
            "last_updated_by": user["name"] if user else email,
            "updated_at":      datetime.utcnow()
        }},
        upsert=True
    )
    return jsonify({"success": True})


# ══════════════════════════════════════════════════════════════
# POLLS
# ══════════════════════════════════════════════════════════════

@polls_bp.route("/api/polls", methods=["POST"])
def create_poll():
    email, user = _auth_token()
    if not email:
        return jsonify({"error": "Unauthorized"}), 403
    if not user or user["role"] not in ("manager", "admin"):
        return jsonify({"error": "Only managers/admins can create polls"}), 403

    data = request.json or {}
    poll = {
        "room_id":    data["room_id"],
        "question":   data["question"],
        "options":    [{"text": opt, "votes": [], "count": 0} for opt in data["options"]],
        "created_by": email,
        "created_at": datetime.utcnow(),
        "is_active":  True,
        "total_votes": 0
    }
    result = _col("meeting_polls").insert_one(poll)
    poll["_id"] = str(result.inserted_id)
    return jsonify({"success": True, "poll": _s(poll)}), 201


@polls_bp.route("/api/polls/<poll_id>/vote", methods=["POST"])
def vote_poll(poll_id):
    email, _ = _auth_token()
    if not email:
        return jsonify({"error": "Unauthorized"}), 403

    data         = request.json or {}
    option_index = data.get("option_index")
    try:
        poll = _col("meeting_polls").find_one({"_id": ObjectId(poll_id)})
    except Exception:
        return jsonify({"error": "Invalid poll id"}), 400
    if not poll:
        return jsonify({"error": "Poll not found"}), 404

    for opt in poll["options"]:
        if email in opt.get("votes", []):
            return jsonify({"error": "Already voted"}), 400

    _col("meeting_polls").update_one(
        {"_id": ObjectId(poll_id)},
        {
            "$addToSet": {"options." + str(option_index) + ".votes": email},
            "$inc":      {"options." + str(option_index) + ".count": 1, "total_votes": 1}
        }
    )
    return jsonify({"success": True})


@polls_bp.route("/api/polls/<room_id>/active", methods=["GET"])
def get_active_poll(room_id):
    email, _ = _auth_token()
    if not email:
        return jsonify({"error": "Unauthorized"}), 403
    poll = _col("meeting_polls").find_one(
        {"room_id": room_id, "is_active": True},
        sort=[("created_at", -1)]
    )
    if not poll:
        return jsonify(None)
    return jsonify(_s(poll))


@polls_bp.route("/api/polls/<poll_id>/close", methods=["POST"])
def close_poll(poll_id):
    email, user = _auth_token()
    if not email:
        return jsonify({"error": "Unauthorized"}), 403
    if not user or user["role"] not in ("manager", "admin"):
        return jsonify({"error": "Only managers/admins can close polls"}), 403
    try:
        _col("meeting_polls").update_one({"_id": ObjectId(poll_id)}, {"$set": {"is_active": False}})
    except Exception:
        return jsonify({"error": "Invalid poll id"}), 400
    return jsonify({"success": True})


# ══════════════════════════════════════════════════════════════
# ACTION ITEMS
# ══════════════════════════════════════════════════════════════

@actions_bp.route("/api/actions", methods=["POST"])
def create_action():
    email, user = _auth_token()
    if not email:
        return jsonify({"error": "Unauthorized"}), 403
    if not user or user["role"] not in ("manager", "admin"):
        return jsonify({"error": "Only managers/admins can assign actions"}), 403

    data   = request.json or {}
    action = {
        "room_id":          data["room_id"],
        "meeting_title":    data.get("meeting_title", ""),
        "task":             data["task"],
        "assigned_to_email": data["assigned_to_email"],
        "assigned_to_name":  data["assigned_to_name"],
        "due_date":         data.get("due_date"),
        "created_by":       email,
        "created_at":       datetime.utcnow(),
        "status":           "pending"
    }
    result = _col("meeting_actions").insert_one(action)
    action["_id"] = str(result.inserted_id)
    return jsonify({"success": True, "action": _s(action)}), 201


@actions_bp.route("/api/actions/mine", methods=["GET"])
def get_my_actions():
    email, _ = _auth_token()
    if not email:
        return jsonify({"error": "Unauthorized"}), 403
    actions = list(_col("meeting_actions").find(
        {"assigned_to_email": email}, {"_id": 1, "room_id": 1, "task": 1,
         "meeting_title": 1, "due_date": 1, "status": 1, "created_at": 1}
    ).sort("due_date", 1))
    return jsonify(_s(actions))


@actions_bp.route("/api/actions/meeting/<room_id>", methods=["GET"])
def get_meeting_actions(room_id):
    email, _ = _auth_token()
    if not email:
        return jsonify({"error": "Unauthorized"}), 403
    actions = list(_col("meeting_actions").find({"room_id": room_id}))
    return jsonify(_s(actions))


@actions_bp.route("/api/actions/<action_id>/status", methods=["POST"])
def update_action_status(action_id):
    email, _ = _auth_token()
    if not email:
        return jsonify({"error": "Unauthorized"}), 403
    data = request.json or {}
    try:
        _col("meeting_actions").update_one(
            {"_id": ObjectId(action_id)},
            {"$set": {"status": data["status"], "updated_at": datetime.utcnow()}}
        )
    except Exception:
        return jsonify({"error": "Invalid action id"}), 400
    return jsonify({"success": True})


# ══════════════════════════════════════════════════════════════
# FEEDBACK
# ══════════════════════════════════════════════════════════════

@feedback_bp.route("/api/feedback", methods=["POST"])
def submit_feedback():
    email, _ = _auth_token()
    if not email:
        return jsonify({"error": "Unauthorized"}), 403

    data = request.json or {}
    _col("meeting_feedback").insert_one({
        "room_id":       data["room_id"],
        "user_email":    email,
        "was_necessary": data.get("was_necessary"),
        "productivity":  data.get("productivity"),
        "improvement":   data.get("improvement", ""),
        "submitted_at":  datetime.utcnow()
    })
    return jsonify({"success": True})


@feedback_bp.route("/api/feedback/<room_id>", methods=["GET"])
def get_feedback(room_id):
    email, user = _auth_token()
    if not email:
        return jsonify({"error": "Unauthorized"}), 403
    if not user or user["role"] not in ("manager", "admin"):
        return jsonify({"error": "Only managers/admins can view feedback"}), 403

    feedbacks = list(_col("meeting_feedback").find({"room_id": room_id}, {"_id": 0}))
    for f in feedbacks:
        if hasattr(f.get("submitted_at"), "strftime"):
            f["submitted_at"] = f["submitted_at"].strftime("%Y-%m-%d %H:%M")

    if not feedbacks:
        return jsonify({"room_id": room_id, "feedbacks": [], "summary": {}})

    total    = len(feedbacks)
    avg_prod = round(sum(f.get("productivity", 0) or 0 for f in feedbacks) / total, 1)
    necessary = sum(1 for f in feedbacks if f.get("was_necessary") == "yes")
    return jsonify({
        "room_id":          room_id,
        "total_responses":  total,
        "avg_productivity": avg_prod,
        "necessary_percent": str(round((necessary / total) * 100)) + "%",
        "feedbacks":        feedbacks
    })