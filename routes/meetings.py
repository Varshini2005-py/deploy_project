"""
routes/meetings.py — Meeting API routes
Part of XAI-ITD-DLP meeting feature
"""

from flask import Blueprint, request, jsonify
from bson import ObjectId
from datetime import datetime
import uuid

meetings_bp = Blueprint("meetings", __name__)


def _get_db():
    from app import socketio
    from models.user import db as _db
    return _db


def _col(name):
    return _get_db()[name]


def _ser(obj):
    """Make MongoDB doc JSON-safe."""
    if isinstance(obj, list):
        return [_ser(o) for o in obj]
    if isinstance(obj, dict):
        out = {}
        for k, v in obj.items():
            if isinstance(v, ObjectId):
                out[k] = str(v)
            elif isinstance(v, datetime):
                out[k] = v.strftime("%Y-%m-%dT%H:%M:%S")
            elif isinstance(v, (dict, list)):
                out[k] = _ser(v)
            else:
                out[k] = v
        return out
    return obj


def _auth():
    """Return (email, role, name) from request context (set by login_required)."""
    return request.auth_email, request.auth_role, request.auth_name


# ─── PAGES ────────────────────────────────────────────────────────────────────

@meetings_bp.route("/meetings")
def meetings_dashboard():
    """Serve meeting dashboard in new tab — reads token from query param."""
    from app import active_tokens
    from models.user import get_user_by_email
    from flask import render_template, redirect, url_for, session

    token = request.args.get("token", "")
    if token and token in active_tokens:
        email = active_tokens[token]
        user  = get_user_by_email(email)
        if user:
            return render_template(
                "meeting/index.html",
                user=user,
                session_email=email,
                session_role=user["role"],
                session_token=token
            )
    # Fallback: check flask session
    if "user_email" in session:
        email = session["user_email"]
        user  = get_user_by_email(email)
        if user:
            return render_template(
                "meeting/index.html",
                user=user,
                session_email=email,
                session_role=user["role"],
                session_token=session.get("token", "")
            )
    return redirect(url_for("login_page"))


@meetings_bp.route("/meeting-room/<room_id>")
def meeting_room_page(room_id):
    """Serve live meeting room page."""
    from app import active_tokens
    from models.user import get_user_by_email
    from flask import render_template, redirect, url_for, session

    meeting = _col("meetings").find_one({"room_id": room_id})
    if not meeting:
        return "Meeting not found", 404

    token = request.args.get("token", "")
    if token and token in active_tokens:
        email = active_tokens[token]
        user  = get_user_by_email(email)
        if user:
            return render_template(
                "meeting/meeting_room.html",
                meeting=_ser(meeting),
                user=user,
                session_email=email,
                session_role=user["role"],
                session_token=token
            )
    if "user_email" in session:
        email = session["user_email"]
        user  = get_user_by_email(email)
        if user:
            return render_template(
                "meeting/meeting_room.html",
                meeting=_ser(meeting),
                user=user,
                session_email=email,
                session_role=user["role"],
                session_token=session.get("token", "")
            )
    return redirect(url_for("login_page"))


# ─── CREATE MEETING ───────────────────────────────────────────────────────────

@meetings_bp.route("/api/meetings", methods=["POST"])
def create_meeting():
    from app import login_required, active_tokens
    token = request.headers.get("X-Auth-Token") or request.args.get("token", "")
    if not token or token not in active_tokens:
        return jsonify({"error": "Unauthorized"}), 403

    from models.user import get_user_by_email
    email = active_tokens[token]
    user  = get_user_by_email(email)
    if not user:
        return jsonify({"error": "User not found"}), 404

    data         = request.json or {}
    role         = user["role"]
    meeting_type = data.get("type", "one_on_one")

    allowed_types = {
        "employee": ["one_on_one"],
        "manager":  ["one_on_one", "team", "client"],
        "admin":    ["one_on_one", "team", "client", "company_wide"]
    }
    if meeting_type not in allowed_types.get(role, []):
        return jsonify({"error": role + " cannot create " + meeting_type + " meetings"}), 403

    room_id = str(uuid.uuid4())[:8].upper()

    meeting = {
        "room_id":          room_id,
        "title":            data.get("title", "Meeting"),
        "type":             meeting_type,
        "host_email":       email,
        "host_name":        user["name"],
        "host_role":        role,
        "invited":          data.get("invited", []),   # list of emails
        "agenda":           data.get("agenda", ""),
        "scheduled_time":   data.get("scheduled_time"),
        "duration_minutes": data.get("duration_minutes", 60),
        "password":         str(uuid.uuid4())[:6].upper(),
        "status":           "scheduled",               # scheduled | active | ended
        "is_recorded":      False,
        "client_link":      ("/join/" + room_id) if meeting_type == "client" else None,
        "created_at":       datetime.utcnow(),
        "ended_at":         None,
        "waiting_room":     [],
        "participants":     [],
        "raised_hands":     []
    }

    result  = _col("meetings").insert_one(meeting)
    meeting["_id"] = str(result.inserted_id)

    # Notify invited users via socket
    from app import emit_to_user
    host_name = user["name"]
    for inv_email in data.get("invited", []):
        emit_to_user(inv_email, "meeting_invite", {
            "room_id":    room_id,
            "title":      meeting["title"],
            "host_name":  host_name,
            "host_email": email,
            "type":       meeting_type,
            "scheduled":  data.get("scheduled_time", ""),
            "time":       datetime.utcnow().strftime("%H:%M:%S")
        })

    from models.user import log_activity
    log_activity(email, "MEETING_CREATED",
                 "Created " + meeting_type + " meeting: " + meeting["title"] + " [" + room_id + "]",
                 "Meeting Dashboard", request.remote_addr, "LOW")

    return jsonify({"success": True, "meeting": _ser(meeting)}), 201


# ─── LIST MEETINGS ────────────────────────────────────────────────────────────

@meetings_bp.route("/api/meetings", methods=["GET"])
def get_meetings():
    from app import active_tokens
    token = request.headers.get("X-Auth-Token") or request.args.get("token", "")
    if not token or token not in active_tokens:
        return jsonify({"error": "Unauthorized"}), 403

    email  = active_tokens[token]
    from models.user import get_user_by_email
    user   = get_user_by_email(email)
    role   = user["role"] if user else "employee"
    status = request.args.get("status")

    query = {}
    if status:
        query["status"] = status
    if role != "admin":
        query["$or"] = [{"host_email": email}, {"invited": email}]

    raw = list(_col("meetings").find(query))
    # Sort: active first, then scheduled by time asc, then ended last
    def _sort_key(m):
        order = {"active": 0, "scheduled": 1, "ended": 2}
        st = m.get("scheduled_time")
        t = st.timestamp() if hasattr(st, "timestamp") else 0
        return (order.get(m.get("status", "scheduled"), 1), t)
    raw.sort(key=_sort_key)
    return jsonify(_ser(raw))


# ─── GET SINGLE MEETING ───────────────────────────────────────────────────────

@meetings_bp.route("/api/meetings/<room_id>", methods=["GET"])
def get_meeting(room_id):
    from app import active_tokens
    token = request.headers.get("X-Auth-Token") or request.args.get("token", "")
    if not token or token not in active_tokens:
        return jsonify({"error": "Unauthorized"}), 403

    meeting = _col("meetings").find_one({"room_id": room_id})
    if not meeting:
        return jsonify({"error": "Meeting not found"}), 404
    return jsonify(_ser(meeting))


# ─── START MEETING ────────────────────────────────────────────────────────────

@meetings_bp.route("/api/meetings/<room_id>/start", methods=["POST"])
def start_meeting(room_id):
    from app import active_tokens
    token = request.headers.get("X-Auth-Token") or request.args.get("token", "")
    if not token or token not in active_tokens:
        return jsonify({"error": "Unauthorized"}), 403

    _col("meetings").update_one(
        {"room_id": room_id},
        {"$set": {"status": "active", "started_at": datetime.utcnow()}}
    )

    # Notify all invited members
    meeting = _col("meetings").find_one({"room_id": room_id})
    if meeting:
        from app import emit_to_user
        for inv_email in meeting.get("invited", []):
            emit_to_user(inv_email, "meeting_started", {
                "room_id":   room_id,
                "title":     meeting.get("title", ""),
                "host_name": meeting.get("host_name", ""),
                "time":      datetime.utcnow().strftime("%H:%M:%S")
            })

    return jsonify({"success": True})


# ─── END MEETING ──────────────────────────────────────────────────────────────

@meetings_bp.route("/api/meetings/<room_id>/end", methods=["POST"])
def end_meeting(room_id):
    from app import active_tokens
    token = request.headers.get("X-Auth-Token") or request.args.get("token", "")
    if not token or token not in active_tokens:
        return jsonify({"error": "Unauthorized"}), 403

    email = active_tokens[token]
    _col("meetings").update_one(
        {"room_id": room_id},
        {"$set": {"status": "ended", "ended_at": datetime.utcnow()}}
    )

    from models.user import log_activity
    log_activity(email, "MEETING_ENDED",
                 "Ended meeting [" + room_id + "]",
                 "Meeting Room", request.remote_addr, "LOW")

    return jsonify({"success": True})


# ─── ADMIT FROM WAITING ROOM ──────────────────────────────────────────────────

@meetings_bp.route("/api/meetings/<room_id>/admit", methods=["POST"])
def admit_participant(room_id):
    from app import active_tokens, emit_to_user
    token = request.headers.get("X-Auth-Token") or request.args.get("token", "")
    if not token or token not in active_tokens:
        return jsonify({"error": "Unauthorized"}), 403

    data    = request.json or {}
    user_id = data.get("user_email")

    _col("meetings").update_one(
        {"room_id": room_id},
        {
            "$pull":     {"waiting_room": {"user_email": user_id}},
            "$addToSet": {"participants": user_id}
        }
    )
    emit_to_user(user_id, "admitted", {"room_id": room_id})
    return jsonify({"success": True})


# ─── RAISE / LOWER HAND ───────────────────────────────────────────────────────

@meetings_bp.route("/api/meetings/<room_id>/raise_hand", methods=["POST"])
def raise_hand(room_id):
    from app import active_tokens
    token = request.headers.get("X-Auth-Token") or request.args.get("token", "")
    if not token or token not in active_tokens:
        return jsonify({"error": "Unauthorized"}), 403

    data   = request.json or {}
    action = data.get("action", "raise")
    email  = active_tokens[token]
    from models.user import get_user_by_email
    user   = get_user_by_email(email)
    entry  = {"user_email": email, "name": user["name"] if user else email,
               "time": datetime.utcnow()}

    if action == "raise":
        _col("meetings").update_one({"room_id": room_id}, {"$addToSet": {"raised_hands": entry}})
    else:
        _col("meetings").update_one({"room_id": room_id}, {"$pull": {"raised_hands": {"user_email": email}}})

    return jsonify({"success": True})


# ─── GET ALL USERS (for invite picker) ───────────────────────────────────────

@meetings_bp.route("/api/meetings/users/list", methods=["GET"])
def list_users_for_invite():
    from app import active_tokens
    token = request.headers.get("X-Auth-Token") or request.args.get("token", "")
    if not token or token not in active_tokens:
        return jsonify({"error": "Unauthorized"}), 403

    email = active_tokens[token]
    from models.user import users_col
    # is_active may not be set on all users — use $ne False to include unset
    docs = list(users_col.find(
        {"is_active": {"$ne": False}, "email": {"$ne": email}},
        {"_id": 0, "name": 1, "email": 1, "role": 1, "department": 1}
    ))
    return jsonify(docs)


# ─── PUBLIC GUEST JOIN (no login needed) ─────────────────────────────────────

@meetings_bp.route("/join/<room_id>")
def guest_join_page(room_id):
    """Public page — client enters name + password to join."""
    from flask import render_template
    meeting = _col("meetings").find_one({"room_id": room_id})
    if not meeting:
        return "Meeting not found or link has expired.", 404
    if meeting.get("status") == "ended":
        return "This meeting has already ended.", 410
    return render_template("meeting/guest_join.html", room_id=room_id)


@meetings_bp.route("/api/guest/meeting-info/<room_id>", methods=["GET"])
def guest_meeting_info(room_id):
    """Returns safe public info about the meeting (no password exposed)."""
    meeting = _col("meetings").find_one({"room_id": room_id})
    if not meeting:
        return jsonify({"error": "Meeting not found."}), 404
    if meeting.get("status") == "ended":
        return jsonify({"error": "This meeting has already ended."}), 410
    return jsonify({
        "room_id":        room_id,
        "title":          meeting.get("title", "Client Meeting"),
        "host_name":      meeting.get("host_name", ""),
        "scheduled_time": meeting.get("scheduled_time", ""),
        "agenda":         meeting.get("agenda", ""),
        "status":         meeting.get("status", "scheduled"),
    })


@meetings_bp.route("/api/guest/join/<room_id>", methods=["POST"])
def guest_join(room_id):
    """Verifies guest name + password before letting them into the room."""
    meeting = _col("meetings").find_one({"room_id": room_id})
    if not meeting:
        return jsonify({"error": "Meeting not found."}), 404
    if meeting.get("status") == "ended":
        return jsonify({"error": "This meeting has already ended."}), 410

    data     = request.get_json() or {}
    name     = (data.get("name") or "").strip()
    password = (data.get("password") or "").strip().upper()

    if not name:
        return jsonify({"error": "Name is required."}), 400
    if password != meeting.get("password", "").upper():
        return jsonify({"error": "Incorrect password. Please check with your host."}), 401

    # Log the guest joining
    _col("meetings").update_one(
        {"room_id": room_id},
        {"$push": {"guest_joins": {
            "name":      name,
            "joined_at": datetime.utcnow()
        }}}
    )

    return jsonify({"success": True, "room_id": room_id})