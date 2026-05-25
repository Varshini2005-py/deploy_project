"""
routes/client_meetings.py
Client directory + client meeting requests + approval + logs
"""

from flask import Blueprint, request, jsonify
from bson import ObjectId
from datetime import datetime

client_bp = Blueprint("client_meetings", __name__)


def _col(name):
    from models.user import db as _db
    return _db[name]


def _auth():
    from models.user import get_user_by_email
    from flask import session
    # 1. Try token auth (X-Auth-Token header or ?token= param)
    token = request.headers.get("X-Auth-Token") or request.args.get("token", "")
    if token:
        from app import active_tokens
        if token in active_tokens:
            email = active_tokens[token]
            user  = get_user_by_email(email)
            return email, user
    # 2. Fall back to Flask session (browser login without token)
    if "user_email" in session:
        email = session["user_email"]
        user  = get_user_by_email(email)
        if user:
            # Re-register token into active_tokens if session has one
            sess_token = session.get("token", "")
            if sess_token:
                from app import active_tokens
                active_tokens[sess_token] = email
            return email, user
    return None, None


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
# CLIENT DIRECTORY — Admin only
# ══════════════════════════════════════════════════════════════

@client_bp.route("/api/admin/clients", methods=["GET"])
def admin_list_clients():
    email, user = _auth()
    if not user or user["role"] != "admin":
        return jsonify({"error": "Unauthorized"}), 403
    clients = list(_col("clients").find({}, {"_id": 1, "name": 1, "email": 1,
        "phone": 1, "company": 1, "notes": 1, "created_at": 1, "is_active": 1}))
    return jsonify(_s(clients))


@client_bp.route("/api/admin/clients", methods=["POST"])
def admin_add_client():
    email, user = _auth()
    if not user or user["role"] != "admin":
        return jsonify({"error": "Unauthorized"}), 403
    data = request.json or {}
    name = data.get("name", "").strip()
    if not name:
        return jsonify({"error": "Client name required"}), 400

    existing = _col("clients").find_one({"email": data.get("email", "").strip().lower(), "is_active": True})
    if existing:
        return jsonify({"error": "Client with this email already exists"}), 409

    client = {
        "name":       name,
        "email":      data.get("email", "").strip().lower(),
        "phone":      data.get("phone", "").strip(),
        "company":    data.get("company", "").strip(),
        "notes":      data.get("notes", "").strip(),
        "is_active":  True,
        "created_at": datetime.utcnow(),
        "created_by": email
    }
    result = _col("clients").insert_one(client)
    client["_id"] = str(result.inserted_id)
    from models.user import log_activity
    log_activity(email, "CLIENT_ADDED", "Added client: " + name, "Admin Dashboard", "internal", "LOW")
    return jsonify({"success": True, "client": _s(client)}), 201


@client_bp.route("/api/admin/clients/<client_id>", methods=["DELETE"])
def admin_delete_client(client_id):
    email, user = _auth()
    if not user or user["role"] != "admin":
        return jsonify({"error": "Unauthorized"}), 403
    try:
        _col("clients").update_one({"_id": ObjectId(client_id)}, {"$set": {"is_active": False}})
    except Exception:
        return jsonify({"error": "Invalid client id"}), 400
    from models.user import log_activity
    log_activity(email, "CLIENT_REMOVED", "Removed client id: " + client_id, "Admin Dashboard", "internal", "LOW")
    return jsonify({"success": True})


# ══════════════════════════════════════════════════════════════
# CLIENT ASSIGNMENTS — Admin assigns clients to employees
# ══════════════════════════════════════════════════════════════

@client_bp.route("/api/admin/client-assignments", methods=["GET"])
def admin_list_assignments():
    email, user = _auth()
    if not user or user["role"] != "admin":
        return jsonify({"error": "Unauthorized"}), 403
    emp_email = request.args.get("employee_email")
    query = {"is_active": True}
    if emp_email:
        query["employee_email"] = emp_email
    assignments = list(_col("client_assignments").find(query))
    return jsonify(_s(assignments))


@client_bp.route("/api/admin/client-assignments", methods=["POST"])
def admin_assign_client():
    email, user = _auth()
    if not user or user["role"] != "admin":
        return jsonify({"error": "Unauthorized"}), 403
    data          = request.json or {}
    emp_email     = data.get("employee_email", "").strip().lower()
    client_id_str = data.get("client_id", "").strip()

    if not emp_email or not client_id_str:
        return jsonify({"error": "employee_email and client_id required"}), 400

    # Validate client exists
    try:
        client = _col("clients").find_one({"_id": ObjectId(client_id_str), "is_active": True})
    except Exception:
        return jsonify({"error": "Invalid client_id"}), 400
    if not client:
        return jsonify({"error": "Client not found"}), 404

    # Check not already assigned
    existing = _col("client_assignments").find_one({
        "employee_email": emp_email,
        "client_id":      client_id_str,
        "is_active":      True
    })
    if existing:
        return jsonify({"error": "Client already assigned to this employee"}), 409

    # Get employee info
    from models.user import get_user_by_email
    emp = get_user_by_email(emp_email)
    if not emp:
        return jsonify({"error": "Employee not found"}), 404

    assignment = {
        "employee_email": emp_email,
        "employee_name":  emp["name"],
        "client_id":      client_id_str,
        "client_name":    client["name"],
        "client_email":   client.get("email", ""),
        "client_company": client.get("company", ""),
        "assigned_by":    email,
        "assigned_at":    datetime.utcnow(),
        "is_active":      True
    }
    _col("client_assignments").insert_one(assignment)

    # Notify employee via socket
    from app import emit_to_user
    emit_to_user(emp_email, "client_assigned", {
        "client_name":    client["name"],
        "client_company": client.get("company", ""),
        "client_email":   client.get("email", ""),
        "message":        "New client assigned to you: " + client["name"] + " (" + client.get("company", "") + ")",
        "time":           datetime.utcnow().strftime("%H:%M:%S")
    })

    from models.user import log_activity
    log_activity(email, "CLIENT_ASSIGNED",
        "Assigned client " + client["name"] + " to " + emp_email,
        "Admin Dashboard", "internal", "LOW")
    return jsonify({"success": True})


@client_bp.route("/api/admin/client-assignments/remove", methods=["POST"])
def admin_remove_assignment():
    email, user = _auth()
    if not user or user["role"] != "admin":
        return jsonify({"error": "Unauthorized"}), 403
    data          = request.json or {}
    emp_email     = data.get("employee_email", "").strip().lower()
    client_id_str = data.get("client_id", "").strip()

    _col("client_assignments").update_one(
        {"employee_email": emp_email, "client_id": client_id_str, "is_active": True},
        {"$set": {"is_active": False, "removed_at": datetime.utcnow(), "removed_by": email}}
    )

    # Get client info for notification
    try:
        client = _col("clients").find_one({"_id": ObjectId(client_id_str)})
    except Exception:
        client = None
    client_name = client["name"] if client else client_id_str

    # Notify employee
    from app import emit_to_user
    emit_to_user(emp_email, "client_removed", {
        "client_name": client_name,
        "message":     "Client removed from your list: " + client_name,
        "time":        datetime.utcnow().strftime("%H:%M:%S")
    })

    from models.user import log_activity
    log_activity(email, "CLIENT_UNASSIGNED",
        "Removed client " + client_name + " from " + emp_email,
        "Admin Dashboard", "internal", "LOW")
    return jsonify({"success": True})


# ══════════════════════════════════════════════════════════════
# EMPLOYEE — View my clients
# ══════════════════════════════════════════════════════════════

@client_bp.route("/api/employee/my-clients", methods=["GET"])
def employee_my_clients():
    email, user = _auth()
    if not user or user["role"] != "employee":
        return jsonify({"error": "Unauthorized"}), 403
    assignments = list(_col("client_assignments").find(
        {"employee_email": email, "is_active": True}
    ))
    # Use data already stored in assignment doc — avoids ObjectId conversion issues
    # Also try to enrich from clients collection if possible
    result = []
    for a in assignments:
        # Try fetching fresh client data
        client = None
        try:
            client = _col("clients").find_one({"_id": ObjectId(str(a["client_id"]))})
        except Exception:
            pass

        if client:
            result.append({
                "client_id":   str(client["_id"]),
                "name":        client.get("name", a.get("client_name", "")),
                "email":       client.get("email", ""),
                "phone":       client.get("phone", ""),
                "company":     client.get("company", a.get("client_company", "")),
                "notes":       client.get("notes", ""),
                "assigned_at": a["assigned_at"].strftime("%Y-%m-%d") if hasattr(a.get("assigned_at"), "strftime") else ""
            })
        elif a.get("client_name"):
            # Fallback: use data stored directly in assignment doc
            result.append({
                "client_id":   str(a.get("client_id", "")),
                "name":        a.get("client_name", ""),
                "email":       a.get("client_email", ""),
                "phone":       "",
                "company":     a.get("client_company", ""),
                "notes":       "",
                "assigned_at": a["assigned_at"].strftime("%Y-%m-%d") if hasattr(a.get("assigned_at"), "strftime") else ""
            })
    return jsonify(result)


# ══════════════════════════════════════════════════════════════
# CLIENT MEETING REQUESTS — Employee → Manager approval
# ══════════════════════════════════════════════════════════════

@client_bp.route("/api/employee/request-client-meeting", methods=["POST"])
def request_client_meeting():
    email, user = _auth()
    if not user or user["role"] != "employee":
        return jsonify({"error": "Unauthorized"}), 403
    data = request.json or {}

    client_id_str = data.get("client_id", "").strip()
    scheduled_str = data.get("scheduled_time", "").strip()
    agenda        = data.get("agenda", "").strip()
    duration      = int(data.get("duration_minutes", 60))

    if not client_id_str or not scheduled_str or not agenda:
        return jsonify({"error": "client_id, scheduled_time and agenda are required"}), 400

    # Verify client is assigned to this employee
    assignment = _col("client_assignments").find_one({
        "employee_email": email,
        "client_id":      client_id_str,
        "is_active":      True
    })
    if not assignment:
        return jsonify({"error": "This client is not assigned to you"}), 403

    try:
        client = _col("clients").find_one({"_id": ObjectId(client_id_str)})
    except Exception:
        return jsonify({"error": "Invalid client_id"}), 400
    if not client:
        return jsonify({"error": "Client not found"}), 404

    # Parse scheduled time
    try:
        scheduled_dt = datetime.strptime(scheduled_str, "%Y-%m-%dT%H:%M")
    except Exception:
        return jsonify({"error": "Invalid scheduled_time format. Use YYYY-MM-DDTHH:MM"}), 400

    req = {
        "employee_email":   email,
        "employee_name":    user["name"],
        "client_id":        client_id_str,
        "client_name":      client["name"],
        "client_company":   client.get("company", ""),
        "scheduled_time":   scheduled_dt,
        "agenda":           agenda,
        "duration_minutes": duration,
        "status":           "pending",   # pending | approved | rejected
        "requested_at":     datetime.utcnow(),
        "approved_by_email": None,
        "approved_by_name":  None,
        "approved_at":       None,
        "reject_reason":     None,
        "room_id":           None        # filled when approved + meeting created
    }
    result = _col("client_meeting_requests").insert_one(req)
    req_id = str(result.inserted_id)

    # Notify all managers via socket
    from app import emit_to_managers
    emit_to_managers("client_meeting_request", {
        "request_id":      req_id,
        "employee_name":   user["name"],
        "employee_email":  email,
        "client_name":     client["name"],
        "client_company":  client.get("company", ""),
        "scheduled_time":  scheduled_str,
        "agenda":          agenda,
        "duration":        duration,
        "time":            datetime.utcnow().strftime("%H:%M:%S")
    })

    from models.user import log_activity
    log_activity(email, "CLIENT_MEETING_REQUESTED",
        "Requested client meeting with " + client["name"] + " on " + scheduled_str,
        "Employee Dashboard", request.remote_addr, "LOW")
    return jsonify({"success": True, "request_id": req_id,
                    "message": "Request sent to manager for approval."})


@client_bp.route("/api/employee/client-meeting-requests", methods=["GET"])
def employee_my_meeting_requests():
    email, user = _auth()
    if not user or user["role"] != "employee":
        return jsonify({"error": "Unauthorized"}), 403
    reqs = list(_col("client_meeting_requests").find(
        {"employee_email": email}
    ).sort("requested_at", -1).limit(50))

    # For approved requests, attach meeting password + join link from meetings collection
    from models.user import db as _appdb
    meetings_col = _appdb["meetings"]
    result = []
    for req in reqs:
        r = dict(req)
        if r.get("status") == "approved" and r.get("room_id"):
            meeting = meetings_col.find_one({"room_id": r["room_id"]})
            if meeting:
                r["meeting_password"] = meeting.get("password", "")
                r["client_link"]      = meeting.get("client_link", "/join/" + r["room_id"])
                r["meeting_status"]   = meeting.get("status", "scheduled")
        result.append(r)
    return jsonify(_s(result))


# ══════════════════════════════════════════════════════════════
# MANAGER — Approve / Reject client meeting requests
# ══════════════════════════════════════════════════════════════

@client_bp.route("/api/manager/client-meeting-requests", methods=["GET"])
def manager_list_requests():
    email, user = _auth()
    if not user or user["role"] not in ("manager", "admin"):
        return jsonify({"error": "Unauthorized"}), 403
    status = request.args.get("status", "pending")
    query  = {}
    if status != "all":
        query["status"] = status
    reqs = list(_col("client_meeting_requests").find(query).sort("requested_at", -1).limit(100))
    return jsonify(_s(reqs))


@client_bp.route("/api/manager/client-meeting-requests/<req_id>/approve", methods=["POST"])
def manager_approve_request(req_id):
    email, user = _auth()
    if not user or user["role"] not in ("manager", "admin"):
        return jsonify({"error": "Unauthorized"}), 403

    try:
        req = _col("client_meeting_requests").find_one({"_id": ObjectId(req_id)})
    except Exception:
        return jsonify({"error": "Invalid request id"}), 400
    if not req:
        return jsonify({"error": "Request not found"}), 404
    if req["status"] != "pending":
        return jsonify({"error": "Request already " + req["status"]}), 400

    # Create the actual meeting
    import uuid
    room_id = str(uuid.uuid4())[:8].upper()
    meeting = {
        "room_id":          room_id,
        "title":            "Client Meeting — " + req["client_name"],
        "type":             "client",
        "host_email":       req["employee_email"],
        "host_name":        req["employee_name"],
        "host_role":        "employee",
        "invited":          [],
        "agenda":           req["agenda"],
        "scheduled_time":   req["scheduled_time"],
        "duration_minutes": req["duration_minutes"],
        "password":         str(uuid.uuid4())[:6].upper(),
        "status":           "scheduled",
        "is_recorded":      False,
        "client_link":      "/join/" + room_id,
        "client_id":        req["client_id"],
        "client_name":      req["client_name"],
        "client_company":   req.get("client_company", ""),
        "approved_by_email": email,
        "approved_by_name":  user["name"],
        "created_at":       datetime.utcnow(),
        "ended_at":         None,
        "waiting_room":     [],
        "participants":     [],
        "raised_hands":     []
    }
    from models.user import db as _db
    _db["meetings"].insert_one(meeting)

    # Update request
    _col("client_meeting_requests").update_one(
        {"_id": ObjectId(req_id)},
        {"$set": {
            "status":           "approved",
            "approved_by_email": email,
            "approved_by_name":  user["name"],
            "approved_at":       datetime.utcnow(),
            "room_id":           room_id
        }}
    )

    # Log to client_meeting_logs
    _col("client_meeting_logs").insert_one({
        "room_id":           room_id,
        "employee_email":    req["employee_email"],
        "employee_name":     req["employee_name"],
        "client_id":         req["client_id"],
        "client_name":       req["client_name"],
        "client_company":    req.get("client_company", ""),
        "scheduled_time":    req["scheduled_time"],
        "duration_minutes":  req["duration_minutes"],
        "agenda":            req["agenda"],
        "approved_by_email": email,
        "approved_by_name":  user["name"],
        "approved_at":       datetime.utcnow(),
        "status":            "scheduled",
        "created_at":        datetime.utcnow()
    })

    # Notify employee
    from app import emit_to_user
    emit_to_user(req["employee_email"], "client_meeting_approved", {
        "room_id":          room_id,
        "client_name":      req["client_name"],
        "scheduled_time":   req["scheduled_time"].strftime("%Y-%m-%d %H:%M"),
        "approved_by":      user["name"],
        "message":          "Your client meeting with " + req["client_name"] + " has been approved!",
        "time":             datetime.utcnow().strftime("%H:%M:%S")
    })

    # ── SEND MEETING INVITE EMAIL ─────────────────────────────────────────────
    # Priority: 1) email from request body  2) CLIENT_MEETING_EMAIL in app.py
    email_sent    = False
    send_to_email = ""
    try:
        from app import send_meeting_invite_email, CLIENT_MEETING_EMAIL

        # Get email from request body if manager entered one in modal
        body         = request.get_json(silent=True) or {}
        custom_email = (body.get("send_to_email") or "").strip()

        # Use custom email if provided, else fall back to static CLIENT_MEETING_EMAIL
        send_to_email = custom_email if custom_email else CLIENT_MEETING_EMAIL

        # Only send if a real email address is configured
        if send_to_email and send_to_email != "YOUR_CLIENT_EMAIL@example.com":
            # Build join URL from request host
            join_url = request.host_url.rstrip("/") + "/join/" + room_id

            # Format scheduled time safely
            st = req.get("scheduled_time")
            if hasattr(st, "strftime"):
                scheduled_str = st.strftime("%Y-%m-%d %H:%M")
            elif st:
                scheduled_str = str(st)
            else:
                scheduled_str = "TBD"

            email_sent = send_meeting_invite_email(
                to_email       = send_to_email,
                client_name    = req.get("client_name", ""),
                employee_name  = req.get("employee_name", ""),
                join_url       = join_url,
                password       = meeting["password"],
                scheduled_time = scheduled_str,
                agenda         = req.get("agenda", "")
            )
            print(f"[MEETING] Email {'sent' if email_sent else 'FAILED'} to {send_to_email} for room {room_id}")
        else:
            print(f"[MEETING] No email configured — skipping invite for room {room_id}")
    except Exception as e:
        print(f"[MEETING] Email error: {e}")
        email_sent = False

    from models.user import log_activity
    log_activity(email, "CLIENT_MEETING_APPROVED",
        "Approved client meeting for " + req["employee_name"] + " with " + req["client_name"],
        "Manager Dashboard", request.remote_addr, "LOW")
    return jsonify({
        "success":    True,
        "room_id":    room_id,
        "password":   meeting["password"],
        "email_sent": email_sent,
        "send_to":    send_to_email
    })


@client_bp.route("/api/manager/client-meeting-requests/<req_id>/reject", methods=["POST"])
def manager_reject_request(req_id):
    email, user = _auth()
    if not user or user["role"] not in ("manager", "admin"):
        return jsonify({"error": "Unauthorized"}), 403

    data   = request.json or {}
    reason = data.get("reason", "Rejected by manager").strip()

    try:
        req = _col("client_meeting_requests").find_one({"_id": ObjectId(req_id)})
    except Exception:
        return jsonify({"error": "Invalid request id"}), 400
    if not req:
        return jsonify({"error": "Request not found"}), 404

    _col("client_meeting_requests").update_one(
        {"_id": ObjectId(req_id)},
        {"$set": {
            "status":           "rejected",
            "approved_by_email": email,
            "approved_by_name":  user["name"],
            "approved_at":       datetime.utcnow(),
            "reject_reason":     reason
        }}
    )

    from app import emit_to_user
    emit_to_user(req["employee_email"], "client_meeting_rejected", {
        "client_name": req["client_name"],
        "reason":      reason,
        "rejected_by": user["name"],
        "message":     "Your client meeting request with " + req["client_name"] + " was rejected. Reason: " + reason,
        "time":        datetime.utcnow().strftime("%H:%M:%S")
    })

    from models.user import log_activity
    log_activity(email, "CLIENT_MEETING_REJECTED",
        "Rejected client meeting for " + req["employee_name"] + " with " + req["client_name"],
        "Manager Dashboard", request.remote_addr, "LOW")
    return jsonify({"success": True})


# ══════════════════════════════════════════════════════════════
# MEETING LOGS
# ══════════════════════════════════════════════════════════════

@client_bp.route("/api/admin/client-meeting-logs", methods=["GET"])
def admin_meeting_logs():
    """Admin gets full details of all client meeting logs."""
    email, user = _auth()
    if not user or user["role"] != "admin":
        return jsonify({"error": "Unauthorized"}), 403
    emp_filter = request.args.get("employee_email")
    query = {}
    if emp_filter:
        query["employee_email"] = emp_filter
    logs = list(_col("client_meeting_logs").find(query).sort("scheduled_time", -1).limit(200))
    return jsonify(_s(logs))


@client_bp.route("/api/manager/client-meeting-logs", methods=["GET"])
def manager_meeting_logs():
    """Manager gets limited view: employee name, client name, meeting start time."""
    email, user = _auth()
    if not user or user["role"] not in ("manager", "admin"):
        return jsonify({"error": "Unauthorized"}), 403
    logs = list(_col("client_meeting_logs").find(
        {},
        {"employee_name": 1, "client_name": 1, "scheduled_time": 1,
         "client_company": 1, "room_id": 1, "_id": 1}
    ).sort("scheduled_time", -1).limit(200))
    return jsonify(_s(logs))


# ══════════════════════════════════════════════════════════════
# ADMIN — Employee detail view with client list + meeting logs
# ══════════════════════════════════════════════════════════════

@client_bp.route("/api/admin/employee-client-detail/<emp_email>", methods=["GET"])
def admin_employee_client_detail(emp_email):
    """Full detail view for admin: employee info + assigned clients + meeting logs."""
    email, user = _auth()
    if not user or user["role"] != "admin":
        return jsonify({"error": "Unauthorized"}), 403

    from models.user import get_user_by_email
    emp = get_user_by_email(emp_email)
    if not emp:
        return jsonify({"error": "Employee not found"}), 404

    # Assigned clients
    assignments = list(_col("client_assignments").find(
        {"employee_email": emp_email, "is_active": True}
    ))
    clients = []
    for a in assignments:
        try:
            c = _col("clients").find_one({"_id": ObjectId(a["client_id"])})
        except Exception:
            c = None
        if c:
            clients.append({
                "client_id":   str(c["_id"]),
                "name":        c["name"],
                "email":       c.get("email", ""),
                "phone":       c.get("phone", ""),
                "company":     c.get("company", ""),
                "notes":       c.get("notes", ""),
                "assigned_at": a["assigned_at"].strftime("%Y-%m-%d") if hasattr(a.get("assigned_at"), "strftime") else ""
            })

    # Meeting logs
    logs = list(_col("client_meeting_logs").find(
        {"employee_email": emp_email}
    ).sort("scheduled_time", -1))

    return jsonify({
        "employee": {
            "name":       emp["name"],
            "email":      emp["email"],
            "department": emp.get("department", ""),
            "role":       emp["role"],
            "is_active":  emp.get("is_active", True)
        },
        "clients":       clients,
        "meeting_logs":  _s(logs)
    })