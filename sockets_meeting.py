"""
sockets_meeting.py — Socket.IO events for the meeting feature
Call register_meeting_sockets(socketio, db) from your app.py
"""

from flask_socketio import emit, join_room, leave_room
from datetime import datetime


def register_meeting_sockets(socketio, db):
    meetings_col = db["meetings"]
    notes_col    = db["meeting_notes"]

    # ─── JOIN WAITING ROOM ────────────────────────────────────────────────────
    @socketio.on("join_waiting_room")
    def on_join_waiting(data):
        room_id = data["room_id"]
        email   = data.get("user_email", "")
        name    = data.get("name", email)
        role    = data.get("role", "employee")

        user_entry = {
            "user_email": email,
            "name":       name,
            "role":       role,
            "joined_at":  datetime.utcnow().isoformat()
        }
        join_room("waiting_" + room_id)
        meetings_col.update_one(
            {"room_id": room_id},
            {"$addToSet": {"waiting_room": user_entry}}
        )
        # Tell the host someone is waiting
        emit("new_waiting_user", user_entry, room="host_" + room_id)

    # ─── HOST ADMITS USER ─────────────────────────────────────────────────────
    @socketio.on("admit_user")
    def on_admit(data):
        room_id    = data["room_id"]
        user_email = data["user_email"]
        meetings_col.update_one(
            {"room_id": room_id},
            {
                "$pull":     {"waiting_room": {"user_email": user_email}},
                "$addToSet": {"participants": user_email}
            }
        )
        emit("admitted", {"room_id": room_id}, room="user_" + user_email)

    # ─── JOIN MEETING ROOM ────────────────────────────────────────────────────
    @socketio.on("join_meeting")
    def on_join_meeting(data):
        room_id    = data["room_id"]
        email      = data.get("user_email", "")
        is_host    = data.get("is_host", False)

        join_room(room_id)
        if is_host:
            join_room("host_" + room_id)
        else:
            join_room("user_" + email)

        emit("user_joined", {
            "user_email": email,
            "name":       data.get("name", email),
            "role":       data.get("role", "employee")
        }, room=room_id)

    # ─── LEAVE MEETING ────────────────────────────────────────────────────────
    @socketio.on("leave_meeting")
    def on_leave_meeting(data):
        room_id = data["room_id"]
        email   = data.get("user_email", "")
        leave_room(room_id)
        emit("user_left", {"user_email": email, "name": data.get("name", email)}, room=room_id)

    # ─── REAL-TIME NOTES SYNC ─────────────────────────────────────────────────
    @socketio.on("update_notes")
    def on_update_notes(data):
        room_id = data["room_id"]
        notes_col.update_one(
            {"room_id": room_id},
            {"$set": {
                "content":         data["content"],
                "last_updated_by": data.get("user_name", ""),
                "updated_at":      datetime.utcnow()
            }},
            upsert=True
        )
        emit("notes_updated",
             {"content": data["content"], "by": data.get("user_name", "")},
             room=room_id, include_self=False)

    # ─── RAISE / LOWER HAND ───────────────────────────────────────────────────
    @socketio.on("raise_hand")
    def on_raise_hand(data):
        room_id = data["room_id"]
        email   = data.get("user_email", "")
        meetings_col.update_one(
            {"room_id": room_id},
            {"$addToSet": {"raised_hands": {
                "user_email": email,
                "name":       data.get("name", email),
                "time":       datetime.utcnow().isoformat()
            }}}
        )
        emit("hand_raised", {"user_email": email, "name": data.get("name", email)}, room=room_id)

    @socketio.on("lower_hand")
    def on_lower_hand(data):
        room_id = data["room_id"]
        email   = data.get("user_email", "")
        meetings_col.update_one(
            {"room_id": room_id},
            {"$pull": {"raised_hands": {"user_email": email}}}
        )
        emit("hand_lowered", {"user_email": email}, room=room_id)

    # ─── LIVE POLL BROADCAST ──────────────────────────────────────────────────
    @socketio.on("broadcast_poll")
    def on_broadcast_poll(data):
        emit("new_poll", data, room=data["room_id"])

    @socketio.on("poll_vote_update")
    def on_poll_vote_update(data):
        emit("poll_updated", data, room=data["room_id"])

    # ─── HOST CONTROLS: MUTE / REMOVE ────────────────────────────────────────
    @socketio.on("mute_user")
    def on_mute(data):
        emit("you_are_muted", {}, room="user_" + data["target_email"])

    @socketio.on("remove_user")
    def on_remove(data):
        emit("you_are_removed", {}, room="user_" + data["target_email"])

    # ─── RECORDING STARTED ────────────────────────────────────────────────────
    @socketio.on("recording_started")
    def on_recording(data):
        emit("recording_notice",
             {"message": "This meeting is now being recorded"},
             room=data["room_id"])

    # ─── CHAT MESSAGE ─────────────────────────────────────────────────────────
    @socketio.on("meeting_chat")
    def on_meeting_chat(data):
        emit("new_meeting_chat", {
            "user_email": data.get("user_email", ""),
            "name":       data.get("name", ""),
            "message":    data.get("message", ""),
            "time":       datetime.utcnow().strftime("%H:%M")
        }, room=data["room_id"])