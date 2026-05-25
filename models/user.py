from pymongo import MongoClient
from pymongo.errors import ConnectionFailure, ServerSelectionTimeoutError
from config import MONGO_URI, DB_NAME
import bcrypt
from datetime import datetime

client = MongoClient(MONGO_URI, serverSelectionTimeoutMS=5000, connectTimeoutMS=5000)
db = client[DB_NAME]

users_col  = db["users"]
otp_col    = db["otps"]
logs_col   = db["activity_logs"]
events_col = db["security_events"]

def check_mongo_connection():
    """Test MongoDB connection and print clear error if it fails."""
    try:
        client.admin.command("ping")
        print("[MongoDB] Connected successfully to", MONGO_URI)
        return True
    except (ConnectionFailure, ServerSelectionTimeoutError) as e:
        print("=" * 60)
        print("[MongoDB] CONNECTION FAILED!")
        print("Make sure MongoDB is running:")
        print("  Windows: net start MongoDB")
        print("  Or start mongod.exe manually")
        print(f"  Error: {e}")
        print("=" * 60)
        return False


def create_user(name, email, password, role, department="IT", allowed_locations=None):
    """Create a new user (employee or manager)."""
    email  = email.strip().lower()   # always store lowercase
    hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
    user = {
        "name": name,
        "email": email,
        "password": hashed,
        "role": role,
        "department": department,
        "device_id": None,
        "created_at": datetime.utcnow(),
        "is_active": True,
        "risk_score": 0,
        "allowed_locations": allowed_locations or [],
        "registered_ip": None,
        "last_login_location": None,
        "last_login_time": None,
        "last_login_location_coords": None,
        "login_history": [],
        # Device fingerprint — enrolled on first login automatically
        "device_profile": None,
        "device_enrolled_at": None,
        # Travel mode — None until employee requests
        "travel_mode": None,
    }
    return users_col.insert_one(user)


def get_user_by_email(email):
    """Case-insensitive lookup — works regardless of how email was stored in DB."""
    import re
    if not email:
        return None
    return users_col.find_one(
        {"email": {"$regex": f"^{re.escape(email.strip())}$", "$options": "i"}}
    )


def verify_password(plain, hashed):
    return bcrypt.checkpw(plain.encode(), hashed)


def update_user_login(email, location, ip):
    login_entry = {"location": location, "ip": ip, "time": datetime.utcnow()}
    users_col.update_one(
        {"email": email},
        {
            "$set": {
                "last_login_location": location,
                "last_login_time": datetime.utcnow(),
                "registered_ip": ip
            },
            "$push": {
                "login_history": {"$each": [login_entry], "$slice": -20}
            }
        }
    )


def set_allowed_locations(email, locations):
    users_col.update_one({"email": email}, {"$set": {"allowed_locations": locations}})


def is_location_allowed(user, city, country):
    if city in ("Localhost", "Unknown", ""):
        return True, "localhost"
    allowed = user.get("allowed_locations", [])
    if not allowed:
        return True, "no_restriction"
    city_lower = city.lower()
    for loc in allowed:
        if loc.lower() in city_lower or city_lower in loc.lower():
            return True, "allowed"
    return False, "blocked"


def get_login_history(email):
    user = users_col.find_one({"email": email}, {"login_history": 1, "_id": 0})
    if not user:
        return []
    history = user.get("login_history", [])
    for h in history:
        if isinstance(h.get("time"), datetime):
            h["time"] = h["time"].strftime("%Y-%m-%d %H:%M:%S")
    return list(reversed(history))


def save_otp(email, otp, expiry):
    otp_col.delete_many({"email": email})
    otp_col.insert_one({"email": email, "otp": otp, "expiry": expiry, "created_at": datetime.utcnow()})


def get_otp(email):
    return otp_col.find_one({"email": email})


def delete_otp(email):
    otp_col.delete_many({"email": email})


def log_activity(user_email, event_type, detail, location, ip, risk_level="LOW"):
    logs_col.insert_one({
        "user_email": user_email,
        "event_type": event_type,
        "detail": detail,
        "location": location,
        "ip": ip,
        "risk_level": risk_level,
        "timestamp": datetime.utcnow()
    })


def log_security_event(user_email, action, detail, location, ip, blocked=False):
    events_col.insert_one({
        "user_email": user_email,
        "action": action,
        "detail": detail,
        "location": location,
        "ip": ip,
        "blocked": blocked,
        "status": "blocked" if blocked else "allowed",
        "timestamp": datetime.utcnow()
    })


def _fmt(docs):
    """Convert datetime fields to strings in a list of dicts."""
    for d in docs:
        for k, v in d.items():
            if isinstance(v, datetime):
                d[k] = v.strftime("%Y-%m-%d %H:%M:%S")
    return docs

def get_all_logs(limit=100):
    return _fmt(list(logs_col.find({}, {"_id": 0}).sort("timestamp", -1).limit(limit)))

def get_all_security_events(limit=100):
    return _fmt(list(events_col.find({}, {"_id": 0}).sort("timestamp", -1).limit(limit)))

def get_user_logs(email, limit=50):
    return _fmt(list(logs_col.find({"user_email": email}, {"_id": 0}).sort("timestamp", -1).limit(limit)))


def get_all_employees():
    users = list(users_col.find({"role": "employee"}, {"_id": 0, "password": 0}))
    for u in users:
        for k, v in u.items():
            if isinstance(v, datetime):
                u[k] = v.strftime("%Y-%m-%d %H:%M:%S")
    return users


def seed_users():
    pass  # Default seed users removed — register users via the admin panel

def normalize_existing_emails():
    """One-time migration: lowercase all emails already in DB.
    Call once from app startup or run manually if users were created with mixed-case emails."""
    count = 0
    for user in users_col.find({}, {"_id": 1, "email": 1}):
        raw = user.get("email", "")
        lowered = raw.strip().lower()
        if raw != lowered:
            users_col.update_one({"_id": user["_id"]}, {"$set": {"email": lowered}})
            count += 1
    if count:
        print(f"[DB MIGRATE] Normalized {count} email(s) to lowercase.")
    return count


# ── ADMIN FUNCTIONS ───────────────────────────────────────────────────────────

def create_admin(name, email, password):
    """Create admin user."""
    if get_user_by_email(email):
        return None
    hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
    user = {
        "name": name, "email": email, "password": hashed,
        "role": "admin", "department": "Administration",
        "device_id": None, "created_at": datetime.utcnow(),
        "is_active": True, "risk_score": 0,
        "allowed_locations": [], "registered_ip": None,
        "last_login_location": None, "last_login_time": None,
        "login_history": []
    }
    return users_col.insert_one(user)


def get_all_users_by_role(role):
    users = list(users_col.find({"role": role}, {"_id": 0, "password": 0}))
    for u in users:
        if isinstance(u.get("created_at"), datetime):
            u["created_at"] = u["created_at"].strftime("%Y-%m-%d %H:%M")
        if isinstance(u.get("last_login_time"), datetime):
            u["last_login_time"] = u["last_login_time"].strftime("%Y-%m-%d %H:%M")
    return users


def get_all_logs_for_user(email, limit=100):
    logs = list(logs_col.find({"user_email": email}, {"_id": 0}).sort("timestamp", -1).limit(limit))
    for l in logs:
        if isinstance(l.get("timestamp"), datetime):
            l["timestamp"] = l["timestamp"].strftime("%Y-%m-%d %H:%M:%S")
    return logs


def get_all_security_events_for_user(email, limit=100):
    events = list(events_col.find({"user_email": email}, {"_id": 0}).sort("timestamp", -1).limit(limit))
    for e in events:
        if isinstance(e.get("timestamp"), datetime):
            e["timestamp"] = e["timestamp"].strftime("%Y-%m-%d %H:%M:%S")
    return events


def get_all_logs_unrestricted(limit=200):
    logs = list(logs_col.find({}, {"_id": 0}).sort("timestamp", -1).limit(limit))
    for l in logs:
        if isinstance(l.get("timestamp"), datetime):
            l["timestamp"] = l["timestamp"].strftime("%Y-%m-%d %H:%M:%S")
    return logs


def get_all_security_events_unrestricted(limit=200):
    events = list(events_col.find({}, {"_id": 0}).sort("timestamp", -1).limit(limit))
    for e in events:
        if isinstance(e.get("timestamp"), datetime):
            e["timestamp"] = e["timestamp"].strftime("%Y-%m-%d %H:%M:%S")
    return events


def deactivate_user(email):
    users_col.update_one({"email": email}, {"$set": {"is_active": False}})


def reactivate_user(email):
    users_col.update_one({"email": email}, {"$set": {"is_active": True}})


def get_system_stats():
    return {
        "total_employees": users_col.count_documents({"role": "employee"}),
        "total_managers":  users_col.count_documents({"role": "manager"}),
        "active_users":    users_col.count_documents({"is_active": True, "role": {"$in": ["employee","manager"]}}),
        "total_logs":      logs_col.count_documents({}),
        "total_security_events": events_col.count_documents({}),
        "high_risk_events": logs_col.count_documents({"risk_level": "HIGH"}),
        "blocked_actions": events_col.count_documents({"blocked": True}),
    }


def seed_admin():
    pass  # Default seed admin removed — create admin via DB or admin panel


# ── DEVICE FINGERPRINT ────────────────────────────────────────────────────────

def save_device_profile(email, fingerprint):
    """
    Save device profile on first login (auto-enroll).
    fingerprint = {os, browser, screen, timezone, ua}
    """
    users_col.update_one(
        {"email": email},
        {"$set": {"device_profile": fingerprint, "device_enrolled_at": datetime.utcnow()}}
    )


def get_device_profile(email):
    user = users_col.find_one({"email": email}, {"device_profile": 1})
    return user.get("device_profile") if user else None


def check_device_mismatch(email, current):
    """
    Compare current fingerprint against stored profile.
    Returns (is_mismatch: bool, reasons: list)
    """
    stored = get_device_profile(email)
    if not stored:
        return False, []   # no profile yet — first login, enroll silently

    reasons = []
    if stored.get("os")       != current.get("os"):
        reasons.append(f"OS changed: {stored.get('os')} → {current.get('os')}")
    if stored.get("timezone") != current.get("timezone"):
        reasons.append(f"Timezone changed: {stored.get('timezone')} → {current.get('timezone')}")
    if stored.get("screen")   != current.get("screen"):
        reasons.append(f"Screen changed: {stored.get('screen')} → {current.get('screen')}")
    # Browser can legitimately update, so only flag major change (Chrome→Firefox)
    stored_browser  = (stored.get("browser") or "").split("/")[0]
    current_browser = (current.get("browser") or "").split("/")[0]
    if stored_browser and current_browser and stored_browser != current_browser:
        reasons.append(f"Browser changed: {stored_browser} → {current_browser}")

    return len(reasons) > 0, reasons


# ── IMPOSSIBLE TRAVEL DETECTION ───────────────────────────────────────────────

SPEED_LIMIT_KMH = 900   # commercial aircraft ~900 km/h

def haversine_km(loc1, loc2):
    """Calculate great-circle distance between two lat/lon points in km."""
    import math
    lat1, lon1 = loc1.get("lat"), loc1.get("lon")
    lat2, lon2 = loc2.get("lat"), loc2.get("lon")
    # Guard: any None coordinate → cannot calculate
    if any(v is None for v in (lat1, lon1, lat2, lon2)):
        return 0.0
    lat1, lon1, lat2, lon2 = float(lat1), float(lon1), float(lat2), float(lon2)
    R = 6371
    dlat = math.radians(lat2 - lat1)
    dlon = math.radians(lon2 - lon1)
    a = math.sin(dlat/2)**2 + math.cos(math.radians(lat1)) * math.cos(math.radians(lat2)) * math.sin(dlon/2)**2
    return R * 2 * math.asin(math.sqrt(a))


def check_impossible_travel(email, current_loc, current_time):
    """
    Compare current login location/time against last login.
    Returns (is_impossible: bool, detail: str)
    """
    user = users_col.find_one({"email": email}, {"last_login_location_coords": 1, "last_login_time": 1})
    if not user:
        return False, ""

    last_coords = user.get("last_login_location_coords")
    last_time   = user.get("last_login_time")

    if not last_coords or not last_time or not current_loc:
        return False, ""

    # Skip if either location has no valid coordinates (e.g. stored from localhost/unknown IP)
    if last_coords.get("lat") is None or last_coords.get("lon") is None:
        return False, ""
    if current_loc.get("lat") is None or current_loc.get("lon") is None:
        return False, ""

    distance_km  = haversine_km(last_coords, current_loc)
    time_diff_h  = (current_time - last_time).total_seconds() / 3600

    if time_diff_h < 0.01:   # less than ~36 seconds apart — ignore
        return False, ""

    speed_kmh = distance_km / time_diff_h

    if speed_kmh > SPEED_LIMIT_KMH and distance_km > 100:
        return True, (
            f"Distance: {distance_km:.0f} km in {time_diff_h:.1f} hrs "
            f"(speed: {speed_kmh:.0f} km/h) — faster than aircraft"
        )
    return False, ""


def update_login_coords(email, coords):
    """Store lat/lon of last login for travel detection."""
    users_col.update_one(
        {"email": email},
        {"$set": {"last_login_location_coords": coords}}
    )


# ── TRAVEL MODE ───────────────────────────────────────────────────────────────

def request_travel_mode(email, destination, start_date, end_date, reason,
                         source=None, src_coords=None, dst_coords=None):
    """Employee/Manager requests travel mode — stored as pending."""
    users_col.update_one(
        {"email": email},
        {"$set": {
            "travel_mode": {
                "status":       "pending",
                "source":       source or destination,
                "destination":  destination,
                "src_coords":   src_coords,
                "dst_coords":   dst_coords,
                "start_date":   start_date,
                "end_date":     end_date,
                "reason":       reason,
                "requested_at": datetime.utcnow(),
                "approved_by":  None,
                "approved_at":  None,
            }
        }}
    )


def approve_travel_mode(email, approved_by):
    users_col.update_one(
        {"email": email},
        {"$set": {
            "travel_mode.status":      "approved",
            "travel_mode.approved_by": approved_by,
            "travel_mode.approved_at": datetime.utcnow(),
        }}
    )


def reject_travel_mode(email, rejected_by):
    users_col.update_one(
        {"email": email},
        {"$set": {
            "travel_mode.status":      "rejected",
            "travel_mode.approved_by": rejected_by,
            "travel_mode.approved_at": datetime.utcnow(),
        }}
    )


def get_travel_mode(email):
    user = users_col.find_one({"email": email}, {"travel_mode": 1})
    if not user or not user.get("travel_mode"):
        return None
    tm = user["travel_mode"]
    for k in ("requested_at", "approved_at", "start_date", "end_date"):
        if isinstance(tm.get(k), datetime):
            tm[k] = tm[k].strftime("%Y-%m-%d %H:%M")
    return tm


def get_travel_history(email):
    """Return all past travel requests for this user, newest first (max 20).
    Falls back to current travel_mode if history array is empty."""
    user = users_col.find_one({"email": email}, {"travel_history": 1, "travel_mode": 1})
    if not user:
        return []
    history = list(user.get("travel_history") or [])
    if not history and user.get("travel_mode"):
        history = [user["travel_mode"]]
    result = []
    for tm in reversed(history):
        tm = dict(tm)
        for k in ("requested_at", "approved_at", "start_date", "end_date"):
            if isinstance(tm.get(k), datetime):
                tm[k] = tm[k].strftime("%Y-%m-%d %H:%M")
        result.append(tm)
    return result


def is_travel_mode_active(email):
    """Returns (True, destination) if approved travel mode covers now."""
    user = users_col.find_one({"email": email}, {"travel_mode": 1})
    if not user:
        return False, None
    tm = user.get("travel_mode")
    if not tm or tm.get("status") != "approved":
        return False, None
    try:
        now   = datetime.utcnow()
        start = tm["start_date"] if isinstance(tm["start_date"], datetime) else datetime.strptime(str(tm["start_date"])[:16], "%Y-%m-%d %H:%M")
        end   = tm["end_date"]   if isinstance(tm["end_date"],   datetime) else datetime.strptime(str(tm["end_date"])[:16],   "%Y-%m-%d %H:%M")
        if start <= now <= end:
            return True, tm.get("destination", "")
    except Exception:
        pass
    return False, None


def get_all_travel_requests():
    """Return all users (employees + managers) who have a travel request.
    Uses dot-notation query which works correctly across all MongoDB versions."""
    users = list(users_col.find(
        {"travel_mode.status": {"$exists": True, "$ne": ""}},
        {"email": 1, "name": 1, "role": 1, "department": 1, "travel_mode": 1, "_id": 0}
    ))
    result = []
    for u in users:
        tm = u.get("travel_mode") or {}
        if not tm or not tm.get("status"):
            continue
        for k in ("requested_at", "approved_at", "start_date", "end_date"):
            v = tm.get(k)
            if isinstance(v, datetime):
                tm[k] = v.strftime("%Y-%m-%d %H:%M")
        result.append(u)
    return result