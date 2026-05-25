"""
File sharing model — MongoDB + GridFS
Files are stored in GridFS (inside MongoDB Atlas) so they survive Render restarts.
UPLOAD_FOLDER is kept only as a temp workspace for virus scanning.
"""
from pymongo import MongoClient
from config import MONGO_URI, DB_NAME
from datetime import datetime
import os

client = MongoClient(MONGO_URI, serverSelectionTimeoutMS=5000, connectTimeoutMS=5000)
db = client[DB_NAME]

shared_files_col = db["shared_files"]
files_col        = shared_files_col   # alias for backwards compat
approval_col     = db["approval_requests"]

# Temp folder — used only for virus scanning, never for permanent storage
UPLOAD_FOLDER = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "uploads")
os.makedirs(UPLOAD_FOLDER, exist_ok=True)


# ── GRIDFS FILE STORAGE ───────────────────────────────────────────────────────
# Files are stored inside MongoDB (GridFS) so they survive Render restarts.

try:
    from gridfs import GridFS as _GridFS
    _fs = _GridFS(db)
except Exception as _gfs_err:
    print(f"[GridFS] init error: {_gfs_err}")
    _fs = None


def save_file_to_gridfs(filename, file_bytes, content_type="application/octet-stream"):
    """Store file bytes in GridFS. Replaces any previous version with same filename."""
    if _fs is None:
        print("[GridFS] GridFS not available")
        return False
    try:
        # Remove any old version with the same filename first
        for old in _fs.find({"filename": filename}):
            _fs.delete(old._id)
        _fs.put(file_bytes, filename=filename, content_type=content_type)
        return True
    except Exception as e:
        print(f"[GridFS] save error: {e}")
        return False


def get_file_from_gridfs(filename):
    """Return file bytes from GridFS, or None if not found."""
    if _fs is None:
        return None
    try:
        f = _fs.find_one({"filename": filename})
        if f:
            return f.read()
        return None
    except Exception as e:
        print(f"[GridFS] read error: {e}")
        return None


def delete_file_from_gridfs(filename):
    """Delete all GridFS chunks for the given filename."""
    if _fs is None:
        return False
    try:
        for f in _fs.find({"filename": filename}):
            _fs.delete(f._id)
        return True
    except Exception as e:
        print(f"[GridFS] delete error: {e}")
        return False


# ── FILE RECORDS ──────────────────────────────────────────────────────────────

def save_file_record(filename, original_name, file_size, file_type,
                     visibility, allowed_emails, uploaded_by,
                     scan_clean=None, scan_engine=None, scan_detail=None):
    """Save file metadata to MongoDB after upload."""
    doc = {
        "filename":       filename,
        "original_name":  original_name,
        "file_size":      file_size,
        "file_type":      file_type,
        "visibility":     visibility,
        "allowed_emails": allowed_emails,
        "uploaded_by":    uploaded_by,
        "uploaded_at":    datetime.utcnow(),
        "is_active":      True,
        "scan_clean":     scan_clean,
        "scan_engine":    scan_engine,
        "scan_detail":    scan_detail,
    }
    result = shared_files_col.insert_one(doc)
    doc["_id"] = str(result.inserted_id)
    if isinstance(doc.get("uploaded_at"), datetime):
        doc["uploaded_at"] = doc["uploaded_at"].strftime("%Y-%m-%d %H:%M")
    return doc


def get_files_for_employee(email):
    """Return files visible to this employee."""
    from bson import ObjectId

    files = list(shared_files_col.find({
        "is_active": True,
        "$or": [
            {"visibility": "public"},
            {"visibility": "private", "allowed_emails": email}
        ]
    }))

    forwarded_reqs = list(approval_col.find({
        "forward_to":   email,
        "request_type": "forward",
        "status":       "approved"
    }))

    if forwarded_reqs:
        existing_ids = {str(f["_id"]) for f in files}
        for r in forwarded_reqs:
            fid = r["file_id"]
            if fid in existing_ids:
                continue
            try:
                fobj = shared_files_col.find_one({"_id": ObjectId(fid), "is_active": True})
                if fobj and str(fobj["_id"]) not in existing_ids:
                    fobj["forwarded"] = True
                    files.append(fobj)
                    existing_ids.add(str(fobj["_id"]))
            except Exception:
                pass

    for f in files:
        f["_id"] = str(f["_id"])
        if isinstance(f.get("uploaded_at"), datetime):
            f["uploaded_at"] = f["uploaded_at"].strftime("%Y-%m-%d %H:%M")
    return files


def get_all_files():
    """Return ALL files — manager has no restrictions."""
    files = list(shared_files_col.find({"is_active": True}).sort("uploaded_at", -1))
    for f in files:
        f["_id"] = str(f["_id"])
        if isinstance(f.get("uploaded_at"), datetime):
            f["uploaded_at"] = f["uploaded_at"].strftime("%Y-%m-%d %H:%M")
    return files


def get_file_by_id(file_id):
    from bson import ObjectId
    try:
        f = shared_files_col.find_one({"_id": ObjectId(file_id), "is_active": True})
        if f:
            f["_id"] = str(f["_id"])
        return f
    except Exception:
        return None


def get_file_by_id_unrestricted(file_id):
    """Manager version — no active check."""
    from bson import ObjectId
    try:
        f = shared_files_col.find_one({"_id": ObjectId(file_id)})
        if f:
            f["_id"] = str(f["_id"])
        return f
    except Exception:
        return None


def delete_file_record(file_id):
    from bson import ObjectId
    try:
        rec = shared_files_col.find_one({"_id": ObjectId(file_id)})
        if rec and rec.get("filename"):
            delete_file_from_gridfs(rec["filename"])
        shared_files_col.update_one({"_id": ObjectId(file_id)}, {"$set": {"is_active": False}})
        return True
    except Exception:
        return False


# ── APPROVAL REQUESTS ─────────────────────────────────────────────────────────

def create_approval_request(file_id, file_name, requested_by,
                             request_type, forward_to=None):
    file_id = str(file_id)
    existing = approval_col.find_one({
        "file_id":      file_id,
        "requested_by": requested_by,
        "request_type": request_type,
        "status":       "pending"
    })
    if existing:
        existing["_id"] = str(existing["_id"])
        return existing, False

    doc = {
        "file_id":       file_id,
        "file_name":     file_name,
        "requested_by":  requested_by,
        "request_type":  request_type,
        "forward_to":    forward_to,
        "status":        "pending",
        "requested_at":  datetime.utcnow(),
        "resolved_at":   None,
        "resolved_by":   None,
        "reject_reason": None
    }
    result = approval_col.insert_one(doc)
    doc["_id"] = str(result.inserted_id)
    return doc, True


def get_pending_approvals():
    reqs = list(approval_col.find({"status": "pending"}).sort("requested_at", -1))
    for r in reqs:
        r["_id"] = str(r["_id"])
        if isinstance(r.get("requested_at"), datetime):
            r["requested_at"] = r["requested_at"].strftime("%Y-%m-%d %H:%M:%S")
    return reqs


def get_all_approvals():
    reqs = list(approval_col.find().sort("requested_at", -1).limit(200))
    for r in reqs:
        r["_id"] = str(r["_id"])
        if isinstance(r.get("requested_at"), datetime):
            r["requested_at"] = r["requested_at"].strftime("%Y-%m-%d %H:%M:%S")
        if isinstance(r.get("resolved_at"), datetime):
            r["resolved_at"] = r["resolved_at"].strftime("%Y-%m-%d %H:%M:%S")
    return reqs


def get_employee_requests(email):
    reqs = list(approval_col.find({"requested_by": email}).sort("requested_at", -1))
    for r in reqs:
        r["_id"] = str(r["_id"])
        if isinstance(r.get("requested_at"), datetime):
            r["requested_at"] = r["requested_at"].strftime("%Y-%m-%d %H:%M:%S")
        if isinstance(r.get("resolved_at"), datetime):
            r["resolved_at"] = r["resolved_at"].strftime("%Y-%m-%d %H:%M:%S")
    return reqs


def resolve_approval(request_id, status, resolved_by, reject_reason=None):
    from bson import ObjectId
    try:
        approval_col.update_one(
            {"_id": ObjectId(request_id)},
            {"$set": {
                "status":        status,
                "resolved_at":   datetime.utcnow(),
                "resolved_by":   resolved_by,
                "reject_reason": reject_reason
            }}
        )
        req = approval_col.find_one({"_id": ObjectId(request_id)})
        if req:
            req["_id"] = str(req["_id"])
        return req
    except Exception:
        return None


def get_approval_by_id(request_id):
    from bson import ObjectId
    try:
        req = approval_col.find_one({"_id": ObjectId(request_id)})
        if req:
            req["_id"] = str(req["_id"])
        return req
    except Exception:
        return None