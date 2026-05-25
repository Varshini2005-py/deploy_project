"""
Module 3 — Step 3
File : D:/rajasri/xai_itd_dlp/dlp/policy_engine.py

What this does:
  Enforces role-based DLP rules by combining three inputs:
    1. User role         (employee / manager / admin)
    2. AI risk label     (LOW / MEDIUM / HIGH / CRITICAL from threat_scores)
    3. Content sensitivity (LOW / MEDIUM / HIGH / CRITICAL from content_scanner)

  Decision matrix:
  ┌────────────┬─────────────┬──────────────┬───────────────────────────┐
  │ Role       │ Risk Label  │ Sensitivity  │ Action                    │
  ├────────────┼─────────────┼──────────────┼───────────────────────────┤
  │ employee   │ any         │ LOW          │ ALLOWED                   │
  │ employee   │ LOW/MEDIUM  │ MEDIUM       │ WARNED                    │
  │ employee   │ HIGH/CRIT   │ MEDIUM       │ BLOCKED                   │
  │ employee   │ any         │ HIGH         │ BLOCKED                   │
  │ employee   │ any         │ CRITICAL     │ BLOCKED                   │
  ├────────────┼─────────────┼──────────────┼───────────────────────────┤
  │ manager    │ any         │ LOW          │ ALLOWED                   │
  │ manager    │ any         │ MEDIUM       │ ALLOWED                   │
  │ manager    │ LOW/MEDIUM  │ HIGH         │ WARNED                    │
  │ manager    │ HIGH/CRIT   │ HIGH         │ BLOCKED                   │
  │ manager    │ any         │ CRITICAL     │ APPROVAL_REQUIRED         │
  ├────────────┼─────────────┼──────────────┼───────────────────────────┤
  │ admin      │ any         │ any          │ ALLOWED (logged only)     │
  └────────────┴─────────────┴──────────────┴───────────────────────────┘

  Higher AI risk score = stricter enforcement automatically.
  e.g. employee with HIGH risk label gets blocked even on MEDIUM files.

  Saves policy decision back to the same dlp_events document.
  Also logs to security_events via log_security_event() from models/user.py.
  Emits Socket.IO alert to manager dashboard for BLOCKED/CRITICAL events.

Called from:
  monitor.py  — after content_scanner.scan_file() on file access
  app.py      — after content_scanner.scan_file() on file upload

Collections used:
  dlp_events    — updated with policy_decision field
  threat_scores — read to get current AI risk label for user
  dlp_policies  — seeded on startup, stores role rules for /api/dlp/policies
"""

import os
import sys
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from models.user import db, log_security_event, get_user_by_email

dlp_events_col    = db["dlp_events"]
threat_scores_col = db["threat_scores"]
dlp_policies_col  = db["dlp_policies"]

# =============================================================================
# SENSITIVITY + RISK LEVEL MAPS
# =============================================================================

LEVEL_ORDER = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}


def _level(label):
    """Convert label string to numeric for comparison."""
    return LEVEL_ORDER.get(label.upper(), 0)


# =============================================================================
# SEED DLP POLICIES INTO MONGODB (called once on app startup)
# =============================================================================

def seed_dlp_policies():
    """
    Seed role-based policy definitions into dlp_policies collection.
    Safe to call multiple times — uses upsert per role.
    """
    policies = [
        {
            "role": "employee",
            "rules": [
                {
                    "sensitivity":  "LOW",
                    "risk_labels":  ["LOW", "MEDIUM", "HIGH", "CRITICAL"],
                    "action":       "ALLOWED",
                    "reason":       "Low sensitivity files are accessible to all employees"
                },
                {
                    "sensitivity":  "MEDIUM",
                    "risk_labels":  ["LOW", "MEDIUM"],
                    "action":       "WARNED",
                    "reason":       "Medium sensitivity files trigger a warning for normal-risk employees"
                },
                {
                    "sensitivity":  "MEDIUM",
                    "risk_labels":  ["HIGH", "CRITICAL"],
                    "action":       "BLOCKED",
                    "reason":       "High-risk employees are blocked from medium sensitivity files"
                },
                {
                    "sensitivity":  "HIGH",
                    "risk_labels":  ["LOW", "MEDIUM", "HIGH", "CRITICAL"],
                    "action":       "BLOCKED",
                    "reason":       "Employees cannot access HIGH sensitivity files regardless of risk"
                },
                {
                    "sensitivity":  "CRITICAL",
                    "risk_labels":  ["LOW", "MEDIUM", "HIGH", "CRITICAL"],
                    "action":       "BLOCKED",
                    "reason":       "Employees are always blocked from CRITICAL sensitivity files"
                }
            ]
        },
        {
            "role": "manager",
            "rules": [
                {
                    "sensitivity":  "LOW",
                    "risk_labels":  ["LOW", "MEDIUM", "HIGH", "CRITICAL"],
                    "action":       "ALLOWED",
                    "reason":       "Managers have full access to low sensitivity files"
                },
                {
                    "sensitivity":  "MEDIUM",
                    "risk_labels":  ["LOW", "MEDIUM", "HIGH", "CRITICAL"],
                    "action":       "ALLOWED",
                    "reason":       "Managers can access medium sensitivity files"
                },
                {
                    "sensitivity":  "HIGH",
                    "risk_labels":  ["LOW", "MEDIUM"],
                    "action":       "WARNED",
                    "reason":       "Managers get a warning for high sensitivity files when low risk"
                },
                {
                    "sensitivity":  "HIGH",
                    "risk_labels":  ["HIGH", "CRITICAL"],
                    "action":       "BLOCKED",
                    "reason":       "High-risk managers are blocked from high sensitivity files"
                },
                {
                    "sensitivity":  "CRITICAL",
                    "risk_labels":  ["LOW", "MEDIUM", "HIGH", "CRITICAL"],
                    "action":       "APPROVAL_REQUIRED",
                    "reason":       "Critical sensitivity files always require manager-level approval"
                }
            ]
        },
        {
            "role": "admin",
            "rules": [
                {
                    "sensitivity":  "ALL",
                    "risk_labels":  ["LOW", "MEDIUM", "HIGH", "CRITICAL"],
                    "action":       "ALLOWED",
                    "reason":       "Admin has full access — all events are logged for audit"
                }
            ]
        }
    ]

    for policy in policies:
        dlp_policies_col.update_one(
            {"role": policy["role"]},
            {"$set": policy},
            upsert=True
        )
    print("[POLICY] DLP policies seeded into MongoDB (dlp_policies)")


# =============================================================================
# GET CURRENT AI RISK LABEL FOR USER
# =============================================================================

def get_user_risk_label(email):
    """
    Fetch the latest AI risk label for a user from threat_scores.
    Returns 'LOW' if no score found (new/inactive user).
    """
    doc = threat_scores_col.find_one(
        {"user_email": email},
        sort=[("scored_at", -1)]
    )
    if doc:
        return doc.get("risk_label", "LOW"), float(doc.get("risk_score", 0.0))
    return "LOW", 0.0


# =============================================================================
# CORE ENFORCEMENT DECISION
# =============================================================================

def evaluate_policy(role, risk_label, sensitivity_level):
    """
    Pure decision function — no DB calls, no side effects.
    Returns (action, reason) based on role + risk + sensitivity.

    Parameters
    ----------
    role              : str — 'employee' / 'manager' / 'admin'
    risk_label        : str — AI risk label from threat_scores
    sensitivity_level : str — from content_scanner

    Returns
    -------
    (action: str, reason: str)
    action is one of: ALLOWED / WARNED / BLOCKED / APPROVAL_REQUIRED
    """
    role        = role.lower()
    risk_lvl    = _level(risk_label)
    sens_lvl    = _level(sensitivity_level)

    # Admin — always allowed, just logged
    if role == "admin":
        return (
            "ALLOWED",
            "Admin access — event logged for audit trail"
        )

    # Manager rules
    if role == "manager":
        if sens_lvl == 0:   # LOW
            return "ALLOWED", "Managers have full access to low sensitivity files"
        if sens_lvl == 1:   # MEDIUM
            return "ALLOWED", "Managers can access medium sensitivity files"
        if sens_lvl == 2:   # HIGH
            if risk_lvl <= 1:   # LOW or MEDIUM AI risk
                return (
                    "WARNED",
                    f"Manager accessing HIGH sensitivity file — AI risk is {risk_label}"
                )
            else:               # HIGH or CRITICAL AI risk
                return (
                    "BLOCKED",
                    f"Manager blocked — HIGH sensitivity + {risk_label} AI risk score"
                )
        if sens_lvl >= 3:   # CRITICAL
            return (
                "APPROVAL_REQUIRED",
                "CRITICAL sensitivity file — requires explicit approval before access"
            )

    # Employee rules
    if role == "employee":
        if sens_lvl == 0:   # LOW
            return "ALLOWED", "Low sensitivity file — no restrictions"
        if sens_lvl == 1:   # MEDIUM
            if risk_lvl <= 1:   # LOW or MEDIUM AI risk
                return (
                    "WARNED",
                    f"Medium sensitivity file — employee AI risk is {risk_label}"
                )
            else:               # HIGH or CRITICAL AI risk
                return (
                    "BLOCKED",
                    f"Employee blocked — MEDIUM sensitivity + elevated AI risk ({risk_label})"
                )
        if sens_lvl >= 2:   # HIGH or CRITICAL
            return (
                "BLOCKED",
                f"Employee blocked — {sensitivity_level} sensitivity files are restricted"
            )

    # Fallback — unknown role, block by default
    return "BLOCKED", f"Unknown role '{role}' — blocked by default"


# =============================================================================
# ENFORCE POLICY ON A DLP EVENT
# =============================================================================

def enforce_policy(event_id, user_email, sensitivity_level,
                   action_type="FILE_ACCESS", socketio_instance=None):
    """
    Full enforcement pipeline for one DLP event:
      1. Fetch user role and AI risk label
      2. Evaluate policy decision
      3. Update dlp_events document with policy_decision
      4. Log to security_events via log_security_event()
      5. Emit Socket.IO alert for BLOCKED / APPROVAL_REQUIRED events

    Parameters
    ----------
    event_id          : str  — MongoDB _id of the dlp_events document
    user_email        : str  — employee email
    sensitivity_level : str  — from content_scanner result
    action_type       : str  — FILE_MODIFIED / FILE_CREATED / UPLOAD etc.
    socketio_instance : SocketIO — passed from app.py for real-time alerts

    Returns
    -------
    dict: {action, reason, risk_label, risk_score, role}
    """
    from bson import ObjectId

    # Get user role
    user      = get_user_by_email(user_email)
    role      = user.get("role", "employee") if user else "employee"

    # Get AI risk label
    risk_label, risk_score = get_user_risk_label(user_email)

    # Evaluate policy
    action, reason = evaluate_policy(role, risk_label, sensitivity_level)

    # Update dlp_events with policy decision
    if event_id:
        try:
            dlp_events_col.update_one(
                {"_id": ObjectId(event_id)},
                {"$set": {
                    "action_taken":    action,
                    "policy_decision": {
                        "role":        role,
                        "risk_label":  risk_label,
                        "risk_score":  risk_score,
                        "action":      action,
                        "reason":      reason,
                        "decided_at":  datetime.now(timezone.utc)
                    }
                }}
            )
        except Exception as e:
            print(f"[POLICY] Could not update dlp_events: {e}")

    # Log to security_events
    try:
        severity_map = {
            "ALLOWED":           "LOW",
            "WARNED":            "MEDIUM",
            "BLOCKED":           "HIGH",
            "APPROVAL_REQUIRED": "HIGH"
        }
        log_security_event(
            user_email,
            f"DLP_{action}",
            f"[{sensitivity_level}] {reason} | action={action_type}",
            "-",
            "-",
            blocked=(action in ("BLOCKED", "APPROVAL_REQUIRED"))
        )
    except Exception as e:
        print(f"[POLICY] log_security_event failed: {e}")

    # Emit Socket.IO alert to manager dashboard for serious events
    if action in ("BLOCKED", "APPROVAL_REQUIRED") and socketio_instance:
        try:
            socketio_instance.emit("dlp_alert", {
                "user_email":        user_email,
                "role":              role,
                "risk_label":        risk_label,
                "sensitivity_level": sensitivity_level,
                "action":            action,
                "reason":            reason,
                "timestamp":         datetime.now(timezone.utc).strftime(
                                         "%Y-%m-%d %H:%M:%S"
                                     )
            })
        except Exception as e:
            print(f"[POLICY] Socket.IO emit failed: {e}")

    print(f"[POLICY] {user_email} ({role}) | risk={risk_label} | "
          f"sensitivity={sensitivity_level} | → {action}")

    return {
        "action":      action,
        "reason":      reason,
        "risk_label":  risk_label,
        "risk_score":  risk_score,
        "role":        role
    }


# =============================================================================
# COMBINED SCAN + ENFORCE (single call from monitor.py / app.py)
# =============================================================================

def scan_and_enforce(file_path, user_email, action_type="FILE_ACCESS",
                     destination="-", socketio_instance=None):
    """
    One-stop function: scan file content then enforce policy.
    This is what monitor.py and app.py should call.

    Parameters
    ----------
    file_path         : str — absolute path to the file
    user_email        : str — employee who triggered the event
    action_type       : str — FILE_MODIFIED / FILE_CREATED / UPLOAD / USB_COPY
    destination       : str — where file is going (USB path, email, '-')
    socketio_instance : SocketIO — for real-time alerts

    Returns
    -------
    dict: {
      sensitivity_level, matched_patterns, matched_lines,
      action, reason, risk_label, role,
      file_size_kb, event_id
    }
    """
    from dlp.content_scanner import scan_file

    # Step 1: Scan file content
    scan_result = scan_file(
        file_path   = file_path,
        user_email  = user_email,
        action_type = action_type,
        destination = destination
    )

    # Step 2: Enforce policy on the saved event
    policy_result = enforce_policy(
        event_id          = scan_result.get("event_id"),
        user_email        = user_email,
        sensitivity_level = scan_result["sensitivity_level"],
        action_type       = action_type,
        socketio_instance = socketio_instance
    )

    # Merge results
    return {
        "sensitivity_level": scan_result["sensitivity_level"],
        "matched_patterns":  scan_result["matched_patterns"],
        "matched_lines":     scan_result["matched_lines"],
        "file_size_kb":      scan_result["file_size_kb"],
        "event_id":          scan_result.get("event_id"),
        "action":            policy_result["action"],
        "reason":            policy_result["reason"],
        "risk_label":        policy_result["risk_label"],
        "risk_score":        policy_result["risk_score"],
        "role":              policy_result["role"]
    }


# =============================================================================
# FETCH POLICIES FOR API
# =============================================================================

def get_all_policies():
    """Return all role policies for GET /api/dlp/policies"""
    docs = list(dlp_policies_col.find({}, {"_id": 0}))
    return docs


# =============================================================================
# STANDALONE TEST
# =============================================================================

if __name__ == "__main__":
    print("=" * 60)
    print("  XAI-ITD-DLP — DLP Policy Engine (standalone test)")
    print("=" * 60)

    # Seed policies first
    seed_dlp_policies()

    # Test all role + risk + sensitivity combinations
    print("\n[TEST] Decision matrix:\n")
    test_cases = [
        ("employee", "LOW",      "LOW"),
        ("employee", "LOW",      "MEDIUM"),
        ("employee", "HIGH",     "MEDIUM"),
        ("employee", "LOW",      "HIGH"),
        ("employee", "CRITICAL", "CRITICAL"),
        ("manager",  "LOW",      "MEDIUM"),
        ("manager",  "LOW",      "HIGH"),
        ("manager",  "HIGH",     "HIGH"),
        ("manager",  "LOW",      "CRITICAL"),
        ("admin",    "HIGH",     "CRITICAL"),
    ]

    for role, risk, sensitivity in test_cases:
        action, reason = evaluate_policy(role, risk, sensitivity)
        print(f"  role={role:8s} risk={risk:8s} sensitivity={sensitivity:8s} "
              f"→ {action:20s}  ({reason[:55]}...)"
              if len(reason) > 55 else
              f"  role={role:8s} risk={risk:8s} sensitivity={sensitivity:8s} "
              f"→ {action:20s}  ({reason})")

    print("\n[TEST] scan_and_enforce on a real file:")
    import tempfile
    test_content = "CONFIDENTIAL\nAadhaar: 9876 5432 1012\nSalary: 85000\n"
    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".txt", delete=False, encoding="utf-8"
    ) as f:
        f.write(test_content)
        test_path = f.name

    result = scan_and_enforce(
        file_path  = test_path,
        user_email = "rajasri@company.com",
        action_type= "FILE_ACCESS"
    )
    print(f"  sensitivity : {result['sensitivity_level']}")
    print(f"  action      : {result['action']}")
    print(f"  reason      : {result['reason']}")
    print(f"  risk_label  : {result['risk_label']}")
    print(f"  role        : {result['role']}")

    import os
    os.unlink(test_path)
    print("\n[TEST] Done.")