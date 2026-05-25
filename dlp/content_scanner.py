"""
Module 3 — Step 2
File : D:/rajasri/xai_itd_dlp/dlp/content_scanner.py

What this does:
  Layer 1 — Regex pattern matching for PII and secrets:
    - Aadhaar number  (12-digit, Indian format)
    - PAN card        (ABCDE1234F format)
    - Credit/debit card numbers (13-16 digits)
    - Passwords       (password=, pwd:, secret= patterns)
    - API keys        (Bearer, sk-, api_key, token patterns)

  Layer 2 — Keyword NLP classifier:
    - Scans document text for sensitive domain keywords
    - Categories: financial, HR/personal, medical, confidential, legal

  Output:
    - sensitivity_level : LOW / MEDIUM / HIGH / CRITICAL
    - matched_patterns  : list of what was found
    - matched_lines     : exact line numbers + snippets where found
    - file_size_kb      : file size in KB

  Saves to MongoDB collection: dlp_events
    {
      user_email        : str,
      filename          : str,
      file_path         : str   (full path),
      file_size_kb      : float,
      action_type       : str   (FILE_MODIFIED / FILE_CREATED / UPLOAD etc.),
      destination       : str   (USB drive, email recipient, or '-'),
      sensitivity_level : str,
      matched_patterns  : [str, ...],
      matched_lines     : [{line_no, snippet, pattern}, ...],
      action_taken      : str   (BLOCKED / WARNED / ALLOWED),
      resolved          : bool,
      resolved_by       : str or None,
      resolved_at       : datetime or None,
      timestamp         : datetime
    }

Called from:
  monitor.py  — SensitiveFileHandler.on_modified / on_created
  app.py      — upload_to_drive_route (file upload scanning)
  policy_engine.py — before enforcement decisions

Academic reference:
  Regex DLP: pattern matching for PII (Personally Identifiable Information)
    Aadhaar : \\b[2-9]{1}[0-9]{3}\\s[0-9]{4}\\s[0-9]{4}\\b
    PAN     : [A-Z]{5}[0-9]{4}[A-Z]{1}
    Credit  : \\b(?:\\d[ -]?){13,16}\\b
  Role-Based DLP: enforcement_level = f(role, risk_label, sensitivity_level)
"""

import os
import re
import sys
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from models.user import db

dlp_events_col = db["dlp_events"]

# =============================================================================
# SUPPORTED FILE EXTENSIONS FOR CONTENT READING
# =============================================================================

TEXT_EXTENSIONS  = {".txt", ".csv", ".py", ".json", ".xml", ".log", ".md",
                    ".html", ".htm", ".yaml", ".yml", ".ini", ".cfg", ".env"}
OFFICE_EXTENSIONS = {".docx", ".xlsx", ".xls", ".pptx"}
PDF_EXTENSION     = {".pdf"}

ALL_SCANNABLE = TEXT_EXTENSIONS | OFFICE_EXTENSIONS | PDF_EXTENSION


# =============================================================================
# LAYER 1 — REGEX PATTERNS
# =============================================================================

# Each pattern: (pattern_name, compiled_regex, severity_weight)
# severity_weight: 1=medium, 2=high, 3=critical
REGEX_PATTERNS = [
    (
        "Aadhaar Number",
        re.compile(r"\b[2-9]{1}[0-9]{3}\s[0-9]{4}\s[0-9]{4}\b"),
        2   # HIGH
    ),
    (
        "PAN Card",
        re.compile(r"\b[A-Z]{5}[0-9]{4}[A-Z]{1}\b"),
        2   # HIGH
    ),
    (
        "Credit/Debit Card",
        re.compile(r"\b(?:\d[ -]?){13,16}\b"),
        3   # CRITICAL
    ),
    (
        "Password/Secret",
        re.compile(
            r"(?i)(password|passwd|pwd|secret|pass)\s*[:=]\s*\S+",
        ),
        2   # HIGH
    ),
    (
        "API Key / Token",
        re.compile(
            r"(?i)(api[_\-]?key|apikey|access[_\-]?token|auth[_\-]?token|"
            r"bearer\s+[A-Za-z0-9\-._~+/]+=*|sk-[A-Za-z0-9]{20,}|"
            r"ghp_[A-Za-z0-9]{36}|AKIA[0-9A-Z]{16})"
        ),
        3   # CRITICAL
    ),
    (
        "Email Address (bulk)",
        re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Z|a-z]{2,}\b"),
        1   # MEDIUM — only critical if many found
    ),
    (
        "Phone Number",
        re.compile(r"(?<!\d)(\+91[\-\s]?)?[6-9]\d{9}(?!\d)"),
        1   # MEDIUM
    ),
    (
        "Bank Account Number",
        re.compile(r"\b\d{9,18}\b"),
        2   # HIGH — long digit strings
    ),
    (
        "IFSC Code",
        re.compile(r"\b[A-Z]{4}0[A-Z0-9]{6}\b"),
        1   # MEDIUM
    ),
    (
        "Private Key",
        re.compile(r"-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"),
        3   # CRITICAL
    ),
]


# =============================================================================
# LAYER 2 — KEYWORD NLP CATEGORIES
# =============================================================================

KEYWORD_CATEGORIES = {
    "Financial / Payroll": {
        "weight": 2,
        "keywords": [
            "salary", "payroll", "compensation", "bonus", "ctc",
            "bank account", "ifsc", "account number", "tax", "tds",
            "income", "invoice", "revenue", "profit", "loss",
            "balance sheet", "quarterly results", "earnings"
        ]
    },
    "HR / Personal Data": {
        "weight": 2,
        "keywords": [
            "employee id", "date of birth", "dob", "address",
            "aadhaar", "pan card", "passport", "visa", "nationality",
            "marital status", "emergency contact", "resignation",
            "termination", "performance review", "appraisal"
        ]
    },
    "Medical / Health": {
        "weight": 2,
        "keywords": [
            "diagnosis", "prescription", "medical", "health",
            "insurance", "hospital", "patient", "treatment",
            "medication", "clinical", "disease", "blood group"
        ]
    },
    "Confidential / Legal": {
        "weight": 3,
        "keywords": [
            "confidential", "classified", "top secret", "restricted",
            "internal only", "do not distribute", "proprietary",
            "nda", "non-disclosure", "lawsuit", "litigation",
            "merger", "acquisition", "takeover", "trade secret"
        ]
    },
    "IT / Infrastructure": {
        "weight": 2,
        "keywords": [
            "password", "credentials", "private key", "ssh",
            "database", "connection string", "server ip",
            "firewall", "vpn", "admin", "root access",
            "api endpoint", "webhook", "secret key"
        ]
    }
}


# =============================================================================
# FILE CONTENT READER
# =============================================================================

def read_file_content(file_path):
    """
    Read text content from file. Supports:
    - Plain text / CSV / code files
    - DOCX (via python-docx)
    - XLSX (via openpyxl)
    - PDF  (via pypdf)

    Returns list of (line_number, line_text) tuples.
    Returns empty list if file cannot be read.
    """
    ext = os.path.splitext(file_path)[1].lower()
    lines = []

    try:
        if ext in TEXT_EXTENSIONS:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                for i, line in enumerate(f, 1):
                    lines.append((i, line.rstrip()))

        elif ext == ".docx":
            try:
                from docx import Document
                doc = Document(file_path)
                for i, para in enumerate(doc.paragraphs, 1):
                    if para.text.strip():
                        lines.append((i, para.text))
            except ImportError:
                print("[SCANNER] python-docx not installed — skipping .docx content scan")

        elif ext in (".xlsx", ".xls"):
            try:
                import openpyxl
                wb = openpyxl.load_workbook(file_path, read_only=True, data_only=True)
                line_no = 1
                for sheet in wb.worksheets:
                    for row in sheet.iter_rows(values_only=True):
                        row_text = " ".join(str(c) for c in row if c is not None)
                        if row_text.strip():
                            lines.append((line_no, row_text))
                            line_no += 1
            except ImportError:
                print("[SCANNER] openpyxl not installed — skipping .xlsx content scan")
            except Exception as e:
                print(f"[SCANNER] xlsx read error: {e}")

        elif ext == ".pdf":
            try:
                from pypdf import PdfReader
                reader = PdfReader(file_path)
                line_no = 1
                for page in reader.pages:
                    text = page.extract_text() or ""
                    for line in text.split("\n"):
                        if line.strip():
                            lines.append((line_no, line.strip()))
                            line_no += 1
            except ImportError:
                print("[SCANNER] pypdf not installed — skipping .pdf content scan")
            except Exception as e:
                print(f"[SCANNER] pdf read error: {e}")

    except Exception as e:
        print(f"[SCANNER] Could not read {file_path}: {e}")

    return lines


# =============================================================================
# LAYER 1: REGEX SCAN
# =============================================================================

def run_regex_scan(lines):
    """
    Scan file lines for PII and secret patterns.

    Returns:
      matched_patterns : list of pattern names found
      matched_lines    : list of {line_no, snippet, pattern}
      max_weight       : highest severity weight found (0/1/2/3)
    """
    matched_patterns = []
    matched_lines    = []
    max_weight       = 0

    # Track email count separately — only flag if bulk
    email_count = 0

    for line_no, line_text in lines:
        for pattern_name, regex, weight in REGEX_PATTERNS:
            matches = regex.findall(line_text)
            if not matches:
                continue

            # Special rule: emails only flagged if 5+ found in file
            if pattern_name == "Email Address (bulk)":
                email_count += len(matches)
                continue

            # Deduplicate pattern names
            if pattern_name not in matched_patterns:
                matched_patterns.append(pattern_name)
                max_weight = max(max_weight, weight)

            # Store matched line with redacted snippet
            snippet = line_text[:120].strip()
            matched_lines.append({
                "line_no":  line_no,
                "snippet":  _redact(snippet, pattern_name),
                "pattern":  pattern_name,
                "count":    len(matches)
            })
            # Only keep first 20 matched lines to avoid huge documents
            if len(matched_lines) >= 20:
                break

        if len(matched_lines) >= 20:
            break

    # Apply email bulk rule
    if email_count >= 5:
        matched_patterns.append(f"Email Address (bulk: {email_count} found)")
        max_weight = max(max_weight, 1)

    return matched_patterns, matched_lines, max_weight


def _redact(text, pattern_name):
    """
    Partially redact sensitive values in snippet for safe display in dashboard.
    Shows enough to confirm the finding without exposing full sensitive data.
    """
    if pattern_name == "Aadhaar Number":
        return re.sub(
            r"\b([2-9]{1}[0-9]{3})\s([0-9]{4})\s([0-9]{4})\b",
            r"\1 XXXX \3", text
        )
    if pattern_name == "PAN Card":
        return re.sub(
            r"\b([A-Z]{5})([0-9]{4})([A-Z]{1})\b",
            r"\1XXXX\3", text
        )
    if pattern_name == "Credit/Debit Card":
        return re.sub(
            r"\b(?:\d[ -]?){13,16}\b",
            "XXXX-XXXX-XXXX-XXXX", text
        )
    if pattern_name in ("Password/Secret", "API Key / Token"):
        # Show key name, hide value
        return re.sub(r"([:=]\s*)\S+", r"\1[REDACTED]", text)
    return text[:80] + "..." if len(text) > 80 else text


# =============================================================================
# LAYER 2: KEYWORD NLP SCAN
# =============================================================================

def run_keyword_scan(lines):
    """
    Scan document text for sensitive keyword categories.

    Returns:
      keyword_hits : list of category names found
      kw_weight    : highest weight among matched categories
    """
    full_text    = " ".join(line.lower() for _, line in lines)
    keyword_hits = []
    kw_weight    = 0

    for category, config in KEYWORD_CATEGORIES.items():
        hits = [kw for kw in config["keywords"] if kw in full_text]
        if len(hits) >= 2:   # at least 2 keywords from same category
            keyword_hits.append(f"{category} ({len(hits)} keywords)")
            kw_weight = max(kw_weight, config["weight"])

    return keyword_hits, kw_weight


# =============================================================================
# SENSITIVITY LEVEL DECISION
# =============================================================================

def determine_sensitivity(regex_weight, kw_weight, matched_patterns):
    """
    Combine regex and keyword weights into final sensitivity level.

    Weight scale:
      0        → LOW
      1        → MEDIUM
      2        → HIGH
      3+       → CRITICAL
    Also escalate to CRITICAL if multiple HIGH patterns found together.
    """
    combined = max(regex_weight, kw_weight)

    # Escalate: if both Aadhaar AND credit card found → CRITICAL
    high_count = sum(
        1 for p in matched_patterns
        if any(x in p for x in ["Aadhaar", "PAN", "Credit", "API Key", "Private Key"])
    )
    if high_count >= 2:
        combined = 3

    if combined == 0:
        return "LOW"
    elif combined == 1:
        return "MEDIUM"
    elif combined == 2:
        return "HIGH"
    else:
        return "CRITICAL"


# =============================================================================
# MAIN SCAN FUNCTION
# =============================================================================

def scan_file(file_path, user_email, action_type="FILE_ACCESS",
              destination="-", action_taken=None):
    """
    Full content scan of a file.

    Parameters
    ----------
    file_path   : str  — absolute path to the file
    user_email  : str  — employee who triggered the event
    action_type : str  — FILE_MODIFIED / FILE_CREATED / UPLOAD / USB_COPY etc.
    destination : str  — where file is going (USB drive letter, email, '-')
    action_taken: str  — override action (BLOCKED/WARNED/ALLOWED)
                         if None, auto-determined from sensitivity level

    Returns
    -------
    dict with keys:
      sensitivity_level, matched_patterns, matched_lines,
      action_taken, file_size_kb, event_id (MongoDB _id as str)
    """
    filename = os.path.basename(file_path)
    ext      = os.path.splitext(file_path)[1].lower()

    # File size
    try:
        file_size_kb = round(os.path.getsize(file_path) / 1024, 2)
    except Exception:
        file_size_kb = 0.0

    # Default result for unscannable files
    if ext not in ALL_SCANNABLE:
        result = {
            "sensitivity_level": "LOW",
            "matched_patterns":  [],
            "matched_lines":     [],
            "action_taken":      "ALLOWED",
            "file_size_kb":      file_size_kb,
            "event_id":          None
        }
        return result

    # Read file content
    lines = read_file_content(file_path)
    if not lines:
        result = {
            "sensitivity_level": "LOW",
            "matched_patterns":  [],
            "matched_lines":     [],
            "action_taken":      "ALLOWED",
            "file_size_kb":      file_size_kb,
            "event_id":          None
        }
        return result

    # Layer 1: Regex
    regex_patterns, matched_lines, regex_weight = run_regex_scan(lines)

    # Layer 2: Keywords
    keyword_hits, kw_weight = run_keyword_scan(lines)

    # Combine all matched patterns
    all_patterns = regex_patterns + keyword_hits

    # Determine sensitivity
    sensitivity = determine_sensitivity(regex_weight, kw_weight, all_patterns)

    # Auto-determine action if not overridden
    if action_taken is None:
        if sensitivity == "CRITICAL":
            action_taken = "BLOCKED"
        elif sensitivity == "HIGH":
            action_taken = "BLOCKED"
        elif sensitivity == "MEDIUM":
            action_taken = "WARNED"
        else:
            action_taken = "ALLOWED"

    # Log to MongoDB
    event_id = _save_dlp_event(
        user_email       = user_email,
        filename         = filename,
        file_path        = file_path,
        file_size_kb     = file_size_kb,
        action_type      = action_type,
        destination      = destination,
        sensitivity_level= sensitivity,
        matched_patterns = all_patterns,
        matched_lines    = matched_lines,
        action_taken     = action_taken
    )

    print(f"[SCANNER] {filename} → {sensitivity} | {action_taken} "
          f"| patterns: {all_patterns[:3]}")

    return {
        "sensitivity_level": sensitivity,
        "matched_patterns":  all_patterns,
        "matched_lines":     matched_lines,
        "action_taken":      action_taken,
        "file_size_kb":      file_size_kb,
        "event_id":          str(event_id) if event_id else None
    }


# =============================================================================
# SAVE DLP EVENT TO MONGODB
# =============================================================================

def _save_dlp_event(user_email, filename, file_path, file_size_kb,
                    action_type, destination, sensitivity_level,
                    matched_patterns, matched_lines, action_taken):
    """
    Insert a new DLP event into dlp_events collection.
    Returns the inserted document _id.
    """
    doc = {
        "user_email":        user_email,
        "filename":          filename,
        "file_path":         file_path,
        "file_size_kb":      file_size_kb,
        "action_type":       action_type,
        "destination":       destination,
        "sensitivity_level": sensitivity_level,
        "matched_patterns":  matched_patterns,
        "matched_lines":     matched_lines,
        "action_taken":      action_taken,
        "resolved":          False,
        "resolved_by":       None,
        "resolved_at":       None,
        "timestamp":         datetime.now(timezone.utc)
    }
    result = dlp_events_col.insert_one(doc)
    return result.inserted_id


# =============================================================================
# RESOLVE A DLP EVENT (called by manager)
# =============================================================================

def resolve_dlp_event(event_id, resolved_by):
    """
    Mark a DLP event as resolved.
    Called by POST /api/dlp/events/<id>/resolve
    """
    from bson import ObjectId
    dlp_events_col.update_one(
        {"_id": ObjectId(event_id)},
        {"$set": {
            "resolved":    True,
            "resolved_by": resolved_by,
            "resolved_at": datetime.now(timezone.utc)
        }}
    )


# =============================================================================
# FETCH DLP EVENTS (for API routes)
# =============================================================================

def get_all_dlp_events(unresolved_only=True, limit=100):
    """
    Fetch DLP events for dashboard display.
    Returns list of dicts with _id as string.
    """
    query = {"resolved": False} if unresolved_only else {}
    docs  = list(dlp_events_col.find(
        query,
        sort=[("timestamp", -1)],
        limit=limit
    ))
    for d in docs:
        d["_id"] = str(d["_id"])
        if isinstance(d.get("timestamp"), datetime):
            d["timestamp"] = d["timestamp"].strftime("%Y-%m-%d %H:%M:%S")
        if isinstance(d.get("resolved_at"), datetime):
            d["resolved_at"] = d["resolved_at"].strftime("%Y-%m-%d %H:%M:%S")
    return docs


def get_dlp_events_for_user(email, limit=50):
    """Fetch DLP events for one employee."""
    docs = list(dlp_events_col.find(
        {"user_email": email},
        sort=[("timestamp", -1)],
        limit=limit
    ))
    for d in docs:
        d["_id"] = str(d["_id"])
        if isinstance(d.get("timestamp"), datetime):
            d["timestamp"] = d["timestamp"].strftime("%Y-%m-%d %H:%M:%S")
        if isinstance(d.get("resolved_at"), datetime):
            d["resolved_at"] = d["resolved_at"].strftime("%Y-%m-%d %H:%M:%S")
    return docs


# =============================================================================
# STANDALONE TEST
# =============================================================================

if __name__ == "__main__":
    import tempfile

    print("=" * 60)
    print("  XAI-ITD-DLP — DLP Content Scanner (standalone test)")
    print("=" * 60)

    # Create a test file with fake sensitive data
    test_content = """Employee Records - Q1 2026
CONFIDENTIAL - INTERNAL USE ONLY

Name        : Rajasri
Aadhaar     : 9876 5432 1012
PAN         : ABCDE1234F
Salary      : 85000
Bank Account: 123456789012
Password    : secret=MyP@ssw0rd123
API Key     : sk-abcdefghijklmnopqrstuvwxyz1234567890

This document contains payroll and personal data.
Do not distribute outside HR department.
"""
    # Write to temp file
    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".txt",
        delete=False, encoding="utf-8"
    ) as f:
        f.write(test_content)
        test_path = f.name

    print(f"\n[TEST] Scanning: {test_path}")
    result = scan_file(
        file_path   = test_path,
        user_email  = "rajasri@company.com",
        action_type = "FILE_ACCESS"
    )

    print(f"\n  Sensitivity   : {result['sensitivity_level']}")
    print(f"  Action taken  : {result['action_taken']}")
    print(f"  File size     : {result['file_size_kb']} KB")
    print(f"  Patterns found: {result['matched_patterns']}")
    print(f"\n  Matched lines:")
    for ml in result["matched_lines"]:
        print(f"    Line {ml['line_no']:3d} [{ml['pattern']}]: {ml['snippet']}")

    print(f"\n[TEST] Event saved to MongoDB with id: {result['event_id']}")

    # Cleanup temp file
    os.unlink(test_path)
    print("\n[TEST] Done.")