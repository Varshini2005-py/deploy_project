"""
Module 3 — Step 4
File : D:/rajasri/xai_itd_dlp/routes/xai_api.py

Flask Blueprint — XAI Explainability + DLP API routes

Routes:
  GET  /api/xai/explanations              — latest SHAP explanation per employee
  GET  /api/xai/explanations/<email>      — SHAP history for one employee
  GET  /api/dlp/events                    — all unresolved DLP events
  GET  /api/dlp/events/<email>            — DLP events for one employee
  POST /api/dlp/events/<id>/resolve       — manager resolves a DLP event
  GET  /api/dlp/policies                  — current role-based policies
  POST /api/xai/report/<email>            — generate + download PDF audit report

Auth:
  All routes require login (session or X-Auth-Token header)
  Manager-only routes: resolve, report
  Employee routes: own events only
"""

import os
import sys
from datetime import datetime, timezone
from functools import wraps

from flask import Blueprint, request, jsonify, session, send_file
from flask import redirect, url_for

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from models.user import get_user_by_email, db

xai_bp = Blueprint("xai_bp", __name__)

# ── Lazy imports (avoid circular at module load) ──────────────────────────────
def _get_active_tokens():
    from app import active_tokens
    return active_tokens


# =============================================================================
# AUTH HELPER — mirrors app.py login_required but self-contained in blueprint
# =============================================================================

def _get_auth(roles=None):
    """
    Extract authenticated user from request.
    Returns (email, role, name) or (None, None, None) if unauthorised.
    Checks X-Auth-Token header first, then Flask session.
    """
    active_tokens = _get_active_tokens()

    token = request.headers.get("X-Auth-Token") or request.args.get("token")
    if token and token in active_tokens:
        email = active_tokens[token]
        user  = get_user_by_email(email)
        if user:
            if roles and user["role"] not in roles:
                return None, None, None
            return email, user["role"], user.get("name", "")

    if "user_email" in session:
        email = session["user_email"]
        role  = session.get("role")
        name  = session.get("name", "")
        if roles and role not in roles:
            return None, None, None
        return email, role, name

    return None, None, None


def _auth_required(roles=None):
    """Decorator — attach to blueprint routes."""
    def decorator(f):
        @wraps(f)
        def wrapped(*args, **kwargs):
            email, role, name = _get_auth(roles=roles)
            if not email:
                return jsonify({"error": "Unauthorized"}), 403
            request.auth_email = email
            request.auth_role  = role
            request.auth_name  = name
            return f(*args, **kwargs)
        return wrapped
    return decorator


# =============================================================================
# XAI ROUTES
# =============================================================================

@xai_bp.route("/api/xai/explanations", methods=["GET"])
@_auth_required(roles=["manager", "admin"])
def xai_all_explanations():
    """
    GET /api/xai/explanations
    Returns latest SHAP explanation for every employee.
    Used by XAI Explainability tab in manager dashboard.
    """
    try:
        from ml.explain_shap import get_latest_explanations
        data = get_latest_explanations()
        return jsonify({"success": True, "explanations": data}), 200
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@xai_bp.route("/api/xai/explanations/<email>", methods=["GET"])
@_auth_required(roles=["manager", "admin"])
def xai_employee_explanation(email):
    """
    GET /api/xai/explanations/<email>
    Returns 30-day SHAP history for one employee.
    """
    try:
        from ml.explain_shap import get_explanation_history
        data = get_explanation_history(email.lower())
        return jsonify({"success": True, "email": email, "history": data}), 200
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


# =============================================================================
# DLP ROUTES
# =============================================================================

@xai_bp.route("/api/dlp/events", methods=["GET"])
@_auth_required(roles=["manager", "admin"])
def dlp_all_events():
    """
    GET /api/dlp/events
    Returns unresolved DLP events by default.
    Pass ?all=true to include resolved events.
    Pass ?email=x to filter by employee.
    """
    try:
        from dlp.content_scanner import get_all_dlp_events, get_dlp_events_for_user

        email_filter  = request.args.get("email")
        include_all   = request.args.get("all", "false").lower() == "true"

        if email_filter:
            data = get_dlp_events_for_user(email_filter.lower())
        else:
            data = get_all_dlp_events(unresolved_only=not include_all)

        return jsonify({"success": True, "events": data, "count": len(data)}), 200
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@xai_bp.route("/api/dlp/events/<email>", methods=["GET"])
@_auth_required(roles=["manager", "admin", "employee"])
def dlp_employee_events(email):
    """
    GET /api/dlp/events/<email>
    Returns DLP events for one employee.
    Employees can only see their own events.
    Managers can see any employee's events.
    """
    try:
        from dlp.content_scanner import get_dlp_events_for_user

        # Employees can only access their own events
        if request.auth_role == "employee":
            if request.auth_email.lower() != email.lower():
                return jsonify({"error": "Unauthorized — can only view own events"}), 403

        data = get_dlp_events_for_user(email.lower())
        return jsonify({"success": True, "email": email, "events": data}), 200
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@xai_bp.route("/api/dlp/events/<event_id>/resolve", methods=["POST"])
@_auth_required(roles=["manager", "admin"])
def dlp_resolve_event(event_id):
    """
    POST /api/dlp/events/<id>/resolve
    Manager marks a DLP event as resolved.
    """
    try:
        from dlp.content_scanner import resolve_dlp_event
        resolve_dlp_event(event_id, resolved_by=request.auth_email)
        return jsonify({
            "success":     True,
            "event_id":    event_id,
            "resolved_by": request.auth_email,
            "resolved_at": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
        }), 200
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@xai_bp.route("/api/dlp/policies", methods=["GET"])
@_auth_required(roles=["manager", "admin"])
def dlp_policies():
    """
    GET /api/dlp/policies
    Returns current role-based DLP policy rules.
    """
    try:
        from dlp.policy_engine import get_all_policies
        data = get_all_policies()
        return jsonify({"success": True, "policies": data}), 200
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


# =============================================================================
# PDF REPORT ROUTE
# =============================================================================

@xai_bp.route("/api/xai/report/<email>", methods=["POST"])
@_auth_required(roles=["manager", "admin"])
def xai_generate_report(email):
    """
    POST /api/xai/report/<email>
    Generates and returns a PDF audit report for one employee.
    Contains: risk score, SHAP chart, 30-day trend, DLP violations,
              recommended actions.
    """
    try:
        pdf_path = _generate_pdf_report(email.lower())
        if not pdf_path:
            return jsonify({"success": False, "error": "Could not generate report"}), 500

        filename = f"audit_report_{email.split('@')[0]}_{datetime.now().strftime('%Y%m%d')}.pdf"
        return send_file(
            pdf_path,
            mimetype    = "application/pdf",
            as_attachment = True,
            download_name = filename
        )
    except Exception as e:
        import traceback; traceback.print_exc()
        return jsonify({"success": False, "error": str(e)}), 500


# =============================================================================
# PDF REPORT GENERATOR
# =============================================================================

def _generate_pdf_report(email):
    """
    Build a PDF audit report for one employee using reportlab.

    Report sections:
      1. Header       — employee name, email, generated date
      2. Risk Summary — current risk score, label, last scored date
      3. SHAP Chart   — horizontal bar chart of top 10 features
      4. 30-day Trend — risk score over time (line chart)
      5. DLP Events   — table of violations in last 30 days
      6. Recommendations — based on risk label

    Returns path to generated PDF file, or None on failure.
    """
    try:
        from reportlab.lib.pagesizes import A4
        from reportlab.lib import colors
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib.units import cm
        from reportlab.platypus import (
            SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
            HRFlowable
        )
        from reportlab.graphics.shapes import Drawing, Rect, String, Line
        from reportlab.graphics.charts.lineplots import LinePlot
        from reportlab.graphics import renderPDF
    except ImportError:
        print("[REPORT] reportlab not installed. Run: pip install reportlab")
        return None

    # ── Fetch data ────────────────────────────────────────────────────────────
    user = get_user_by_email(email)
    if not user:
        print(f"[REPORT] User not found: {email}")
        return None

    name = user.get("name", email)
    role = user.get("role", "employee")

    # Latest SHAP explanation
    from ml.explain_shap import get_latest_explanations, get_explanation_history
    all_exp  = get_latest_explanations()
    emp_exp  = next((e for e in all_exp if e["user_email"] == email), None)
    history  = get_explanation_history(email)   # 30-day history

    # Latest threat score
    threat_col = db["threat_scores"]
    threat_doc = threat_col.find_one(
        {"user_email": email}, sort=[("scored_at", -1)]
    )
    risk_score = float(threat_doc.get("risk_score", 0)) if threat_doc else 0.0
    risk_label = threat_doc.get("risk_label", "UNKNOWN") if threat_doc else "UNKNOWN"
    scored_at  = threat_doc.get("scored_at", datetime.now()) if threat_doc else datetime.now()

    # 30-day trend data from SHAP history
    trend_data = []
    for h in reversed(history):
        trend_data.append((h["day"], float(h.get("risk_score", 0))))

    # DLP events
    from dlp.content_scanner import get_dlp_events_for_user
    dlp_events = get_dlp_events_for_user(email, limit=30)

    # ── Output path ───────────────────────────────────────────────────────────
    reports_dir = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        "reports"
    )
    os.makedirs(reports_dir, exist_ok=True)
    pdf_path = os.path.join(
        reports_dir,
        f"report_{email.split('@')[0]}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
    )

    # ── Colors ────────────────────────────────────────────────────────────────
    DARK_BG    = colors.HexColor("#0a0f1e")
    CYAN       = colors.HexColor("#4fc3f7")
    GREEN      = colors.HexColor("#43e8a0")
    RED        = colors.HexColor("#e53935")
    YELLOW     = colors.HexColor("#ffd740")
    ORANGE     = colors.HexColor("#ff9800")
    LIGHT_GRAY = colors.HexColor("#c0cfe0")
    MID_GRAY   = colors.HexColor("#7a9bb5")
    WHITE      = colors.white

    RISK_COLORS = {
        "LOW":      GREEN,
        "MEDIUM":   YELLOW,
        "HIGH":     ORANGE,
        "CRITICAL": RED,
        "UNKNOWN":  MID_GRAY
    }
    risk_color = RISK_COLORS.get(risk_label, MID_GRAY)

    # ── Styles ────────────────────────────────────────────────────────────────
    styles = getSampleStyleSheet()

    def _style(name, **kwargs):
        return ParagraphStyle(name, **kwargs)

    style_title   = _style("title",   fontSize=22, textColor=CYAN,
                            fontName="Helvetica-Bold", spaceAfter=4)
    style_sub     = _style("sub",     fontSize=11, textColor=MID_GRAY,
                            fontName="Helvetica", spaceAfter=2)
    style_section = _style("section", fontSize=13, textColor=CYAN,
                            fontName="Helvetica-Bold", spaceBefore=14, spaceAfter=6)
    style_body    = _style("body",    fontSize=10, textColor=LIGHT_GRAY,
                            fontName="Helvetica", spaceAfter=4)
    style_label   = _style("label",   fontSize=9,  textColor=MID_GRAY,
                            fontName="Helvetica")
    style_risk    = _style("risk",    fontSize=28, textColor=risk_color,
                            fontName="Helvetica-Bold")
    style_rec     = _style("rec",     fontSize=10, textColor=LIGHT_GRAY,
                            fontName="Helvetica", leftIndent=12, spaceAfter=3)

    # ── Build document ────────────────────────────────────────────────────────
    doc   = SimpleDocTemplate(
        pdf_path,
        pagesize     = A4,
        leftMargin   = 2*cm, rightMargin  = 2*cm,
        topMargin    = 2*cm, bottomMargin = 2*cm
    )
    story = []

    # ── Background canvas callback ────────────────────────────────────────────
    def _dark_bg(canvas, doc):
        canvas.saveState()
        canvas.setFillColor(DARK_BG)
        canvas.rect(0, 0, A4[0], A4[1], fill=1, stroke=0)
        # Header accent line
        canvas.setStrokeColor(CYAN)
        canvas.setLineWidth(2)
        canvas.line(2*cm, A4[1]-1.5*cm, A4[0]-2*cm, A4[1]-1.5*cm)
        # Footer
        canvas.setFont("Helvetica", 8)
        canvas.setFillColor(MID_GRAY)
        canvas.drawString(2*cm, 1*cm,
            f"XAI-ITD-DLP Framework — Confidential Audit Report — "
            f"Generated {datetime.now().strftime('%Y-%m-%d %H:%M')}")
        canvas.drawRightString(A4[0]-2*cm, 1*cm, f"Page {doc.page}")
        canvas.restoreState()

    # ── Section 1: Header ─────────────────────────────────────────────────────
    story.append(Spacer(1, 0.3*cm))
    story.append(Paragraph("XAI-ITD-DLP FRAMEWORK", style_title))
    story.append(Paragraph("Employee Security Audit Report", style_sub))
    story.append(HRFlowable(width="100%", thickness=0.5,
                             color=CYAN, spaceAfter=12))

    # Employee info table
    info_data = [
        ["Employee",   name,  "Role",     role.capitalize()],
        ["Email",      email, "Report Date",
         datetime.now().strftime("%Y-%m-%d %H:%M")],
    ]
    info_table = Table(info_data, colWidths=[3*cm, 7*cm, 3*cm, 4*cm])
    info_table.setStyle(TableStyle([
        ("FONTNAME",    (0,0), (-1,-1), "Helvetica"),
        ("FONTSIZE",    (0,0), (-1,-1), 9),
        ("TEXTCOLOR",   (0,0), (0,-1), MID_GRAY),
        ("TEXTCOLOR",   (2,0), (2,-1), MID_GRAY),
        ("TEXTCOLOR",   (1,0), (1,-1), LIGHT_GRAY),
        ("TEXTCOLOR",   (3,0), (3,-1), LIGHT_GRAY),
        ("BACKGROUND",  (0,0), (-1,-1), colors.HexColor("#0d1526")),
        ("ROWBACKGROUNDS", (0,0), (-1,-1),
         [colors.HexColor("#0d1526"), colors.HexColor("#111d30")]),
        ("GRID",        (0,0), (-1,-1), 0.25, colors.HexColor("#1e3a5f")),
        ("PADDING",     (0,0), (-1,-1), 6),
    ]))
    story.append(info_table)
    story.append(Spacer(1, 0.4*cm))

    # ── Section 2: Risk Summary ───────────────────────────────────────────────
    story.append(Paragraph("CURRENT RISK SUMMARY", style_section))

    score_display = f"{risk_score:.1f} / 100"
    summary_data = [
        ["Risk Score", "Risk Label", "Last Scored", "AI Models Used"],
        [
            score_display,
            risk_label,
            scored_at.strftime("%Y-%m-%d") if isinstance(scored_at, datetime) else str(scored_at),
            "IF + DBLOF + BiLSTM + GCN + Z-Score + Rules"
        ]
    ]
    summary_table = Table(summary_data, colWidths=[4*cm, 3.5*cm, 4*cm, 6*cm])
    summary_table.setStyle(TableStyle([
        ("FONTNAME",    (0,0), (-1,0),  "Helvetica-Bold"),
        ("FONTNAME",    (0,1), (-1,-1), "Helvetica"),
        ("FONTSIZE",    (0,0), (-1,-1), 9),
        ("TEXTCOLOR",   (0,0), (-1,0),  MID_GRAY),
        ("TEXTCOLOR",   (0,1), (0,1),   risk_color),
        ("TEXTCOLOR",   (1,1), (1,1),   risk_color),
        ("TEXTCOLOR",   (2,1), (-1,1),  LIGHT_GRAY),
        ("FONTSIZE",    (0,1), (0,1),   14),
        ("FONTNAME",    (0,1), (0,1),   "Helvetica-Bold"),
        ("BACKGROUND",  (0,0), (-1,0),  colors.HexColor("#0d1526")),
        ("BACKGROUND",  (0,1), (-1,1),  colors.HexColor("#111d30")),
        ("GRID",        (0,0), (-1,-1), 0.25, colors.HexColor("#1e3a5f")),
        ("PADDING",     (0,0), (-1,-1), 8),
    ]))
    story.append(summary_table)
    story.append(Spacer(1, 0.4*cm))

    # ── Section 3: SHAP Feature Attribution ──────────────────────────────────
    story.append(Paragraph("XAI FEATURE ATTRIBUTION (SHAP)", style_section))
    story.append(Paragraph(
        "Red bars indicate features increasing risk. "
        "Green bars indicate features reducing risk. "
        "Values show Shapley attribution weight.",
        style_body
    ))

    if emp_exp and emp_exp.get("shap_values"):
        top_features = emp_exp["shap_values"][:10]
        shap_data    = [["Feature", "SHAP Value", "Actual Value", "Direction"]]
        for feat in top_features:
            direction = "▲ INCREASES RISK" if feat["shap_value"] > 0 else "▼ REDUCES RISK"
            shap_data.append([
                feat["feature"],
                f"{feat['shap_value']:+.4f}",
                str(feat["feature_value"]),
                direction
            ])

        shap_table = Table(shap_data, colWidths=[6*cm, 3*cm, 3*cm, 5.5*cm])
        shap_style = [
            ("FONTNAME",   (0,0),  (-1,0),  "Helvetica-Bold"),
            ("FONTNAME",   (0,1),  (-1,-1), "Helvetica"),
            ("FONTSIZE",   (0,0),  (-1,-1), 8.5),
            ("TEXTCOLOR",  (0,0),  (-1,0),  MID_GRAY),
            ("BACKGROUND", (0,0),  (-1,0),  colors.HexColor("#0d1526")),
            ("GRID",       (0,0),  (-1,-1), 0.25, colors.HexColor("#1e3a5f")),
            ("PADDING",    (0,0),  (-1,-1), 6),
            ("ROWBACKGROUNDS", (0,1), (-1,-1),
             [colors.HexColor("#0d1526"), colors.HexColor("#111d30")]),
        ]
        # Color SHAP value column by direction
        for i, feat in enumerate(top_features, start=1):
            c = RED if feat["shap_value"] > 0 else GREEN
            shap_style.append(("TEXTCOLOR", (1,i), (1,i), c))
            shap_style.append(("TEXTCOLOR", (3,i), (3,i), c))
            shap_style.append(("TEXTCOLOR", (0,i), (0,i), LIGHT_GRAY))
            shap_style.append(("TEXTCOLOR", (2,i), (2,i), LIGHT_GRAY))

        shap_table.setStyle(TableStyle(shap_style))
        story.append(shap_table)
    else:
        story.append(Paragraph(
            "No SHAP data available for this employee.", style_body
        ))

    story.append(Spacer(1, 0.4*cm))

    # ── Section 4: 30-day Risk Score Trend ───────────────────────────────────
    story.append(Paragraph("30-DAY RISK SCORE TREND", style_section))

    if len(trend_data) >= 2:
        trend_table_data = [["Date", "Risk Score", "Label"]]
        for h in history[:10]:
            trend_table_data.append([
                h["day"],
                f"{float(h.get('risk_score', 0)):.1f}",
                h.get("risk_label", "UNKNOWN")
            ])

        trend_table = Table(trend_table_data, colWidths=[5*cm, 4*cm, 4*cm])
        trend_style = [
            ("FONTNAME",   (0,0),  (-1,0),  "Helvetica-Bold"),
            ("FONTNAME",   (0,1),  (-1,-1), "Helvetica"),
            ("FONTSIZE",   (0,0),  (-1,-1), 9),
            ("TEXTCOLOR",  (0,0),  (-1,0),  MID_GRAY),
            ("BACKGROUND", (0,0),  (-1,0),  colors.HexColor("#0d1526")),
            ("GRID",       (0,0),  (-1,-1), 0.25, colors.HexColor("#1e3a5f")),
            ("PADDING",    (0,0),  (-1,-1), 6),
            ("ROWBACKGROUNDS", (0,1), (-1,-1),
             [colors.HexColor("#0d1526"), colors.HexColor("#111d30")]),
        ]
        for i, h in enumerate(history[:10], start=1):
            lbl = h.get("risk_label", "UNKNOWN")
            c   = RISK_COLORS.get(lbl, MID_GRAY)
            trend_style.append(("TEXTCOLOR", (1,i), (2,i), c))
        trend_table.setStyle(TableStyle(trend_style))
        story.append(trend_table)
    else:
        story.append(Paragraph(
            "Insufficient history data for trend analysis (minimum 2 days required).",
            style_body
        ))

    story.append(Spacer(1, 0.4*cm))

    # ── Section 5: DLP Violations ─────────────────────────────────────────────
    story.append(Paragraph("DLP VIOLATIONS — LAST 30 DAYS", style_section))

    if dlp_events:
        dlp_data = [["Filename", "Sensitivity", "Action", "Patterns", "Date"]]
        for ev in dlp_events[:15]:
            patterns_str = ", ".join(ev.get("matched_patterns", [])[:2])
            if len(ev.get("matched_patterns", [])) > 2:
                patterns_str += f" +{len(ev['matched_patterns'])-2} more"
            dlp_data.append([
                ev.get("filename", "-")[:30],
                ev.get("sensitivity_level", "-"),
                ev.get("action_taken", "-"),
                patterns_str[:40] or "keywords only",
                ev.get("timestamp", "-")[:10]
            ])

        dlp_table = Table(dlp_data,
                          colWidths=[4.5*cm, 2.5*cm, 2.5*cm, 5*cm, 3*cm])
        dlp_style = [
            ("FONTNAME",   (0,0),  (-1,0),  "Helvetica-Bold"),
            ("FONTNAME",   (0,1),  (-1,-1), "Helvetica"),
            ("FONTSIZE",   (0,0),  (-1,-1), 8),
            ("TEXTCOLOR",  (0,0),  (-1,0),  MID_GRAY),
            ("BACKGROUND", (0,0),  (-1,0),  colors.HexColor("#0d1526")),
            ("GRID",       (0,0),  (-1,-1), 0.25, colors.HexColor("#1e3a5f")),
            ("PADDING",    (0,0),  (-1,-1), 5),
            ("ROWBACKGROUNDS", (0,1), (-1,-1),
             [colors.HexColor("#0d1526"), colors.HexColor("#111d30")]),
        ]
        SENS_COLORS = {
            "CRITICAL": RED, "HIGH": ORANGE,
            "MEDIUM": YELLOW, "LOW": GREEN
        }
        ACT_COLORS = {"BLOCKED": RED, "WARNED": ORANGE, "ALLOWED": GREEN}
        for i, ev in enumerate(dlp_events[:15], start=1):
            sc = SENS_COLORS.get(ev.get("sensitivity_level", ""), LIGHT_GRAY)
            ac = ACT_COLORS.get(ev.get("action_taken", ""), LIGHT_GRAY)
            dlp_style.append(("TEXTCOLOR", (0,i), (0,i), LIGHT_GRAY))
            dlp_style.append(("TEXTCOLOR", (1,i), (1,i), sc))
            dlp_style.append(("TEXTCOLOR", (2,i), (2,i), ac))
            dlp_style.append(("TEXTCOLOR", (3,i), (4,i), LIGHT_GRAY))
        dlp_table.setStyle(TableStyle(dlp_style))
        story.append(dlp_table)
    else:
        story.append(Paragraph(
            "No DLP violations recorded in the last 30 days.", style_body
        ))

    story.append(Spacer(1, 0.4*cm))

    # ── Section 6: Recommendations ────────────────────────────────────────────
    story.append(Paragraph("RECOMMENDED ACTIONS", style_section))
    story.append(HRFlowable(width="100%", thickness=0.5,
                             color=colors.HexColor("#1e3a5f"), spaceAfter=8))

    recommendations = _get_recommendations(risk_label, dlp_events, emp_exp)
    for rec in recommendations:
        story.append(Paragraph(f"• {rec}", style_rec))

    # ── Build PDF ─────────────────────────────────────────────────────────────
    doc.build(story, onFirstPage=_dark_bg, onLaterPages=_dark_bg)
    print(f"[REPORT] PDF generated: {pdf_path}")
    return pdf_path


def _get_recommendations(risk_label, dlp_events, emp_exp):
    """Generate context-aware recommendations based on risk and violations."""
    recs = []

    if risk_label == "CRITICAL":
        recs.append("IMMEDIATE ACTION: Suspend file access privileges pending review.")
        recs.append("Escalate to HR and IT Security for urgent investigation.")
        recs.append("Review all activity logs from the past 30 days.")
    elif risk_label == "HIGH":
        recs.append("Schedule a security review meeting with the employee.")
        recs.append("Restrict USB access and external file transfers temporarily.")
        recs.append("Increase monitoring frequency — flag for weekly review.")
    elif risk_label == "MEDIUM":
        recs.append("Send a security policy reminder to the employee.")
        recs.append("Monitor file access patterns over the next 2 weeks.")
    else:
        recs.append("No immediate action required — continue standard monitoring.")

    # DLP-specific recommendations
    if dlp_events:
        sensitivity_levels = [e.get("sensitivity_level") for e in dlp_events]
        if "CRITICAL" in sensitivity_levels:
            recs.append("CRITICAL files were accessed — verify business justification.")
        if len(dlp_events) > 5:
            recs.append(f"{len(dlp_events)} DLP events recorded — review access patterns.")

    # SHAP-specific recommendations
    if emp_exp and emp_exp.get("shap_values"):
        top = emp_exp["shap_values"][0]
        if top["shap_value"] > 0:
            feat = top["feature"].replace("_", " ")
            recs.append(
                f"Top risk driver: '{feat}' — investigate this behaviour specifically."
            )

    if not recs:
        recs.append("Employee profile is within normal parameters.")

    return recs


# =============================================================================
# SEED POLICIES ON BLUEPRINT REGISTRATION
# =============================================================================

def init_xai_bp():
    """
    Call this after registering the blueprint in app.py
    to seed DLP policies into MongoDB on startup.
    """
    try:
        from dlp.policy_engine import seed_dlp_policies
        seed_dlp_policies()
    except Exception as e:
        print(f"[XAI_BP] Policy seed failed: {e}")