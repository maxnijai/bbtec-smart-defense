import os
import json
import hashlib
from datetime import datetime, timedelta
from functools import wraps
from flask import Flask, request, jsonify, session, send_from_directory
import gspread
from google.oauth2.service_account import Credentials

app = Flask(__name__, static_folder="static", template_folder="templates")
app.secret_key = os.environ.get("SECRET_KEY", "bbtec-smart-defense-2026")

# ─────────────────────────────────────────────
# Google Sheets Setup (lazy init — no crash on boot)
# ─────────────────────────────────────────────
SPREADSHEET_ID = os.environ.get("SPREADSHEET_ID", "1RBWr-lKva_XOqmcKwEE-E7hqIodbWWK1XHzuV8QJ-7Q")
SCOPES = ["https://www.googleapis.com/auth/spreadsheets"]
_gc_client = None

def get_gc():
    global _gc_client
    if _gc_client is not None:
        return _gc_client
    creds_json = os.environ.get("GOOGLE_CREDENTIALS_JSON")
    if creds_json:
        info = json.loads(creds_json)
        creds = Credentials.from_service_account_info(info, scopes=SCOPES)
    elif os.path.exists("credentials.json"):
        creds = Credentials.from_service_account_file("credentials.json", scopes=SCOPES)
    else:
        raise RuntimeError("ไม่พบ GOOGLE_CREDENTIALS_JSON หรือ credentials.json")
    _gc_client = gspread.authorize(creds)
    return _gc_client

def get_sheet(sheet_name):
    gc = get_gc()
    return gc.open_by_key(SPREADSHEET_ID).worksheet(sheet_name)

# ─────────────────────────────────────────────
# Column constants — NOR_Penalty_Ticket
# ─────────────────────────────────────────────
# Existing ticket columns (read-only from system)
COL_TICKETID            = "TICKETID"
COL_STATUS              = "STATUS"
COL_SEVERITY            = "TRUESEVERITY_DESC"
COL_URGENCY             = "TRUEURGENCY"
COL_CREATIONDATE        = "CREATIONDATE"
COL_TARGETFINISH        = "TARGETFINISH"
COL_RESTORATIONDATE     = "RESTORATIONDATE"
COL_SUBJECT             = "SUBJECT"
COL_CATEGORIES          = "CATEGORIES"
COL_OWNERGROUP          = "TRUEOWNERGROUP"
COL_REGION              = "TrackB_Region"
COL_DOWNTIME            = "DOWN_TIME_MINUTE"
COL_TICKET_SLA          = "TICKET_SLA"
COL_PROBLEM             = "PROBLEM"
COL_SUB_CAUSE           = "SUB_CAUSE"
COL_EXTERNALSYSTEM      = "EXTERNALSYSTEM"
COL_EXTERNALSYSTEM_TID  = "EXTERNALSYSTEM_TICKETID"
COL_TICKETING_SYSTEM    = "Ticketing_System"
COL_ACTSTART            = "ACTSTART"
COL_ACT_RESTORATION     = "ACT_RESTORATIONDATE"
COL_ACTIVITY_HR         = "ACTIVITY_DURATION_HR"
COL_ACTIVITY_MIN        = "ACTIVITY_DURATION_MIN"
COL_ACTIVITY_SLA        = "ACTIVITY_SLA"
COL_CONTRACT_GROUP      = "CONTRACTTICKET_TRACKB"
COL_PENALTY_FLAG        = "PENALTY_FLAG"
COL_PENALTYHOUR         = "PENALTYHOUR_TRACKB"
COL_PENALTYRATE         = "PENALTYRATE_TRACKB"
COL_PENALTYBAHT         = "PENALTYBAHT_TRACKB"

# Step 1 — Engineer fills
COL_OWNER               = "Owner"
COL_GROUP_PROBLEM       = "Group problem"
COL_SUB_PROBLEM         = "Sub Problem"
COL_ACCIDENT            = "Accident"
COL_OVERDUE_DETAIL      = "Overdue Detail แนบLINK รูป"   # Column AG — combined field
COL_LINK_PHOTO          = "Overdue Detail แนบLINK รูป"   # same column, kept for compat
COL_LINK_EVIDENCE       = "แนบ LINK ชี้แจง"

# Step 2 — FSO fills
COL_FSO_DECISION        = "FSO พิจารณา (ปรับ/ไม่ปรับ)"
COL_FSO_APPROVE         = "FSO approve (ลงชื่อ FSO)"
COL_FSO_DATE            = "วันที่ FSO อนุมัติ"
COL_FSO_REMARK          = "Remark FSO"

# Step 3 — Reviewer / Defend
COL_REVIEWER            = "Reviewer"
COL_DEFEND              = "BBTEC Defend\nไม่สมควรปรับ"  # actual Sheet column has newline
COL_CHECK               = "Check"

# ── New columns added by this system ──
COL_STEP                = "STEP"
COL_DEFEND_COUNT        = "DEFEND_COUNT"
COL_LOCKED              = "LOCKED"
COL_LAST_UPDATED        = "LAST_UPDATED"
COL_UPDATED_BY          = "UPDATED_BY"
COL_FINAL_RESULT        = "FINAL_RESULT"

NEW_COLUMNS = [COL_STEP, COL_DEFEND_COUNT, COL_LOCKED, COL_LAST_UPDATED, COL_UPDATED_BY, COL_FINAL_RESULT]

# ─────────────────────────────────────────────
# Role definitions
# ─────────────────────────────────────────────
ROLE_ENGINEER   = "Engineer"
ROLE_SITE_SUP   = "Site Sup"
ROLE_FSO        = "FSO"
ROLE_FSO_MGR    = "FSO Manager"
ROLE_REGIONAL   = "Regional"
ROLE_MANAGER    = "Manager"

# Accept all variants used in USER_ACCOUNT sheet
STEP1_ROLES = [ROLE_ENGINEER, ROLE_SITE_SUP, "ENGINEER_ZONE", "engineer", "site_sup", "Engineer Zone"]
STEP2_ROLES = [ROLE_FSO, ROLE_FSO_MGR, "FSO_ZONE", "FSO Zone", "fso", "FSO Manager Zone"]
STEP5_ROLES = [ROLE_MANAGER, "MANAGER", "Manager NOR1", "Manager NOR2", "BBTEC Manager"]
VIEW_ONLY_ROLES = [ROLE_REGIONAL, "REGIONAL", "Regional"]

def is_step1_role(role):
    r = str(role).strip().upper()
    return r in [x.upper() for x in STEP1_ROLES]

def is_step2_role(role):
    r = str(role).strip().upper()
    return r in [x.upper() for x in STEP2_ROLES]

def is_step5_role(role):
    r = str(role).strip().upper()
    return r in [x.upper() for x in STEP5_ROLES]

# ─────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────
def hash_password(pw):
    return hashlib.sha256(pw.encode()).hexdigest()

def now_str():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def rows_to_dicts(sheet):
    """Read sheet handling duplicate column names by renaming them."""
    all_values = sheet.get_all_values()
    if not all_values:
        return []
    raw_headers = all_values[0]
    # Deduplicate headers: TICKETID, TICKETID_2, TICKETID_3 ...
    seen = {}
    headers = []
    for h in raw_headers:
        h = str(h).strip()
        if h in seen:
            seen[h] += 1
            headers.append(f"{h}_{seen[h]}")
        else:
            seen[h] = 1
            headers.append(h)
    records = []
    for row in all_values[1:]:
        # Pad short rows
        padded = row + [""] * (len(headers) - len(row))
        records.append(dict(zip(headers, padded)))
    return records

def find_row_index(sheet, ticketid):
    """Return 1-based row index for a given TICKETID (header is row 1).
    Uses the FIRST column named TICKETID to avoid duplicate-header issues."""
    headers = sheet.row_values(1)
    tid_col = 1  # fallback to col A
    for i, h in enumerate(headers):
        if str(h).strip() == COL_TICKETID:
            tid_col = i + 1
            break
    col_values = sheet.col_values(tid_col)
    for i, val in enumerate(col_values):
        if str(val).strip() == str(ticketid).strip() and i > 0:
            return i + 1
    return None

def get_col_index(headers, col_name):
    """Return 1-based column index from header list."""
    if col_name in headers:
        return headers.index(col_name) + 1
    return None

def ensure_new_columns(sheet):
    """Add system columns if they don't exist yet.
    Uses batch update to avoid exceeding grid limits."""
    headers = sheet.row_values(1)
    missing = [c for c in NEW_COLUMNS if c not in headers]
    if not missing:
        return headers

    # How many columns does the sheet currently have?
    # gspread sheet.col_count gives the actual grid width
    try:
        current_cols = sheet.col_count
    except Exception:
        current_cols = len(headers)

    needed = len(headers) + len(missing)
    if needed > current_cols:
        # Resize the sheet to fit — adds blank columns
        sheet.resize(cols=needed)

    # Now write the missing headers
    for col_name in missing:
        next_col = len(headers) + 1
        sheet.update_cell(1, next_col, col_name)
        headers.append(col_name)

    return headers

def update_ticket_fields(sheet, headers, row_idx, fields: dict):
    """Update specific fields for a ticket row."""
    for col_name, value in fields.items():
        col_idx = get_col_index(headers, col_name)
        if col_idx:
            sheet.update_cell(row_idx, col_idx, value)

# ─────────────────────────────────────────────
# Auth
# ─────────────────────────────────────────────
def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if "user" not in session:
            return jsonify({"error": "Unauthorized"}), 401
        return f(*args, **kwargs)
    return decorated

def require_role(*roles):
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            user_role = str(session.get("role","")).strip().upper()
            allowed = [str(r).strip().upper() for r in roles]
            if user_role not in allowed:
                return jsonify({"error": f"Forbidden: role '{session.get('role')}' not in {roles}"}), 403
            return f(*args, **kwargs)
        return decorated
    return decorator

# ─────────────────────────────────────────────
# Routes — Auth
# ─────────────────────────────────────────────
@app.route("/api/login", methods=["POST"])
def login():
    data = request.json or {}
    username = data.get("username", "").strip()
    password = data.get("password", "").strip()
    if not username or not password:
        return jsonify({"error": "กรุณากรอก Username และ Password"}), 400
    try:
        sheet = get_sheet("USER_ACCOUNT")
        users = rows_to_dicts(sheet)
        for u in users:
            if str(u.get("User", "")).strip() == username:
                if str(u.get("Active", "")).strip().upper() != "TRUE":
                    return jsonify({"error": "บัญชีนี้ถูกระงับการใช้งาน"}), 403
                stored_pass = str(u.get("Pass", "")).strip()
                # Support both plain text (legacy) and hashed passwords
                if stored_pass == password or stored_pass == hash_password(password):
                    session["user"]     = username
                    session["name"]     = str(u.get("Name", username))
                    session["role"]     = str(u.get("Role", "")).strip()
                    session["group"]    = str(u.get("Group", "")).strip()
                    session["region"]   = str(u.get("Region", "")).strip()
                    session["province"] = str(u.get("Province", "")).strip()
                    return jsonify({
                        "success": True,
                        "user": session["name"],
                        "role": session["role"],
                        "region": session["region"],
                        "province": session["province"],
                    })
        return jsonify({"error": "Username หรือ Password ไม่ถูกต้อง"}), 401
    except Exception as e:
        return jsonify({"error": f"ไม่สามารถเชื่อมต่อ Google Sheet: {str(e)}"}), 500

@app.route("/api/logout", methods=["POST"])
def logout():
    session.clear()
    return jsonify({"success": True})

@app.route("/api/me")
@login_required
def me():
    return jsonify({
        "user":     session.get("user"),
        "name":     session.get("name"),
        "role":     session.get("role"),
        "group":    session.get("group"),
        "region":   session.get("region"),
        "province": session.get("province"),
    })

# ─────────────────────────────────────────────
# Routes — Tickets
# ─────────────────────────────────────────────
@app.route("/api/tickets")
@login_required
def get_tickets():
    try:
        sheet = get_sheet("NOR_Penalty_Ticket")
        ensure_new_columns(sheet)
        records = rows_to_dicts(sheet)
        role     = session.get("role")
        region   = session.get("region")
        province = session.get("province")

        # Filter by region/province for non-manager roles
        filtered = []
        for r in records:
            if not r.get(COL_TICKETID):
                continue
            # Flexible region filter — NOR1 matches "02) North", "NOR1", "North" etc.
            if region:
                row_region = str(r.get(COL_REGION, "")).strip()
                region_upper = region.upper()
                if row_region and region_upper not in row_region.upper() and row_region.upper() not in region_upper:
                    if not any(x in row_region.upper() for x in ["NORTH","NOR1","NOR2","NOR"]):
                        continue
            filtered.append(r)

        return jsonify({"tickets": filtered, "total": len(filtered)})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/ticket/<ticketid>")
@login_required
def get_ticket(ticketid):
    try:
        sheet = get_sheet("NOR_Penalty_Ticket")
        records = rows_to_dicts(sheet)
        ticket = next((r for r in records if str(r.get(COL_TICKETID)) == ticketid), None)
        if not ticket:
            return jsonify({"error": "ไม่พบ Ticket"}), 404
        # Add normalized defend_reason — column name has actual newline in Sheet
        defend_reason = str(ticket.get(COL_DEFEND, "") or "")
        if not defend_reason:
            # Fallback: scan all keys
            for k, v in ticket.items():
                if "Defend" in str(k) and ("สมควร" in str(k) or "BBTEC" in str(k)) and v:
                    defend_reason = str(v)
                    break
        ticket["_defend_reason"] = defend_reason
        return jsonify(ticket)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# ─────────────────────────────────────────────
# Step 1 — Engineer Review
# ─────────────────────────────────────────────
@app.route("/api/ticket/<ticketid>/step1", methods=["POST"])
@login_required
@require_role(ROLE_ENGINEER, ROLE_SITE_SUP, "ENGINEER_ZONE", "Engineer Zone")
def submit_step1(ticketid):
    data = request.json or {}
    try:
        sheet = get_sheet("NOR_Penalty_Ticket")
        headers = ensure_new_columns(sheet)
        row_idx = find_row_index(sheet, ticketid)
        if not row_idx:
            return jsonify({"error": "ไม่พบ Ticket"}), 404

        records = rows_to_dicts(sheet)
        ticket = next((r for r in records if str(r.get(COL_TICKETID)) == ticketid), None)

        # Block if locked
        if str(ticket.get(COL_LOCKED, "")).upper() == "TRUE":
            return jsonify({"error": "Ticket นี้ถูก Lock แล้ว ไม่สามารถแก้ไขได้"}), 403

        current_step = str(ticket.get(COL_STEP, "")).strip()
        if current_step not in ("", "0", "1"):
            return jsonify({"error": f"Ticket อยู่ที่ Step {current_step} แล้ว ไม่สามารถแก้ไข Step 1"}), 403

        # AG column = "Overdue Detail แนบLINK รูป" — combine overdue text + photo link
        overdue_text = data.get("overdue_detail", "")
        link_photo   = data.get("link_photo", "")
        overdue_combined = overdue_text
        if link_photo:
            overdue_combined = f"{overdue_text} / {link_photo}" if overdue_text else link_photo

        fields = {
            COL_OWNER:          session.get("name"),
            COL_GROUP_PROBLEM:  data.get("group_problem", ""),
            COL_SUB_PROBLEM:    data.get("sub_problem", ""),
            COL_ACCIDENT:       data.get("accident", ""),
            COL_OVERDUE_DETAIL: overdue_combined,
            COL_LINK_EVIDENCE:  data.get("link_evidence", ""),
            COL_STEP:           "1",
            COL_LAST_UPDATED:   now_str(),
            COL_UPDATED_BY:     session.get("user"),
        }
        update_ticket_fields(sheet, headers, row_idx, fields)
        return jsonify({"success": True, "message": "บันทึก Step 1 สำเร็จ ยืนยันแล้วไม่สามารถแก้ไขได้"})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# ─────────────────────────────────────────────
# Step 2 — FSO Review
# ─────────────────────────────────────────────
@app.route("/api/ticket/<ticketid>/step2", methods=["POST"])
@login_required
@require_role(ROLE_FSO, ROLE_FSO_MGR, "FSO_ZONE", "FSO Zone", "FSO Manager Zone")
def submit_step2(ticketid):
    data = request.json or {}
    decision = data.get("fso_decision", "").strip()  # "ปรับ" or "ไม่ปรับ"
    if decision not in ("ปรับ", "ไม่ปรับ"):
        return jsonify({"error": "กรุณาเลือก: ปรับ หรือ ไม่ปรับ"}), 400
    try:
        sheet = get_sheet("NOR_Penalty_Ticket")
        headers = ensure_new_columns(sheet)
        row_idx = find_row_index(sheet, ticketid)
        if not row_idx:
            return jsonify({"error": "ไม่พบ Ticket"}), 404

        records = rows_to_dicts(sheet)
        ticket = next((r for r in records if str(r.get(COL_TICKETID)) == ticketid), None)

        if str(ticket.get(COL_LOCKED, "")).upper() == "TRUE":
            return jsonify({"error": "Ticket นี้ถูก Lock แล้ว"}), 403

        current_step = str(ticket.get(COL_STEP, "")).strip()
        if current_step not in ("1", "2"):
            return jsonify({"error": f"Ticket ยังไม่ผ่าน Step 1 หรืออยู่ที่ Step {current_step}"}), 403

        fields = {
            COL_FSO_DECISION: decision,
            COL_FSO_APPROVE:  session.get("name"),
            COL_FSO_DATE:     now_str(),
            COL_FSO_REMARK:   data.get("remark", ""),
            COL_STEP:         "2",
            COL_LAST_UPDATED: now_str(),
            COL_UPDATED_BY:   session.get("user"),
        }
        # If FSO says ไม่ปรับ → skip to Step 4, lock
        if decision == "ไม่ปรับ":
            fields[COL_STEP]         = "4"
            fields[COL_FINAL_RESULT] = "ไม่ปรับ"
            fields[COL_LOCKED]       = "TRUE"

        update_ticket_fields(sheet, headers, row_idx, fields)
        msg = "FSO ตัดสิน: ไม่ปรับ — Lock และส่ง Step 4 แล้ว" if decision == "ไม่ปรับ" else "FSO ตัดสิน: ปรับ — Engineer สามารถขอ Defend ได้"
        return jsonify({"success": True, "message": msg, "fso_decision": decision})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# ─────────────────────────────────────────────
# Step 3 — Request Defend (Engineer)
# ─────────────────────────────────────────────
@app.route("/api/ticket/<ticketid>/defend/request", methods=["POST"])
@login_required
@require_role(ROLE_ENGINEER, ROLE_SITE_SUP, "ENGINEER_ZONE", "Engineer Zone")
def request_defend(ticketid):
    data = request.json or {}
    defend_reason = data.get("defend_reason", "").strip()
    if not defend_reason:
        return jsonify({"error": "กรุณากรอกเหตุผลการขอ Defend"}), 400
    try:
        sheet = get_sheet("NOR_Penalty_Ticket")
        headers = ensure_new_columns(sheet)
        row_idx = find_row_index(sheet, ticketid)
        if not row_idx:
            return jsonify({"error": "ไม่พบ Ticket"}), 404

        records = rows_to_dicts(sheet)
        ticket = next((r for r in records if str(r.get(COL_TICKETID)) == ticketid), None)

        if str(ticket.get(COL_LOCKED, "")).upper() == "TRUE":
            return jsonify({"error": "Ticket นี้ถูก Lock แล้ว"}), 403

        current_step = str(ticket.get(COL_STEP, "")).strip()
        fso_decision = (
            str(ticket.get(COL_FSO_DECISION, "") or "").strip() or
            str(ticket.get("FSO พิจารณา", "") or "").strip()
        )
        # step=2 = FSO พิจารณาแล้ว (ปรับ) — allow defend
        # step=3 = กำลัง defend อยู่ — allow re-defend
        if current_step not in ("2", "3"):
            return jsonify({"error": f"ยังไม่ถึง Step Defend (step={current_step})"}), 403
        # ถ้า FSO ตัดสิน ไม่ปรับ ชัดเจน — ห้าม defend
        if fso_decision == "ไม่ปรับ":
            return jsonify({"error": "FSO ตัดสิน ไม่ปรับ แล้ว ไม่จำเป็นต้อง Defend"}), 403

        try:
            defend_count = int(ticket.get(COL_DEFEND_COUNT, 0) or 0)
        except (ValueError, TypeError):
            defend_count = 0

        if defend_count >= 2:
            return jsonify({"error": "หมดสิทธิ์ Defend แล้ว (สูงสุด 2 ครั้ง)"}), 403

        fields = {
            COL_DEFEND:       defend_reason,
            COL_DEFEND_COUNT: str(defend_count + 1),
            COL_STEP:         "3",
            COL_LAST_UPDATED: now_str(),
            COL_UPDATED_BY:   session.get("user"),
        }
        update_ticket_fields(sheet, headers, row_idx, fields)
        return jsonify({
            "success": True,
            "message": f"ส่งคำขอ Defend ครั้งที่ {defend_count + 1} สำเร็จ",
            "defend_count": defend_count + 1,
            "remaining": 2 - (defend_count + 1),
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# ─────────────────────────────────────────────
# Step 3 — FSO Re-review Defend
# ─────────────────────────────────────────────
@app.route("/api/ticket/<ticketid>/defend/review", methods=["POST"])
@login_required
@require_role(ROLE_FSO, ROLE_FSO_MGR, "FSO_ZONE", "FSO Zone", "FSO Manager Zone")
def review_defend(ticketid):
    data = request.json or {}
    decision = data.get("decision", "").strip()  # "ปรับ" or "ไม่ปรับ"
    if decision not in ("ปรับ", "ไม่ปรับ"):
        return jsonify({"error": "กรุณาเลือก: ปรับ หรือ ไม่ปรับ"}), 400
    try:
        sheet = get_sheet("NOR_Penalty_Ticket")
        headers = ensure_new_columns(sheet)
        row_idx = find_row_index(sheet, ticketid)
        if not row_idx:
            return jsonify({"error": "ไม่พบ Ticket"}), 404

        records = rows_to_dicts(sheet)
        ticket = next((r for r in records if str(r.get(COL_TICKETID)) == ticketid), None)

        if str(ticket.get(COL_LOCKED, "")).upper() == "TRUE":
            return jsonify({"error": "Ticket นี้ถูก Lock แล้ว"}), 403

        try:
            defend_count = int(ticket.get(COL_DEFEND_COUNT, 0) or 0)
        except (ValueError, TypeError):
            defend_count = 0

        fields = {
            COL_FSO_DECISION: decision,
            COL_FSO_APPROVE:  session.get("name"),
            COL_FSO_DATE:     now_str(),
            COL_FSO_REMARK:   data.get("remark", ""),
            COL_LAST_UPDATED: now_str(),
            COL_UPDATED_BY:   session.get("user"),
        }

        if decision == "ไม่ปรับ":
            # Defend สำเร็จ → Step 4 ไม่ปรับ Lock
            fields[COL_STEP]         = "4"
            fields[COL_FINAL_RESULT] = "ไม่ปรับ"
            fields[COL_LOCKED]       = "TRUE"
            msg = "Defend สำเร็จ — ไม่ปรับ ข้อมูล Lock แล้ว"
        elif defend_count >= 2:
            # ครบ 2 ครั้ง ยังปรับ → Step 4 ปรับ Lock
            fields[COL_STEP]         = "4"
            fields[COL_FINAL_RESULT] = "ปรับ"
            fields[COL_LOCKED]       = "TRUE"
            msg = "Defend ครบ 2 ครั้ง — ยืนยัน ปรับ ข้อมูล Lock แล้ว"
        else:
            # FSO reject defend ครั้งนี้ → set step กลับเป็น 2 เพื่อให้ Engineer เห็นปุ่ม Defend ครั้งถัดไป
            fields[COL_STEP] = "2"
            msg = f"FSO ยังตัดสิน ปรับ — Engineer สามารถขอ Defend ครั้งที่ {defend_count + 1} ได้ (เหลือ {2 - defend_count} ครั้ง)"

        update_ticket_fields(sheet, headers, row_idx, fields)
        return jsonify({"success": True, "message": msg, "decision": decision, "defend_count": defend_count})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# ─────────────────────────────────────────────
# Accept Penalty (Engineer ยอมรับค่าปรับ — skip defend)
# ─────────────────────────────────────────────
@app.route("/api/ticket/<ticketid>/accept", methods=["POST"])
@login_required
@require_role(ROLE_ENGINEER, ROLE_SITE_SUP, "ENGINEER_ZONE", "Engineer Zone")
def accept_penalty(ticketid):
    try:
        sheet = get_sheet("NOR_Penalty_Ticket")
        headers = ensure_new_columns(sheet)
        row_idx = find_row_index(sheet, ticketid)
        if not row_idx:
            return jsonify({"error": "ไม่พบ Ticket"}), 404
        records = rows_to_dicts(sheet)
        ticket = next((r for r in records if str(r.get(COL_TICKETID)) == ticketid), None)
        if str(ticket.get(COL_LOCKED, "")).upper() == "TRUE":
            return jsonify({"error": "Ticket ถูก Lock แล้ว"}), 403
        fields = {
            COL_STEP:         "4",
            COL_FINAL_RESULT: "ปรับ",
            COL_LOCKED:       "TRUE",
            COL_LAST_UPDATED: now_str(),
            COL_UPDATED_BY:   session.get("user"),
        }
        update_ticket_fields(sheet, headers, row_idx, fields)
        return jsonify({"success": True, "message": "ยอมรับค่าปรับแล้ว — ส่ง Step 4 รอ Manager Approve"})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# ─────────────────────────────────────────────
# Step 5 — Manager Approve
# ─────────────────────────────────────────────
@app.route("/api/ticket/<ticketid>/approve", methods=["POST"])
@login_required
@require_role(ROLE_MANAGER, "MANAGER", "BBTEC Manager", "Manager NOR1", "Manager NOR2")
def manager_approve(ticketid):
    try:
        sheet = get_sheet("NOR_Penalty_Ticket")
        headers = ensure_new_columns(sheet)
        row_idx = find_row_index(sheet, ticketid)
        if not row_idx:
            return jsonify({"error": "ไม่พบ Ticket"}), 404

        records = rows_to_dicts(sheet)
        ticket = next((r for r in records if str(r.get(COL_TICKETID)) == ticketid), None)

        current_step = str(ticket.get(COL_STEP, "")).strip()
        if current_step != "4":
            return jsonify({"error": f"Ticket อยู่ที่ Step {current_step} ยังไม่ถึง Step 5"}), 403

        fields = {
            COL_STEP:         "5",
            COL_LOCKED:       "TRUE",
            COL_LAST_UPDATED: now_str(),
            COL_UPDATED_BY:   session.get("user"),
            COL_REVIEWER:     session.get("name"),
        }
        update_ticket_fields(sheet, headers, row_idx, fields)
        return jsonify({"success": True, "message": "Manager อนุมัติสำเร็จ ข้อมูลสมบูรณ์"})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# ─────────────────────────────────────────────
# Dashboard KPI Summary
# ─────────────────────────────────────────────
@app.route("/api/dashboard/summary")
@login_required
def dashboard_summary():
    try:
        sheet = get_sheet("NOR_Penalty_Ticket")
        records = rows_to_dicts(sheet)
        region = session.get("region")

        total = reviewed = fso_penalty = fso_no_penalty = 0
        defend_req = defend_success = defend_round2 = 0
        final_penalty = final_no_penalty = 0
        approved = pending_approve = 0
        total_penalty_baht = final_penalty_baht = 0

        for r in records:
            if not r.get(COL_TICKETID):
                continue
            # Region filter: flexible match (NOR1 matches "02) North", "NOR1", etc.)
            if region:
                row_region = str(r.get(COL_REGION, "")).strip()
                region_upper = region.upper()
                # Skip only if region clearly doesn't match
                if row_region and region_upper not in row_region.upper() and row_region.upper() not in region_upper:
                    # Also allow NOR1/NOR2 to see all "North" tickets
                    if not any(x in row_region.upper() for x in ["NORTH","NOR1","NOR2","NOR"]):
                        continue
            total += 1
            try:
                total_penalty_baht += float(str(r.get(COL_PENALTYBAHT, "0") or 0).replace(",", ""))
            except Exception:
                pass

            step = str(r.get(COL_STEP, "")).strip()
            if step in ("1", "2", "3", "4", "5"):
                reviewed += 1
            fso_dec = str(r.get(COL_FSO_DECISION, "")).strip()
            if fso_dec == "ปรับ":
                fso_penalty += 1
            elif fso_dec == "ไม่ปรับ":
                fso_no_penalty += 1

            try:
                dc = int(r.get(COL_DEFEND_COUNT, 0) or 0)
            except Exception:
                dc = 0
            if dc > 0:
                defend_req += 1
            if dc >= 2:
                defend_round2 += 1

            final = str(r.get(COL_FINAL_RESULT, "")).strip()
            if final == "ปรับ":
                final_penalty += 1
                try:
                    final_penalty_baht += float(str(r.get(COL_PENALTYBAHT, "0") or 0).replace(",", ""))
                except Exception:
                    pass
            elif final == "ไม่ปรับ":
                final_no_penalty += 1
                if dc > 0:
                    defend_success += 1

            if step == "5":
                approved += 1
            elif step == "4":
                pending_approve += 1

        return jsonify({
            "total":              total,
            "reviewed":           reviewed,
            "reviewed_pct":       round(reviewed / total * 100, 1) if total else 0,
            "fso_penalty":        fso_penalty,
            "fso_no_penalty":     fso_no_penalty,
            "defend_requested":   defend_req,
            "defend_success":     defend_success,
            "final_penalty":      final_penalty,
            "final_no_penalty":   final_no_penalty,
            "approved":           approved,
            "pending_approve":    pending_approve,
            "total_penalty_baht": total_penalty_baht,
            "final_penalty_baht": final_penalty_baht,
            "saved_baht":         total_penalty_baht - final_penalty_baht,
            "defend_round2":      defend_round2,
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# ─────────────────────────────────────────────
# Serve frontend
# ─────────────────────────────────────────────
@app.route("/", defaults={"path": ""})
@app.route("/<path:path>")
def serve_frontend(path):
    if path and os.path.exists(os.path.join(app.static_folder, path)):
        return send_from_directory(app.static_folder, path)
    return send_from_directory(app.static_folder, "index.html")

# ─────────────────────────────────────────────
# Health check (Railway uses this — no auth needed)
# ─────────────────────────────────────────────
@app.route("/health")
def health():
    return jsonify({"status": "ok", "service": "BBTEC Smart Defense"}), 200

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=False)
