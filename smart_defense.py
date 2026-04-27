import os, json, time, hmac, hashlib, base64, logging, re
from datetime import datetime, timedelta
from functools import wraps
from flask import Blueprint, request, jsonify
import gspread
from google.oauth2.service_account import Credentials

bp = Blueprint("smart_defense", __name__, url_prefix="/api/smart-defense")
log = logging.getLogger("smart_defense")
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

SHEET_ID = os.environ.get("SMART_DEFENSE_SHEET_ID", "1RBWr-lKva_XOqmcKwEE-E7hqIodbWWK1XHzuV8QJ-7Q")
TICKET_SHEET = os.environ.get("SMART_DEFENSE_TICKET_SHEET", "NOR_Penalty_Ticket")
USER_SHEET = os.environ.get("SMART_DEFENSE_USER_SHEET", "USER_ACCOUNT")
AUDIT_SHEET = os.environ.get("SMART_DEFENSE_AUDIT_SHEET", "SD_AUDIT_LOG")
SECRET = os.environ.get("SMART_DEFENSE_SECRET", "bbtec-smart-defense-change-me")

TTL_TICKETS = int(os.environ.get("SMART_DEFENSE_CACHE_TICKETS_SEC", "300"))
TTL_USERS = int(os.environ.get("SMART_DEFENSE_CACHE_USERS_SEC", "900"))
MIN_READ_INTERVAL = int(os.environ.get("SMART_DEFENSE_MIN_READ_INTERVAL_SEC", "45"))

CACHE = {
    "tickets": None, "tickets_ts": 0, "tickets_last_read": 0, "tickets_error": None,
    "users": None, "users_ts": 0, "users_last_read": 0, "users_error": None,
    "headers": None, "header_map": None,
}

BASE_HEADERS = [
    "TICKETID","STATUS","TRUESEVERITY_DESC","TRUEURGENCY","CREATIONDATE","TARGETFINISH",
    "RESTORATIONDATE","SUBJECT","CATEGORIES","TRUEOWNERGROUP","TrackB_Region","DOWN_TIME_MINUTE"
]

WORKFLOW_HEADERS = [
    "Group problem","Sub Problem","Accident","Overdue Detail แนบLINK รูป","แนบ LINK ชี้แจง",
    "FSO พิจารณา (ปรับ/ไม่ปรับ)","FSO approve (ลงชื่อ FSO)","วันที่ FSO อนุมัติ","Remark FSO",
    "SD_STEP","SD_LOCK_STEP1","SD_LOCK_STEP2","SD_FINAL_LOCK","SD_DEFEND_COUNT",
    "SD_STEP1_BY","SD_STEP1_AT","SD_FSO_BY","SD_FSO_AT",
    "SD_DEFEND1_BY","SD_DEFEND1_AT","SD_DEFEND2_BY","SD_DEFEND2_AT",
    "SD_FINAL_BY","SD_FINAL_AT","SD_MANAGER_BY","SD_MANAGER_AT","SD_LAST_UPDATE"
]

REGION_MAP = {
    "NOR1": ["TRUE-TH-BBT-NOR1-CMI1-NOP","TRUE-TH-BBT-NOR1-CMI2-NOP","TRUE-TH-BBT-NOR1-CRI-NOP",
             "TRUE-TH-BBT-NOR1-LPG-NOP","TRUE-TH-BBT-NOR1-LPN-NOP","TRUE-TH-BBT-NOR1-MHS-NOP",
             "TRUE-TH-BBT-NOR1-NAN-NOP","TRUE-TH-BBT-NOR1-PHE-NOP","TRUE-TH-BBT-NOR1-PYO-NOP"],
    "NOR2": ["TRUE-TH-BBT-NOR2-KPP-NOP","TRUE-TH-BBT-NOR2-PCB-NOP","TRUE-TH-BBT-NOR2-PCT-NOP",
             "TRUE-TH-BBT-NOR2-PSN-NOP","TRUE-TH-BBT-NOR2-SKT-NOP","TRUE-TH-BBT-NOR2-TAK-NOP",
             "TRUE-TH-BBT-NOR2-UTR-NOP"]
}
ALIAS = {p.split("-")[-2]: p for arr in REGION_MAP.values() for p in arr}
ALIAS.update({"CMI": "TRUE-TH-BBT-NOR1-CMI1-NOP"})

def now_str():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def norm(v):
    return str(v or "").strip()

def norm_up(v):
    return norm(v).upper().replace(" ", "")

def split_multi(v):
    s = norm(v)
    if not s:
        return []
    return [x.strip() for x in re.split(r"[,;|]", s) if x.strip()]

def normalize_area(v):
    s = norm_up(v)
    if s in ("", "ALL"):
        return s or "ALL"
    return ALIAS.get(s, s)

def parse_amount(v):
    s = str(v or "").replace(",", "").replace("บาท", "").strip()
    try:
        return float(s)
    except Exception:
        return 0.0

def get_client():
    raw = os.environ.get("GOOGLE_CREDENTIALS_JSON")
    if not raw:
        raise RuntimeError("Missing GOOGLE_CREDENTIALS_JSON")
    info = json.loads(raw)
    creds = Credentials.from_service_account_info(
        info, scopes=["https://www.googleapis.com/auth/spreadsheets"]
    )
    return gspread.authorize(creds)

def get_ws(name):
    return get_client().open_by_key(SHEET_ID).worksheet(name)

def ensure_headers(ws):
    headers = ws.row_values(1)
    clean = [norm(h) for h in headers]
    missing = [h for h in WORKFLOW_HEADERS if h not in clean]
    if missing:
        start_col = len(clean) + 1
        ws.update_cell(1, start_col, missing[0]) if len(missing)==1 else ws.update([missing], f"{gspread.utils.rowcol_to_a1(1,start_col)}:{gspread.utils.rowcol_to_a1(1,start_col+len(missing)-1)}")
        headers = ws.row_values(1)
        clean = [norm(h) for h in headers]
        log.info("Added workflow headers: %s", missing)
    return clean, {h:i+1 for i,h in enumerate(clean)}

def records_from_values(values):
    if not values:
        return [], [], {}
    headers = [norm(h) for h in values[0]]
    hmap = {h:i for i,h in enumerate(headers)}
    rows = []
    for idx, row in enumerate(values[1:], start=2):
        d = {"_row": idx}
        for h, i in hmap.items():
            d[h] = row[i] if i < len(row) else ""
        rows.append(d)
    return rows, headers, hmap

def load_users(force=False):
    now = time.time()
    if not force and CACHE["users"] is not None and now - CACHE["users_ts"] < TTL_USERS:
        return CACHE["users"]
    if not force and CACHE["users"] is not None and now - CACHE["users_last_read"] < MIN_READ_INTERVAL:
        return CACHE["users"]
    try:
        CACHE["users_last_read"] = now
        ws = get_ws(USER_SHEET)
        rows, headers, hmap = records_from_values(ws.get_all_values())
        users = []
        for r in rows:
            active = norm_up(r.get("Active", "TRUE"))
            if active not in ("TRUE","1","YES","Y","ACTIVE"):
                continue
            users.append({
                "user": norm(r.get("User")),
                "pass": norm(r.get("Pass")),
                "name": norm(r.get("Name") or r.get("User")),
                "group": norm_up(r.get("Group")),
                "role": norm_up(r.get("Role")),
                "region": norm_up(r.get("Region") or "ALL"),
                "province": norm(r.get("Province") or "ALL"),
                "systems": [norm_up(x) for x in split_multi(r.get("Systems") or "SMART_DEFENSE")],
                "active": True,
            })
        CACHE["users"], CACHE["users_ts"], CACHE["users_error"] = users, now, None
        log.info("SD users loaded: %s", len(users))
        return users
    except Exception as e:
        CACHE["users_error"] = str(e)
        log.exception("load_users error")
        if CACHE["users"] is not None:
            return CACHE["users"]
        raise

def load_tickets(force=False, ensure=True):
    now = time.time()
    if not force and CACHE["tickets"] is not None and now - CACHE["tickets_ts"] < TTL_TICKETS:
        return CACHE["tickets"]
    if not force and CACHE["tickets"] is not None and now - CACHE["tickets_last_read"] < MIN_READ_INTERVAL:
        return CACHE["tickets"]
    try:
        CACHE["tickets_last_read"] = now
        ws = get_ws(TICKET_SHEET)
        if ensure:
            headers, col_map = ensure_headers(ws)
        values = ws.get_all_values()
        rows, headers, hmap0 = records_from_values(values)
        CACHE["headers"] = headers
        CACHE["header_map"] = {h:i+1 for i,h in enumerate(headers)}
        tickets = [normalize_ticket(r) for r in rows if norm(r.get("TICKETID") or r.get("Ticket") or r.get("ticket"))]
        CACHE["tickets"], CACHE["tickets_ts"], CACHE["tickets_error"] = tickets, now, None
        log.info("SD tickets loaded: %s from sheet_id=%s tab=%s headers=%s", len(tickets), SHEET_ID, TICKET_SHEET, headers[:15])
        return tickets
    except Exception as e:
        CACHE["tickets_error"] = str(e)
        log.exception("load_tickets error")
        if CACHE["tickets"] is not None:
            return CACHE["tickets"]
        raise

def normalize_ticket(r):
    tid = norm(r.get("TICKETID") or r.get("Ticket") or r.get("ticket"))
    owner = norm(r.get("TRUEOWNERGROUP") or r.get("Province"))
    region = norm_up(r.get("TrackB_Region") or infer_region(owner))
    step = norm(r.get("SD_STEP") or "1")
    try:
        step_int = int(float(step))
    except Exception:
        step_int = 1
    penalty = parse_amount(r.get("PENALTYBAHT_TRACKB") or r.get("PENALTY") or r.get("Penalty") or r.get("Penalty Amount"))
    return {
        "_row": r.get("_row"),
        "ticket": tid,
        "raw": r,
        "step": step_int,
        "region": region,
        "province": normalize_area(owner),
        "province_display": owner,
        "severity": norm(r.get("TRUESEVERITY_DESC")),
        "creation": norm(r.get("CREATIONDATE")),
        "target": norm(r.get("TARGETFINISH")),
        "subject": norm(r.get("SUBJECT")),
        "penalty": penalty,
        "problem": norm(r.get("Group problem")),
        "sub_problem": norm(r.get("Sub Problem")),
        "accident": norm(r.get("Accident")),
        "overdue_link": norm(r.get("Overdue Detail แนบLINK รูป")),
        "explain_link": norm(r.get("แนบ LINK ชี้แจง")),
        "fso_decision": norm(r.get("FSO พิจารณา (ปรับ/ไม่ปรับ)")),
        "fso_approve": norm(r.get("FSO approve (ลงชื่อ FSO)")),
        "fso_date": norm(r.get("วันที่ FSO อนุมัติ")),
        "fso_remark": norm(r.get("Remark FSO")),
        "defend_count": int(float(r.get("SD_DEFEND_COUNT") or 0)),
        "lock1": norm_up(r.get("SD_LOCK_STEP1")) in ("TRUE","YES","1","LOCK"),
        "lock2": norm_up(r.get("SD_LOCK_STEP2")) in ("TRUE","YES","1","LOCK"),
        "final_lock": norm_up(r.get("SD_FINAL_LOCK")) in ("TRUE","YES","1","LOCK"),
        "last_update": norm(r.get("SD_LAST_UPDATE")),
        "step1_by": norm(r.get("SD_STEP1_BY")),
        "fso_by": norm(r.get("SD_FSO_BY")),
        "final_by": norm(r.get("SD_FINAL_BY")),
        "manager_by": norm(r.get("SD_MANAGER_BY")),
    }

def infer_region(owner):
    s = norm_up(owner)
    if "NOR1" in s:
        return "NOR1"
    if "NOR2" in s:
        return "NOR2"
    return ""

def sign_token(payload):
    data = dict(payload)
    data["exp"] = int(time.time()) + 60*60*12
    raw = base64.urlsafe_b64encode(json.dumps(data, ensure_ascii=False).encode()).decode().rstrip("=")
    sig = hmac.new(SECRET.encode(), raw.encode(), hashlib.sha256).hexdigest()
    return raw + "." + sig

def verify_token(token):
    try:
        raw, sig = token.split(".", 1)
        good = hmac.new(SECRET.encode(), raw.encode(), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(sig, good):
            return None
        data = json.loads(base64.urlsafe_b64decode(raw + "="*((4-len(raw)%4)%4)).decode())
        if data.get("exp", 0) < time.time():
            return None
        return data
    except Exception:
        return None

def current_user():
    auth = request.headers.get("Authorization", "")
    token = auth.replace("Bearer ", "").strip()
    data = verify_token(token) if token else None
    return data

def require_auth(fn):
    @wraps(fn)
    def wrap(*args, **kwargs):
        u = current_user()
        if not u:
            return jsonify({"ok": False, "error": "unauthorized"}), 401
        request.user = u
        return fn(*args, **kwargs)
    return wrap

def allowed_ticket(user, t):
    if "SMART_DEFENSE" not in user.get("systems", ["SMART_DEFENSE"]):
        return False
    ureg = norm_up(user.get("region") or "ALL")
    if ureg != "ALL" and norm_up(t.get("region")) != ureg:
        return False
    provs_raw = split_multi(user.get("province") or "ALL")
    provs = [normalize_area(p) for p in provs_raw] or ["ALL"]
    if "ALL" not in [norm_up(p) for p in provs] and normalize_area(t.get("province")) not in provs:
        return False
    return True

def can_step1(user):
    return user.get("group") in ("ENGINEER","SITE") or user.get("role") in ("ENGINEER_ZONE","SITE_SUP")

def can_step2(user):
    return user.get("group") == "FSO" or user.get("role") in ("FSO_ZONE","FSO_MANAGER","FSO_REGIONAL")

def can_manager(user):
    return user.get("group") == "BBTEC" or user.get("role") in ("BBTEC_MANAGER","BBTEC_REGIONAL")

def ticket_by_id(ticket_id):
    for t in load_tickets():
        if norm(t["ticket"]) == norm(ticket_id):
            return t
    return None

def get_col_map():
    if not CACHE.get("header_map"):
        ws = get_ws(TICKET_SHEET)
        headers, col_map = ensure_headers(ws)
        CACHE["headers"], CACHE["header_map"] = headers, col_map
    return CACHE["header_map"]

def update_row(row_num, updates):
    ws = get_ws(TICKET_SHEET)
    col_map = get_col_map()
    cells = []
    for k, v in updates.items():
        if k not in col_map:
            headers, col_map = ensure_headers(ws)
            CACHE["headers"], CACHE["header_map"] = headers, col_map
        col = col_map[k]
        cells.append(gspread.Cell(row_num, col, v))
    if cells:
        ws.update_cells(cells, value_input_option="USER_ENTERED")
    CACHE["tickets_ts"] = 0

def append_audit(user, action, ticket, step="", detail=None):
    try:
        ss = get_client().open_by_key(SHEET_ID)
        try:
            ws = ss.worksheet(AUDIT_SHEET)
        except Exception:
            ws = ss.add_worksheet(AUDIT_SHEET, rows=1000, cols=10)
            ws.append_row(["Time","User","Name","Group","Role","Action","Ticket","Step","Detail","IP"])
        ws.append_row([
            now_str(), user.get("user"), user.get("name"), user.get("group"), user.get("role"),
            action, ticket, step, json.dumps(detail or {}, ensure_ascii=False), request.remote_addr or ""
        ], value_input_option="USER_ENTERED")
    except Exception as e:
        log.warning("audit failed: %s", e)

@bp.route("/login", methods=["POST"])
def login():
    data = request.get_json(force=True) or {}
    username = norm(data.get("user") or data.get("username"))
    password = norm(data.get("pass") or data.get("password"))
    for u in load_users():
        if norm_up(u["user"]) == norm_up(username) and u["pass"] == password:
            public = {k:v for k,v in u.items() if k != "pass"}
            return jsonify({"ok": True, "token": sign_token(public), "user": public})
    return jsonify({"ok": False, "error": "invalid username/password"}), 401

@bp.route("/me")
@require_auth
def me():
    return jsonify({"ok": True, "user": request.user})

@bp.route("/cache-status")
@require_auth
def cache_status():
    return jsonify({
        "ok": True,
        "sheet_id": SHEET_ID,
        "ticket_sheet": TICKET_SHEET,
        "user_sheet": USER_SHEET,
        "cache": {
            "tickets_cached": CACHE["tickets"] is not None,
            "ticket_count_cached": len(CACHE["tickets"] or []),
            "tickets_age_sec": round(time.time()-CACHE["tickets_ts"],1) if CACHE["tickets_ts"] else None,
            "tickets_error": CACHE["tickets_error"],
            "users_cached": CACHE["users"] is not None,
            "user_count_cached": len(CACHE["users"] or []),
            "users_error": CACHE["users_error"],
            "headers": CACHE["headers"][:30] if CACHE["headers"] else None,
        },
        "updated_at": now_str()
    })

@bp.route("/debug")
@require_auth
def debug():
    rows = load_tickets(force=request.args.get("force")=="1")
    allowed = [t for t in rows if allowed_ticket(request.user, t)]
    sample = [{k:t.get(k) for k in ("ticket","region","province_display","province","step","penalty","subject")} for t in allowed[:5]]
    return jsonify({"ok": True, "raw_count": len(rows), "allowed_count": len(allowed), "sample": sample, "user": request.user, "cache_error": CACHE["tickets_error"]})

@bp.route("/clear-cache", methods=["POST","GET"])
@require_auth
def clear_cache():
    CACHE["tickets"] = None; CACHE["tickets_ts"] = 0; CACHE["users"] = None; CACHE["users_ts"] = 0
    return jsonify({"ok": True})

@bp.route("/tickets")
@require_auth
def tickets():
    q = norm_up(request.args.get("q"))
    step = norm(request.args.get("step"))
    rows = [t for t in load_tickets() if allowed_ticket(request.user, t)]
    if step and step.lower() not in ("all","ทุก step","ทุกstep"):
        try:
            s = int(step)
            rows = [t for t in rows if t["step"] == s]
        except Exception:
            pass
    if q:
        rows = [t for t in rows if q in norm_up(t["ticket"]+" "+t["subject"]+" "+t["province_display"]+" "+t["severity"])]
    sort = request.args.get("sort") or "penalty"
    direction = request.args.get("dir") or "desc"
    rows.sort(key=lambda x: x.get(sort) if sort != "penalty" else x.get("penalty",0), reverse=(direction=="desc"))
    out = [{k:v for k,v in t.items() if k != "raw"} for t in rows]
    summary = make_summary(rows)
    return jsonify({"ok": True, "rows": out, "total": len(out), "total_amount": sum(t["penalty"] for t in rows), "summary": summary, "updated_at": now_str()})

def make_summary(rows):
    return {
        "total": len(rows),
        "amount": sum(t["penalty"] for t in rows),
        "step1_done": sum(1 for t in rows if t.get("lock1")),
        "fso_penalty": sum(1 for t in rows if "ปรับ" == t.get("fso_decision")),
        "fso_no_penalty": sum(1 for t in rows if "ไม่ปรับ" == t.get("fso_decision")),
        "defend": sum(1 for t in rows if t.get("defend_count",0)>0),
        "final": sum(1 for t in rows if t.get("final_lock")),
        "approved": sum(1 for t in rows if t.get("manager_by")),
    }

@bp.route("/ticket/<ticket_id>")
@require_auth
def ticket_detail(ticket_id):
    t = ticket_by_id(ticket_id)
    if not t or not allowed_ticket(request.user, t):
        return jsonify({"ok": False, "error": "not found or not allowed"}), 404
    return jsonify({"ok": True, "ticket": {k:v for k,v in t.items() if k != "raw"}, "raw": t["raw"], "permissions": ticket_permissions(request.user, t)})

def ticket_permissions(user, t):
    return {
        "can_edit_step1": can_step1(user) and t["step"] == 1 and not t["lock1"] and not t["final_lock"],
        "can_confirm_step1": can_step1(user) and t["step"] == 1 and not t["lock1"] and not t["final_lock"],
        "can_fso": can_step2(user) and t["step"] in (2,3) and not t["final_lock"],
        "can_defend": can_step1(user) and t["step"] == 3 and t.get("defend_count",0) < 2 and not t["final_lock"],
        "can_accept_final": can_step1(user) and t["step"] == 3 and not t["final_lock"],
        "can_manager_approve": can_manager(user) and t["step"] == 5 and not t.get("manager_by") and not t["final_lock"],
    }

@bp.route("/step1/save", methods=["POST"])
@require_auth
def step1_save():
    data = request.get_json(force=True) or {}
    tid = data.get("ticket")
    t = ticket_by_id(tid)
    if not t or not allowed_ticket(request.user, t):
        return jsonify({"ok": False, "error": "not allowed"}), 403
    if not ticket_permissions(request.user, t)["can_edit_step1"]:
        return jsonify({"ok": False, "error": "step1 locked or no permission"}), 403
    updates = {
        "Group problem": norm(data.get("problem")),
        "Sub Problem": norm(data.get("sub_problem")),
        "Accident": norm(data.get("accident")),
        "Overdue Detail แนบLINK รูป": norm(data.get("overdue_link")),
        "แนบ LINK ชี้แจง": norm(data.get("explain_link")),
        "SD_LAST_UPDATE": now_str()
    }
    update_row(t["_row"], updates)
    append_audit(request.user, "STEP1_SAVE", tid, "1", updates)
    return jsonify({"ok": True})

@bp.route("/step1/confirm", methods=["POST"])
@require_auth
def step1_confirm():
    data = request.get_json(force=True) or {}
    tid = data.get("ticket")
    t = ticket_by_id(tid)
    if not t or not allowed_ticket(request.user, t):
        return jsonify({"ok": False, "error": "not allowed"}), 403
    if not ticket_permissions(request.user, t)["can_confirm_step1"]:
        return jsonify({"ok": False, "error": "step1 locked or no permission"}), 403
    updates = {
        "SD_STEP": 2,
        "SD_LOCK_STEP1": "TRUE",
        "SD_STEP1_BY": request.user.get("name") or request.user.get("user"),
        "SD_STEP1_AT": now_str(),
        "SD_LAST_UPDATE": now_str()
    }
    update_row(t["_row"], updates)
    append_audit(request.user, "STEP1_CONFIRM", tid, "1", updates)
    return jsonify({"ok": True, "next_step": 2})

@bp.route("/fso/decision", methods=["POST"])
@require_auth
def fso_decision():
    data = request.get_json(force=True) or {}
    tid = data.get("ticket")
    t = ticket_by_id(tid)
    if not t or not allowed_ticket(request.user, t):
        return jsonify({"ok": False, "error": "not allowed"}), 403
    if not ticket_permissions(request.user, t)["can_fso"]:
        return jsonify({"ok": False, "error": "fso no permission or locked"}), 403
    decision = norm(data.get("decision"))
    if decision not in ("ปรับ","ไม่ปรับ"):
        return jsonify({"ok": False, "error": "decision must be ปรับ or ไม่ปรับ"}), 400
    # If FSO says ปรับ -> Step3 for engineer defend. If ไม่ปรับ -> Step4 final.
    next_step = 3 if decision == "ปรับ" else 4
    updates = {
        "FSO พิจารณา (ปรับ/ไม่ปรับ)": decision,
        "FSO approve (ลงชื่อ FSO)": norm(data.get("approve") or request.user.get("name") or request.user.get("user")),
        "วันที่ FSO อนุมัติ": norm(data.get("date") or now_str().split()[0]),
        "Remark FSO": norm(data.get("remark")),
        "SD_STEP": next_step,
        "SD_LOCK_STEP2": "TRUE",
        "SD_FSO_BY": request.user.get("name") or request.user.get("user"),
        "SD_FSO_AT": now_str(),
        "SD_LAST_UPDATE": now_str()
    }
    update_row(t["_row"], updates)
    append_audit(request.user, "FSO_DECISION", tid, "2", updates)
    return jsonify({"ok": True, "next_step": next_step})

@bp.route("/defend/request", methods=["POST"])
@require_auth
def defend_request():
    data = request.get_json(force=True) or {}
    tid = data.get("ticket")
    t = ticket_by_id(tid)
    if not t or not allowed_ticket(request.user, t):
        return jsonify({"ok": False, "error": "not allowed"}), 403
    if not ticket_permissions(request.user, t)["can_defend"]:
        return jsonify({"ok": False, "error": "defend not allowed or max 2"}), 403
    n = int(t.get("defend_count",0)) + 1
    updates = {
        "SD_DEFEND_COUNT": n,
        "SD_STEP": 2,  # send back to FSO review again
        f"SD_DEFEND{n}_BY": request.user.get("name") or request.user.get("user"),
        f"SD_DEFEND{n}_AT": now_str(),
        "SD_LOCK_STEP2": "",  # unlock FSO recheck
        "SD_LAST_UPDATE": now_str()
    }
    update_row(t["_row"], updates)
    append_audit(request.user, "DEFEND_REQUEST", tid, "3", {"count": n, "remark": data.get("remark")})
    return jsonify({"ok": True, "defend_count": n, "next_step": 2})

@bp.route("/final/accept", methods=["POST"])
@require_auth
def final_accept():
    data = request.get_json(force=True) or {}
    tid = data.get("ticket")
    t = ticket_by_id(tid)
    if not t or not allowed_ticket(request.user, t):
        return jsonify({"ok": False, "error": "not allowed"}), 403
    # Engineer can accept after FSO ปรับ, or anyone allowed can finalize no-penalty in step4.
    if not (ticket_permissions(request.user, t)["can_accept_final"] or (t["step"]==4 and (can_step1(request.user) or can_step2(request.user) or can_manager(request.user)))):
        return jsonify({"ok": False, "error": "final accept not allowed"}), 403
    updates = {
        "SD_STEP": 5,
        "SD_FINAL_LOCK": "TRUE",
        "SD_FINAL_BY": request.user.get("name") or request.user.get("user"),
        "SD_FINAL_AT": now_str(),
        "SD_LAST_UPDATE": now_str()
    }
    update_row(t["_row"], updates)
    append_audit(request.user, "FINAL_ACCEPT", tid, "4", updates)
    return jsonify({"ok": True, "next_step": 5})

@bp.route("/manager/approve", methods=["POST"])
@require_auth
def manager_approve():
    data = request.get_json(force=True) or {}
    tid = data.get("ticket")
    t = ticket_by_id(tid)
    if not t or not allowed_ticket(request.user, t):
        return jsonify({"ok": False, "error": "not allowed"}), 403
    if not can_manager(request.user):
        return jsonify({"ok": False, "error": "manager permission required"}), 403
    updates = {
        "SD_STEP": 5,
        "SD_FINAL_LOCK": "TRUE",
        "SD_MANAGER_BY": request.user.get("name") or request.user.get("user"),
        "SD_MANAGER_AT": now_str(),
        "SD_LAST_UPDATE": now_str()
    }
    update_row(t["_row"], updates)
    append_audit(request.user, "MANAGER_APPROVE", tid, "5", updates)
    return jsonify({"ok": True})

@bp.route("/audit/<ticket_id>")
@require_auth
def audit(ticket_id):
    try:
        ws = get_ws(AUDIT_SHEET)
        rows, headers, hmap = records_from_values(ws.get_all_values())
        rows = [r for r in rows if norm(r.get("Ticket")) == norm(ticket_id)]
        return jsonify({"ok": True, "rows": rows[-100:]})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e), "rows": []})
