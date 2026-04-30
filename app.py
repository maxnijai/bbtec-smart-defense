import os, json, hashlib, time, threading
from datetime import datetime, timedelta
from functools import wraps
from flask import Flask, request, jsonify, session, send_from_directory
import psycopg2
from psycopg2.extras import RealDictCursor
from psycopg2 import pool
import gspread
from google.oauth2.service_account import Credentials

app = Flask(__name__, static_folder="static", template_folder="templates")
app.secret_key = os.environ.get("SECRET_KEY", "bbtec-smart-defense-2026")

# ─────────────────────────────────────────────
# PostgreSQL connection pool
# ─────────────────────────────────────────────
DATABASE_URL = os.environ.get("DATABASE_URL", "")
_db_pool = None

def get_pool():
    global _db_pool
    if _db_pool is None:
        _db_pool = pool.ThreadedConnectionPool(
            minconn=1, maxconn=10,
            dsn=DATABASE_URL,
            cursor_factory=RealDictCursor
        )
    return _db_pool

def get_conn():
    return get_pool().getconn()

def release_conn(conn):
    get_pool().putconn(conn)

def db_execute(sql, params=None, fetch="none"):
    conn = get_conn()
    try:
        with conn.cursor() as cur:
            cur.execute(sql, params or ())
            if fetch == "one":
                result = cur.fetchone()
            elif fetch == "all":
                result = cur.fetchall()
            else:
                result = None
            conn.commit()
        return result
    except Exception:
        conn.rollback()
        raise
    finally:
        release_conn(conn)

# ─────────────────────────────────────────────
# Google Sheets (read-only — for sync + user auth)
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
        creds = Credentials.from_service_account_info(json.loads(creds_json), scopes=SCOPES)
    elif os.path.exists("credentials.json"):
        creds = Credentials.from_service_account_file("credentials.json", scopes=SCOPES)
    else:
        raise RuntimeError("ไม่พบ credentials")
    _gc_client = gspread.authorize(creds)
    return _gc_client

def get_sheet(name):
    return get_gc().open_by_key(SPREADSHEET_ID).worksheet(name)

def sheets_retry(fn, *args, max_retries=4, **kwargs):
    delay = 2
    for attempt in range(max_retries):
        try:
            return fn(*args, **kwargs)
        except Exception as e:
            if ("429" in str(e) or "quota" in str(e).lower()) and attempt < max_retries - 1:
                time.sleep(delay + attempt * 1.5)
                delay = min(delay * 2, 30)
            else:
                raise

def rows_to_dicts(sheet):
    all_values = sheets_retry(sheet.get_all_values)
    if not all_values:
        return []
    raw_headers = all_values[0]
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
        padded = row + [""] * (len(headers) - len(row))
        records.append(dict(zip(headers, padded)))
    return records

# ─────────────────────────────────────────────
# DB Schema bootstrap
# ─────────────────────────────────────────────
def init_db():
    db_execute("""
    CREATE TABLE IF NOT EXISTS tickets (
        ticketid TEXT PRIMARY KEY,
        data JSONB NOT NULL DEFAULT '{}',
        step TEXT DEFAULT '',
        defend_count INT DEFAULT 0,
        locked BOOLEAN DEFAULT FALSE,
        fso_decision TEXT DEFAULT '',
        final_result TEXT DEFAULT '',
        owner1 TEXT DEFAULT '',
        updated_by TEXT DEFAULT '',
        last_updated TIMESTAMPTZ DEFAULT NOW(),
        synced_at TIMESTAMPTZ DEFAULT NOW()
    );
    CREATE INDEX IF NOT EXISTS idx_tickets_step ON tickets(step);
    CREATE INDEX IF NOT EXISTS idx_tickets_locked ON tickets(locked);

    CREATE TABLE IF NOT EXISTS audit_log (
        id SERIAL PRIMARY KEY,
        ts TIMESTAMPTZ DEFAULT NOW(),
        username TEXT, name TEXT, role TEXT,
        ticketid TEXT, action TEXT, detail TEXT,
        step_from TEXT, step_to TEXT
    );
    CREATE INDEX IF NOT EXISTS idx_audit_ticketid ON audit_log(ticketid);

    CREATE TABLE IF NOT EXISTS users (
        username TEXT PRIMARY KEY,
        name TEXT, role TEXT, "group" TEXT,
        region TEXT, province TEXT,
        pass_hash TEXT, active BOOLEAN DEFAULT TRUE,
        synced_at TIMESTAMPTZ DEFAULT NOW()
    );
    """)
    # Productivity table for drill down
    db_execute("""
    CREATE TABLE IF NOT EXISTS productivity (
        id SERIAL PRIMARY KEY,
        ticket TEXT,
        plan TEXT,
        team_id TEXT,
        que TEXT,
        travel_time TEXT,
        start_repair TEXT,
        hold TEXT,
        link_up TEXT,
        status_team TEXT,
        hold_reason TEXT,
        update_log TEXT,
        cause1 TEXT,
        fix_method TEXT,
        work_detail TEXT,
        url_picture TEXT,
        raw_data JSONB DEFAULT '{}',
        synced_at TIMESTAMPTZ DEFAULT NOW()
    );
    CREATE INDEX IF NOT EXISTS idx_prod_ticket ON productivity(ticket);
    CREATE INDEX IF NOT EXISTS idx_prod_team ON productivity(team_id);
    """)
    # Manager Defend columns (migrate safe)
    try:
        db_execute("ALTER TABLE tickets ADD COLUMN IF NOT EXISTS manager_defend TEXT DEFAULT ''")
        db_execute("ALTER TABLE tickets ADD COLUMN IF NOT EXISTS manager_defend_remark TEXT DEFAULT ''")
    except Exception:
        pass
    # Migrate: add url_picture column if not exists (for existing deployments)
    try:
        db_execute("ALTER TABLE productivity ADD COLUMN IF NOT EXISTS url_picture TEXT DEFAULT ''")
    except Exception:
        pass
    print("✅ DB schema ready")

# ─────────────────────────────────────────────
# Sync: Sheets → DB  (run on startup + /api/sync)
# ─────────────────────────────────────────────
def sync_tickets_from_sheets():
    """Pull all tickets from Sheets and upsert into DB. Sheets is master — overwrites all fields."""
    try:
        sheet = get_sheet("NOR_Penalty_Ticket")
        records = rows_to_dicts(sheet)
        if not records:
            return 0

        sheet_ids = set()
        for r in records:
            tid = str(r.get("TICKETID","")).strip()
            if tid:
                sheet_ids.add(tid)

        conn = get_conn()
        count = 0
        try:
            with conn.cursor() as cur:
                for r in records:
                    tid = str(r.get("TICKETID","")).strip()
                    if not tid:
                        continue
                    # Sheets is master — take ALL fields from Sheets including step/fso/final
                    step         = str(r.get("STEP","")).strip()
                    defend_count = int(r.get("DEFEND_COUNT",0) or 0)
                    locked       = str(r.get("LOCKED","")).upper() == "TRUE"
                    fso_decision = str(r.get("FSO พิจารณา (ปรับ/ไม่ปรับ)","")).strip()
                    final_result = str(r.get("FINAL_RESULT","")).strip()
                    owner1       = str(r.get("owner1","")).strip()
                    updated_by   = str(r.get("UPDATED_BY","")).strip()

                    cur.execute("""
                        INSERT INTO tickets
                            (ticketid, data, step, defend_count, locked,
                             fso_decision, final_result, owner1, updated_by, synced_at)
                        VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,NOW())
                        ON CONFLICT (ticketid) DO UPDATE SET
                            data         = EXCLUDED.data,
                            step         = EXCLUDED.step,
                            defend_count = EXCLUDED.defend_count,
                            locked       = EXCLUDED.locked,
                            fso_decision = EXCLUDED.fso_decision,
                            final_result = EXCLUDED.final_result,
                            owner1       = EXCLUDED.owner1,
                            updated_by   = EXCLUDED.updated_by,
                            synced_at    = NOW()
                    """, (tid, json.dumps(r), step, defend_count, locked,
                          fso_decision, final_result, owner1, updated_by))
                    count += 1

                # Delete tickets no longer in Sheets
                cur.execute("SELECT ticketid FROM tickets")
                db_ids = {row["ticketid"] for row in cur.fetchall()}
                to_delete = db_ids - sheet_ids
                if to_delete:
                    cur.execute("DELETE FROM tickets WHERE ticketid = ANY(%s)", (list(to_delete),))
                    print(f"🗑️  Deleted {len(to_delete)} tickets removed from Sheets")

            conn.commit()
        finally:
            release_conn(conn)
        print(f"✅ Synced {count} tickets from Sheets")
        return count
    except Exception as e:
        print(f"❌ Sync error: {e}")
        return 0

def sync_users_from_sheets():
    try:
        sheet = get_sheet("USER_ACCOUNT")
        users = rows_to_dicts(sheet)
        conn = get_conn()
        try:
            with conn.cursor() as cur:
                for u in users:
                    uname = str(u.get("User","")).strip()
                    if not uname:
                        continue
                    raw_pass = str(u.get("Pass","")).strip()
                    cur.execute("""
                        INSERT INTO users (username, name, role, "group", region, province, pass_hash, active)
                        VALUES (%s,%s,%s,%s,%s,%s,%s,%s)
                        ON CONFLICT (username) DO UPDATE SET
                            name=EXCLUDED.name, role=EXCLUDED.role, "group"=EXCLUDED."group",
                            region=EXCLUDED.region, province=EXCLUDED.province,
                            pass_hash=EXCLUDED.pass_hash, active=EXCLUDED.active, synced_at=NOW()
                    """, (
                        uname,
                        str(u.get("Name", uname)),
                        str(u.get("Role","")).strip(),
                        str(u.get("Group","")).strip(),
                        str(u.get("Region","")).strip(),
                        str(u.get("Province","")).strip(),
                        raw_pass,
                        str(u.get("Active","TRUE")).strip().upper() == "TRUE",
                    ))
            conn.commit()
        finally:
            release_conn(conn)
        print(f"✅ Synced {len(users)} users")
    except Exception as e:
        print(f"❌ User sync error: {e}")

def sync_productivity_from_sheets():
    """Sync Sheet1 (productivity/MAXMA) → DB. Handles 90k rows with batch insert."""
    try:
        gc = get_gc()
        ss = gc.open_by_key(DRILLDOWN_SHEET_ID)
        ws = ss.worksheet(DRILLDOWN_SHEET_NAME)
        print("🔄 Reading Sheet1 (this may take 30-60s for 90k rows)...")
        all_vals = sheets_retry(ws.get_all_values)
        if not all_vals:
            return 0

        # Find header row
        header_idx = 0
        for i, row in enumerate(all_vals[:5]):
            if any(str(c).strip() in ('Ticket','Plan','Team ID') for c in row):
                header_idx = i
                break

        headers = [str(h).strip() for h in all_vals[header_idx]]

        # Column mapping
        def col(name):
            try: return headers.index(name)
            except ValueError: return None

        c_ticket  = col('Ticket')
        c_plan    = col('Plan')
        c_team    = col('Team ID')
        c_que     = col('Que')
        c_travel  = col('เวลาเดินทาง')
        c_start   = col('เวลาเริ่มซ่อม')
        c_hold    = col('Hold')
        c_linkup  = col('Link Up')
        c_status  = col('Status Team')
        c_hreason = col('สาเหตุการ Hold')
        c_log     = col('Update Log')
        c_cause1  = col('สาเหตุ 1')
        c_fix     = col('วิธีแก้ไข')
        c_detail  = col('รายละเอียดการเก็บงาน')
        c_urlpic  = col('URL PICTURE')

        def g(row, idx):
            if idx is None or idx >= len(row): return ''
            return str(row[idx]).strip()

        data_rows = all_vals[header_idx+1:]
        print(f"📊 Processing {len(data_rows)} rows...")

        conn = get_conn()
        try:
            with conn.cursor() as cur:
                # Clear existing data
                cur.execute("TRUNCATE TABLE productivity RESTART IDENTITY")

                # Batch insert — 1000 rows at a time
                batch_size = 1000
                count = 0
                for i in range(0, len(data_rows), batch_size):
                    batch = data_rows[i:i+batch_size]
                    values = []
                    for row in batch:
                        padded = row + [''] * max(0, len(headers) - len(row))
                        row_dict = dict(zip(headers, padded))
                        ticket_val = g(padded, c_ticket)
                        if not ticket_val:
                            continue
                        values.append((
                            ticket_val,
                            g(padded, c_plan),
                            g(padded, c_team),
                            g(padded, c_que),
                            g(padded, c_travel),
                            g(padded, c_start),
                            g(padded, c_hold),
                            g(padded, c_linkup),
                            g(padded, c_status),
                            g(padded, c_hreason),
                            g(padded, c_log),
                            g(padded, c_cause1),
                            g(padded, c_fix),
                            g(padded, c_detail),
                            g(padded, c_urlpic),
                            json.dumps(row_dict),
                        ))
                        count += 1

                    if values:
                        cur.executemany("""
                            INSERT INTO productivity
                                (ticket,plan,team_id,que,travel_time,start_repair,
                                 hold,link_up,status_team,hold_reason,update_log,
                                 cause1,fix_method,work_detail,url_picture,raw_data)
                            VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
                        """, values)

                    if (i // batch_size) % 10 == 0:
                        print(f"  → {count} rows inserted...")

                conn.commit()
        finally:
            release_conn(conn)

        print(f"✅ Synced {count} productivity rows")
        return count
    except Exception as e:
        print(f"❌ Productivity sync error: {e}")
        return 0
    """Write workflow fields back to Sheets async (best-effort)."""
    def _write():
        try:
            sheet = get_sheet("NOR_Penalty_Ticket")
            all_vals = sheets_retry(sheet.get_all_values)
            if not all_vals: return
            headers = all_vals[0]
            for i, row in enumerate(all_vals[1:], start=2):
                if len(row) > 0 and str(row[0]).strip() == str(ticketid).strip():
                    updates = []
                    for col_name, value in fields.items():
                        if col_name in headers:
                            col_idx = headers.index(col_name) + 1
                            col_letter = _col_letter(col_idx)
                            updates.append({"range": f"{col_letter}{i}", "values": [[value]]})
                    if updates:
                        sheets_retry(sheet.batch_update, updates, value_input_option="USER_ENTERED")
                    break
        except Exception as e:
            print(f"⚠️ write_back_to_sheets error: {e}")
    threading.Thread(target=_write, daemon=True).start()

def _col_letter(idx):
    result = ""
    while idx > 0:
        idx, rem = divmod(idx - 1, 26)
        result = chr(65 + rem) + result
    return result

# ─────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────
def now_str():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def hash_password(pw):
    return hashlib.sha256(pw.encode()).hexdigest()

def ticket_to_dict(row):
    """Merge DB workflow fields into Sheets data dict."""
    if row is None:
        return None
    d = dict(row.get("data") or {})
    d["TICKETID"]                      = row["ticketid"]
    d["STEP"]                          = row["step"] or ""
    d["DEFEND_COUNT"]                  = str(row["defend_count"] or 0)
    d["LOCKED"]                        = "TRUE" if row["locked"] else ""
    d["FSO พิจารณา (ปรับ/ไม่ปรับ)"]   = row["fso_decision"] or ""
    d["FINAL_RESULT"]                  = row["final_result"] or ""
    d["owner1"]                        = row["owner1"] or ""
    d["UPDATED_BY"]                    = row["updated_by"] or ""
    d["MANAGER_DEFEND"]                = row.get("manager_defend") or ""
    d["Manager Defend Reason"]         = row.get("manager_defend") or ""
    return d

def log_audit(ticketid, action, detail="", step_from="", step_to=""):
    try:
        db_execute("""
            INSERT INTO audit_log (username, name, role, ticketid, action, detail, step_from, step_to)
            VALUES (%s,%s,%s,%s,%s,%s,%s,%s)
        """, (
            session.get("user",""), session.get("name",""), session.get("role",""),
            ticketid, action, str(detail)[:300], step_from, step_to
        ))
    except Exception:
        pass

# ─────────────────────────────────────────────
# Auth decorators
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
            r = str(session.get("role","")).strip().upper()
            if r not in [str(x).strip().upper() for x in roles]:
                return jsonify({"error": f"Forbidden: role '{r}'"}), 403
            return f(*args, **kwargs)
        return decorated
    return decorator

ROLE_ENGINEER = "ENGINEER_ZONE"
ROLE_SITE_SUP = "SITE_SUPERVISOR"
ROLE_FSO      = "FSO_ZONE"
ROLE_FSO_MGR  = "FSO_MANAGER"
ROLE_MANAGER  = "BBTEC_MANAGER"

def is_manager(role):
    r = str(role).upper().replace(" ","_")
    return "MANAGER" in r

# ─────────────────────────────────────────────
# Routes — Auth
# ─────────────────────────────────────────────
@app.route("/api/login", methods=["POST"])
def login():
    data = request.json or {}
    username = data.get("username","").strip()
    password = data.get("password","").strip()
    if not username or not password:
        return jsonify({"error": "กรุณากรอก Username และ Password"}), 400
    try:
        u = db_execute("SELECT * FROM users WHERE username=%s AND active=TRUE", (username,), fetch="one")
        if not u:
            # Fallback to Sheets if user not in DB yet
            sheet = get_sheet("USER_ACCOUNT")
            users = rows_to_dicts(sheet)
            u_sheet = next((x for x in users if str(x.get("User","")).strip() == username), None)
            if not u_sheet:
                return jsonify({"error": "Username หรือ Password ไม่ถูกต้อง"}), 401
            if str(u_sheet.get("Active","")).upper() != "TRUE":
                return jsonify({"error": "บัญชีนี้ถูกระงับ"}), 403
            stored = str(u_sheet.get("Pass","")).strip()
            if stored != password and stored != hash_password(password):
                return jsonify({"error": "Username หรือ Password ไม่ถูกต้อง"}), 401
            session.update({
                "user": username, "name": str(u_sheet.get("Name", username)),
                "role": str(u_sheet.get("Role","")).strip(),
                "group": str(u_sheet.get("Group","")).strip(),
                "region": str(u_sheet.get("Region","")).strip(),
                "province": str(u_sheet.get("Province","")).strip(),
            })
        else:
            stored = str(u["pass_hash"]).strip()
            if stored != password and stored != hash_password(password):
                return jsonify({"error": "Username หรือ Password ไม่ถูกต้อง"}), 401
            session.update({
                "user": username, "name": u["name"] or username,
                "role": u["role"] or "", "group": u["group"] or "",
                "region": u["region"] or "", "province": u["province"] or "",
            })
        return jsonify({"success": True, "user": session["name"], "role": session["role"],
                        "region": session["region"], "province": session["province"]})
    except Exception as e:
        return jsonify({"error": f"เชื่อมต่อไม่ได้: {e}"}), 500

@app.route("/api/logout", methods=["POST"])
def logout():
    session.clear()
    return jsonify({"success": True})

@app.route("/api/me")
@login_required
def me():
    return jsonify({k: session.get(k) for k in ["user","name","role","group","region","province"]})

# ─────────────────────────────────────────────
# Routes — Tickets (DB)
# ─────────────────────────────────────────────
@app.route("/api/tickets")
@login_required
def get_tickets():
    try:
        province = session.get("province","")
        region   = session.get("region","")
        allowed  = [p.strip() for p in province.split(",") if p.strip() and p.upper() != "ALL"] if province and province.upper() not in ("ALL","") else []

        rows = db_execute("SELECT ticketid, data, step, defend_count, locked, fso_decision, final_result, owner1, updated_by, COALESCE(manager_defend,'') as manager_defend FROM tickets ORDER BY (data->>'PENALTYBAHT_TRACKB')::numeric DESC NULLS LAST", fetch="all")
        tickets = []
        for row in (rows or []):
            t = ticket_to_dict(row)
            if allowed:
                if str(t.get("TRUEOWNERGROUP","")).strip() not in allowed:
                    continue
            elif region and region.upper() not in ("ALL",""):
                rr = str(t.get("TrackB_Region","")).upper()
                if rr and region.upper() not in rr and not any(x in rr for x in ["NOR1","NOR2","NOR"]):
                    continue
            tickets.append(t)
        return jsonify({"tickets": tickets, "total": len(tickets)})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/ticket/<ticketid>")
@login_required
def get_ticket(ticketid):
    try:
        row = db_execute("SELECT * FROM tickets WHERE ticketid=%s", (ticketid,), fetch="one")
        if not row:
            return jsonify({"error": "ไม่พบ Ticket"}), 404
        return jsonify(ticket_to_dict(row))
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# ─────────────────────────────────────────────
# Step 1 — Engineer
# ─────────────────────────────────────────────
@app.route("/api/ticket/<ticketid>/step1", methods=["POST"])
@login_required
@require_role(ROLE_ENGINEER, ROLE_SITE_SUP, "ENGINEER_ZONE", "Engineer Zone")
def submit_step1(ticketid):
    data = request.json or {}
    try:
        row = db_execute("SELECT locked, step FROM tickets WHERE ticketid=%s", (ticketid,), fetch="one")
        if not row:
            return jsonify({"error": "ไม่พบ Ticket"}), 404
        if row["locked"]:
            return jsonify({"error": "Ticket นี้ถูก Lock แล้ว"}), 403
        if str(row["step"] or "").strip() not in ("","0","1"):
            return jsonify({"error": f"Ticket อยู่ที่ Step {row['step']} แล้ว"}), 403

        overdue = data.get("overdue_detail","")
        if data.get("link_photo",""):
            overdue = f"{overdue} / {data['link_photo']}" if overdue else data["link_photo"]

        db_execute("""
            UPDATE tickets SET
                step='1', owner1=%s, updated_by=%s, last_updated=NOW(),
                data = data ||
                    jsonb_build_object(
                        'Group problem', %s::text,
                        'Sub Problem',   %s::text,
                        'Accident',      %s::text,
                        'Overdue Detail แนบLINK รูป', %s::text,
                        'แนบ LINK ชี้แจง', %s::text,
                        'STEP', '1',
                        'UPDATED_BY', %s::text,
                        'owner1', %s::text
                    )
            WHERE ticketid=%s
        """, (
            session.get("user"), session.get("user"),
            data.get("group_problem",""), data.get("sub_problem",""),
            data.get("accident",""), overdue, data.get("link_evidence",""),
            session.get("user"), session.get("user"),
            ticketid
        ))
        log_audit(ticketid, "STEP1_SUBMIT", f"Group:{data.get('group_problem','')}", "", "1")
        # Write-back to Sheets async
        write_back_to_sheets(ticketid, {
            "owner1": session.get("user",""),
            "STEP": "1", "UPDATED_BY": session.get("user",""),
            "Group problem": data.get("group_problem",""),
            "Sub Problem": data.get("sub_problem",""),
            "Overdue Detail แนบLINK รูป": overdue,
            "แนบ LINK ชี้แจง": data.get("link_evidence",""),
        })
        return jsonify({"success": True, "message": "บันทึก Step 1 สำเร็จ"})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# ─────────────────────────────────────────────
# Step 2 — FSO
# ─────────────────────────────────────────────
@app.route("/api/ticket/<ticketid>/step2", methods=["POST"])
@login_required
@require_role(ROLE_FSO, ROLE_FSO_MGR, "FSO_ZONE", "FSO Zone", "FSO Manager Zone")
def submit_step2(ticketid):
    data = request.json or {}
    decision = data.get("fso_decision","").strip()
    if decision not in ("ปรับ","ไม่ปรับ"):
        return jsonify({"error": "กรุณาเลือก ปรับ หรือ ไม่ปรับ"}), 400
    try:
        row = db_execute("SELECT locked, step FROM tickets WHERE ticketid=%s", (ticketid,), fetch="one")
        if not row: return jsonify({"error":"ไม่พบ Ticket"}), 404
        if row["locked"]: return jsonify({"error":"Ticket ถูก Lock แล้ว"}), 403
        if str(row["step"] or "").strip() not in ("1","2"):
            return jsonify({"error": f"Ticket ยังไม่ผ่าน Step 1"}), 403

        new_step = "4" if decision == "ไม่ปรับ" else "2"
        final    = "ไม่ปรับ" if decision == "ไม่ปรับ" else ""
        locked   = decision == "ไม่ปรับ"

        db_execute("""
            UPDATE tickets SET
                step=%s, fso_decision=%s, final_result=%s, locked=%s,
                updated_by=%s, last_updated=NOW(),
                data = data || jsonb_build_object(
                    'FSO พิจารณา (ปรับ/ไม่ปรับ)', %s::text,
                    'FSO approve (ลงชื่อ FSO)', %s::text,
                    'วันที่ FSO อนุมัติ', %s::text,
                    'Remark FSO', %s::text,
                    'STEP', %s::text,
                    'FINAL_RESULT', %s::text,
                    'UPDATED_BY', %s::text
                )
            WHERE ticketid=%s
        """, (
            new_step, decision, final, locked, session.get("user"),
            decision, session.get("name"), now_str(), data.get("remark",""),
            new_step, final, session.get("user"),
            ticketid
        ))
        log_audit(ticketid, "FSO_DECISION", f"ผล:{decision}", "1", new_step)
        write_back_to_sheets(ticketid, {
            "FSO พิจารณา (ปรับ/ไม่ปรับ)": decision,
            "FSO approve (ลงชื่อ FSO)": session.get("name",""),
            "Remark FSO": data.get("remark",""),
            "STEP": new_step, "FINAL_RESULT": final,
            "LOCKED": "TRUE" if locked else "",
        })
        msg = "FSO ตัดสิน: ไม่ปรับ — Lock แล้ว" if decision=="ไม่ปรับ" else "FSO ตัดสิน: ปรับ — Engineer สามารถขอ Defend ได้"
        return jsonify({"success": True, "message": msg, "fso_decision": decision})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# ─────────────────────────────────────────────
# Step 3 — Defend Request (Engineer)
# ─────────────────────────────────────────────
@app.route("/api/ticket/<ticketid>/defend/request", methods=["POST"])
@login_required
@require_role(ROLE_ENGINEER, ROLE_SITE_SUP, "ENGINEER_ZONE", "Engineer Zone")
def request_defend(ticketid):
    data = request.json or {}
    reason = data.get("defend_reason","").strip()
    if not reason: return jsonify({"error": "กรุณากรอกเหตุผล"}), 400
    try:
        row = db_execute("SELECT locked, step, defend_count, fso_decision FROM tickets WHERE ticketid=%s", (ticketid,), fetch="one")
        if not row: return jsonify({"error":"ไม่พบ Ticket"}), 404
        if row["locked"]: return jsonify({"error":"Ticket ถูก Lock แล้ว"}), 403
        if str(row["step"] or "") not in ("2","3"): return jsonify({"error":"ยังไม่ถึง Step Defend"}), 403
        if str(row["fso_decision"] or "") == "ไม่ปรับ": return jsonify({"error":"FSO ตัดสิน ไม่ปรับ แล้ว"}), 403
        dc = int(row["defend_count"] or 0)
        if dc >= 2: return jsonify({"error":"หมดสิทธิ์ Defend (สูงสุด 2 ครั้ง)"}), 403

        col_defend = "BBTEC Defend\nไม่สมควรปรับ"
        db_execute("""
            UPDATE tickets SET step='3', defend_count=%s, updated_by=%s, last_updated=NOW(),
                data = data || jsonb_build_object(
                    %s, %s::text, 'STEP','3','DEFEND_COUNT',%s::text,'UPDATED_BY',%s::text
                )
            WHERE ticketid=%s
        """, (dc+1, session.get("user"), col_defend, reason, str(dc+1), session.get("user"), ticketid))
        log_audit(ticketid, "DEFEND_REQUEST", f"ครั้ง:{dc+1}", "2", "3")
        write_back_to_sheets(ticketid, {
            col_defend: reason,
            "STEP": "3", "DEFEND_COUNT": str(dc+1), "UPDATED_BY": session.get("user",""),
        })
        return jsonify({"success": True, "message": f"ส่งคำขอ Defend ครั้งที่ {dc+1}", "defend_count": dc+1})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# ─────────────────────────────────────────────
# Step 3 — Defend Review (FSO)
# ─────────────────────────────────────────────
@app.route("/api/ticket/<ticketid>/defend/review", methods=["POST"])
@login_required
@require_role(ROLE_FSO, ROLE_FSO_MGR, "FSO_ZONE", "FSO Zone", "FSO Manager Zone")
def review_defend(ticketid):
    data = request.json or {}
    decision = data.get("decision","").strip()
    if decision not in ("ปรับ","ไม่ปรับ"): return jsonify({"error":"กรุณาเลือกผล"}), 400
    try:
        row = db_execute("SELECT locked, defend_count FROM tickets WHERE ticketid=%s", (ticketid,), fetch="one")
        if not row: return jsonify({"error":"ไม่พบ Ticket"}), 404
        if row["locked"]: return jsonify({"error":"Ticket ถูก Lock แล้ว"}), 403
        dc = int(row["defend_count"] or 0)

        if decision == "ไม่ปรับ":
            new_step, final, locked, msg = "4","ไม่ปรับ",True,"Defend สำเร็จ — ไม่ปรับ Lock แล้ว"
        elif dc >= 2:
            new_step, final, locked, msg = "4","ปรับ",True,"Defend ครบ 2 ครั้ง — ยืนยัน ปรับ Lock แล้ว"
        else:
            new_step, final, locked = "2","",False
            msg = f"FSO ยังตัดสิน ปรับ — Engineer ขอ Defend ครั้งที่ {dc+1} ได้"

        db_execute("""
            UPDATE tickets SET step=%s, fso_decision=%s, final_result=%s, locked=%s,
                updated_by=%s, last_updated=NOW(),
                data = data || jsonb_build_object(
                    'FSO พิจารณา (ปรับ/ไม่ปรับ)',%s::text,
                    'FSO approve (ลงชื่อ FSO)',%s::text,
                    'Remark FSO',%s::text,
                    'STEP',%s::text,'FINAL_RESULT',%s::text,
                    'LOCKED',%s::text,'UPDATED_BY',%s::text
                )
            WHERE ticketid=%s
        """, (
            new_step, decision, final, locked, session.get("user"),
            decision, session.get("name"), data.get("remark",""),
            new_step, final, "TRUE" if locked else "", session.get("user"),
            ticketid
        ))
        log_audit(ticketid, "DEFEND_REVIEW", f"ผล:{decision}", "3", new_step)
        write_back_to_sheets(ticketid, {
            "FSO พิจารณา (ปรับ/ไม่ปรับ)": decision,
            "Remark FSO": data.get("remark",""),
            "STEP": new_step, "FINAL_RESULT": final,
            "LOCKED": "TRUE" if locked else "",
        })
        return jsonify({"success": True, "message": msg, "decision": decision, "defend_count": dc})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# ─────────────────────────────────────────────
# Accept Penalty
# ─────────────────────────────────────────────
@app.route("/api/ticket/<ticketid>/accept", methods=["POST"])
@login_required
def accept_penalty(ticketid):
    try:
        db_execute("""
            UPDATE tickets SET step='4', final_result='ปรับ', locked=TRUE,
                updated_by=%s, last_updated=NOW(),
                data = data || jsonb_build_object('STEP','4','FINAL_RESULT','ปรับ','LOCKED','TRUE','UPDATED_BY',%s::text)
            WHERE ticketid=%s AND NOT locked
        """, (session.get("user"), session.get("user"), ticketid))
        log_audit(ticketid, "ACCEPT_PENALTY","ยอมรับค่าปรับ","2","4")
        write_back_to_sheets(ticketid, {"STEP":"4","FINAL_RESULT":"ปรับ","LOCKED":"TRUE"})
        return jsonify({"success": True, "message": "ยอมรับค่าปรับแล้ว"})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# ─────────────────────────────────────────────
# Manager Approve
# ─────────────────────────────────────────────
@app.route("/api/ticket/<ticketid>/approve", methods=["POST"])
@login_required
def manager_approve(ticketid):
    try:
        row = db_execute("SELECT step, final_result FROM tickets WHERE ticketid=%s", (ticketid,), fetch="one")
        if not row: return jsonify({"error":"ไม่พบ Ticket"}), 404
        if str(row["step"] or "") != "4":
            return jsonify({"error":"Ticket ยังไม่อยู่ที่ Step 4"}), 403

        db_execute("""
            UPDATE tickets SET step='5', updated_by=%s, last_updated=NOW(),
                data = data || jsonb_build_object('STEP','5','UPDATED_BY',%s::text,'Reviewer',%s::text)
            WHERE ticketid=%s
        """, (session.get("user"), session.get("user"), session.get("name"), ticketid))
        log_audit(ticketid,"MANAGER_APPROVE","อนุมัติ","4","5")
        write_back_to_sheets(ticketid,{"STEP":"5","Reviewer":session.get("name","")})
        return jsonify({"success": True, "message": "Manager อนุมัติสำเร็จ"})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# ─────────────────────────────────────────────
# Bulk Approve
# ─────────────────────────────────────────────
@app.route("/api/tickets/bulk-approve", methods=["POST"])
@login_required
def bulk_approve():
    data = request.json or {}
    ids = data.get("ticket_ids", [])
    if not ids: return jsonify({"error":"ไม่มี ticket ที่เลือก"}), 400
    ok, fail = [], []
    for tid in ids:
        try:
            row = db_execute("SELECT step FROM tickets WHERE ticketid=%s", (tid,), fetch="one")
            if row and str(row["step"] or "") == "4":
                db_execute("""
                    UPDATE tickets SET step='5', updated_by=%s, last_updated=NOW(),
                        data=data||jsonb_build_object('STEP','5','UPDATED_BY',%s::text,'Reviewer',%s::text)
                    WHERE ticketid=%s
                """, (session.get("user"), session.get("user"), session.get("name"), tid))
                write_back_to_sheets(tid,{"STEP":"5","Reviewer":session.get("name","")})
                ok.append(tid)
            else:
                fail.append(tid)
        except Exception:
            fail.append(tid)
    return jsonify({"success": True, "approved": len(ok), "failed": len(fail)})

# ─────────────────────────────────────────────
# Dashboard Summary (from DB — fast!)
# ─────────────────────────────────────────────
@app.route("/api/dashboard/summary")
@login_required
def dashboard_summary():
    try:
        rows = db_execute("SELECT step, defend_count, locked, fso_decision, final_result, data FROM tickets", fetch="all")
        total=reviewed=fso_penalty=fso_no_penalty=0
        defend_req=defend_round2=0
        final_penalty=final_no_penalty=approved=0
        total_baht=final_baht=0

        for row in (rows or []):
            total += 1
            try:
                total_baht += float(str(row["data"].get("PENALTYBAHT_TRACKB","0") or "0").replace(",",""))
            except: pass
            s  = str(row["step"] or "").strip()
            fd = str(row["fso_decision"] or "").strip()
            fr = str(row["final_result"] or "").strip()
            dc = int(row["defend_count"] or 0)

            # reviewed = มีการ submit Step 1 ขึ้นไปแล้ว
            if s in ("1","2","3","4","5"): reviewed += 1

            # FSO decision — นับเฉพาะที่ FSO ตัดสินแล้วจริงๆ (step >= 2)
            if s in ("2","3","4","5"):
                if fd == "ปรับ":   fso_penalty += 1
                elif fd == "ไม่ปรับ": fso_no_penalty += 1

            # Defend — นับเฉพาะ ticket ที่เคยขอ Defend (defend_count > 0)
            # ไม่นับ ticket ที่ไม่ปรับตั้งแต่แรก (ไม่ได้ defend)
            if dc > 0:
                defend_req += 1
                if dc >= 2: defend_round2 += 1

            # Final result — step 4 หรือ 5 เท่านั้น
            if s in ("4","5"):
                if fr == "ปรับ":
                    final_penalty += 1
                    try: final_baht += float(str(row["data"].get("PENALTYBAHT_TRACKB","0") or "0").replace(",",""))
                    except: pass
                elif fr == "ไม่ปรับ":
                    final_no_penalty += 1

            if s == "5": approved += 1

        # defend_success = ticket ที่ defend แล้วได้ผล ไม่ปรับ
        defend_success = 0
        no_defend_count = 0  # FSO ตัดสินปรับ แต่ไม่ขอ Defend (ยอมรับหรือรอ)
        for row in (rows or []):
            dc = int(row["defend_count"] or 0)
            fr = str(row["final_result"] or "").strip()
            fd = str(row["fso_decision"] or "").strip()
            s  = str(row["step"] or "").strip()
            if dc > 0 and fr == "ไม่ปรับ":
                defend_success += 1
            # ไม่ Defend = FSO ตัดสินปรับ + step >= 2 + defend_count = 0
            if fd == "ปรับ" and dc == 0 and s in ("2","4","5"):
                no_defend_count += 1

        return jsonify({
            "total": total, "reviewed": reviewed,
            "fso_penalty": fso_penalty, "fso_no_penalty": fso_no_penalty,
            "defend_req": defend_req, "defend_success": defend_success,
            "no_defend": no_defend_count,
            "defend_round2": defend_round2,
            "final_penalty": final_penalty, "final_no_penalty": final_no_penalty,
            "approved": approved, "pending_approve": max(0, final_penalty - approved),
            "total_penalty_baht": total_baht, "final_penalty_baht": final_baht,
            "saved_baht": max(0, total_baht - final_baht),
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# ─────────────────────────────────────────────
# Audit log
# ─────────────────────────────────────────────
@app.route("/api/ticket/<ticketid>/audit")
@login_required
def get_audit_log(ticketid):
    try:
        rows = db_execute(
            "SELECT ts, username, name, role, action, detail, step_from, step_to FROM audit_log WHERE ticketid=%s ORDER BY ts DESC",
            (ticketid,), fetch="all"
        )
        logs = [{"timestamp": str(r["ts"]), "user": r["username"], "name": r["name"],
                 "role": r["role"], "action": r["action"], "detail": r["detail"],
                 "step_from": r["step_from"], "step_to": r["step_to"]} for r in (rows or [])]
        return jsonify({"logs": logs})
    except Exception as e:
        return jsonify({"logs": []})

# ─────────────────────────────────────────────
# Sync endpoints
# ─────────────────────────────────────────────
@app.route("/api/sync", methods=["POST"])
@login_required
def manual_sync():
    try:
        count = sync_tickets_from_sheets()
        sync_users_from_sheets()
        return jsonify({"success": True, "synced": count})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/sync/status")
@login_required
def sync_status():
    try:
        row = db_execute("SELECT COUNT(*) as cnt, MAX(synced_at) as last_sync FROM tickets", fetch="one")
        return jsonify({"tickets": row["cnt"], "last_sync": str(row["last_sync"])})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# ─────────────────────────────────────────────
# Drill Down — Queue data from MAXMA sheet
# ─────────────────────────────────────────────
DRILLDOWN_SHEET_ID   = "1_l5UAj1etjGgLCR4DSG6qDoK8c1unFnO6NVHVwvmbAU"
DRILLDOWN_SHEET_NAME = "Sheet1"
DRILLDOWN_COLS = ['Plan','Team ID','Que','เวลาเดินทาง','เวลาเริ่มซ่อม',
                  'Hold','Link Up','Status Team','สาเหตุการ Hold','Update Log',
                  'สาเหตุ 1','วิธีแก้ไข','รายละเอียดการเก็บงาน','URL PICTURE']

@app.route("/api/drilldown-sheets")
@login_required
def list_drilldown_sheets():
    try:
        gc = get_gc()
        ss = gc.open_by_key(DRILLDOWN_SHEET_ID)
        sheets = [ws.title for ws in ss.worksheets()]
        return jsonify({"sheets": sheets})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/drilldown/<ticketid>")
@login_required
def drilldown(ticketid):
    """Fast drilldown from PostgreSQL — ~50ms vs 5-8s from Sheets."""
    try:
        tid_clean = str(ticketid).strip()
        rows = db_execute("""
            SELECT plan, team_id, que, travel_time, start_repair,
                   hold, link_up, status_team, hold_reason, update_log,
                   cause1, fix_method, work_detail, url_picture
            FROM productivity
            WHERE ticket = %s
            ORDER BY id
        """, (tid_clean,), fetch="all")

        if rows is None or len(rows) == 0:
            cnt = db_execute("SELECT COUNT(*) as c FROM productivity", fetch="one")
            if cnt and cnt["c"] == 0:
                return jsonify({
                    "rows": [],
                    "message": "ยังไม่มีข้อมูล Productivity ใน DB กรุณากด Sync Productivity ก่อนครับ"
                })
            return jsonify({"rows": [], "total": 0})

        result = []
        col_map = {
            "Plan": "plan", "Team ID": "team_id", "Que": "que",
            "เวลาเดินทาง": "travel_time", "เวลาเริ่มซ่อม": "start_repair",
            "Hold": "hold", "Link Up": "link_up", "Status Team": "status_team",
            "สาเหตุการ Hold": "hold_reason", "Update Log": "update_log",
            "สาเหตุ 1": "cause1", "วิธีแก้ไข": "fix_method",
            "รายละเอียดการเก็บงาน": "work_detail",
            "URL PICTURE": "url_picture"
        }
        for row in rows:
            result.append({k: row[v] or '' for k, v in col_map.items()})

        return jsonify({"rows": result, "total": len(result), "source": "postgresql"})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/change-password", methods=["POST"])
@login_required
def change_password():
    data = request.json or {}
    old_pwd = str(data.get("old_password","")).strip()
    new_pwd = str(data.get("new_password","")).strip()

    if not old_pwd or not new_pwd:
        return jsonify({"error": "กรุณากรอกข้อมูลให้ครบ"}), 400
    if len(new_pwd) < 8:
        return jsonify({"error": "รหัสผ่านใหม่ต้องมีอย่างน้อย 8 ตัวอักษร"}), 400
    if old_pwd == new_pwd:
        return jsonify({"error": "รหัสผ่านใหม่ต้องไม่เหมือนรหัสผ่านเดิม"}), 400

    try:
        username = session.get("user")
        u = db_execute("SELECT pass_hash FROM users WHERE username=%s", (username,), fetch="one")
        if not u:
            return jsonify({"error": "ไม่พบผู้ใช้"}), 404

        stored = str(u["pass_hash"]).strip()
        # Accept plain text or hashed
        if stored != old_pwd and stored != hash_password(old_pwd):
            return jsonify({"error": "รหัสผ่านเดิมไม่ถูกต้อง"}), 401

        # Save new password (store as plain for now, matching existing system)
        db_execute("UPDATE users SET pass_hash=%s WHERE username=%s", (new_pwd, username))

        # Also update in Sheets async (best effort)
        def _update_sheet():
            try:
                sheet = get_sheet("USER_ACCOUNT")
                all_vals = sheets_retry(sheet.get_all_values)
                if not all_vals: return
                headers = [str(h).strip() for h in all_vals[0]]
                if 'User' not in headers or 'Pass' not in headers: return
                user_col = headers.index('User') + 1
                pass_col = headers.index('Pass') + 1
                for i, row in enumerate(all_vals[1:], start=2):
                    if len(row) >= user_col and str(row[user_col-1]).strip() == username:
                        sheets_retry(sheet.update_cell, i, pass_col, new_pwd)
                        break
            except Exception as e:
                print(f"⚠️ Sheet password update failed: {e}")
        threading.Thread(target=_update_sheet, daemon=True).start()

        return jsonify({"success": True, "message": "เปลี่ยนรหัสผ่านสำเร็จ"})
    except Exception as e:
        return jsonify({"error": str(e)}), 500
@login_required
def sync_productivity():
    """Sync Sheet1 → productivity table. Run every 3 days."""
    def _run():
        sync_productivity_from_sheets()
    threading.Thread(target=_run, daemon=True).start()
    return jsonify({
        "success": True,
        "message": "เริ่ม Sync Productivity แล้ว (90k rows ใช้เวลา ~2-3 นาที) ตรวจสอบ logs ได้ที่ Railway"
    })

# ─────────────────────────────────────────────
# Static + health
# ─────────────────────────────────────────────

# ─────────────────────────────────────────────
# Manager Defend — Request (BBTEC_MANAGER)
# ─────────────────────────────────────────────
@app.route("/api/ticket/<ticketid>/manager-defend/request", methods=["POST"])
@login_required
def manager_defend_request(ticketid):
    data = request.json or {}
    reason = str(data.get("reason","")).strip()
    if not reason:
        return jsonify({"error": "กรุณากรอกเหตุผล"}), 400
    try:
        row = db_execute("SELECT step, defend_count, final_result, locked FROM tickets WHERE ticketid=%s", (ticketid,), fetch="one")
        if not row: return jsonify({"error":"ไม่พบ Ticket"}), 404
        if row["locked"]: return jsonify({"error":"Ticket ถูก Lock แล้ว"}), 403
        if str(row["step"] or "") != "4": return jsonify({"error":"Ticket ต้องอยู่ที่ Step 4 ก่อน"}), 403
        if int(row["defend_count"] or 0) < 2: return jsonify({"error":"ใช้ได้เมื่อ Defend ครบ 2 ครั้งเท่านั้น"}), 403
        if str(row["final_result"] or "").strip() != "ปรับ": return jsonify({"error":"ใช้ได้เฉพาะ ticket ที่ถูกตัดสิน ปรับ"}), 403

        # Check if manager_defend already used
        row2 = db_execute("SELECT COALESCE(manager_defend,'') as mgr FROM tickets WHERE ticketid=%s", (ticketid,), fetch="one")
        if row2 and str(row2["mgr"]).strip(): return jsonify({"error":"Manager Defend ถูกใช้ไปแล้ว"}), 403

        db_execute("""
            UPDATE tickets SET step='3', manager_defend=%s, updated_by=%s, last_updated=NOW(),
                data = data || jsonb_build_object(
                    'STEP','3','Manager Defend Reason',%s::text,'MANAGER_DEFEND',%s::text,'UPDATED_BY',%s::text
                )
            WHERE ticketid=%s
        """, (reason, session.get("user"), reason, reason, session.get("user"), ticketid))
        log_audit(ticketid,"MANAGER_DEFEND_REQUEST",f"เหตุผล:{reason[:100]}","4","3")
        write_back_to_sheets(ticketid,{"STEP":"3","Manager Defend Reason":reason})
        return jsonify({"success":True,"message":"ส่ง Manager Defend แล้ว รอ FSO Manager ตัดสิน"})
    except Exception as e:
        return jsonify({"error":str(e)}), 500

# ─────────────────────────────────────────────
# Manager Defend — Review (FSO_MANAGER only)
# ─────────────────────────────────────────────
@app.route("/api/ticket/<ticketid>/manager-defend/review", methods=["POST"])
@login_required
def manager_defend_review(ticketid):
    data = request.json or {}
    decision = str(data.get("decision","")).strip()
    if decision not in ("ปรับ","ไม่ปรับ"):
        return jsonify({"error":"กรุณาเลือกผลการพิจารณา"}), 400
    role = str(session.get("role","")).upper().replace(" ","_")
    if "FSO_MANAGER" not in role:
        return jsonify({"error":"เฉพาะ FSO Manager เท่านั้นที่ตัดสินได้"}), 403
    try:
        row = db_execute("SELECT step, COALESCE(manager_defend,'') as mgr FROM tickets WHERE ticketid=%s", (ticketid,), fetch="one")
        if not row: return jsonify({"error":"ไม่พบ Ticket"}), 404
        if str(row["step"] or "") != "3": return jsonify({"error":"Ticket ไม่ได้อยู่ใน Manager Defend step"}), 403
        if not str(row["mgr"]).strip(): return jsonify({"error":"ไม่พบ Manager Defend request"}), 403

        remark = str(data.get("remark","")).strip()
        db_execute("""
            UPDATE tickets SET step='4', final_result=%s, locked=TRUE,
                manager_defend_remark=%s, updated_by=%s, last_updated=NOW(),
                data = data || jsonb_build_object(
                    'STEP','4','FINAL_RESULT',%s::text,'LOCKED','TRUE',
                    'Remark FSO Manager (Final)',%s::text,
                    'FSO พิจารณา (ปรับ/ไม่ปรับ)',%s::text,'UPDATED_BY',%s::text
                )
            WHERE ticketid=%s
        """, (decision, remark, session.get("user"), decision, remark, decision, session.get("user"), ticketid))
        log_audit(ticketid,"FSO_MANAGER_FINAL",f"ผล:{decision}","3","4")
        write_back_to_sheets(ticketid,{"STEP":"4","FINAL_RESULT":decision,"LOCKED":"TRUE","Remark FSO Manager (Final)":remark})
        msg = "FSO Manager ตัดสิน: ไม่ปรับ ✅" if decision=="ไม่ปรับ" else "FSO Manager ตัดสิน: ยังปรับ 🔒"
        return jsonify({"success":True,"message":msg,"decision":decision})
    except Exception as e:
        return jsonify({"error":str(e)}), 500

@app.route("/system-flow.png")
def serve_sysflow():
    return send_from_directory(app.static_folder, "system-flow.png")

@app.route("/health")
def health():
    return jsonify({"status": "ok", "db": "postgresql", "service": "BBTEC Smart Defense"}), 200

@app.route("/", defaults={"path": ""})
@app.route("/<path:path>")
def serve_frontend(path):
    if path and os.path.exists(os.path.join(app.static_folder, path)):
        return send_from_directory(app.static_folder, path)
    return send_from_directory(app.static_folder, "index.html")

# ─────────────────────────────────────────────
# Startup
# ─────────────────────────────────────────────
def startup():
    if not DATABASE_URL:
        print("⚠️  DATABASE_URL not set — DB features disabled")
        return
    try:
        init_db()
        # Initial sync on first boot
        row = db_execute("SELECT COUNT(*) as cnt FROM tickets", fetch="one")
        if row["cnt"] == 0:
            print("🔄 First boot — syncing from Sheets...")
            sync_tickets_from_sheets()
            sync_users_from_sheets()
        else:
            print(f"✅ DB has {row['cnt']} tickets — skipping initial sync")
    except Exception as e:
        print(f"❌ Startup error: {e}")

with app.app_context():
    startup()

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=False)
