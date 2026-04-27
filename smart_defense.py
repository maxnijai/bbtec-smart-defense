import os, json, time, hmac, hashlib, base64, logging, re
from datetime import datetime, timezone
from functools import wraps
from typing import Dict, List, Any, Tuple

from flask import Blueprint, request, jsonify
import gspread
from google.oauth2.service_account import Credentials

log = logging.getLogger('smart_defense')
logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(message)s')

bp = Blueprint('smart_defense', __name__, url_prefix='/api/smart-defense')

# ====== ENV ======
SHEET_ID = os.environ.get('SMART_DEFENSE_SHEET_ID', '1RBWr-lKva_XOqmcKwEE-E7hqIodbWWK1XHzuV8QJ-7Q')
TICKET_SHEET = os.environ.get('SMART_DEFENSE_TICKET_SHEET', 'NOR_Penalty_Ticket')
USER_SHEET = os.environ.get('SMART_DEFENSE_USER_SHEET', 'USER_ACCOUNT')
AUDIT_SHEET = os.environ.get('SMART_DEFENSE_AUDIT_SHEET', 'SD_AUDIT_LOG')
SECRET = os.environ.get('SMART_DEFENSE_SECRET', 'bbtec-2026-secure')
CACHE_TICKETS_SEC = int(os.environ.get('SMART_DEFENSE_CACHE_TICKETS_SEC', '600'))
CACHE_USERS_SEC = int(os.environ.get('SMART_DEFENSE_CACHE_USERS_SEC', '900'))
MIN_READ_INTERVAL_SEC = int(os.environ.get('SMART_DEFENSE_MIN_READ_INTERVAL_SEC', '90'))
AUDIT_LOGIN = os.environ.get('SMART_DEFENSE_AUDIT_LOGIN', 'FALSE').upper() == 'TRUE'

# ====== ROLE CONSTANTS ======
REGION_MAP = {
    'TRUE-TH-BBT-NOR1-CMI1-NOP': 'NOR1','TRUE-TH-BBT-NOR1-CMI2-NOP': 'NOR1','TRUE-TH-BBT-NOR1-CRI-NOP': 'NOR1',
    'TRUE-TH-BBT-NOR1-LPG-NOP': 'NOR1','TRUE-TH-BBT-NOR1-LPN-NOP': 'NOR1','TRUE-TH-BBT-NOR1-MHS-NOP': 'NOR1',
    'TRUE-TH-BBT-NOR1-NAN-NOP': 'NOR1','TRUE-TH-BBT-NOR1-PHE-NOP': 'NOR1','TRUE-TH-BBT-NOR1-PYO-NOP': 'NOR1',
    'TRUE-TH-BBT-NOR2-KPP-NOP': 'NOR2','TRUE-TH-BBT-NOR2-PCB-NOP': 'NOR2','TRUE-TH-BBT-NOR2-PCT-NOP': 'NOR2',
    'TRUE-TH-BBT-NOR2-PSN-NOP': 'NOR2','TRUE-TH-BBT-NOR2-SKT-NOP': 'NOR2','TRUE-TH-BBT-NOR2-TAK-NOP': 'NOR2','TRUE-TH-BBT-NOR2-UTR-NOP': 'NOR2',
}
ALIAS = {
    'CMI1':'TRUE-TH-BBT-NOR1-CMI1-NOP','CMI2':'TRUE-TH-BBT-NOR1-CMI2-NOP','CRI':'TRUE-TH-BBT-NOR1-CRI-NOP',
    'LPG':'TRUE-TH-BBT-NOR1-LPG-NOP','LPN':'TRUE-TH-BBT-NOR1-LPN-NOP','MHS':'TRUE-TH-BBT-NOR1-MHS-NOP',
    'NAN':'TRUE-TH-BBT-NOR1-NAN-NOP','PHE':'TRUE-TH-BBT-NOR1-PHE-NOP','PYO':'TRUE-TH-BBT-NOR1-PYO-NOP',
    'KPP':'TRUE-TH-BBT-NOR2-KPP-NOP','PCB':'TRUE-TH-BBT-NOR2-PCB-NOP','PCT':'TRUE-TH-BBT-NOR2-PCT-NOP',
    'PSN':'TRUE-TH-BBT-NOR2-PSN-NOP','SKT':'TRUE-TH-BBT-NOR2-SKT-NOP','TAK':'TRUE-TH-BBT-NOR2-TAK-NOP','UTR':'TRUE-TH-BBT-NOR2-UTR-NOP',
}

# Existing source headers (read-only display)
HEADER_ALIASES = {
    'ticket_id': ['TICKETID','Ticket ID','Ticket','TICKET'],
    'severity': ['TRUESEVERITY_DESC','SEVERITY','TRUESEVERITY'],
    'creation': ['CREATIONDATE','Creation Date','CREATEDATE'],
    'target': ['TARGETFINISH','Target Finish','TARGET_FINISH'],
    'subject': ['SUBJECT','Subject'],
    'external': ['EXTERNALSYSTEM_TICKETID','EXTERNAL SYSTEM TICKETID','External Ticket'],
    'penalty': ['PENALTYBAHT_TRACKB','PENALTY','Penalty','Penalty Baht'],
    'owner': ['TRUEOWNERGROUP','OWNERGROUP','OWNER_GROUP','Province','PROVINCE'],
    'region': ['REGION','Region'],
    'province': ['PROVINCE','Province','TRUEOWNERGROUP'],
    # editable source columns
    'group_problem': ['Group problem','GROUP PROBLEM','GROUP_PROBLEM'],
    'sub_problem': ['Sub Problem','SUB PROBLEM','SUB_PROBLEM'],
    'accident': ['Accident','ACCIDENT'],
    'overdue_detail': ['Overdue Detail แนบLINK รูป','Overdue Detail','OVERDUE_DETAIL'],
    'explain_link': ['แนบ LINK ชี้แจง','Explain Link','EXPLAIN_LINK'],
    'fso_decision': ['FSO พิจารณา (ปรับ/ไม่ปรับ)','FSO_DECISION'],
    'fso_approve': ['FSO approve (ลงชื่อ FSO)','FSO_APPROVE'],
    'fso_approve_date': ['วันที่ FSO อนุมัติ','FSO_APPROVE_DATE'],
    'fso_remark': ['Remark FSO','FSO_REMARK'],
}

# Workflow columns - MUST exist in Google Sheet; backend will NOT add headers automatically
WF_HEADERS = {
    'sd_step':'SD_STEP',
    'sd_status':'SD_STATUS',
    'sd_engineer_confirm':'SD_ENGINEER_CONFIRM',
    'sd_engineer_confirm_by':'SD_ENGINEER_CONFIRM_BY',
    'sd_engineer_confirm_at':'SD_ENGINEER_CONFIRM_AT',
    'sd_fso_confirm':'SD_FSO_CONFIRM',
    'sd_fso_confirm_by':'SD_FSO_CONFIRM_BY',
    'sd_fso_confirm_at':'SD_FSO_CONFIRM_AT',
    'sd_defend_count':'SD_DEFEND_COUNT',
    'sd_defend_request':'SD_DEFEND_REQUEST',
    'sd_defend_by':'SD_DEFEND_BY',
    'sd_defend_at':'SD_DEFEND_AT',
    'sd_final_status':'SD_FINAL_STATUS',
    'sd_manager_approve':'SD_MANAGER_APPROVE',
    'sd_manager_approve_by':'SD_MANAGER_APPROVE_BY',
    'sd_manager_approve_at':'SD_MANAGER_APPROVE_AT',
    'sd_updated_by':'SD_UPDATED_BY',
    'sd_updated_at':'SD_UPDATED_AT',
}

AUDIT_HEADERS = ['TIME','USER','GROUP','ROLE','ACTION','TICKETID','STEP','DETAIL']

_cache = {'tickets': None, 'ticket_ts': 0, 'ticket_headers': None, 'ticket_colmap': None,
          'users': None, 'user_ts': 0, 'last_ticket_read_attempt': 0, 'last_error': None}

# ====== UTIL ======
def now_iso():
    return datetime.now(timezone.utc).astimezone().strftime('%Y-%m-%d %H:%M:%S')

def norm(v):
    return str(v or '').strip()

def norm_key(v):
    return re.sub(r'\s+', ' ', str(v or '').strip()).upper()

def parse_list(v):
    if v is None: return []
    s = str(v).strip()
    if not s: return []
    return [x.strip() for x in re.split(r'[,;|]', s) if x.strip()]

def norm_area(v):
    s = str(v or '').strip().upper().replace(' ', '')
    if not s: return ''
    if s == 'ALL': return 'ALL'
    return ALIAS.get(s, s)

def money(v):
    try:
        return float(re.sub(r'[^0-9.\-]', '', str(v or '')) or 0)
    except Exception:
        return 0.0

def get_client():
    raw = os.environ.get('GOOGLE_CREDENTIALS_JSON')
    if not raw:
        raise RuntimeError('Missing GOOGLE_CREDENTIALS_JSON')
    info = json.loads(raw)
    creds = Credentials.from_service_account_info(info, scopes=['https://www.googleapis.com/auth/spreadsheets'])
    return gspread.authorize(creds)

def open_ws(name):
    return get_client().open_by_key(SHEET_ID).worksheet(name)

def header_map(headers: List[str]) -> Dict[str,int]:
    return {norm_key(h): i+1 for i,h in enumerate(headers) if str(h).strip()}

def find_col(headers, aliases):
    hm = header_map(headers)
    for a in aliases:
        k = norm_key(a)
        if k in hm: return hm[k]
    return None

def get_row_value(row, headers, aliases, default=''):
    c = find_col(headers, aliases)
    if not c: return default
    return row[c-1] if c-1 < len(row) else default

def ensure_workflow_headers_exist(headers):
    # PRO STABLE: do NOT write headers automatically. Return missing list only.
    hm = header_map(headers)
    missing = [h for h in WF_HEADERS.values() if norm_key(h) not in hm]
    return missing

def sign_token(payload: Dict[str,Any]) -> str:
    body = base64.urlsafe_b64encode(json.dumps(payload, ensure_ascii=False).encode()).decode().rstrip('=')
    sig = hmac.new(SECRET.encode(), body.encode(), hashlib.sha256).hexdigest()
    return body + '.' + sig

def read_token(token: str):
    try:
        body, sig = token.split('.',1)
        expected = hmac.new(SECRET.encode(), body.encode(), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(sig, expected): return None
        pad = '=' * (-len(body) % 4)
        return json.loads(base64.urlsafe_b64decode((body+pad).encode()).decode())
    except Exception:
        return None

def auth_required(fn):
    @wraps(fn)
    def wrap(*args, **kwargs):
        auth = request.headers.get('Authorization','')
        token = auth.replace('Bearer ','').strip() if auth.startswith('Bearer ') else ''
        user = read_token(token)
        if not user:
            return jsonify({'ok': False, 'error': 'unauthorized'}), 401
        request.user = user
        return fn(*args, **kwargs)
    return wrap

# ====== USERS ======
def load_users(force=False):
    if (not force) and _cache['users'] is not None and time.time() - _cache['user_ts'] < CACHE_USERS_SEC:
        return _cache['users']
    ws = open_ws(USER_SHEET)
    values = ws.get_all_values()
    if not values: return []
    headers = values[0]
    rows = []
    for r in values[1:]:
        if not any(r): continue
        d = {headers[i].strip(): (r[i].strip() if i < len(r) else '') for i in range(len(headers)) if headers[i].strip()}
        if str(d.get('Active','')).strip().upper() in ('TRUE','YES','1','ACTIVE'):
            rows.append(d)
    _cache['users'] = rows; _cache['user_ts'] = time.time()
    return rows

def clean_user(u):
    return {
        'user': norm(u.get('User')),
        'name': norm(u.get('Name') or u.get('User')),
        'group': norm(u.get('Group')).upper(),
        'role': norm(u.get('Role')).upper(),
        'region': norm(u.get('Region')).upper() or 'ALL',
        'province': norm(u.get('Province')).upper() or 'ALL',
        'systems': norm(u.get('Systems')).upper() or 'SMART_DEFENSE',
    }

# ====== TICKETS ======
def load_tickets(force=False):
    now = time.time()
    if (not force) and _cache['tickets'] is not None and now - _cache['ticket_ts'] < CACHE_TICKETS_SEC:
        return _cache['tickets']
    if (not force) and now - _cache['last_ticket_read_attempt'] < MIN_READ_INTERVAL_SEC and _cache['tickets'] is not None:
        return _cache['tickets']
    _cache['last_ticket_read_attempt'] = now
    try:
        ws = open_ws(TICKET_SHEET)
        values = ws.get_all_values()  # one read only
        if not values:
            _cache['tickets'] = []; _cache['ticket_ts'] = now; return []
        headers = [str(h).strip() for h in values[0]]
        missing_wf = ensure_workflow_headers_exist(headers)
        hm = header_map(headers)
        tickets = []
        for idx, row in enumerate(values[1:], start=2):
            if not any(row): continue
            ticket_id = norm(get_row_value(row, headers, HEADER_ALIASES['ticket_id']))
            if not ticket_id: continue
            owner = norm(get_row_value(row, headers, HEADER_ALIASES['owner']))
            province = norm(get_row_value(row, headers, HEADER_ALIASES['province'])) or owner
            province_n = norm_area(province)
            region = norm(get_row_value(row, headers, HEADER_ALIASES['region'])).upper() or REGION_MAP.get(province_n, '')
            step = norm(row[hm[norm_key('SD_STEP')]-1]) if norm_key('SD_STEP') in hm and hm[norm_key('SD_STEP')]-1 < len(row) else '1'
            if not step: step = '1'
            status = norm(row[hm[norm_key('SD_STATUS')]-1]) if norm_key('SD_STATUS') in hm and hm[norm_key('SD_STATUS')]-1 < len(row) else 'STEP1'
            t = {
                '_row': idx, 'ticket_id': ticket_id, 'severity': norm(get_row_value(row, headers, HEADER_ALIASES['severity'])),
                'creation': norm(get_row_value(row, headers, HEADER_ALIASES['creation'])), 'target': norm(get_row_value(row, headers, HEADER_ALIASES['target'])),
                'subject': norm(get_row_value(row, headers, HEADER_ALIASES['subject'])), 'external': norm(get_row_value(row, headers, HEADER_ALIASES['external'])),
                'penalty': money(get_row_value(row, headers, HEADER_ALIASES['penalty'])), 'penalty_raw': norm(get_row_value(row, headers, HEADER_ALIASES['penalty'])),
                'owner': owner, 'province': province_n or province, 'region': region, 'step': step, 'status': status,
                'group_problem': norm(get_row_value(row, headers, HEADER_ALIASES['group_problem'])),
                'sub_problem': norm(get_row_value(row, headers, HEADER_ALIASES['sub_problem'])),
                'accident': norm(get_row_value(row, headers, HEADER_ALIASES['accident'])),
                'overdue_detail': norm(get_row_value(row, headers, HEADER_ALIASES['overdue_detail'])),
                'explain_link': norm(get_row_value(row, headers, HEADER_ALIASES['explain_link'])),
                'fso_decision': norm(get_row_value(row, headers, HEADER_ALIASES['fso_decision'])),
                'fso_approve': norm(get_row_value(row, headers, HEADER_ALIASES['fso_approve'])),
                'fso_approve_date': norm(get_row_value(row, headers, HEADER_ALIASES['fso_approve_date'])),
                'fso_remark': norm(get_row_value(row, headers, HEADER_ALIASES['fso_remark'])),
                'defend_count': int(float(norm(row[hm[norm_key('SD_DEFEND_COUNT')]-1] or 0))) if norm_key('SD_DEFEND_COUNT') in hm and hm[norm_key('SD_DEFEND_COUNT')]-1 < len(row) and str(row[hm[norm_key('SD_DEFEND_COUNT')]-1]).strip() else 0,
                'final_status': norm(row[hm[norm_key('SD_FINAL_STATUS')]-1]) if norm_key('SD_FINAL_STATUS') in hm and hm[norm_key('SD_FINAL_STATUS')]-1 < len(row) else '',
            }
            tickets.append(t)
        _cache['tickets'] = tickets; _cache['ticket_ts'] = now; _cache['ticket_headers'] = headers; _cache['ticket_colmap'] = hm; _cache['last_error'] = None
        if missing_wf:
            _cache['last_error'] = {'type':'missing_headers', 'missing': missing_wf, 'message':'Workflow columns are missing. Add them manually to the sheet. Backend will not auto-add columns.'}
        return tickets
    except Exception as e:
        log.exception('load_tickets error')
        _cache['last_error'] = {'type':'load_error','message':str(e)}
        return _cache['tickets'] or []

def allowed_ticket(user, t):
    if user.get('region','ALL') != 'ALL' and (t.get('region') or '').upper() != user.get('region'):
        return False
    user_provs = [norm_area(x) for x in parse_list(user.get('province','ALL'))]
    if 'ALL' not in user_provs and norm_area(t.get('province')) not in user_provs:
        return False
    return True

def col_for(field_key):
    headers = _cache.get('ticket_headers') or []
    hm = _cache.get('ticket_colmap') or header_map(headers)
    # workflow header key
    if field_key in WF_HEADERS:
        return hm.get(norm_key(WF_HEADERS[field_key]))
    # display/edit alias key
    if field_key in HEADER_ALIASES:
        return find_col(headers, HEADER_ALIASES[field_key])
    return None

def row_by_ticket(ticket_id):
    rows = load_tickets()
    for t in rows:
        if t['ticket_id'] == ticket_id:
            return t
    return None

def update_cells(row_num:int, updates:Dict[str,Any]):
    ws = open_ws(TICKET_SHEET)
    # validate columns exist; DO NOT auto-add
    missing = []
    cells = []
    for key,val in updates.items():
        col = col_for(key)
        if not col:
            missing.append(key)
        else:
            cells.append(gspread.Cell(row_num, col, val))
    if missing:
        return False, f'Missing columns for fields: {missing}. Please add workflow/edit headers manually.'
    if cells:
        ws.update_cells(cells, value_input_option='USER_ENTERED')
    _cache['tickets'] = None; _cache['ticket_ts'] = 0
    return True, 'updated'

def can_action(user, t, action):
    g = user.get('group','').upper(); role = user.get('role','').upper(); step = str(t.get('step','1'))
    if t.get('final_status') or t.get('status') in ('FINAL','MANAGER_APPROVED'):
        return action in ('open',)
    if action in ('save_step1','confirm_step1'):
        return step in ('1','STEP1') and g in ('ENGINEER','SITE')
    if action in ('fso_decision','confirm_step2'):
        return step in ('2','STEP2','3','STEP3') and g == 'FSO'
    if action in ('request_defend','accept_final'):
        return step in ('3','STEP3') and g in ('ENGINEER','SITE')
    if action in ('manager_approve',):
        return step in ('5','STEP5') and g == 'BBTEC'
    return False

def audit(user, action, ticket_id='', step='', detail=None):
    try:
        ws = open_ws(AUDIT_SHEET)
    except Exception:
        return
    try:
        vals = ws.get_all_values()
        if not vals:
            ws.append_row(AUDIT_HEADERS, value_input_option='USER_ENTERED')
        ws.append_row([now_iso(), user.get('user',''), user.get('group',''), user.get('role',''), action, ticket_id, step, json.dumps(detail or {}, ensure_ascii=False)], value_input_option='USER_ENTERED')
    except Exception as e:
        log.warning('audit failed: %s', e)

# ====== ROUTES ======
@bp.route('/login', methods=['POST'])
def login():
    data = request.get_json(silent=True) or {}
    username = norm(data.get('user') or data.get('username'))
    password = norm(data.get('pass') or data.get('password'))
    for u in load_users():
        if norm(u.get('User')) == username and norm(u.get('Pass')) == password:
            cu = clean_user(u)
            token = sign_token({**cu, 'iat': int(time.time())})
            if AUDIT_LOGIN: audit(cu, 'LOGIN')
            return jsonify({'ok': True, 'token': token, 'user': cu})
    return jsonify({'ok': False, 'error': 'invalid user/password'}), 401

@bp.route('/me')
@auth_required
def me():
    return jsonify({'ok': True, 'user': request.user})

@bp.route('/tickets')
@auth_required
def tickets():
    rows = [t for t in load_tickets() if allowed_ticket(request.user, t)]
    q = norm(request.args.get('q')).lower()
    step = norm(request.args.get('step'))
    if q:
        rows = [r for r in rows if q in json.dumps(r, ensure_ascii=False).lower()]
    if step and step.upper() != 'ALL':
        rows = [r for r in rows if str(r.get('step')) == str(step)]
    total_penalty = sum(r.get('penalty',0) for r in rows)
    return jsonify({'ok': True, 'rows': rows, 'total': len(rows), 'total_penalty': total_penalty, 'warning': _cache.get('last_error')})

@bp.route('/debug')
@auth_required
def debug():
    raw = load_tickets()
    allowed = [t for t in raw if allowed_ticket(request.user, t)]
    return jsonify({'ok': True, 'sheet_id': SHEET_ID, 'ticket_sheet': TICKET_SHEET, 'user_sheet': USER_SHEET,
                    'raw_count': len(raw), 'allowed_count': len(allowed), 'user': request.user,
                    'headers': _cache.get('ticket_headers'), 'last_error': _cache.get('last_error'),
                    'cache_age_sec': int(time.time()-(_cache.get('ticket_ts') or 0)) if _cache.get('ticket_ts') else None})

@bp.route('/clear-cache', methods=['POST'])
@auth_required
def clear_cache():
    _cache['tickets'] = None; _cache['users'] = None; _cache['ticket_ts'] = 0; _cache['user_ts'] = 0
    return jsonify({'ok': True})

@bp.route('/ticket/<ticket_id>')
@auth_required
def ticket_detail(ticket_id):
    t = row_by_ticket(ticket_id)
    if not t or not allowed_ticket(request.user, t): return jsonify({'ok': False, 'error': 'not found'}), 404
    actions = {a: can_action(request.user, t, a) for a in ['save_step1','confirm_step1','fso_decision','confirm_step2','request_defend','accept_final','manager_approve']}
    return jsonify({'ok': True, 'ticket': t, 'actions': actions, 'warning': _cache.get('last_error')})

@bp.route('/action/<action>', methods=['POST'])
@auth_required
def do_action(action):
    data = request.get_json(silent=True) or {}
    ticket_id = norm(data.get('ticket_id'))
    t = row_by_ticket(ticket_id)
    if not t or not allowed_ticket(request.user, t): return jsonify({'ok': False, 'error':'ticket not found'}), 404
    if not can_action(request.user, t, action): return jsonify({'ok': False, 'error':'permission denied or step locked'}), 403
    user = request.user; ts = now_iso(); updates = {'sd_updated_by': user.get('user'), 'sd_updated_at': ts}
    detail = {}
    if action == 'save_step1':
        for key in ['group_problem','sub_problem','accident','overdue_detail','explain_link']:
            if key in data: updates[key] = data.get(key,''); detail[key] = data.get(key,'')
    elif action == 'confirm_step1':
        updates.update({'sd_step':'2','sd_status':'STEP2_FSO_REVIEW','sd_engineer_confirm':'TRUE','sd_engineer_confirm_by':user.get('user'),'sd_engineer_confirm_at':ts})
    elif action == 'fso_decision':
        for key in ['fso_decision','fso_approve','fso_approve_date','fso_remark']:
            if key in data: updates[key] = data.get(key,''); detail[key] = data.get(key,'')
    elif action == 'confirm_step2':
        # ถ้า FSO ไม่ปรับ => final/manager step, ถ้าปรับ => engineer defend step
        decision = norm(data.get('fso_decision') or t.get('fso_decision'))
        if decision == 'ไม่ปรับ':
            next_step, status = '5', 'STEP5_MANAGER_APPROVE'
        else:
            next_step, status = '3', 'STEP3_DEFEND_DECISION'
        updates.update({'sd_step':next_step,'sd_status':status,'sd_fso_confirm':'TRUE','sd_fso_confirm_by':user.get('user'),'sd_fso_confirm_at':ts})
        for key in ['fso_decision','fso_approve','fso_approve_date','fso_remark']:
            if key in data: updates[key] = data.get(key,'')
    elif action == 'request_defend':
        cnt = int(t.get('defend_count') or 0)
        if cnt >= 2: return jsonify({'ok': False, 'error':'defend limit reached'}), 400
        updates.update({'sd_step':'2','sd_status':'STEP2_FSO_REVIEW_DEFEND','sd_defend_count':cnt+1,'sd_defend_request':'TRUE','sd_defend_by':user.get('user'),'sd_defend_at':ts})
        if 'explain_link' in data: updates['explain_link'] = data.get('explain_link','')
        if 'overdue_detail' in data: updates['overdue_detail'] = data.get('overdue_detail','')
    elif action == 'accept_final':
        updates.update({'sd_step':'5','sd_status':'STEP5_MANAGER_APPROVE','sd_final_status':'ACCEPT_PENALTY'})
    elif action == 'manager_approve':
        updates.update({'sd_step':'FINAL','sd_status':'MANAGER_APPROVED','sd_final_status':'FINAL','sd_manager_approve':'TRUE','sd_manager_approve_by':user.get('user'),'sd_manager_approve_at':ts})
    ok, msg = update_cells(t['_row'], updates)
    if not ok: return jsonify({'ok': False, 'error': msg}), 400
    audit(user, action, ticket_id, t.get('step'), {'updates': updates, 'detail': detail})
    return jsonify({'ok': True, 'message': msg})

@bp.route('/audit')
@auth_required
def audit_list():
    try:
        ws = open_ws(AUDIT_SHEET); vals = ws.get_all_values()
        if not vals: return jsonify({'ok': True, 'rows': []})
        headers = vals[0]
        rows = [{headers[i]: (r[i] if i < len(r) else '') for i in range(len(headers))} for r in vals[1:][-500:]]
        return jsonify({'ok': True, 'rows': rows})
    except Exception as e:
        return jsonify({'ok': False, 'error': str(e), 'rows': []})
