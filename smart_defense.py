import os, json, time, hmac, hashlib, base64, logging
from datetime import datetime, timezone
from functools import wraps
from flask import Blueprint, request, jsonify
import gspread
from google.oauth2.service_account import Credentials

log = logging.getLogger('bbtec-smart-defense')
logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(message)s')

bp = Blueprint('smart_defense', __name__, url_prefix='/api/smart-defense')

# IMPORTANT: This standalone service reads ONLY this spreadsheet unless env overrides it.
DEFAULT_SD_SHEET_ID = '1RBWr-lKva_XOqmcKwEE-E7hqIodbWWK1XHzuV8QJ-7Q'
SD_SHEET_ID = os.environ.get('SMART_DEFENSE_SHEET_ID', DEFAULT_SD_SHEET_ID).strip()
TICKET_SHEET = os.environ.get('SMART_DEFENSE_TICKET_SHEET', 'NOR_Penalty_Ticket').strip()
USER_SHEET = os.environ.get('SMART_DEFENSE_USER_SHEET', 'USER_ACCOUNT').strip()
AUDIT_SHEET = os.environ.get('SMART_DEFENSE_AUDIT_SHEET', 'SD_AUDIT_LOG').strip()
SECRET = os.environ.get('SMART_DEFENSE_SECRET', 'bbtec-smart-defense-change-me')
TTL_TICKETS = int(os.environ.get('SMART_DEFENSE_CACHE_TICKETS_SEC', '600'))
TTL_USERS = int(os.environ.get('SMART_DEFENSE_CACHE_USERS_SEC', '900'))
MIN_READ = int(os.environ.get('SMART_DEFENSE_MIN_READ_INTERVAL_SEC', '90'))

CACHE = {
    'tickets': None, 'tickets_ts': 0, 'tickets_error': None, 'tickets_headers': [],
    'users': None, 'users_ts': 0, 'users_error': None,
    'last_ticket_read_attempt': 0,
}

PROV_TO_REGION = {
    'TRUE-TH-BBT-NOR1-CMI1-NOP':'NOR1','TRUE-TH-BBT-NOR1-CMI2-NOP':'NOR1','TRUE-TH-BBT-NOR1-CRI-NOP':'NOR1',
    'TRUE-TH-BBT-NOR1-LPG-NOP':'NOR1','TRUE-TH-BBT-NOR1-LPN-NOP':'NOR1','TRUE-TH-BBT-NOR1-MHS-NOP':'NOR1',
    'TRUE-TH-BBT-NOR1-NAN-NOP':'NOR1','TRUE-TH-BBT-NOR1-PHE-NOP':'NOR1','TRUE-TH-BBT-NOR1-PYO-NOP':'NOR1',
    'TRUE-TH-BBT-NOR2-KPP-NOP':'NOR2','TRUE-TH-BBT-NOR2-PCB-NOP':'NOR2','TRUE-TH-BBT-NOR2-PCT-NOP':'NOR2',
    'TRUE-TH-BBT-NOR2-PSN-NOP':'NOR2','TRUE-TH-BBT-NOR2-SKT-NOP':'NOR2','TRUE-TH-BBT-NOR2-TAK-NOP':'NOR2',
    'TRUE-TH-BBT-NOR2-UTR-NOP':'NOR2',
}

def now_iso():
    return datetime.now().strftime('%Y-%m-%d %H:%M:%S')

def norm(v):
    return str(v or '').strip()

def norm_key(v):
    return norm(v).upper().replace(' ', '')

def split_multi(v):
    s = norm(v)
    if not s: return []
    return [x.strip() for x in s.split(',') if x.strip()]

def get_client():
    raw = os.environ.get('GOOGLE_CREDENTIALS_JSON')
    if not raw:
        raise RuntimeError('Missing GOOGLE_CREDENTIALS_JSON')
    info = json.loads(raw)
    scopes = ['https://www.googleapis.com/auth/spreadsheets']
    creds = Credentials.from_service_account_info(info, scopes=scopes)
    return gspread.authorize(creds)

def open_ws(sheet_name):
    gc = get_client()
    return gc.open_by_key(SD_SHEET_ID).worksheet(sheet_name)

def make_token(user):
    payload = {
        'user': user.get('user'), 'name': user.get('name'), 'group': user.get('group'), 'role': user.get('role'),
        'region': user.get('region'), 'province': user.get('province'), 'systems': user.get('systems'),
        'iat': int(time.time())
    }
    body = base64.urlsafe_b64encode(json.dumps(payload, ensure_ascii=False).encode()).decode().rstrip('=')
    sig = hmac.new(SECRET.encode(), body.encode(), hashlib.sha256).hexdigest()
    return body + '.' + sig

def parse_token(token):
    if not token or '.' not in token: return None
    body, sig = token.rsplit('.', 1)
    exp_sig = hmac.new(SECRET.encode(), body.encode(), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(sig, exp_sig): return None
    pad = '=' * (-len(body) % 4)
    return json.loads(base64.urlsafe_b64decode((body + pad).encode()).decode())

def auth_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        auth = request.headers.get('Authorization', '')
        token = auth.replace('Bearer ', '').strip() if auth.startswith('Bearer ') else ''
        user = parse_token(token)
        if not user:
            return jsonify({'ok': False, 'error': 'unauthorized'}), 401
        request.sd_user = user
        return fn(*args, **kwargs)
    return wrapper

def rows_to_dicts(values):
    if not values: return []
    headers = [norm(h) for h in values[0]]
    rows = []
    for idx, row in enumerate(values[1:], start=2):
        d = {'_row': idx}
        for i, h in enumerate(headers):
            if h:
                d[h] = norm(row[i]) if i < len(row) else ''
        rows.append(d)
    return rows

def load_users(force=False):
    age = time.time() - CACHE['users_ts']
    if not force and CACHE['users'] is not None and age < TTL_USERS:
        return CACHE['users']
    try:
        ws = open_ws(USER_SHEET)
        vals = ws.get_all_values()
        users = []
        for r in rows_to_dicts(vals):
            active = norm_key(r.get('Active', 'TRUE'))
            if active not in ('TRUE','YES','1','Y'):
                continue
            users.append({
                'user': norm(r.get('User')), 'pass': norm(r.get('Pass')), 'name': norm(r.get('Name')),
                'group': norm_key(r.get('Group')), 'role': norm_key(r.get('Role')), 'region': norm_key(r.get('Region') or 'ALL'),
                'province': norm(r.get('Province') or 'ALL'), 'systems': norm(r.get('Systems') or 'SMART_DEFENSE'),
                'remark': norm(r.get('Remark'))
            })
        CACHE['users'], CACHE['users_ts'], CACHE['users_error'] = users, time.time(), None
        log.info('SD users loaded: %s from %s/%s', len(users), SD_SHEET_ID, USER_SHEET)
        return users
    except Exception as e:
        CACHE['users_error'] = str(e)
        log.exception('SD load_users error')
        return CACHE['users'] or []

def find_header(row_headers, candidates):
    lookup = {norm_key(h): h for h in row_headers if h}
    for c in candidates:
        if norm_key(c) in lookup:
            return lookup[norm_key(c)]
    # contains fallback
    for h in row_headers:
        hk = norm_key(h)
        for c in candidates:
            if norm_key(c) in hk:
                return h
    return None

def infer_region(province):
    p = norm_key(province)
    if 'NOR1' in p: return 'NOR1'
    if 'NOR2' in p: return 'NOR2'
    return PROV_TO_REGION.get(p, '')

def getv(row, key):
    return norm(row.get(key, '')) if key else ''

def normalize_ticket_row(r, headers):
    h_ticket = find_header(headers, ['TICKETID','Ticket','TT','Ticket ID'])
    h_sev = find_header(headers, ['TRUESEVERITY_DESC','Severity','SLA'])
    h_creation = find_header(headers, ['CREATIONDATE','Creation Date','Created'])
    h_target = find_header(headers, ['TARGETFINISH','Target Finish','Target'])
    h_subject = find_header(headers, ['SUBJECT','Subject'])
    h_ext = find_header(headers, ['EXTERNALSYSTEM_TICKETID','External Ticket'])
    h_penalty = find_header(headers, ['PENALTYBAHT_TRACKB','Penalty','Penalty Amount'])
    h_prov = find_header(headers, ['Province','TRUEOWNERGROUP','OWNERGROUP','TrueOwnerGroup','Region'])
    h_group_problem = find_header(headers, ['Group problem','Group Problem'])
    h_sub_problem = find_header(headers, ['Sub Problem'])
    h_accident = find_header(headers, ['Accident'])
    h_overdue = find_header(headers, ['Overdue Detail','Overdue'])
    h_pic = find_header(headers, ['แนบLINK รูป','Link รูป','Picture Link'])
    h_explain = find_header(headers, ['แนบ LINK ชี้แจง','Link ชี้แจง','Explain Link'])
    h_fso_decision = find_header(headers, ['FSO พิจารณา','FSO Decision'])
    h_fso_approve = find_header(headers, ['FSO approve','FSO Approve'])
    h_fso_date = find_header(headers, ['วันที่ FSO อนุมัติ','FSO Date'])
    h_fso_remark = find_header(headers, ['Remark FSO','FSO Remark'])
    h_step = find_header(headers, ['SD_STEP','Step'])
    h_defend = find_header(headers, ['DEFEND_COUNT','Defend Count'])
    h_final = find_header(headers, ['FINAL_STATUS','Final Status'])
    h_approved = find_header(headers, ['MANAGER_APPROVED','Manager Approved'])
    province = getv(r, h_prov)
    region = infer_region(province)
    def to_int(v, default=1):
        try: return int(float(norm(v)))
        except Exception: return default
    def to_money(v):
        try: return float(norm(v).replace(',',''))
        except Exception: return 0.0
    return {
        '_row': r.get('_row'),
        'ticket': getv(r, h_ticket), 'severity': getv(r, h_sev), 'creation': getv(r, h_creation), 'target': getv(r, h_target),
        'subject': getv(r, h_subject), 'external_ticket': getv(r, h_ext), 'penalty': to_money(getv(r, h_penalty)),
        'region': region, 'province': province,
        'group_problem': getv(r, h_group_problem), 'sub_problem': getv(r, h_sub_problem), 'accident': getv(r, h_accident),
        'overdue_detail': getv(r, h_overdue), 'picture_link': getv(r, h_pic), 'explain_link': getv(r, h_explain),
        'fso_decision': getv(r, h_fso_decision), 'fso_approve': getv(r, h_fso_approve), 'fso_date': getv(r, h_fso_date),
        'fso_remark': getv(r, h_fso_remark), 'step': to_int(getv(r, h_step), 1), 'defend_count': to_int(getv(r, h_defend), 0),
        'final_status': getv(r, h_final), 'manager_approved': getv(r, h_approved),
        'last_update': ''
    }

def load_tickets(force=False):
    age = time.time() - CACHE['tickets_ts']
    if not force and CACHE['tickets'] is not None and age < TTL_TICKETS:
        return CACHE['tickets']
    # Throttle read attempts to prevent 429 storms. Return stale cache if available.
    since_attempt = time.time() - CACHE['last_ticket_read_attempt']
    if not force and since_attempt < MIN_READ and CACHE['tickets'] is not None:
        return CACHE['tickets']
    CACHE['last_ticket_read_attempt'] = time.time()
    try:
        ws = open_ws(TICKET_SHEET)
        vals = ws.get_all_values()
        if not vals:
            tickets = []
            headers = []
        else:
            headers = [norm(h) for h in vals[0]]
            raw_rows = rows_to_dicts(vals)
            tickets = [normalize_ticket_row(r, headers) for r in raw_rows]
            # remove blank rows without ticket and subject
            tickets = [t for t in tickets if t.get('ticket') or t.get('subject') or t.get('province')]
        CACHE['tickets'], CACHE['tickets_ts'], CACHE['tickets_error'], CACHE['tickets_headers'] = tickets, time.time(), None, headers
        log.info('SD tickets loaded: %s from sheet_id=%s tab=%s headers=%s', len(tickets), SD_SHEET_ID, TICKET_SHEET, headers[:12])
        return tickets
    except Exception as e:
        CACHE['tickets_error'] = str(e)
        log.exception('SD load_tickets error')
        return CACHE['tickets'] or []

def user_can_see(user, ticket):
    if 'SMART_DEFENSE' not in [norm_key(x) for x in split_multi(user.get('systems'))]:
        return False
    u_region = norm_key(user.get('region') or 'ALL')
    if u_region != 'ALL' and norm_key(ticket.get('region')) != u_region:
        return False
    u_provs = [norm_key(x) for x in split_multi(user.get('province') or 'ALL')]
    if 'ALL' not in u_provs:
        if norm_key(ticket.get('province')) not in u_provs:
            return False
    return True

def filter_tickets_for_user(user, tickets):
    return [t for t in tickets if user_can_see(user, t)]

def summary(rows):
    total = len(rows)
    amount = sum(float(r.get('penalty') or 0) for r in rows)
    step1 = sum(1 for r in rows if int(r.get('step') or 1) >= 2)
    fso_penalty = sum(1 for r in rows if norm_key(r.get('fso_decision')) in ('ปรับ','PENALTY','YES'))
    fso_no = sum(1 for r in rows if norm_key(r.get('fso_decision')) in ('ไม่ปรับ','NOPENTALTY','NO','NO_PENALTY'))
    defend = sum(1 for r in rows if int(r.get('defend_count') or 0) > 0)
    approved = sum(1 for r in rows if norm_key(r.get('manager_approved')) in ('TRUE','YES','APPROVED','อนุมัติ'))
    by = {}
    for r in rows:
        for typ, key in [('region', r.get('region') or '-'), ('province', r.get('province') or '-')]:
            k = (typ, key)
            if k not in by:
                by[k] = {'type': typ, 'key': key, 'total': 0, 'step1_done': 0, 'fso_penalty': 0, 'fso_no': 0, 'defend': 0, 'final': 0, 'approved': 0, 'amount': 0}
            b = by[k]; b['total'] += 1; b['amount'] += float(r.get('penalty') or 0)
            if int(r.get('step') or 1) >= 2: b['step1_done'] += 1
            if norm_key(r.get('fso_decision')) in ('ปรับ','PENALTY','YES'): b['fso_penalty'] += 1
            if norm_key(r.get('fso_decision')) in ('ไม่ปรับ','NO','NO_PENALTY'): b['fso_no'] += 1
            if int(r.get('defend_count') or 0) > 0: b['defend'] += 1
            if int(r.get('step') or 1) >= 4: b['final'] += 1
            if norm_key(r.get('manager_approved')) in ('TRUE','YES','APPROVED','อนุมัติ'): b['approved'] += 1
    return {'total': total, 'total_amount': amount, 'step1_done': step1, 'fso_penalty': fso_penalty, 'fso_no': fso_no, 'defend': defend, 'approved': approved, 'by': list(by.values())}

@bp.route('/login', methods=['POST'])
def login():
    data = request.get_json(force=True, silent=True) or {}
    username, password = norm(data.get('user')), norm(data.get('pass'))
    for u in load_users():
        if norm_key(u.get('user')) == norm_key(username) and u.get('pass') == password:
            safe = {k:v for k,v in u.items() if k != 'pass'}
            return jsonify({'ok': True, 'token': make_token(safe), 'user': safe})
    return jsonify({'ok': False, 'error': 'invalid username or password'}), 401

@bp.route('/me')
@auth_required
def me():
    return jsonify({'ok': True, 'user': request.sd_user})

@bp.route('/tickets')
@auth_required
def tickets():
    force = request.args.get('force') == '1'
    q = norm_key(request.args.get('q',''))
    step = norm(request.args.get('step',''))
    all_rows = load_tickets(force=force)
    visible = filter_tickets_for_user(request.sd_user, all_rows)
    if q:
        visible = [r for r in visible if q in norm_key(r.get('ticket')) or q in norm_key(r.get('subject')) or q in norm_key(r.get('province'))]
    if step and step not in ('all','ทุก Step'):
        try:
            s = int(step)
            visible = [r for r in visible if int(r.get('step') or 1) == s]
        except Exception:
            pass
    return jsonify({'ok': True, 'rows': visible[:1000], 'summary': summary(visible), 'total_raw': len(all_rows), 'total_after_auth': len(filter_tickets_for_user(request.sd_user, all_rows)), 'updated_at': now_iso(), 'last_error': CACHE.get('tickets_error')})

@bp.route('/debug')
@auth_required
def debug():
    rows = load_tickets(force=request.args.get('force') == '1')
    visible = filter_tickets_for_user(request.sd_user, rows)
    sample = rows[:5]
    return jsonify({'ok': True, 'config': {'sheet_id': SD_SHEET_ID, 'ticket_sheet': TICKET_SHEET, 'user_sheet': USER_SHEET, 'audit_sheet': AUDIT_SHEET}, 'headers': CACHE.get('tickets_headers'), 'cache': cache_info(), 'user': request.sd_user, 'total_raw': len(rows), 'total_after_auth': len(visible), 'sample_raw': sample[:3], 'sample_visible': visible[:3], 'last_error': CACHE.get('tickets_error')})

def cache_info():
    return {
        'tickets_cached': CACHE['tickets'] is not None,
        'ticket_count_cached': len(CACHE['tickets'] or []),
        'tickets_age_sec': round(time.time() - CACHE['tickets_ts'], 1) if CACHE['tickets_ts'] else None,
        'users_cached': CACHE['users'] is not None,
        'user_count_cached': len(CACHE['users'] or []),
        'users_age_sec': round(time.time() - CACHE['users_ts'], 1) if CACHE['users_ts'] else None,
        'last_error': CACHE.get('tickets_error') or CACHE.get('users_error'),
        'ttl_tickets_sec': TTL_TICKETS,
        'ttl_users_sec': TTL_USERS,
        'min_read_interval_sec': MIN_READ
    }

@bp.route('/cache-status')
@auth_required
def cache_status():
    return jsonify({'ok': True, 'cache': cache_info(), 'updated_at': now_iso()})

@bp.route('/clear-cache', methods=['POST'])
@auth_required
def clear_cache():
    CACHE.update({'tickets': None, 'tickets_ts': 0, 'tickets_error': None, 'users': None, 'users_ts': 0, 'users_error': None, 'last_ticket_read_attempt': 0})
    return jsonify({'ok': True})
