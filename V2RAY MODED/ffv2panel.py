#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
visibleTech V2Ray WEB PANEL  -  manages the accounts of ffv2ray.py from a browser

  * standard library only (Python 3.6+), no pip packages, no external files from the internet
  * reads accounts / usage / settings straight from ffv2ray.py's files and runs ffv2ray.py for every change,
    so the file locking, the daemon and the nginx / Xray rendering stay exactly the same as in the terminal menu
  * login with a password (PBKDF2), HttpOnly session cookie, login rate limit, secret URL base path, optional HTTPS
    (re-uses the certificate of the V2Ray domain)

Files (put them in the same folder as ffv2ray.py, or set FFV2RAY_PY):
  ffv2panel.py   this file
  ffv2panel.html the page (served at <base>/)

Usage (as root):
  python3 ffv2panel.py install                 create password + secret path, install and start the systemd service
  python3 ffv2panel.py install --port 2096 --base /mysecret --password 'xxxxxxxx'
  python3 ffv2panel.py passwd                  set a new panel password
  python3 ffv2panel.py info                    show the panel address / settings
  python3 ffv2panel.py serve                   run in the foreground (what the service does)
  python3 ffv2panel.py update                  download the newest ffv2ray.py + panel files from GitHub and restart
  python3 ffv2panel.py uninstall               stop and remove the service
"""
import argparse
import getpass
import hashlib
import hmac
import http.server
import importlib.machinery
import importlib.util
import json
import os
import re
import secrets
import shutil
import socketserver
import ssl
import subprocess
import sys
import threading
import time
import urllib.parse

HERE = os.path.dirname(os.path.abspath(__file__))
REPO_BASE = os.environ.get('FFV2_REPO_BASE', 'https://raw.githubusercontent.com/wavy07/Script4/main/V2RAY%20MODED')
SERVICE = 'ff-v2panel'
UNIT_FILE = '/etc/systemd/system/%s.service' % SERVICE
SESSION_SECONDS = 12 * 3600
MAX_BODY = 64 * 1024
ANSI_RE = re.compile(r'\x1b\[[0-9;?]*[A-Za-z]')


# ------------------------------------------------------------------ the V2Ray core (ffv2ray.py)
def find_core():
    cands = [os.environ.get('FFV2RAY_PY'), os.path.join(HERE, 'ffv2ray.py'), '/usr/local/bin/ffv2ray',
             '/usr/local/bin/ffv2ray.py', '/opt/visibleTech/ffv2ray.py', shutil.which('ffv2ray')]
    for c in cands:
        if c and os.path.isfile(c):
            return os.path.abspath(c)
    sys.stderr.write('Cannot find ffv2ray.py. Put ffv2panel.py next to it or set FFV2RAY_PY=/path/to/ffv2ray.py\n')
    sys.exit(1)


CORE_PATH = find_core()


def load_core(path):
    loader = importlib.machinery.SourceFileLoader('ffv2ray_core', path)
    spec = importlib.util.spec_from_loader('ffv2ray_core', loader)
    mod = importlib.util.module_from_spec(spec)
    loader.exec_module(mod)
    return mod


core = load_core(CORE_PATH)
PANEL_FILE = os.path.join(core.V2_DIR, 'panel.json')
HTML_FILE = os.path.join(HERE, 'ffv2panel.html')


class ApiError(Exception):
    def __init__(self, msg, code=400):
        Exception.__init__(self, msg)
        self.msg = msg
        self.code = code


def ff(args, timeout=90):
    """Run ffv2ray.py with arguments. Returns (ok, text)."""
    env = dict(os.environ)
    env['NO_COLOR'] = '1'
    try:
        p = subprocess.run([sys.executable, CORE_PATH] + [str(a) for a in args], stdout=subprocess.PIPE,
                           stderr=subprocess.PIPE, universal_newlines=True, timeout=timeout, env=env)
    except Exception as exc:
        return False, str(exc)
    text = ANSI_RE.sub('', (p.stdout or '') + (p.stderr or '')).strip()
    return p.returncode == 0, text


def ff_must(args):
    ok, text = ff(args)
    if not ok:
        msg = text.splitlines()[-1] if text else 'The command failed.'
        raise ApiError(re.sub(r'^Error:\s*', '', msg))
    return text


# ------------------------------------------------------------------ panel login data
def load_cfg():
    return core.read_json(PANEL_FILE, {})


def save_cfg(cfg):
    os.makedirs(core.V2_DIR, exist_ok=True)
    core.write_json(PANEL_FILE, cfg)


def hash_pw(password, salt=None, iters=200000):
    salt = salt or secrets.token_hex(16)
    h = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt.encode(), iters).hex()
    return {'salt': salt, 'hash': h, 'iters': iters}


def check_pw(cfg, user, password):
    ok_user = hmac.compare_digest(str(user or '').encode(), str(cfg.get('user', 'admin')).encode())
    h = hash_pw(str(password or ''), cfg.get('salt', ''), int(cfg.get('iters', 200000)))['hash']
    ok_pw = hmac.compare_digest(h, str(cfg.get('hash', '')))
    return ok_user and ok_pw


def norm_base(b):
    b = '/' + (b or '').strip().strip('/')
    return '' if b == '/' else b


# ------------------------------------------------------------------ sessions / rate limit
_sessions = {}
_fails = {}
_lock = threading.Lock()


def new_session(ip):
    tok = secrets.token_urlsafe(32)
    with _lock:
        now = time.time()
        for k in [k for k, v in _sessions.items() if v[0] < now]:
            del _sessions[k]
        _sessions[tok] = (now + SESSION_SECONDS, ip)
    return tok


def valid_session(tok):
    if not tok:
        return False
    with _lock:
        v = _sessions.get(tok)
        if not v or v[0] < time.time():
            _sessions.pop(tok, None)
            return False
        return True


def drop_session(tok):
    with _lock:
        _sessions.pop(tok, None)


def blocked(ip):
    with _lock:
        now = time.time()
        lst = [t for t in _fails.get(ip, []) if now - t < 600]
        _fails[ip] = lst
        return len(lst) >= 5


def add_fail(ip):
    with _lock:
        _fails.setdefault(ip, []).append(time.time())


# ------------------------------------------------------------------ state for the page
_ver = {'t': 0, 'v': ''}


def xray_version(st):
    if time.time() - _ver['t'] > 120:
        rc, out, _ = core.run([st.get('xray_bin') or core.DEFAULTS['xray_bin'], 'version'], timeout=10)
        _ver.update(t=time.time(), v=(out.splitlines()[0][:48] if out else ''))
    return _ver['v']


def build_state():
    st = core.load_settings()
    users = core.load_users()
    usage = core.load_usage()
    now = int(time.time())
    try:
        act = core.device_activity()
    except Exception:
        act = {}
    rows = []
    online = 0
    day_bytes = 0
    for name in sorted(users):
        u = users[name]
        usg = usage['users'].get(name) or core.new_usage(now)
        status = core.user_status(u, usg, now)
        live = bool(usg.get('last')) and now - usg['last'] <= 30
        dev = core.device_count(act.get(name))
        if live or dev:
            online += 1
        day_bytes += usg.get('daily', 0) if usg.get('day') == core.today_str(now) else 0
        rows.append({
            'name': name, 'proto': u.get('proto'), 'id': u.get('id'), 'created': u.get('created', 0),
            'expiry': u.get('expiry', 0), 'total_gb': float(u.get('total_gb', 0) or 0),
            'daily_gb': float(u.get('daily_gb', 0) or 0), 'conn_limit': core.user_conn_limit(u),
            'locked': bool(u.get('locked')), 'trial': bool(u.get('trial')), 'status': status,
            'used': usg.get('total', 0), 'used_daily': usg.get('daily', 0) if usg.get('day') == core.today_str(now) else 0,
            'up': usg.get('up', 0), 'down': usg.get('down', 0),
            'rate_up': usg.get('rate_up', 0) if live else 0, 'rate_down': usg.get('rate_down', 0) if live else 0,
            'last': usg.get('last', 0), 'live': live, 'devices': dev,
        })
    try:
        services = core.service_states()
    except Exception:
        services = {}
    try:
        xh = core.xhttp_supported(st)
    except Exception:
        xh = False
    try:
        reject_ok = core.nginx_reject_supported(st)
    except Exception:
        reject_ok = False
    keys = ('domain', 'tls_port', 'http_port', 'cfg_address', 'cfg_sni', 'cfg_host', 'xhttp_path', 'xhttp_mode',
            'xhttp_padding', 'xhttp_max_post', 'xhttp_min_interval', 'xhttp_max_buffered', 'xhttp_extra',
            'sni_lock', 'cdn', 'fake_site')
    settings = dict((k, st.get(k, '')) for k in keys)
    settings['xhttp_supported'] = xh
    settings['nginx_reject_ok'] = reject_ok
    settings['sni_lock_active'] = bool(core.sni_lock_names(st))
    settings['decoy_port'] = int(st.get('decoy_port') or 0)
    return {
        'now': now, 'installed': core.installed(), 'xray': xray_version(st), 'services': services,
        'online': online, 'day_bytes': day_bytes, 'accounts': rows, 'settings': settings,
        'protos': list(core.PROTO_ORDER), 'xhttp_modes': list(core.XHTTP_MODES),
        'usage_age': now - int(usage.get('ts', 0) or 0),
    }


# ------------------------------------------------------------------ API actions
def f_num(body, key, default=0.0, lo=0.0, hi=100000.0):
    v = body.get(key, default)
    if v in (None, ''):
        v = default
    try:
        v = float(v)
    except (TypeError, ValueError):
        raise ApiError('%s must be a number.' % key)
    if v < lo or v > hi:
        raise ApiError('%s must be between %g and %g.' % (key, lo, hi))
    return v


def g_name(body):
    name = str(body.get('name', '')).strip()
    if name not in core.load_users():
        raise ApiError('Account not found.', 404)
    return name


def a_state(body, qs):
    return build_state()


def a_add(body, qs):
    proto = str(body.get('proto', ''))
    name = str(body.get('name', '')).strip()
    if proto not in core.PROTOS:
        raise ApiError('Choose a protocol.')
    if not core.NAME_RE.match(name):
        raise ApiError('Name: 2-24 characters, letters, digits, _ or -')
    days = f_num(body, 'days', 30, 0.01, 3650)
    args = ['add', '--proto', proto, '--name', name, '--days', days,
            '--total', f_num(body, 'total_gb'), '--daily', f_num(body, 'daily_gb'),
            '--conn', int(f_num(body, 'conn_limit', 0, 0, 1000))]
    cid = str(body.get('id', '') or '').strip()
    if cid:
        args += ['--id', cid]
    if body.get('trial'):
        args.append('--trial')
    ff_must(args)
    return {'ok': True, 'name': name}


def a_del(body, qs):
    ff_must(['del', g_name(body)])
    return {'ok': True}


def a_lock(body, qs):
    ff_must(['lock', g_name(body)])
    return {'ok': True}


def a_unlock(body, qs):
    ff_must(['unlock', g_name(body)])
    return {'ok': True}


def a_renew(body, qs):
    args = ['renew', g_name(body), '--days', f_num(body, 'days', 30, 0.01, 3650)]
    if body.get('reset'):
        args.append('--reset')
    ff_must(args)
    return {'ok': True}


def a_expiry(body, qs):
    name = g_name(body)
    if body.get('never'):
        ff_must(['setexpiry', name, '--never'])
    else:
        ff_must(['setexpiry', name, '--days', f_num(body, 'days', 30, 0, 3650)])
    return {'ok': True}


def a_limit(body, qs):
    args = ['limit', g_name(body), '--total', f_num(body, 'total_gb'), '--daily', f_num(body, 'daily_gb'),
            '--conn', int(f_num(body, 'conn_limit', 0, 0, 1000))]
    if body.get('reset'):
        args.append('--reset')
    ff_must(args)
    return {'ok': True}


def a_links(body, qs):
    name = (qs.get('name') or [''])[0]
    users = core.load_users()
    if name not in users:
        raise ApiError('Account not found.', 404)
    st = core.load_settings()
    return {'links': [{'label': l, 'text': t} for l, t in core.build_links(st, name, users[name])]}


def a_set_client(body, qs):
    args = ['clientopts']
    for key, flag in (('cfg_address', '--address'), ('cfg_sni', '--sni'), ('cfg_host', '--host')):
        if key in body:
            v = str(body[key] or '').strip()
            if v and not core.HOST_RE.match(v):
                raise ApiError('Use a domain name or IP (letters, digits, dot, dash).')
            args += [flag, v]
    if len(args) > 1:
        ff_must(args)
    return {'ok': True}


def a_set_xhttp(body, qs):
    args = ['xhttpopts']
    for key, flag in (('xhttp_path', '--path'), ('xhttp_mode', '--mode'), ('xhttp_padding', '--padding'),
                      ('xhttp_max_post', '--max-post'), ('xhttp_min_interval', '--min-interval'),
                      ('xhttp_max_buffered', '--max-buffered'), ('xhttp_extra', '--extra')):
        if key in body:
            args += [flag, str(body[key] or '').strip()]
    if len(args) > 1:
        ff_must(args)
    return {'ok': True}


def a_snilock(body, qs):
    ff_must(['snilock', '--on' if body.get('on') else '--off'])
    return {'ok': True}


def a_restart(body, qs):
    ff_must(['render', '--restart'])
    return {'ok': True}


def a_password(body, qs):
    cfg = load_cfg()
    if not check_pw(cfg, cfg.get('user', 'admin'), body.get('old', '')):
        raise ApiError('The current password is wrong.', 403)
    new = str(body.get('new', ''))
    if len(new) < 8:
        raise ApiError('The new password needs at least 8 characters.')
    cfg.update(hash_pw(new))
    save_cfg(cfg)
    with _lock:
        _sessions.clear()
    return {'ok': True, 'relogin': True}


API = {
    ('GET', 'state'): a_state, ('GET', 'links'): a_links,
    ('POST', 'add'): a_add, ('POST', 'del'): a_del, ('POST', 'lock'): a_lock, ('POST', 'unlock'): a_unlock,
    ('POST', 'renew'): a_renew, ('POST', 'expiry'): a_expiry, ('POST', 'limit'): a_limit,
    ('POST', 'client'): a_set_client, ('POST', 'xhttp'): a_set_xhttp, ('POST', 'snilock'): a_snilock,
    ('POST', 'restart'): a_restart, ('POST', 'password'): a_password,
}


# ------------------------------------------------------------------ HTTP server
class Server(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True
    allow_reuse_address = True
    request_queue_size = 64


class Handler(http.server.BaseHTTPRequestHandler):
    server_version = 'nginx'
    sys_version = ''
    protocol_version = 'HTTP/1.1'

    def log_message(self, *a):
        pass

    # --- helpers
    def ip(self):
        return self.client_address[0]

    def cookie(self):
        for part in (self.headers.get('Cookie') or '').split(';'):
            k, _, v = part.strip().partition('=')
            if k == 'ffv2s':
                return v
        return ''

    def send(self, code, body, ctype='application/json', extra=None):
        data = body if isinstance(body, bytes) else body.encode('utf-8')
        self.send_response(code)
        self.send_header('Content-Type', ctype)
        self.send_header('Content-Length', str(len(data)))
        self.send_header('Cache-Control', 'no-store')
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('X-Frame-Options', 'DENY')
        self.send_header('Referrer-Policy', 'no-referrer')
        for k, v in (extra or []):
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(data)

    def jsend(self, code, obj, extra=None):
        self.send(code, json.dumps(obj), 'application/json', extra)

    def not_found(self):
        self.send(404, '404 page not found\n', 'text/plain')

    # --- routing
    def do_GET(self):
        self.route('GET')

    def do_POST(self):
        self.route('POST')

    def do_HEAD(self):
        self.not_found()

    def route(self, method):
        try:
            self._route(method)
        except ApiError as e:
            self.jsend(e.code, {'error': e.msg})
        except (BrokenPipeError, ConnectionResetError):
            pass
        except Exception as e:                                            # never leak a traceback to the browser
            sys.stderr.write('panel error: %r\n' % (e,))
            try:
                self.jsend(500, {'error': 'Internal error. See: journalctl -u %s' % SERVICE})
            except Exception:
                pass

    def _route(self, method):
        base = self.server.base
        sp = urllib.parse.urlsplit(self.path)
        path = sp.path
        qs = urllib.parse.parse_qs(sp.query)
        if base:
            if path == base:
                return self.send(302, '', 'text/plain', [('Location', base + '/')])
            if not path.startswith(base + '/'):
                return self.not_found()
            path = path[len(base):]
        if path == '/' and method == 'GET':
            return self.page()
        if not path.startswith('/api/'):
            return self.not_found()
        ep = path[5:]
        if method == 'POST':
            if self.headers.get('X-Requested-With') != 'ffv2panel':
                raise ApiError('Bad request.', 400)
            n = int(self.headers.get('Content-Length') or 0)
            if n > MAX_BODY:
                raise ApiError('Request too large.', 413)
            raw = self.rfile.read(n) if n else b'{}'
            try:
                body = json.loads(raw.decode('utf-8') or '{}')
            except ValueError:
                raise ApiError('Bad JSON.')
            if not isinstance(body, dict):
                raise ApiError('Bad JSON.')
        else:
            body = {}
        if method == 'POST' and ep == 'login':
            return self.login(body)
        if method == 'POST' and ep == 'logout':
            drop_session(self.cookie())
            return self.jsend(200, {'ok': True}, [('Set-Cookie', self.cookie_header('', 0))])
        if not valid_session(self.cookie()):
            return self.jsend(401, {'error': 'login'})
        fn = API.get((method, ep))
        if not fn:
            return self.not_found()
        self.jsend(200, fn(body, qs))

    def cookie_header(self, value, age):
        c = 'ffv2s=%s; Path=/; HttpOnly; SameSite=Strict; Max-Age=%d' % (value, age)
        if self.server.tls:
            c += '; Secure'
        return c

    def login(self, body):
        ip = self.ip()
        if blocked(ip):
            raise ApiError('Too many attempts. Wait 10 minutes.', 429)
        cfg = load_cfg()
        if not cfg.get('hash'):
            raise ApiError('No password set. Run: python3 ffv2panel.py passwd', 403)
        if not check_pw(cfg, body.get('user', ''), body.get('password', '')):
            add_fail(ip)
            time.sleep(1)
            raise ApiError('Wrong username or password.', 403)
        tok = new_session(ip)
        self.jsend(200, {'ok': True}, [('Set-Cookie', self.cookie_header(tok, SESSION_SECONDS))])

    def page(self):
        try:
            with open(HTML_FILE, 'rb') as f:
                html = f.read().decode('utf-8')
        except (IOError, OSError):
            return self.send(500, 'ffv2panel.html is missing next to ffv2panel.py\n', 'text/plain')
        nonce = secrets.token_hex(12)
        html = html.replace('__NONCE__', nonce)
        csp = ("default-src 'none'; script-src 'nonce-%s'; style-src 'nonce-%s'; style-src-attr 'unsafe-inline'; "
               "connect-src 'self'; img-src 'self' data:; base-uri 'none'; form-action 'none'; frame-ancestors 'none'") % (nonce, nonce)
        self.send(200, html, 'text/html; charset=utf-8', [('Content-Security-Policy', csp)])


def make_server(host, port, base, tls):
    srv = Server((host, port), Handler)
    srv.base = base
    srv.tls = False
    st = core.load_settings()
    if tls:
        cert, key = st.get('cert'), st.get('key')
        if cert and key and os.path.exists(cert) and os.path.exists(key):
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER) if hasattr(ssl, 'PROTOCOL_TLS_SERVER') else ssl.SSLContext(ssl.PROTOCOL_SSLv23)
            ctx.load_cert_chain(cert, key)
            srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
            srv.tls = True
        else:
            sys.stderr.write('No certificate found - the panel runs on plain HTTP.\n')
    return srv


# ------------------------------------------------------------------ commands
def panel_url(cfg):
    st = core.load_settings()
    scheme = 'https' if cfg.get('tls', True) and os.path.exists(st.get('cert', '') or '/nonexistent') else 'http'
    host = st.get('domain') or 'SERVER-IP'
    return '%s://%s:%s%s/' % (scheme, host, cfg.get('port', 2096), norm_base(cfg.get('base', '')))


def cmd_serve(a):
    cfg = load_cfg()
    if not cfg.get('hash'):
        sys.exit('No password set yet. Run: python3 ffv2panel.py install   (or passwd)')
    host = a.host or cfg.get('host', '0.0.0.0')
    port = int(a.port or cfg.get('port', 2096))
    srv = make_server(host, port, norm_base(cfg.get('base', '')), cfg.get('tls', True))
    print('Panel listening on %s:%d%s (%s)' % (host, port, norm_base(cfg.get('base', '')) + '/', 'https' if srv.tls else 'http'))
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass


def cmd_passwd(a):
    cfg = load_cfg()
    pw = a.password
    if not pw:
        pw = getpass.getpass('New panel password (min 8 characters): ')
        if pw != getpass.getpass('Repeat: '):
            sys.exit('The passwords do not match.')
    if len(pw) < 8:
        sys.exit('The password needs at least 8 characters.')
    cfg.setdefault('user', 'admin')
    cfg.update(hash_pw(pw))
    save_cfg(cfg)
    print('Password saved for user "%s".' % cfg['user'])


def cmd_install(a):
    if os.geteuid() != 0:
        sys.exit('Run as root.')
    cfg = load_cfg()
    generated = None
    if a.user:
        cfg['user'] = a.user
    cfg.setdefault('user', 'admin')
    if a.password or not cfg.get('hash'):
        pw = a.password or secrets.token_urlsafe(9)
        if len(pw) < 8:
            sys.exit('The password needs at least 8 characters.')
        cfg.update(hash_pw(pw))
        generated = pw
    if a.port:
        cfg['port'] = int(a.port)
    cfg.setdefault('port', 2096)
    if a.base is not None:
        cfg['base'] = norm_base(a.base)
    elif 'base' not in cfg:
        cfg['base'] = '/' + secrets.token_hex(5)
    cfg['tls'] = not a.no_tls
    cfg.setdefault('host', '0.0.0.0')
    save_cfg(cfg)
    unit = ('[Unit]\nDescription=visibleTech V2Ray web panel\nAfter=network.target\n\n[Service]\nType=simple\n'
            'Environment=PYTHONUNBUFFERED=1\nEnvironment=FFV2RAY_PY=%s\nExecStart=%s %s serve\nRestart=always\nRestartSec=3\n\n'
            '[Install]\nWantedBy=multi-user.target\n') % (CORE_PATH, sys.executable, os.path.abspath(__file__))
    with open(UNIT_FILE, 'w') as f:
        f.write(unit)
    subprocess.call(['systemctl', 'daemon-reload'])
    subprocess.call(['systemctl', 'enable', '--now', SERVICE])
    subprocess.call(['systemctl', 'restart', SERVICE])
    print('\nPanel installed.')
    print('  Address : %s' % panel_url(cfg))
    print('  Username: %s' % cfg['user'])
    if generated:
        print('  Password: %s   (shown once - change it with: python3 ffv2panel.py passwd)' % generated)
    print('  Open port %s in your firewall. Keep the secret path in the address private.' % cfg['port'])


def cmd_info(a):
    cfg = load_cfg()
    print('Address : %s' % panel_url(cfg))
    print('Username: %s' % cfg.get('user', 'admin'))
    print('Service : %s' % ('active' if subprocess.call(['systemctl', 'is-active', '--quiet', SERVICE]) == 0 else 'inactive'))


def cmd_update(a):
    import urllib.request
    files = ['ffv2panel.py', 'ffv2panel.html', 'ffv2ray.py']
    got = {}
    for f in files:
        url = '%s/%s' % (REPO_BASE.rstrip('/'), f)
        try:
            with urllib.request.urlopen(url, timeout=30) as r:
                data = r.read()
        except Exception as exc:
            sys.exit('Download failed for %s: %s' % (url, exc))
        if len(data) < 500:
            sys.exit('%s looks empty - nothing was changed.' % f)
        if f.endswith('.py'):
            try:
                compile(data, f, 'exec')
            except SyntaxError as exc:
                sys.exit('%s is not valid Python (%s) - nothing was changed.' % (f, exc))
        got[f] = data
    here = {'ffv2panel.py': os.path.abspath(__file__), 'ffv2panel.html': HTML_FILE, 'ffv2ray.py': CORE_PATH}
    for f, data in got.items():
        tmp = here[f] + '.new'
        with open(tmp, 'wb') as fh:
            fh.write(data)
        os.chmod(tmp, 0o644 if f.endswith('.html') else 0o755)
        os.replace(tmp, here[f])
    if os.path.exists(UNIT_FILE):
        subprocess.call(['systemctl', 'restart', SERVICE])
    print('Updated from %s and restarted the panel.' % REPO_BASE)


def cmd_uninstall(a):
    subprocess.call(['systemctl', 'disable', '--now', SERVICE])
    if os.path.exists(UNIT_FILE):
        os.remove(UNIT_FILE)
    subprocess.call(['systemctl', 'daemon-reload'])
    print('Panel service removed (panel.json kept).')


def main():
    p = argparse.ArgumentParser(prog='ffv2panel')
    sub = p.add_subparsers(dest='cmd')
    sub.required = True
    s = sub.add_parser('serve')
    s.add_argument('--host', default=None)
    s.add_argument('--port', default=None)
    s.set_defaults(fn=cmd_serve)
    s = sub.add_parser('passwd')
    s.add_argument('--password', default=None)
    s.set_defaults(fn=cmd_passwd)
    s = sub.add_parser('install')
    s.add_argument('--port', default=None)
    s.add_argument('--base', default=None, help='secret URL path, e.g. /mysecret ("" = none)')
    s.add_argument('--user', default=None)
    s.add_argument('--password', default=None)
    s.add_argument('--no-tls', action='store_true', help='plain HTTP (use only behind another HTTPS front)')
    s.set_defaults(fn=cmd_install)
    sub.add_parser('info').set_defaults(fn=cmd_info)
    sub.add_parser('update', help='download the newest files from GitHub').set_defaults(fn=cmd_update)
    sub.add_parser('uninstall').set_defaults(fn=cmd_uninstall)
    a = p.parse_args()
    a.fn(a)


if __name__ == '__main__':
    main()
