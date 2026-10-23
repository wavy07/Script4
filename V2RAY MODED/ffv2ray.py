#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
visibleTech V2Ray (Xray)  INSTALLER + MANAGER   -   VMess / VLESS / Trojan  (WS + gRPC + XHTTP)

  * keeps the accounts (users.json) and the live traffic counters (usage.json)
  * renders the Xray config and the nginx front config from those files
  * `daemon` polls the Xray stats API, counts bandwidth per user, and takes a
    user out of the config when the total/daily quota or the expiry is reached
  * works on Python 3.6+  (Ubuntu 18.04 - 26.04, all Debian)

Usage (as root):
  python3 ffv2ray.py            installer on a fresh server, the V2Ray manager menu afterwards
  ffv2ray                       same, after the install (the installer creates this command)
  ffv2ray.py install | update | uninstall | status | cdn --enable --refresh | add / del / list ...

Imperva CDN: when the domain sits behind Imperva, turn on "Imperva CDN" (installer question or menu [13]).
nginx then takes the real visitor IP from Incap-Client-IP / X-Forwarded-For, only from Imperva networks.

Layout (all of it can be moved with the FFV2_DIR environment variable):
  /etc/visibleTech/v2ray/{settings.json,users.json,usage.json,config.json,nginx.conf}
"""
FFV2RAY_API = 4

import argparse
import base64
import contextlib
import fcntl
import io
import ipaddress
import json
import math
import os
import pwd
import re
import shutil
import platform
import subprocess
import sys
import tempfile
import time
import urllib.parse
import urllib.request
import uuid

V2_DIR = os.environ.get('FFV2_DIR', '/etc/visibleTech/v2ray')
SETTINGS_FILE = os.path.join(V2_DIR, 'settings.json')
USERS_FILE = os.path.join(V2_DIR, 'users.json')
USAGE_FILE = os.path.join(V2_DIR, 'usage.json')
XRAY_CONF = os.path.join(V2_DIR, 'config.json')
NGINX_CONF = os.path.join(V2_DIR, 'nginx.conf')
SITE_DIR = os.environ.get('FFV2_SITE_DIR', '/var/www/visibleTech-site')
ACCESS_LOG = os.environ.get('FFV2_ACCESS_LOG', '/var/log/xray/access.log')
XRAY_SERVICE = 'ff-xray'
NGINX_SERVICE = 'ff-v2ray-nginx'
GB = 1073741824
INTERVAL = 3          # seconds between two stats polls of the daemon
MAX_RATE = 1250000000.0   # 10 Gbit/s: a higher speed can only be a measuring mistake
LIMITS_FILE = os.path.join(V2_DIR, 'limits.json')
DEVICE_WINDOW = 120   # a device (source IP) counts as online if it connected in the last N seconds
BLOCK_SECONDS = 120   # an extra device over the account's limit is refused for this long
LOCAL_IPS = ('127.0.0.1', '::1', '')
# Phones on mobile data (carrier NAT / IPv6 privacy addresses) change their public IP all the time, so counting
# every IP as a device showed 40 devices for one phone. Addresses of the same network block now count as ONE
# device: IPv4 by /24, IPv6 by /64. Change with "device_v4_prefix" / "device_v6_prefix" in settings.json
# (v4 prefix 32 = every IP is a device again, 16 = very tolerant).
EAT_OFFSET = 3 * 3600      # East Africa Time (UTC+3): every day starts at 00:00 EAT
DEVICE_V4_PREFIX = 24
DEVICE_V6_PREFIX = 64

PROTO_ORDER = ['vmess', 'vless', 'trojan']
PROTOS = {
    'vmess':  {'label': 'Vmess',  'path': '/vmess',     'grpc': 'vmess-grpc',  'port': 10001, 'gport': 10011,
               'xpath': '/xhttp-vmess',  'xport': 10021},
    'vless':  {'label': 'Vless',  'path': '/vless',     'grpc': 'vless-grpc',  'port': 10002, 'gport': 10012,
               'xpath': '/xhttp-vless',  'xport': 10022},
    'trojan': {'label': 'Trojan', 'path': '/trojan-ws', 'grpc': 'trojan-grpc', 'port': 10003, 'gport': 10013,
               'xpath': '/xhttp-trojan', 'xport': 10023},
}
XHTTP_MIN_VERSION = (24, 11, 30)   # first Xray-core release that knows the "xhttp" network (SplitHTTP renamed)
_xhttp_ok = {}

DEFAULTS = {
    'domain': '',
    'tls_port': 443,
    'http_port': 80,
    'cert': '/etc/visibleTech/ssl/visibleTech.crt',
    'key': '/etc/visibleTech/ssl/visibleTech.key',
    'xray_bin': '/usr/local/lib/visibleTech-v2ray/xray',
    'nginx_bin': '/usr/sbin/nginx',
    'api_port': 10085,
    # client config options ("bug host" technique): connect address, TLS SNI and WS Host header
    'cfg_address': '',
    'cfg_sni': '',
    'cfg_host': '',
    # XHTTP customization (like the 3x-ui XHTTP form); '' = Xray default / script default
    'xhttp_path': '',            # base path, default /xhttp  (final path = <base>-<vmess|vless|trojan>)
    'xhttp_mode': '',            # auto | packet-up | stream-up | stream-one
    'xhttp_padding': '',         # xPaddingBytes, e.g. 100-1000
    'xhttp_max_post': '',        # scMaxEachPostBytes, e.g. 1000000
    'xhttp_min_interval': '',    # scMinPostsIntervalMs, e.g. 30
    'xhttp_max_buffered': '',    # scMaxBufferedPosts, e.g. 30
    'xhttp_extra': '',           # raw JSON object merged into xhttpSettings (advanced)
    'sni_lock': False,   # True: TLS handshakes whose SNI is not cfg_sni get "unrecognized_name" (the domain itself too)
    'fake_site': '',     # decoy website template served on '/' ('' = off)
    'decoy_port': 0,     # >0: the port multiplexer owns 80/443, nginx only serves the decoy on 127.0.0.1:<port>
    # CDN in front of the server ('' = none, 'imperva' = Imperva Cloud WAF / CDN)
    'cdn': '',
    'cdn_ip_header': 'Incap-Client-IP',   # header that carries the real visitor IP (Imperva also sends X-Forwarded-For)
    'cdn_ranges': [],          # Imperva edge networks, downloaded automatically
    'cdn_ranges_extra': [],    # extra trusted networks added by hand
    'cdn_ranges_ts': 0,
    'cdn_trust_any': False,    # trust the header from every source (only when the firewall admits Imperva only)
    'cdn_grpc': False,         # show gRPC links for a CDN domain (CDNs usually do not proxy gRPC)
}

NAME_RE = re.compile(r'^[A-Za-z0-9_-]{2,24}$')
ID_RE = re.compile(r'^[A-Za-z0-9._-]{3,30}$')   # custom short id (Xray turns non-UUID ids into a UUID itself)
HOST_RE = re.compile(r'^[A-Za-z0-9.-]{1,253}$')


# ------------------------------------------------------------------ colors
class C(object):
    on = sys.stdout.isatty() and not os.environ.get('NO_COLOR')

    @staticmethod
    def c(code, text):
        text = str(text)
        return '\033[%sm%s\033[0m' % (code, text) if C.on else text


def grn(s): return C.c('0;32', s)
def red(s): return C.c('0;31', s)
def yel(s): return C.c('1;33', s)
def cyn(s): return C.c('0;36', s)
def org(s): return C.c('0;33', s)
def wht(s): return C.c('1;37', s)
def dim(s): return C.c('2', s)


def die(msg, code=1):
    sys.stderr.write(red('Error: ' + msg) + '\n')
    sys.exit(code)


# ------------------------------------------------------------------ files / lock
_lock_fd = None
_lock_depth = 0


@contextlib.contextmanager
def locked():
    global _lock_fd, _lock_depth
    if _lock_depth == 0:
        os.makedirs(V2_DIR, exist_ok=True)
        _lock_fd = open(os.path.join(V2_DIR, '.lock'), 'a+')
        fcntl.flock(_lock_fd, fcntl.LOCK_EX)
    _lock_depth += 1
    try:
        yield
    finally:
        _lock_depth -= 1
        if _lock_depth == 0:
            fcntl.flock(_lock_fd, fcntl.LOCK_UN)
            _lock_fd.close()
            _lock_fd = None


def read_json(path, default):
    try:
        with open(path) as f:
            return json.load(f)
    except (IOError, OSError, ValueError):
        return default


def write_text(path, text, mode=0o600):
    tmp = path + '.tmp'
    with open(tmp, 'w') as f:
        f.write(text)
        f.flush()
        os.fsync(f.fileno())
    os.chmod(tmp, mode)
    os.replace(tmp, path)


def write_json(path, data, mode=0o600):
    write_text(path, json.dumps(data, indent=1, sort_keys=True) + '\n', mode)


def read_text(path):
    try:
        with open(path) as f:
            return f.read()
    except (IOError, OSError):
        return None


def load_settings():
    s = dict(DEFAULTS)
    s.update(read_json(SETTINGS_FILE, {}))
    return s


def load_users():
    return read_json(USERS_FILE, {})


def save_users(users):
    write_json(USERS_FILE, users)


def load_usage():
    u = read_json(USAGE_FILE, {})
    if not isinstance(u, dict):
        u = {}
    u.setdefault('users', {})
    u.setdefault('ts', 0)
    return u


def save_usage(usage, users=None):
    if users is not None:
        for name in list(usage['users'].keys()):
            if name not in users:
                del usage['users'][name]
    write_json(USAGE_FILE, usage)


def load_limits():
    d = read_json(LIMITS_FILE, {})
    if not isinstance(d, dict):
        d = {}
    d.setdefault('devices', {})
    d.setdefault('blocks', {})
    return d


def save_limits(d):
    write_json(LIMITS_FILE, d)


def user_conn_limit(u):
    """Max devices for an account. 0 = unlimited (also for old accounts without the field)."""
    try:
        return max(0, int(u.get('conn_limit', 0)))
    except (TypeError, ValueError):
        return 0


def run(cmd, timeout=60):
    try:
        p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                           universal_newlines=True, timeout=timeout)
        return p.returncode, p.stdout, p.stderr
    except Exception as exc:                       # missing binary, timeout ...
        return 127, '', str(exc)


# ------------------------------------------------------------------ formatting
def human(n):
    n = float(n)
    for unit in ('B', 'KB', 'MB', 'GB', 'TB'):
        if n < 1024 or unit == 'TB':
            return ('%d %s' % (n, unit)) if unit == 'B' else ('%.2f %s' % (n, unit))
        n /= 1024.0


def human_rate(n):
    return human(n) + '/s'


def gb_str(gb):
    gb = float(gb)
    return ('%d' % gb) if gb == int(gb) else ('%g' % gb)


def fmt_time(ts):
    return time.strftime('%Y-%m-%d %H:%M', time.gmtime(ts + EAT_OFFSET)) + ' EAT'


def today_str(now):
    return time.strftime('%Y-%m-%d', time.gmtime(now + EAT_OFFSET))      # daily usage restarts at 00:00 EAT


def eat_day_end(now, days):
    """00:00 EAT of the day after (today + days): the account is valid through that day."""
    day = int((now + EAT_OFFSET) // 86400) + int(days)
    return (day + 1) * 86400 - EAT_OFFSET


def quota_bytes(gb):
    try:
        return int(float(gb) * GB)
    except (TypeError, ValueError):
        return 0


def new_usage(now):
    return {'total': 0, 'daily': 0, 'day': today_str(now), 'up': 0, 'down': 0,
            'rate_up': 0, 'rate_down': 0, 'peak_up': 0, 'peak_down': 0, 'last': 0}


def user_status(u, usg, now):
    if u.get('locked'):
        return 'locked'
    if u.get('expiry') and now >= u['expiry']:
        return 'expired'
    tl = quota_bytes(u.get('total_gb', 0))
    if tl > 0 and usg.get('total', 0) >= tl:
        return 'quota'
    dl = quota_bytes(u.get('daily_gb', 0))
    if dl > 0 and usg.get('daily', 0) >= dl:
        return 'daily'
    return 'active'


STATUS_TEXT = {
    'active': ('Active', grn), 'locked': ('Locked', yel), 'expired': ('Expired', red),
    'quota': ('Quota Full', red), 'daily': ('Daily Full', red),
}


def status_label(status):
    text, color = STATUS_TEXT.get(status, (status, wht))
    return color(text)


def usage_text(u, usg):
    tl = u.get('total_gb', 0)
    dl = u.get('daily_gb', 0)
    parts = []
    parts.append('%s/%sG' % (('%.1f' % (usg.get('total', 0) / float(GB))), gb_str(tl)) if float(tl) > 0
                 else '%s/inf' % human(usg.get('total', 0)).replace(' ', ''))
    if float(dl) > 0:
        parts.append('%s/%sG/d' % (('%.1f' % (usg.get('daily', 0) / float(GB))), gb_str(dl)))
    return ' | '.join(parts)


# ------------------------------------------------------------------ xray / nginx rendering
def active_clients(users, usage, now):
    result = {p: [] for p in PROTO_ORDER}
    for name in sorted(users):
        u = users[name]
        usg = usage['users'].get(name, {})
        if user_status(u, usg, now) != 'active':
            continue
        p = u['proto']
        if p == 'trojan':
            result[p].append({'password': u['id'], 'email': name})
        else:
            result[p].append({'id': u['id'], 'email': name})
    return result


def block_rules(users, now):
    """Device limit enforcement is OFF: no routing rules are ever added, so Xray is never restarted because of devices."""
    return []
    rules = []
    blocks = load_limits().get('blocks', {})
    for name in sorted(blocks):
        if name not in users or user_conn_limit(users[name]) <= 0:
            continue
        ips = sorted(ip for ip, until in blocks[name].items() if until > now)
        if ips:
            rules.append({'type': 'field', 'user': [name], 'source': ips, 'outboundTag': 'blocked'})
    return rules


XHTTP_MODES = ('auto', 'packet-up', 'stream-up', 'stream-one')


def xhttp_path(st, proto):
    base = '/' + (st.get('xhttp_path') or '/xhttp').strip().strip('/')
    return '%s-%s' % (base, proto)


def _rng(v):
    v = str(v).strip()
    return int(v) if v.isdigit() else v


def xhttp_extra_obj(st):
    """Customizations that must be identical on server and client (also go into share links as "extra")."""
    out = {}
    for key, name in (('xhttp_padding', 'xPaddingBytes'), ('xhttp_max_post', 'scMaxEachPostBytes'),
                      ('xhttp_min_interval', 'scMinPostsIntervalMs'), ('xhttp_max_buffered', 'scMaxBufferedPosts')):
        if str(st.get(key) or '').strip():
            out[name] = _rng(st[key])
    raw = (st.get('xhttp_extra') or '').strip()
    if raw:
        try:
            d = json.loads(raw)
            if isinstance(d, dict):
                out.update(d)
        except ValueError:
            pass
    return out


def xhttp_settings(st, proto, host=None, client=False):
    mode = (st.get('xhttp_mode') or '').strip()
    if not mode:
        mode = xhttp_mode(st) if client else 'auto'
    d = {'path': xhttp_path(st, proto), 'mode': mode}
    if host:
        d['host'] = host
    d.update(xhttp_extra_obj(st))
    return d


def xhttp_supported(st):
    """True when the installed Xray core is new enough for the xhttp transport (an older core would refuse the
    whole config, so the xhttp inbounds are simply left out in that case)."""
    binp = st.get('xray_bin') or DEFAULTS['xray_bin']
    if binp in _xhttp_ok:
        return _xhttp_ok[binp]
    ok = False
    try:
        out = subprocess.run([binp, 'version'], stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                             universal_newlines=True, timeout=10).stdout
        m = re.search(r'Xray\s+v?(\d+)\.(\d+)\.(\d+)', out)
        if m:
            ok = tuple(int(x) for x in m.groups()) >= XHTTP_MIN_VERSION
    except Exception:
        ok = False
    _xhttp_ok[binp] = ok
    return ok


def render_xray(st, users, usage, now):
    clients = active_clients(users, usage, now)
    with_xhttp = xhttp_supported(st)
    inbounds = [{
        'tag': 'api', 'listen': '127.0.0.1', 'port': int(st['api_port']),
        'protocol': 'dokodemo-door', 'settings': {'address': '127.0.0.1'},
    }]
    for proto in PROTO_ORDER:
        if not clients[proto]:
            continue
        p = PROTOS[proto]
        settings = {'clients': clients[proto]}
        if proto == 'vless':
            settings['decryption'] = 'none'
        inbounds.append({
            'tag': proto + '-ws', 'listen': '127.0.0.1', 'port': p['port'], 'protocol': proto,
            'settings': settings,
            'streamSettings': {'network': 'ws', 'security': 'none', 'wsSettings': {'path': p['path']}},
        })
        inbounds.append({
            'tag': proto + '-grpc', 'listen': '127.0.0.1', 'port': p['gport'], 'protocol': proto,
            'settings': settings,
            'streamSettings': {'network': 'grpc', 'security': 'none',
                               'grpcSettings': {'serviceName': p['grpc']}},
        })
        if with_xhttp:
            inbounds.append({
                'tag': proto + '-xhttp', 'listen': '127.0.0.1', 'port': p['xport'], 'protocol': proto,
                'settings': settings,
                'streamSettings': {'network': 'xhttp', 'security': 'none',
                                   'xhttpSettings': xhttp_settings(st, proto)},
            })
    return {
        'log': {'access': ACCESS_LOG, 'error': '/var/log/xray/error.log', 'loglevel': 'warning'},
        'api': {'tag': 'api', 'services': ['StatsService']},
        'stats': {},
        'policy': {'levels': {'0': {'statsUserUplink': True, 'statsUserDownlink': True}}},
        'inbounds': inbounds,
        'outbounds': [{'protocol': 'freedom', 'tag': 'direct'},
                      {'protocol': 'blackhole', 'tag': 'blocked'}],
        'routing': {'rules': [
            {'type': 'field', 'inboundTag': ['api'], 'outboundTag': 'api'},
        ] + block_rules(users, now) + [
            {'type': 'field', 'outboundTag': 'blocked',
             'ip': ['127.0.0.0/8', '10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16',
                    '169.254.0.0/16', '::1/128', 'fc00::/7', 'fe80::/10']},
        ]},
    }


# ------------------------------------------------------------------ fake website (decoy for the domain)
SITE_TEMPLATES = ('business', 'cloud', 'blog')


def _site_brand(domain):
    parts = [x for x in (domain or '').split('.') if x]
    label = parts[-2] if len(parts) >= 2 else (parts[0] if parts else 'Example')
    label = re.sub(r'[^A-Za-z0-9]+', ' ', label).strip() or 'Example'
    return label.title()


def _site_page(tpl, brand, domain, title, body, active):
    import html as _h
    brand_e, domain_e = _h.escape(brand), _h.escape(domain)
    themes = {
        'business': ('#1d4ed8', '#f8fafc', '#0f172a', '#ffffff', 'system-ui,Segoe UI,Arial,sans-serif'),
        'cloud':    ('#0d9488', '#0b1220', '#e2e8f0', '#111a2e', 'system-ui,Segoe UI,Arial,sans-serif'),
        'blog':     ('#9a3412', '#fffbf5', '#292524', '#ffffff', 'Georgia,Times New Roman,serif'),
    }
    accent, bg, fg, card, font = themes[tpl]
    suffix = {'business': 'Digital Solutions', 'cloud': 'Cloud', 'blog': 'Journal'}[tpl]
    nav = ''.join('<a href="%s"%s>%s</a>' % (href, ' class="on"' if key == active else '', label)
                  for key, href, label in (('home', '/', 'Home'), ('about', '/about.html', 'About'),
                                           ('contact', '/contact.html', 'Contact')))
    css = ('*{box-sizing:border-box}body{margin:0;background:%(bg)s;color:%(fg)s;font-family:%(font)s;line-height:1.6}'
           'header{background:%(card)s;border-bottom:1px solid rgba(128,128,128,.25)}'
           '.w{max-width:960px;margin:0 auto;padding:0 20px}.bar{display:flex;justify-content:space-between;align-items:center;padding:16px 0}'
           '.logo{font-weight:700;font-size:1.15rem;color:%(accent)s}nav a{margin-left:18px;color:%(fg)s;text-decoration:none;opacity:.8}'
           'nav a.on,nav a:hover{color:%(accent)s;opacity:1}.hero{padding:70px 0 40px}.hero h1{font-size:2.2rem;margin:0 0 12px}'
           '.hero p{max-width:620px;opacity:.85}.btn{display:inline-block;margin-top:16px;padding:10px 20px;background:%(accent)s;color:#fff;'
           'text-decoration:none;border-radius:6px}.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(240px,1fr));gap:18px;padding:20px 0 50px}'
           '.c{background:%(card)s;border:1px solid rgba(128,128,128,.25);border-radius:10px;padding:20px}.c h3{margin:0 0 8px;color:%(accent)s}'
           'main{padding:40px 0}footer{border-top:1px solid rgba(128,128,128,.25);padding:22px 0;font-size:.85rem;opacity:.7}'
           % {'bg': bg, 'fg': fg, 'font': font, 'card': card, 'accent': accent})
    return ('<!DOCTYPE html>\n<html lang="en"><head><meta charset="utf-8">'
            '<meta name="viewport" content="width=device-width,initial-scale=1">'
            '<title>%s - %s %s</title><style>%s</style></head><body>'
            '<header><div class="w bar"><span class="logo">%s %s</span><nav>%s</nav></div></header>'
            '%s<footer><div class="w">&copy; 2026 %s %s &middot; %s</div></footer></body></html>\n'
            % (_h.escape(title), brand_e, suffix, css, brand_e, suffix, nav, body, brand_e, suffix, domain_e))


def _site_files(tpl, domain):
    import html as _h
    brand = _site_brand(domain)
    be = _h.escape(brand)
    de = _h.escape(domain)
    if tpl == 'business':
        hero = ('<div class="hero"><h1>Reliable IT services for growing companies</h1>'
                '<p>%s helps small and medium businesses run smoothly with practical, well-documented technology support.</p>'
                '<a class="btn" href="/contact.html">Talk to us</a></div>' % be)
        cards = [('Managed IT support', 'Day-to-day help desk, device management and updates so your team can stay productive.'),
                 ('Cloud migration', 'Move email, files and line-of-business apps to the cloud with a clear plan and minimal downtime.'),
                 ('Network and security', 'Reviews of your network, backups and access controls with plain-language recommendations.')]
        about = ('About us', '%s is a small team of engineers and support specialists. We prefer simple setups, clear documentation and honest advice.' % be)
    elif tpl == 'cloud':
        hero = ('<div class="hero"><h1>Simple cloud hosting and storage</h1>'
                '<p>%s offers straightforward virtual servers and file storage for projects of any size. No surprises, no long contracts.</p>'
                '<a class="btn" href="/contact.html">Get in touch</a></div>' % be)
        cards = [('Virtual servers', 'Fast SSD-backed machines in several regions, ready in minutes.'),
                 ('Object storage', 'Store and share files with versioning and simple access rules.'),
                 ('Daily backups', 'Automatic snapshots so you can roll back when you need to.')]
        about = ('About the platform', '%s is run by a small infrastructure team focused on reliability and clear pricing.' % be)
    else:
        hero = ('<div class="hero"><h1>Notes on technology and travel</h1>'
                '<p>%s is a personal journal: short write-ups on gadgets, software I use, and places worth visiting.</p>'
                '<a class="btn" href="/about.html">About this journal</a></div>' % be)
        cards = [('Setting up a home network', 'What worked, what did not, and the cheap upgrades that made the biggest difference.'),
                 ('A week with a mechanical keyboard', 'First impressions, typing feel and whether the noise is worth it.'),
                 ('Weekend trip notes', 'Routes, small cafes and a few lessons learned about packing light.')]
        about = ('About this journal', '%s is written by one person in their spare time. New posts appear whenever there is something worth sharing.' % be)
    grid = '<div class="grid">%s</div>' % ''.join('<div class="c"><h3>%s</h3><p>%s</p></div>' % (_h.escape(t), _h.escape(d)) for t, d in cards)
    pages = {
        'index.html': _site_page(tpl, brand, domain, 'Home', '<div class="w">%s%s</div>' % (hero, grid), 'home'),
        'about.html': _site_page(tpl, brand, domain, 'About', '<main><div class="w"><h1>%s</h1><p>%s</p></div></main>' % (_h.escape(about[0]), _h.escape(about[1])), 'about'),
        'contact.html': _site_page(tpl, brand, domain, 'Contact', '<main><div class="w"><h1>Contact</h1><p>Questions are welcome. Send us an email at <b>info@%s</b> and we will reply as soon as we can.</p></div></main>' % de, 'contact'),
        '404.html': _site_page(tpl, brand, domain, 'Page not found', '<main><div class="w"><h1>404 - Page not found</h1><p>The page you are looking for does not exist. <a href="/">Back to the home page</a>.</p></div></main>', ''),
        'robots.txt': 'User-agent: *\nAllow: /\n',
    }
    return pages


def write_site(tpl, domain):
    shutil.rmtree(SITE_DIR, ignore_errors=True)
    os.makedirs(SITE_DIR, 0o755)
    os.chmod(SITE_DIR, 0o755)
    for name, content in _site_files(tpl, domain).items():
        path = os.path.join(SITE_DIR, name)
        with open(path, 'w') as f:
            f.write(content)
        os.chmod(path, 0o644)


def cmd_fakesite(a):
    """Install / remove / show the decoy website served by the V2Ray front nginx on '/'."""
    st = need_installed()
    with locked():
        st = load_settings()
        if a.off:
            st['fake_site'] = ''
            write_json(SETTINGS_FILE, st)
            apply_all()
            shutil.rmtree(SITE_DIR, ignore_errors=True)
        elif a.template:
            if a.template not in SITE_TEMPLATES:
                die('Unknown template. Choose: %s' % ', '.join(SITE_TEMPLATES))
            write_site(a.template, st['domain'])
            st['fake_site'] = a.template
            write_json(SETTINGS_FILE, st)
            apply_all()
    st = load_settings()
    print(json.dumps({'template': st.get('fake_site', ''), 'enabled': bool(st.get('fake_site')),
                      'templates': list(SITE_TEMPLATES), 'dir': SITE_DIR}))


_nginx_reject_ok = {}


def nginx_reject_supported(st):
    """ssl_reject_handshake (the TLS unrecognized_name alert) needs nginx 1.19.4 or newer."""
    binp = st.get('nginx_bin') or DEFAULTS['nginx_bin']
    if binp in _nginx_reject_ok:
        return _nginx_reject_ok[binp]
    ok = False
    rc, out, err = run([binp, '-v'], timeout=10)
    m = re.search(r'nginx/(\d+)\.(\d+)\.(\d+)', (out or '') + (err or ''))
    if m:
        ok = tuple(int(x) for x in m.groups()) >= (1, 19, 4)
    _nginx_reject_ok[binp] = ok
    return ok


def sni_lock_names(st):
    """The only TLS server names nginx accepts when the SNI lock is on (empty list = lock not usable)."""
    if not st.get('sni_lock'):
        return []
    sni = (st.get('cfg_sni') or '').strip().lower()
    if not sni or sni == (st.get('domain') or '').strip().lower() or not nginx_reject_supported(st):
        return []
    return [sni]


def render_nginx(st, realip=True):
    ipv6 = os.path.exists('/proc/net/if_inet6')
    try:
        pwd.getpwnam('www-data')
        user_line = 'user www-data;\n'
    except KeyError:
        user_line = ''

    def locations():
        out = []
        for proto in PROTO_ORDER:
            p = PROTOS[proto]
            out.append(
                '    location %(path)s {\n'
                '        proxy_pass http://127.0.0.1:%(port)d;\n'
                '        proxy_http_version 1.1;\n'
                '        proxy_set_header Upgrade $http_upgrade;\n'
                '        proxy_set_header Connection $connection_upgrade;\n'
                '        proxy_set_header Host $host;\n'
                '        proxy_set_header X-Real-IP $remote_addr;\n'
                '        proxy_set_header X-Forwarded-For $remote_addr;\n'
                '        proxy_read_timeout 86400s;\n'
                '        proxy_send_timeout 86400s;\n'
                '        proxy_buffering off;\n'
                '    }\n' % {'path': p['path'], 'port': p['port']})
        return ''.join(out)

    def grpc_locations():
        out = []
        for proto in PROTO_ORDER:
            p = PROTOS[proto]
            out.append(
                '    location /%(svc)s {\n'
                '        grpc_pass grpc://127.0.0.1:%(port)d;\n'
                '        grpc_read_timeout 1h;\n'
                '        grpc_send_timeout 1h;\n'
                '        client_body_timeout 1h;\n'
                '        client_max_body_size 0;\n'
                '        grpc_set_header Host $host;\n'
                '        grpc_set_header X-Real-IP $remote_addr;\n'
                '        grpc_set_header X-Forwarded-For $remote_addr;\n'
                '    }\n' % {'svc': p['grpc'], 'port': p['gport']})
        return ''.join(out)

    def xhttp_locations():
        out = []
        for proto in PROTO_ORDER:
            p = PROTOS[proto]
            out.append(
                '    location %(path)s {\n'
                '        proxy_pass http://127.0.0.1:%(port)d;\n'
                '        proxy_http_version 1.1;\n'
                '        proxy_set_header Connection \"\";\n'
                '        proxy_set_header Host $host;\n'
                '        proxy_set_header X-Real-IP $remote_addr;\n'
                '        proxy_set_header X-Forwarded-For $remote_addr;\n'
                '        proxy_buffering off;\n'
                '        proxy_request_buffering off;\n'
                '        proxy_read_timeout 1h;\n'
                '        proxy_send_timeout 1h;\n'
                '        client_body_timeout 1h;\n'
                '        client_max_body_size 0;\n'
                '    }\n' % {'path': xhttp_path(st, proto), 'port': p['xport']})
        return ''.join(out) if xhttp_supported(st) else ''

    if st.get('fake_site') and os.path.isdir(SITE_DIR):
        fallback = ('    root %s;\n    index index.html;\n    error_page 404 /404.html;\n'
                    '    location / { try_files $uri $uri/ =404; }\n'
                    '    location = /404.html { internal; }\n' % SITE_DIR)
    else:
        fallback = '    location / { return 404; }\n'

    decoy_port = int(st.get('decoy_port') or 0)
    if decoy_port:
        # HAProxy (port multiplexer) owns 80/443 and sends browsers here: serve only the fake site, on loopback
        return ('# generated by ffv2ray.py - do not edit, changes are overwritten\n'
                + user_line +
                'worker_processes 1;\n'
                'pid /run/ff-v2ray-nginx.pid;\n'
                'error_log /var/log/xray/nginx-error.log warn;\n'
                'events { worker_connections 1024; }\n'
                'http {\n'
                '  access_log off;\n'
                '  server_tokens off;\n'
                '  server {\n'
                '    listen 127.0.0.1:%d default_server;\n'
                '    server_name _;\n'
                '%s'
                '  }\n'
                '}\n') % (decoy_port, fallback)

    http_listen = '    listen %d default_server;\n' % int(st['http_port'])
    tls_listen = '    listen %d ssl http2 default_server;\n' % int(st['tls_port'])
    if ipv6:
        http_listen += '    listen [::]:%d default_server;\n' % int(st['http_port'])
        tls_listen += '    listen [::]:%d ssl http2 default_server;\n' % int(st['tls_port'])

    def tls_blocks():
        body = locations() + grpc_locations() + xhttp_locations() + fallback
        ssl_common = ('    ssl_certificate %s;\n'
                      '    ssl_certificate_key %s;\n'
                      '    ssl_protocols TLSv1.2 TLSv1.3;\n'
                      '    ssl_session_cache shared:ffv2ray:10m;\n'
                      '    ssl_session_timeout 1d;\n') % (st['cert'], st['key'])
        names = sni_lock_names(st)
        if not names:
            return '  server {\n' + tls_listen + '    server_name _;\n' + ssl_common + body + '  }\n'
        # SNI lock: the default server refuses every handshake (TLS alert unrecognized_name, this is what Host
        # Checker shows for the domain). Its locations still answer the HTTP requests that arrive over a
        # connection opened with an allowed SNI, whatever Host header they carry (Host = the real domain).
        return ('  server {\n' + tls_listen + '    server_name _;\n    ssl_reject_handshake on;\n' + body + '  }\n'
                '  server {\n' + tls_listen.replace(' default_server', '') +
                '    server_name %s;\n' % ' '.join(names) + ssl_common + body + '  }\n')

    return (
        '# generated by ffv2ray.py - do not edit, changes are overwritten\n'
        + user_line +
        'worker_processes auto;\n'
        'pid /run/ff-v2ray-nginx.pid;\n'
        'error_log /var/log/xray/nginx-error.log warn;\n'
        'worker_rlimit_nofile 65535;\n'
        'events { worker_connections 8192; }\n'
        'http {\n'
        '  access_log off;\n'
        '  server_tokens off;\n'
        + (cdn_realip_block(st) if realip else '') +
        '  map $http_upgrade $connection_upgrade { default upgrade; \'\' close; }\n'
        '  server {\n'
        + http_listen +
        '    server_name _;\n'
        + locations() + xhttp_locations() + fallback +
        '  }\n'
        + tls_blocks() +
        '}\n')


def apply_all(force=False):
    """Re-render config files; restart Xray / nginx only when their config changed."""
    st = load_settings()
    users = load_users()
    usage = load_usage()
    now = int(time.time())
    try:
        os.makedirs('/var/log/xray', exist_ok=True)
    except OSError:
        pass

    cfg_text = json.dumps(render_xray(st, users, usage, now), indent=2, sort_keys=True) + '\n'
    xray_changed = cfg_text != read_text(XRAY_CONF)
    if xray_changed:
        write_text(XRAY_CONF, cfg_text)

    ngx_text = render_nginx(st)
    if ngx_text != read_text(NGINX_CONF) and cdn_realip_block(st):
        ngx_text = checked_cdn_nginx(st, ngx_text)
    nginx_changed = ngx_text != read_text(NGINX_CONF)
    if nginx_changed:
        write_text(NGINX_CONF, ngx_text, 0o644)

    if xray_changed or force:
        run(['systemctl', 'restart', XRAY_SERVICE])
    if nginx_changed:
        run(['systemctl', 'restart', NGINX_SERVICE])
    return xray_changed, nginx_changed


# ------------------------------------------------------------------ stats
def query_stats(st):
    """Read (and reset) the per-user counters of Xray. None when Xray is not reachable."""
    cmd = [st['xray_bin'], 'api', 'statsquery', '--server=127.0.0.1:%d' % int(st['api_port']),
           '-pattern', 'user>>>', '-reset']
    rc, out, _ = run(cmd, timeout=10)
    if rc != 0:
        return None
    try:
        data = json.loads(out.strip() or '{}')
    except ValueError:
        return None
    result = {}
    for item in (data.get('stat') or []):
        parts = str(item.get('name', '')).split('>>>')
        if len(parts) != 4 or parts[0] != 'user' or parts[2] != 'traffic':
            continue
        try:
            val = int(item.get('value', 0) or 0)
        except (TypeError, ValueError):
            continue
        d = result.setdefault(parts[1], {'up': 0, 'down': 0})
        if parts[3] == 'uplink':
            d['up'] += val
        elif parts[3] == 'downlink':
            d['down'] += val
    return result


def accumulate(usage, deltas, now, dt=0):
    today = today_str(now)
    ulist = usage['users']
    for u in ulist.values():
        if u.get('day') != today:
            u['daily'] = 0
            u['day'] = today
        if deltas is not None and dt >= 2:
            u['rate_up'] = 0
            u['rate_down'] = 0
    for name, d in (deltas or {}).items():
        u = ulist.setdefault(name, new_usage(now))
        total = d['up'] + d['down']
        u['up'] += d['up']
        u['down'] += d['down']
        u['total'] += total
        u['daily'] += total
        if total > 0:
            u['last'] = now
        if dt >= 2:                                         # a 0-1 second window gives wild numbers: no speed from it
            u['rate_up'] = min(d['up'] / float(dt), MAX_RATE)
            u['rate_down'] = min(d['down'] / float(dt), MAX_RATE)
            if u['rate_up'] > u.get('peak_up', 0):          # highest speed ever seen on this account
                u['peak_up'] = u['rate_up']
            if u['rate_down'] > u.get('peak_down', 0):
                u['peak_down'] = u['rate_down']
        for k in ('peak_up', 'peak_down'):
            if u.get(k, 0) > MAX_RATE:                      # repair a record saved by an older version
                u[k] = 0
    usage['ts'] = now


def collect_now(st):
    """Fold the traffic counted since the last poll into usage.json."""
    users = load_users()
    usage = load_usage()
    deltas = query_stats(st)
    if deltas is not None:
        accumulate(usage, deltas, int(time.time()))
        save_usage(usage, users)
    return usage


# ------------------------------------------------------------------ account links / cards
def client_opts(st):
    """(address, sni, host, insecure) used in client configs. With nothing set it is the plain domain."""
    d = st['domain']
    addr = (st.get('cfg_address') or '').strip() or d
    sni = (st.get('cfg_sni') or '').strip() or addr
    host = (st.get('cfg_host') or '').strip() or d
    # a TLS name that is not the server's own domain cannot match the server certificate
    insecure = (sni != d)
    return addr, sni, host, insecure


def cdn_on(st):
    return (st.get('cdn') or '') == 'imperva'


def show_grpc(st):
    return (not cdn_on(st)) or bool(st.get('cdn_grpc'))


def xhttp_mode(st):
    """packet-up works over plain HTTP/1.1 hops, which is what a CDN uses towards the origin."""
    return 'packet-up' if cdn_on(st) else 'auto'


def build_client_json(st, name, u, kind):
    """Full client config (socks inbound + proxy outbound) for apps that import a JSON config.
    kind: 'tls' (WS+TLS), 'none' (WS, no TLS), 'grpc' (gRPC+TLS), 'xhttp' (XHTTP+TLS) or 'xhttpnone' (XHTTP, no TLS)."""
    d, sni, host, insecure = client_opts(st)
    tls, http = int(st['tls_port']), int(st['http_port'])
    p = PROTOS[u['proto']]
    ident = u['id']
    port = http if kind in ('none', 'xhttpnone') else tls
    if u['proto'] == 'vless':
        settings = {'vnext': [{'address': d, 'port': port,
                               'users': [{'id': ident, 'level': 8, 'encryption': 'none'}]}]}
    elif u['proto'] == 'vmess':
        settings = {'vnext': [{'address': d, 'port': port,
                               'users': [{'id': ident, 'alterId': 0, 'security': 'auto', 'level': 8}]}]}
    else:
        settings = {'servers': [{'address': d, 'port': port, 'password': ident, 'level': 8}]}
    tls_settings = {'serverName': sni, 'fingerprint': 'chrome', 'show': False}
    if insecure:
        tls_settings['allowInsecure'] = True
    if kind == 'grpc':
        stream = {'network': 'grpc', 'security': 'tls',
                  'grpcSettings': {'serviceName': p['grpc'], 'multiMode': False},
                  'tlsSettings': tls_settings}
    elif kind == 'xhttp':
        stream = {'network': 'xhttp', 'security': 'tls',
                  'xhttpSettings': xhttp_settings(st, u['proto'], host, True),
                  'tlsSettings': tls_settings}
    elif kind == 'xhttpnone':
        stream = {'network': 'xhttp', 'security': 'none',
                  'xhttpSettings': xhttp_settings(st, u['proto'], host, True)}
    elif kind == 'none':
        stream = {'network': 'ws', 'security': 'none',
                  'wsSettings': {'path': p['path'], 'headers': {'Host': host}}}
    else:
        stream = {'network': 'ws', 'security': 'tls',
                  'wsSettings': {'path': p['path'], 'headers': {'Host': host}},
                  'tlsSettings': tls_settings}
    mux = {'enabled': False, 'concurrency': 8, 'xudpConcurrency': 8, 'xudpProxyUDP443': ''}
    cfg = {
        'remarks': name,
        'log': {'loglevel': 'warning'},
        'inbounds': [{'tag': 'socks', 'port': 10808, 'protocol': 'socks',
                      'settings': {'auth': 'noauth', 'udp': True, 'userLevel': 8},
                      'sniffing': {'enabled': True, 'destOverride': ['http', 'tls', 'quic'], 'routeOnly': False}}],
        'outbounds': [
            {'tag': 'proxy', 'protocol': u['proto'], 'settings': settings, 'streamSettings': stream,
             'mux': {'enabled': False, 'concurrency': -1, 'xudpConcurrency': 8, 'xudpProxyUDP443': ''}},
            {'tag': 'direct', 'protocol': 'freedom', 'settings': {'domainStrategy': 'UseIP'}, 'mux': dict(mux)},
            {'tag': 'block', 'protocol': 'blackhole', 'settings': {'response': {'type': 'http'}}, 'mux': dict(mux)},
        ],
        'dns': {
            'servers': ['1.1.1.1'],
            'hosts': {
                'domain:googleapis.cn': 'googleapis.com',
                'dns.alidns.com': ['223.5.5.5', '223.6.6.6', '2400:3200::1', '2400:3200:baba::1'],
                'one.one.one.one': ['1.1.1.1', '1.0.0.1', '2606:4700:4700::1111', '2606:4700:4700::1001'],
                'dot.pub': ['1.12.12.12', '120.53.53.53'],
                'dns.google': ['8.8.8.8', '8.8.4.4', '2001:4860:4860::8888', '2001:4860:4860::8844'],
                'dns.quad9.net': ['9.9.9.9', '149.112.112.112', '2620:fe::fe', '2620:fe::9'],
                'common.dot.dns.yandex.net': ['77.88.8.8', '77.88.8.1', '2a02:6b8::feed:0ff', '2a02:6b8:0:1::feed:0ff'],
            },
            'queryStrategy': 'UseIPv4',
        },
        'routing': {'domainStrategy': 'AsIs', 'rules': [
            {'type': 'field', 'ip': ['1.1.1.1'], 'outboundTag': 'proxy', 'port': '53'},
            {'type': 'field', 'ip': ['223.5.5.5'], 'outboundTag': 'direct', 'port': '53'},
        ]},
    }
    return json.dumps(cfg, separators=(',', ':'), ensure_ascii=False)


def build_links(st, name, u):
    links = _build_share_links(st, name, u)
    kinds = [('Json TLS', 'tls'), ('Json none TLS', 'none')]
    if show_grpc(st):
        kinds.append(('Json GRPC', 'grpc'))
    if xhttp_supported(st):
        kinds += [('Json XHTTP', 'xhttp'), ('Json XHTTP none TLS', 'xhttpnone')]
    for label, kind in kinds:
        links.append((label, build_client_json(st, name, u, kind)))
    return links


def _build_share_links(st, name, u):
    links = _build_base_share_links(st, name, u)
    if not show_grpc(st):
        links = [l for l in links if 'GRPC' not in l[0]]
    if xhttp_supported(st):
        links += _build_xhttp_share_links(st, name, u)
    return links


def _build_xhttp_share_links(st, name, u):
    """XHTTP share links (TLS and none-TLS). mode=auto lets the client pick packet-up on HTTP/1.1 and CDNs."""
    d, sni, host, insecure = client_opts(st)
    tls, http = int(st['tls_port']), int(st['http_port'])
    p = PROTOS[u['proto']]
    tag = urllib.parse.quote(name, safe='')
    ident = u['id']
    xp = xhttp_path(st, u['proto'])
    path = urllib.parse.quote(xp, safe='')
    ins = '&allowInsecure=1' if insecure else ''
    mode = xhttp_settings(st, u['proto'], None, True)['mode']
    xe = xhttp_extra_obj(st)
    if xe:
        ins += '&extra=' + urllib.parse.quote(json.dumps(xe, separators=(',', ':')), safe='')
    if u['proto'] == 'vmess':
        def vm(port, tls_on):
            obj = {'v': '2', 'ps': name, 'add': d, 'port': str(port), 'id': ident, 'aid': '0',
                   'scy': 'auto', 'net': 'xhttp', 'type': 'auto', 'host': host, 'path': xp,
                   'tls': 'tls' if tls_on else '', 'sni': sni if tls_on else ''}
            if tls_on and insecure:
                obj['allowInsecure'] = True
            raw = json.dumps(obj, separators=(',', ':')).encode()
            return 'vmess://' + base64.b64encode(raw).decode()
        return [('Link XHTTP', vm(tls, True)), ('Link XHTTP none TLS', vm(http, False))]
    scheme = u['proto']
    enc = '&encryption=none' if scheme == 'vless' else ''
    return [
        ('Link XHTTP', '%s://%s@%s:%d?security=tls%s&type=xhttp&mode=%s&host=%s&path=%s&sni=%s&fp=chrome%s#%s'
         % (scheme, ident, d, tls, enc, mode, host, path, sni, ins, tag)),
        ('Link XHTTP none TLS', '%s://%s@%s:%d?security=none%s&type=xhttp&mode=%s&host=%s&path=%s#%s'
         % (scheme, ident, d, http, enc, mode, host, path, tag)),
    ]


def _build_base_share_links(st, name, u):
    d, sni, host, insecure = client_opts(st)
    custom = (d != st['domain']) or (sni != st['domain']) or (host != st['domain'])
    tls, http = int(st['tls_port']), int(st['http_port'])
    p = PROTOS[u['proto']]
    tag = urllib.parse.quote(name, safe='')
    ident = u['id']
    extra_tls = ''
    extra_none = ''
    if custom:
        extra_tls = '&host=%s&sni=%s%s' % (host, sni, '&allowInsecure=1' if insecure else '')
        extra_none = '&host=%s' % host
    if u['proto'] == 'vless':
        return [
            ('Link TLS', 'vless://%s@%s:%d?path=%s&security=tls&encryption=none&type=ws%s#%s' % (ident, d, tls, p['path'], extra_tls, tag)),
            ('Link none TLS', 'vless://%s@%s:%d?path=%s&encryption=none&type=ws%s#%s' % (ident, d, http, p['path'], extra_none, tag)),
            ('Link GRPC', 'vless://%s@%s:%d?mode=gun&security=tls&encryption=none&type=grpc&serviceName=%s&sni=%s%s#%s' % (ident, d, tls, p['grpc'], sni, '&allowInsecure=1' if insecure else '', tag)),
        ]
    if u['proto'] == 'vmess':
        def vm(port, net, path, tls_on, typ):
            obj = {'v': '2', 'ps': name, 'add': d, 'port': str(port), 'id': ident, 'aid': '0',
                   'scy': 'auto', 'net': net, 'type': typ, 'host': host, 'path': path,
                   'tls': 'tls' if tls_on else '', 'sni': sni if tls_on else ''}
            if tls_on and insecure:
                obj['allowInsecure'] = True
            raw = json.dumps(obj, separators=(',', ':')).encode()
            return 'vmess://' + base64.b64encode(raw).decode()
        return [
            ('Link TLS', vm(tls, 'ws', p['path'], True, 'none')),
            ('Link none TLS', vm(http, 'ws', p['path'], False, 'none')),
            ('Link GRPC', vm(tls, 'grpc', p['grpc'], True, 'gun')),
        ]
    path = urllib.parse.quote(p['path'], safe='')
    ins = '&allowInsecure=1' if insecure else ''
    return [
        ('Link TLS', 'trojan://%s@%s:%d?path=%s&security=tls&host=%s&type=ws&sni=%s%s#%s' % (ident, d, tls, path, host, sni, ins, tag)),
        ('Link none TLS', 'trojan://%s@%s:%d?path=%s&security=none&host=%s&type=ws#%s' % (ident, d, http, path, host, tag)),
        ('Link GRPC', 'trojan://%s@%s:%d?mode=gun&security=tls&type=grpc&serviceName=%s&sni=%s%s#%s' % (ident, d, tls, p['grpc'], sni, ins, tag)),
    ]


def row(key, val):
    return '%s : %s' % (key.ljust(14), val)


def limit_text(u):
    tl, dl = float(u.get('total_gb', 0)), float(u.get('daily_gb', 0))
    if tl <= 0 and dl <= 0:
        return 'Unlimited'
    parts = []
    if tl > 0:
        parts.append('%s GB total' % gb_str(tl))
    if dl > 0:
        parts.append('%s GB/day' % gb_str(dl))
    return ' | '.join(parts)


def account_card(name, u, st):
    p = PROTOS[u['proto']]
    bar = org('━' * 46)
    out = ['', bar, wht('  Xray/%s Account' % p['label']), bar]
    out.append(row('Remarks', name))
    out.append(row('Domain', st['domain']))
    if cdn_on(st):
        out.append(row('CDN', 'Imperva'))
    out.append(row('port TLS', st['tls_port']))
    out.append(row('port none TLS', st['http_port']))
    if show_grpc(st):
        out.append(row('Port  GRPC', st['tls_port']))
    if u['proto'] == 'trojan':
        out.append(row('Password', u['id']))
    else:
        out.append(row('id', u['id']))
    if u['proto'] == 'vless':
        out.append(row('Encryption', 'none'))
    elif u['proto'] == 'vmess':
        out.append(row('alterId', '0'))
        out.append(row('Security', 'auto'))
    out.append(row('Network', 'ws'))
    out.append(row('Path', p['path']))
    if show_grpc(st):
        out.append(row('ServiceName', p['grpc']))
    if xhttp_supported(st):
        out.append(row('XHTTP Path', xhttp_path(st, u['proto'])))
        if cdn_on(st):
            out.append(row('XHTTP Mode', 'packet-up (CDN)'))
        else:
            out.append(row('XHTTP Mode', 'auto (packet-up if your app asks)'))
    out.append(bar)
    for label, link in build_links(st, name, u):
        out.append(row(label, cyn(link)))
        out.append(bar)
    out.append(row('Expired On', fmt_time(u['expiry']) if u.get('expiry') else 'Never'))
    out.append(row('Bandwidth', limit_text(u)))
    cl = user_conn_limit(u)
    out.append(row('Devices', str(cl) if cl > 0 else 'Unlimited'))
    out.append(bar)
    return '\n'.join(out)


def progress_bar(pct, width=30):
    pct = max(0.0, min(100.0, pct))
    filled = int(round(pct / 100.0 * width))
    color = grn if pct <= 50 else (yel if pct <= 80 else red)
    return color('[' + '█' * filled + '░' * (width - filled) + ']') + ' %.1f%%' % pct


def usage_card(name, u, usg, now):
    status = user_status(u, usg, now)
    tl, dl = quota_bytes(u.get('total_gb', 0)), quota_bytes(u.get('daily_gb', 0))
    out = ['', wht('--- Bandwidth Details: %s (%s) ---' % (name, u['proto'])), '']
    out.append(row('Status', status_label(status)))
    out.append(row('Data Used', '%s' % human(usg.get('total', 0))))
    if tl > 0:
        out.append(row('Total Limit', '%s GB' % gb_str(u['total_gb'])))
        out.append(row('Remaining', human(max(0, tl - usg.get('total', 0)))))
        out.append(row('Usage', progress_bar(usg.get('total', 0) * 100.0 / tl)))
    else:
        out.append(row('Total Limit', grn('Unlimited')))
    out.append(row('Used Today', human(usg.get('daily', 0))))
    if dl > 0:
        out.append(row('Daily Limit', '%s GB/day' % gb_str(u['daily_gb'])))
        out.append(row('Today', progress_bar(usg.get('daily', 0) * 100.0 / dl)))
    else:
        out.append(row('Daily Limit', grn('Unlimited')))
    out.append(row('Upload', human(usg.get('up', 0))))
    out.append(row('Download', human(usg.get('down', 0))))
    out.append(row('Speed now', 'down %s | up %s' % (human_rate(usg.get('rate_down', 0)), human_rate(usg.get('rate_up', 0)))))
    out.append(row('Max speed', 'down %s | up %s' % (human_rate(usg.get('peak_down', 0)), human_rate(usg.get('peak_up', 0)))))
    out.append(row('Expires', fmt_time(u['expiry']) if u.get('expiry') else 'Never'))
    if status == 'quota':
        out.append('\n' + red('  Total bandwidth finished - account is switched off'))
    elif status == 'daily':
        out.append('\n' + red('  Daily bandwidth finished - back after midnight'))
    return '\n'.join(out)


# ------------------------------------------------------------------ commands
def need_installed():
    st = load_settings()
    if not st.get('domain'):
        die('V2Ray is not set up yet (no settings found). Install it from the menu first.')
    return st


def cmd_api(a):
    print('FFV2RAY-API %d' % FFV2RAY_API)


def cmd_init(a):
    with locked():
        os.makedirs(V2_DIR, mode=0o700, exist_ok=True)
        st = load_settings()
        for key, attr in (('domain', 'domain'), ('tls_port', 'tls_port'), ('http_port', 'http_port'),
                          ('cert', 'cert'), ('key', 'key'), ('xray_bin', 'xray_bin'),
                          ('nginx_bin', 'nginx_bin'), ('decoy_port', 'decoy_port')):
            val = getattr(a, attr)
            if val is not None:
                st[key] = int(val) if key.endswith('_port') else val
        if st['tls_port'] == st['http_port']:
            die('TLS port and non-TLS port must be different.')
        write_json(SETTINGS_FILE, st)
        if not os.path.exists(USERS_FILE):
            save_users({})
        if not os.path.exists(USAGE_FILE):
            save_usage(load_usage())
        apply_all(force=False)
    print('OK')


def cmd_render(a):
    with locked():
        xc, nc = apply_all(force=a.restart)
    print('xray_changed=%s nginx_changed=%s' % (xc, nc))


def cmd_get(a):
    st = load_settings()
    print(st.get(a.key, ''))


def cmd_clientopts(a):
    """Show / set the client config options: connect address (bug host), SNI and WS Host header."""
    with locked():
        st = load_settings()
        changed = False
        if a.reset:
            for k in ('cfg_address', 'cfg_sni', 'cfg_host'):
                st[k] = ''
            changed = True
        for key, val in (('cfg_address', a.address), ('cfg_sni', a.sni), ('cfg_host', a.host)):
            if val is None:
                continue
            val = val.strip()
            if val and not HOST_RE.match(val):
                die('Invalid value for %s: use a domain name or IP (letters, digits, dot, dash).' % key[4:])
            st[key] = val
            changed = True
        if changed:
            write_json(SETTINGS_FILE, st)
    print(json.dumps({'address': st.get('cfg_address', ''), 'sni': st.get('cfg_sni', ''),
                      'host': st.get('cfg_host', ''), 'domain': st.get('domain', '')}))


def cmd_xhttpopts(a):
    """Show / set the XHTTP customizations (path, mode, padding, post size/interval, raw extra JSON)."""
    keys = (('path', 'xhttp_path'), ('mode', 'xhttp_mode'), ('padding', 'xhttp_padding'),
            ('max_post', 'xhttp_max_post'), ('min_interval', 'xhttp_min_interval'),
            ('max_buffered', 'xhttp_max_buffered'), ('extra', 'xhttp_extra'))
    with locked():
        st = load_settings()
        if a.reset:
            for _, k in keys:
                st[k] = ''
        for arg, k in keys:
            v = getattr(a, arg)
            if v is None:
                continue
            v = v.strip()
            if v:
                if arg == 'path' and not re.match(r'^/?[A-Za-z0-9_./-]{1,60}$', v):
                    die('Invalid path.')
                if arg == 'mode' and v not in XHTTP_MODES:
                    die('Mode must be one of: ' + ', '.join(XHTTP_MODES))
                if arg in ('padding', 'max_post', 'min_interval', 'max_buffered') and not re.match(r'^\d+(-\d+)?$', v):
                    die('%s must be a number or a range like 100-1000.' % arg)
                if arg == 'extra':
                    try:
                        if not isinstance(json.loads(v), dict):
                            raise ValueError
                    except ValueError:
                        die('extra must be a JSON object, e.g. {"xmux":{"maxConcurrency":"16-32"}}')
            st[k] = v
        write_json(SETTINGS_FILE, st)
    apply_all()
    print(json.dumps({arg: st.get(k, '') for arg, k in keys}))


def cmd_snilock(a):
    """Turn the SNI lock on / off: the domain (and every unknown name) is refused at the TLS handshake."""
    with locked():
        st = load_settings()
        if a.on:
            sni = (st.get('cfg_sni') or '').strip()
            if not sni or sni.lower() == (st.get('domain') or '').strip().lower():
                die('Set a client SNI different from the domain first (ffv2ray clientopts --sni www.example.com).')
            if not nginx_reject_supported(st):
                die('This nginx is older than 1.19.4 and cannot refuse a handshake. Update nginx first.')
            if int(st.get('decoy_port') or 0):
                print(yel('Note: HAProxy owns 80/443 here, so nginx is not the TLS front. Apply the lock in HAProxy.'))
            if cdn_on(st):
                print(yel('Note: the CDN must connect to your origin with SNI "%s", not with the domain.' % sni))
            st['sni_lock'] = True
        elif a.off:
            st['sni_lock'] = False
        write_json(SETTINGS_FILE, st)
    if a.on or a.off:
        apply_all()
    print('sni_lock=%s names=%s' % ('on' if st.get('sni_lock') else 'off', ','.join(sni_lock_names(st)) or '-'))


def cmd_add(a):
    st = need_installed()
    name = a.name
    if a.proto not in PROTOS:
        die('Unknown protocol.')
    if not NAME_RE.match(name):
        die('Name must be 2-24 characters: letters, digits, _ or -')
    secs = int(a.days * 86400 + a.hours * 3600 + a.minutes * 60)
    if secs <= 0:
        die('Duration must be greater than zero.')
    custom_id = (a.id or '').strip()
    if custom_id and not ID_RE.match(custom_id):
        die('ID must be 3-30 characters: letters, digits, dot, _ or -')
    with locked():
        users = load_users()
        if name in users:
            die("Account '%s' already exists." % name)
        if custom_id and any(x.get('id') == custom_id for x in users.values()):
            die("ID '%s' is already used by another account." % custom_id)
        collect_now(st)
        now = int(time.time())
        users = load_users()
        users[name] = {
            'proto': a.proto, 'id': custom_id or str(uuid.uuid4()), 'created': now, 'expiry': now + secs,
            'total_gb': a.total, 'daily_gb': a.daily, 'locked': False, 'trial': bool(a.trial),
            'conn_limit': max(0, int(a.conn)), 'owner': a.owner or 'admin',
        }
        save_users(users)
        usage = load_usage()
        usage['users'][name] = new_usage(now)
        save_usage(usage, users)
        apply_all()
    print('OK')


def cmd_exists(a):
    sys.exit(0 if a.name in load_users() else 1)


def _need_user(users, name):
    if name not in users:
        die("Account '%s' was not found." % name)
    return users[name]


def cmd_del(a):
    st = need_installed()
    with locked():
        users = load_users()
        _need_user(users, a.name)
        collect_now(st)
        users = load_users()
        del users[a.name]
        save_users(users)
        usage = load_usage()
        save_usage(usage, users)
        apply_all()
    print('OK')


def cmd_renew(a):
    st = need_installed()
    with locked():
        users = load_users()
        u = _need_user(users, a.name)
        collect_now(st)
        users = load_users()
        u = users[a.name]
        now = int(time.time())
        base = max(now, u.get('expiry') or 0)
        u['expiry'] = base + int(a.days * 86400)
        save_users(users)
        if a.reset:
            usage = load_usage()
            usage['users'][a.name] = new_usage(now)
            save_usage(usage, users)
        apply_all()
    print('OK')


def cmd_setexpiry(a):
    """Set the expiry to N days from today (or never)."""
    st = need_installed()
    if not a.never and a.days is None:
        die('Give --days N (days from today) or --never.')
    with locked():
        users = load_users()
        _need_user(users, a.name)
        collect_now(st)
        users = load_users()
        u = users[a.name]
        now = int(time.time())
        if a.never:
            u['expiry'] = 0
        elif a.mode == 'day':
            u['expiry'] = eat_day_end(now, a.days)
        else:
            u['expiry'] = now + int(a.days * 86400)
        save_users(users)
        apply_all()
    print('OK')


def cmd_limit(a):
    st = need_installed()
    with locked():
        users = load_users()
        _need_user(users, a.name)
        collect_now(st)
        users = load_users()
        if a.total is not None:
            users[a.name]['total_gb'] = a.total
        if a.daily is not None:
            users[a.name]['daily_gb'] = a.daily
        if a.conn is not None:
            users[a.name]['conn_limit'] = max(0, int(a.conn))
            lim = load_limits()                      # new limit: forget old blocks of this account
            if lim['blocks'].pop(a.name, None) is not None:
                save_limits(lim)
        save_users(users)
        if a.reset:
            usage = load_usage()
            usage['users'][a.name] = new_usage(int(time.time()))
            save_usage(usage, users)
        apply_all()
    print('OK')


def _set_lock(name, value):
    st = need_installed()
    with locked():
        users = load_users()
        _need_user(users, name)
        collect_now(st)
        users = load_users()
        users[name]['locked'] = value
        save_users(users)
        apply_all()
    print('OK')


def cmd_lock(a):
    _set_lock(a.name, True)


def cmd_unlock(a):
    _set_lock(a.name, False)


def cmd_cleanup(a):
    st = need_installed()
    with locked():
        collect_now(st)
        users = load_users()
        usage = load_usage()
        now = int(time.time())
        gone = [n for n, u in users.items()
                if u.get('expiry') and now >= u['expiry']]
        for n in gone:
            del users[n]
        save_users(users)
        save_usage(usage, users)
        apply_all()
    print('Removed %d expired account(s).' % len(gone))


def select_names(proto=None):
    users = load_users()
    names = sorted(users)
    if proto:
        names = [n for n in names if users[n]['proto'] == proto]
    return users, names


def cmd_names(a):
    users, names = select_names(a.proto)
    usage = load_usage()
    now = int(time.time())
    for n in names:
        u = users[n]
        usg = usage['users'].get(n, {})
        print('%s|%s|%s|%s|%s' % (n, u['proto'], user_status(u, usg, now),
                                  fmt_time(u['expiry']) if u.get('expiry') else 'Never',
                                  usage_text(u, usg)))


def cmd_counts(a):
    users = load_users()
    counts = {p: 0 for p in PROTO_ORDER}
    for u in users.values():
        counts[u['proto']] = counts.get(u['proto'], 0) + 1
    print(' '.join('%s=%d' % (p, counts[p]) for p in PROTO_ORDER))


def mag(s): return C.c('0;35', s)


SPINNER = '⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏'
SPEED_FLOOR = 1048576.0       # the speed bars are at least 1 MB/s wide, so tiny speeds do not look full


def term_size():
    try:
        sz = shutil.get_terminal_size((80, 24))
        return sz.columns, sz.lines
    except Exception:
        return 80, 24


def bar(frac, width, color):
    frac = max(0.0, min(1.0, frac))
    filled = int(round(frac * width))
    return color('█' * filled) + dim('░' * (width - filled))


def pct_color(frac):
    return grn if frac <= 0.5 else (yel if frac <= 0.8 else red)


def stat_row(label, frac, width, color, text):
    return '  %s %s %s' % (label.ljust(8), bar(frac, width, color), text)


def collect_view(proto):
    """Everything the dashboard needs, read once (the live view calls this about once a second)."""
    users, names = select_names(proto)
    usage = load_usage()
    now = int(time.time())
    devs = device_activity()
    return {'users': users, 'names': names, 'usage': usage, 'now': now, 'devs': devs}


STATUS_ICON = {'active': '🟢', 'locked': '🔒', 'expired': '🗓️', 'quota': '📦', 'daily': '📦'}


def badge(bg, text):
    return C.c('1;38;5;16;48;5;%d' % bg, ' %s ' % text)


def gauge(frac, width):
    """Usage gauge like the SSH list: green below 65%, orange below 90%, red above."""
    frac = max(0.0, min(1.0, frac))
    filled = int(round(frac * width))
    col = grn if frac < 0.65 else (yel if frac < 0.9 else red)
    return col('▰' * filled) + dim('▱' * (width - filled)) + ' ' + col('%3d%%' % int(frac * 100))


def reseller_names():
    """Reseller accounts known to the panel (resellers.db lives next to the v2ray folder)."""
    names = set()
    try:
        with open(os.path.join(os.path.dirname(V2_DIR.rstrip('/')), 'resellers.db')) as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):
                    names.add(line.split(':', 1)[0])
    except OSError:
        pass
    return names


def head_lines(summary, cols, title='V2RAY USERS'):
    parts = summary.split('\n')
    out = [wht(title) + '  ' + dim(parts[0])]
    out += [dim(p) for p in parts[1:]]
    out.append(dim('─' * min(cols - 1, 60)))
    return out


def dashboard(view, disp, frame, cols, animate):
    """One block of lines per account: devices, today, total, download and upload speed as bars.
    `disp` keeps the speeds that are drawn so the speed bars glide to their new value."""
    users, names, usage, now, devs = view['users'], view['names'], view['usage'], view['now'], view['devs']
    today = today_str(now)
    fresh = (now - usage.get('ts', 0)) <= 20          # the limiter service must be updating the counters
    width = max(8, min(24, cols - 40))

    info = {}
    for n in names:
        usg = usage['users'].get(n, {})
        daily = usg.get('daily', 0) if usg.get('day') == today else 0
        r_dn = usg.get('rate_down', 0) if fresh else 0
        r_up = usg.get('rate_up', 0) if fresh else 0
        d = disp.setdefault(n, {'down': 0.0, 'up': 0.0})
        for key, target in (('down', r_dn), ('up', r_up)):
            if animate:
                d[key] += (target - d[key]) * 0.35
                if abs(target - d[key]) < 1:
                    d[key] = float(target)
            else:
                d[key] = float(target)
        info[n] = (usg, daily, d['down'], d['up'])

    max_daily = max([v[1] for v in info.values()] + [1])
    max_total = max([v[0].get('total', 0) for v in info.values()] + [1])
    scale = max([SPEED_FLOOR] + [v[2] for v in info.values()] + [v[3] for v in info.values()])
    live_n = 0
    blocks = []
    reseller_set = reseller_names()
    admin_n = res_n = tot_used = tot_today = 0
    for n in names:
        u = users[n]
        usg, daily, r_dn, r_up = info[n]
        status = user_status(u, usg, now)
        live = bool(usg.get('last', 0) and now - usg['last'] <= 30 and fresh)
        live_n += 1 if live else 0
        if live:
            dot = grn(SPINNER[frame % len(SPINNER)] if animate else '●')
        else:
            dot = dim('○')
        # ---- card (same look as the SSH "Managed Users" list) ----
        owner = u.get('owner') or 'admin'
        cl = user_conn_limit(u)
        dv = device_count(devs.get(n))
        icon = STATUS_ICON.get(status, '•')
        rule = dim('│')
        rows = ['%s 👤 %s %s %s %s%s' % (dim('╭─'), wht(n), dim('[%s]' % u['proto']), icon, status_label(status),
                                        ('  ' + dot + dim(' live')) if live else '')]
        if owner == 'admin':
            who = badge(46, '👑 ADMIN')
            admin_n += 1
        elif owner in reseller_set:
            who = badge(208, '🏷️ RESELLER') + ' ' + C.c('1;38;5;208', owner)
            res_n += 1
        else:
            who = badge(240, '🏷️ RESELLER') + ' ' + dim(owner + ' (removed)')
            res_n += 1
        rows.append('%s  🧑‍💼 %s %s' % (rule, dim('Created by'), who))
        if u.get('expiry'):
            left = int(math.ceil((u['expiry'] - now) / 86400.0))
            if left < 0:
                dtxt = red('(expired)')
            else:
                dcol = red if left <= 3 else (yel if left <= 7 else grn)
                dtxt = dcol('(%d day(s) left)' % left)
            rows.append('%s  📅 %s %s  %s' % (rule, dim('Expires '), yel(fmt_time(u['expiry']).split(' ')[0]), dtxt))
        else:
            rows.append('%s  📅 %s %s  %s' % (rule, dim('Expires '), yel('Never'), dim('(never expires)')))
        dcolr = red if (cl > 0 and dv >= cl) else grn
        dots = ''
        if 0 < cl <= 10:
            dots = ''.join((dcolr('●') if i < dv else dim('○')) for i in range(cl)) + '  '
        rows.append('%s  🔌 %s %s%s' % (rule, dim('Devices '), dots, dcolr('%d / %s' % (dv, cl if cl > 0 else '∞'))))

        # total + today usage
        dl, tl = quota_bytes(u.get('daily_gb', 0)), quota_bytes(u.get('total_gb', 0))
        total = usg.get('total', 0)
        tot_used += total
        tot_today += daily
        if tl > 0:
            frac = total / float(tl)
            rows.append('%s  📦 %s %s' % (rule, dim('Total   '), gauge(frac, 18)))
            rows.append('%s     %s %s %s' % (rule, wht('%s / %s GB' % (human(total), gb_str(u['total_gb']))), dim('•'),
                                            grn('%s left' % human(max(0, tl - total)))))
        else:
            rows.append('%s  📦 %s %s %s %s' % (rule, dim('Total   '), cyn('∞ Unlimited'), dim('•'), wht('used ' + human(total))))
        if dl > 0:
            frac = daily / float(dl)
            rows.append('%s  📆 %s %s' % (rule, dim('Today   '), gauge(frac, 18)))
            rows.append('%s     %s %s %s' % (rule, wht('%s / %s GB' % (human(daily), gb_str(u['daily_gb']))), dim('•'),
                                            grn('%s left' % human(max(0, dl - daily)))))
        else:
            rows.append('%s  📆 %s %s %s' % (rule, dim('Today   '), wht('used ' + human(daily)), dim('(no daily limit)')))

        # live speed
        rows.append('%s  ⚡ %s ↓ %s ↑ %s' % (rule, dim('Speed   '), cyn(human_rate(r_dn).ljust(10)), mag(human_rate(r_up))))
        rows.append(dim('╰' + '─' * 42))
        blocks.append(rows)

    tot_dn = sum(v[2] for v in info.values())
    tot_up = sum(v[3] for v in info.values())
    summary = '%d account%s · %d live · ↓ %s  ↑ %s\n%d by admin · %d by resellers · used %s · today %s' % (
        len(names), '' if len(names) == 1 else 's', live_n, human_rate(tot_dn), human_rate(tot_up),
        admin_n, res_n, human(tot_used), human(tot_today))
    warn = None if fresh else red('! limiter service has not updated the counters - speeds show 0')
    return blocks, summary, warn


def render_static(view, proto):
    disp = {}
    cols = term_size()[0]
    blocks, summary, warn = dashboard(view, disp, 0, cols, False)
    out = head_lines(summary, cols)
    if warn:
        out.append(warn)
    for rows in blocks:
        out.extend(rows)
        out.append('')
    return out


def cmd_list(a):
    users, names = select_names(a.proto)
    if not names:
        print(yel('No accounts found.'))
        return
    interactive = sys.stdout.isatty() and sys.stdin.isatty() and not a.once
    if not interactive:
        print('\n'.join(render_static(collect_view(a.proto), a.proto)))
        return
    try:
        import select
        import termios
        import tty
    except ImportError:                                # no terminal control: fall back to one static view
        print('\n'.join(render_static(collect_view(a.proto), a.proto)))
        return
    fd = sys.stdin.fileno()
    old = termios.tcgetattr(fd)
    disp, page, frame, next_load, view = {}, 0, 0, 0.0, None
    sys.stdout.write('\033[?25l\033[2J')
    try:
        tty.setcbreak(fd)
        while True:
            t = time.time()
            if view is None or t >= next_load:
                view = collect_view(a.proto)
                next_load = t + 1.0
            cols, rows_avail = term_size()
            blocks, summary, warn = dashboard(view, disp, frame, cols, True)
            block_h = (len(blocks[0]) + 1) if blocks else 12           # a card + 1 blank line
            per_page = max(1, (rows_avail - 7) // block_h)
            pages = max(1, (len(blocks) + per_page - 1) // per_page)
            page = max(0, min(page, pages - 1))
            out = head_lines(summary, cols)
            if warn:
                out.append(warn)
            for rows in blocks[page * per_page:(page + 1) * per_page]:
                out.extend(rows)
                out.append('')
            keys = '[n]ext [p]rev ' if pages > 1 else ''
            out.append(dim('page %d/%d   %s[q] quit   live, refreshes every second' % (page + 1, pages, keys)))
            sys.stdout.write('\033[H' + '\033[K\n'.join(out) + '\033[K\n\033[J')
            sys.stdout.flush()
            frame += 1
            if select.select([fd], [], [], 0.2)[0]:
                key = os.read(fd, 8)
                if key in (b'q', b'Q'):
                    break
                if key in (b'n', b'N', b' ', b'\x1b[C', b'\x1b[B'):
                    page = (page + 1) % pages
                elif key in (b'p', b'P', b'\x1b[D', b'\x1b[A'):
                    page = (page - 1) % pages
                sys.stdout.write('\033[2J')
    except KeyboardInterrupt:
        pass
    finally:
        termios.tcsetattr(fd, termios.TCSADRAIN, old)
        sys.stdout.write('\033[?25h\n')
        sys.stdout.flush()


def cmd_show(a):
    st = need_installed()
    users = load_users()
    u = _need_user(users, a.name)
    print(account_card(a.name, u, st))


def cmd_usage(a):
    users = load_users()
    u = _need_user(users, a.name)
    usage = load_usage()
    print(usage_card(a.name, u, usage['users'].get(a.name, new_usage(int(time.time()))), int(time.time())))


LOG_RE = re.compile(r'^(\d{4}/\d\d/\d\d \d\d:\d\d:\d\d)(?:\.\d+)? (?:from )?(\S+) accepted .*?email: (\S+)')


def recent_log_activity(window):
    """{email: {'ips': set, 'conns': n, 'last': ts}} from the Xray access log."""
    result = {}
    try:
        size = os.path.getsize(ACCESS_LOG)
        with open(ACCESS_LOG, 'rb') as f:
            f.seek(max(0, size - 4 * 1024 * 1024))
            data = f.read().decode('utf-8', 'replace')
    except (IOError, OSError):
        return result
    now = time.time()
    for line in data.splitlines():
        m = LOG_RE.match(line)
        if not m:
            continue
        try:
            ts = time.mktime(time.strptime(m.group(1), '%Y/%m/%d %H:%M:%S'))
        except ValueError:
            continue
        if now - ts > window:
            continue
        addr = m.group(2)
        ip = addr.rsplit(':', 1)[0].strip('[]') if ':' in addr else addr
        d = result.setdefault(m.group(3), {'ips': set(), 'conns': 0, 'last': 0})
        d['ips'].add(ip)
        d['conns'] += 1
        d['last'] = max(d['last'], ts)
    return result


def _log_ip(addr):
    """Client IP out of the address field of an Xray access-log line."""
    for pre in ('tcp:', 'udp:'):
        if addr.startswith(pre):
            addr = addr[len(pre):]
    if addr.startswith('['):
        return addr[1:addr.find(']')] if ']' in addr else addr.strip('[]')
    return addr.rsplit(':', 1)[0] if ':' in addr else addr


def device_prefixes():
    st = load_settings()
    out = []
    for key, default, lo, hi in (('device_v4_prefix', DEVICE_V4_PREFIX, 8, 32), ('device_v6_prefix', DEVICE_V6_PREFIX, 32, 128)):
        try:
            out.append(min(hi, max(lo, int(st.get(key, default)))))
        except (TypeError, ValueError):
            out.append(default)
    return out[0], out[1]


def device_key(ip, v4=DEVICE_V4_PREFIX, v6=DEVICE_V6_PREFIX):
    """One key per physical device: the network block (/24 or /64) the source IP lives in."""
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return ip
    if a.version == 6 and a.ipv4_mapped is not None:
        a = a.ipv4_mapped
    bits = v4 if a.version == 4 else v6
    full = 32 if a.version == 4 else 128
    if bits >= full:
        return str(a)
    return str(ipaddress.ip_network('%s/%d' % (a, bits), strict=False))


_dev_cache = {'t': 0.0, 'w': 0, 'v': {}}


def device_activity(window=DEVICE_WINDOW):
    """{email: {'ips': {device_key: first_ts}, 'last_ip': {device_key: ts}, 'conns': n, 'last': ts, 'proxy': bool}}
    Devices are told apart by the network block (/24, IPv6 /64) of their source IP. Connections that Xray sees as local (127.0.0.1)
    cannot be told apart, they only show that the account is active. A device that was refused
    because the account is over its limit is not counted while it is refused."""
    nowt = time.time()
    if _dev_cache['v'] and _dev_cache['w'] == window and nowt - _dev_cache['t'] < 2:
        return _dev_cache['v']
    blocks = load_limits().get('blocks', {})
    p4, p6 = device_prefixes()
    result = {}
    try:
        size = os.path.getsize(ACCESS_LOG)
        with open(ACCESS_LOG, 'rb') as f:
            f.seek(max(0, size - 4 * 1024 * 1024))
            data = f.read().decode('utf-8', 'replace')
    except (IOError, OSError):
        return result
    for line in data.splitlines():
        m = LOG_RE.match(line)
        if not m:
            continue
        try:
            ts = time.mktime(time.strptime(m.group(1), '%Y/%m/%d %H:%M:%S'))
        except ValueError:
            continue
        if nowt - ts > window:
            continue
        ip, name = _log_ip(m.group(2)), m.group(3)
        d = result.setdefault(name, {'ips': {}, 'last_ip': {}, 'conns': 0, 'last': 0, 'proxy': False})
        if ip in LOCAL_IPS:
            d['proxy'] = True
        else:
            ip = device_key(ip, p4, p6)               # same network block = same device
            if ts < blocks.get(name, {}).get(ip, 0):
                continue                              # refused device: ignore its attempts
            d['ips'].setdefault(ip, ts)
            d['last_ip'][ip] = max(d['last_ip'].get(ip, 0), ts)
        d['conns'] += 1
        d['last'] = max(d['last'], ts)
    _dev_cache.update(t=nowt, w=window, v=result)
    return result


def device_count(d):
    """Number of devices online for one account entry of device_activity()."""
    if not d:
        return 0
    return max(len(d['ips']), 1 if d['conns'] else 0)


def cmd_online(a):
    users, names = select_names(a.proto)
    if a.name:
        _need_user(users, a.name)
        names = [a.name]
    if not names:
        print(yel('No accounts found.'))
        return
    window = a.minutes * 60
    log = recent_log_activity(window)
    usage = load_usage()
    now = time.time()
    print(wht('Login check (live = traffic in last 30s, recent = connections in last %d min)' % a.minutes))
    print(dim('-' * 66))
    for n in names:
        usg = usage['users'].get(n, {})
        live = usg.get('last', 0) and now - usg['last'] <= 30
        d = log.get(n)
        dot = grn('●') if live else (yel('●') if d else dim('○'))
        state = grn('LIVE') if live else (yel('recent') if d else dim('offline'))
        extra = ''
        if d:
            ips = sorted(i for i in d['ips'] if i not in ('127.0.0.1', '::1'))
            extra = '  conns:%d  ips:%s  last:%ds ago' % (
                d['conns'], (','.join(ips[:3]) if ips else 'via proxy'), int(now - d['last']))
        cl = user_conn_limit(users[n])
        dv = device_count(device_activity().get(n))
        extra += '  devices:%d/%s' % (dv, cl if cl > 0 else 'inf')
        print('%s %-14s %-6s %s%s' % (dot, n[:14], users[n]['proto'], state, extra))


def build_monitor():
    st = load_settings()
    users = load_users()
    usage = load_usage()
    now = int(time.time())
    lines = [wht('XRAY LIVE BANDWIDTH MONITOR') + dim('   (Ctrl+C to exit)'), dim('─' * 50)]
    age = now - usage.get('ts', 0)
    if age > 20:
        lines.append(red('! limiter service has not updated for %ds - is it running?' % age))
    if not users:
        lines.append(yel('No accounts yet.'))
    tot_rate_d = tot_rate_u = 0
    for n in sorted(users):
        u = users[n]
        usg = usage['users'].get(n, new_usage(now))
        status = user_status(u, usg, now)
        tl = quota_bytes(u.get('total_gb', 0))
        dl = quota_bytes(u.get('daily_gb', 0))
        live = usg.get('last', 0) and now - usg['last'] <= 30
        lines.append('%s %s %s  %s' % (grn('●') if live else dim('○'), wht(n), dim('[%s]' % u['proto']), status_label(status)))
        if tl > 0:
            lines.append('   Total : %s / %s GB  %s' % (human(usg.get('total', 0)), gb_str(u['total_gb']),
                                                         progress_bar(usg.get('total', 0) * 100.0 / tl, 16)))
        else:
            lines.append('   Total : %s / Unlimited' % human(usg.get('total', 0)))
        if dl > 0:
            lines.append('   Today : %s / %s GB  %s' % (human(usg.get('daily', 0)), gb_str(u['daily_gb']),
                                                         progress_bar(usg.get('daily', 0) * 100.0 / dl, 16)))
        else:
            lines.append('   Today : %s' % human(usg.get('daily', 0)))
        lines.append('   Speed : down %s | up %s' % (human_rate(usg.get('rate_down', 0)), human_rate(usg.get('rate_up', 0))))
        lines.append('   Exp   : %s' % (fmt_time(u['expiry']) if u.get('expiry') else 'Never'))
        tot_rate_d += usg.get('rate_down', 0)
        tot_rate_u += usg.get('rate_up', 0)
    lines.append(dim('─' * 50))
    lines.append('All users now: down %s | up %s' % (human_rate(tot_rate_d), human_rate(tot_rate_u)))
    return '\n'.join(lines)


def cmd_monitor(a):
    if a.once:
        print(build_monitor())
        return
    try:
        while True:
            sys.stdout.write('\033[H\033[2J' + build_monitor() + '\n')
            sys.stdout.flush()
            time.sleep(1)
    except KeyboardInterrupt:
        print()


def enforce_device_limits(users, now):
    """Device limit enforcement is OFF. Devices are only counted for display (menu and panel).
    Nobody is refused and Xray is not restarted. Old stored blocks are cleared once."""
    lim = load_limits()
    if lim.get('blocks'):
        lim['blocks'] = {}
        save_limits(lim)


def daemon_tick(last_ts):
    """One poll: count traffic, enforce limits, drop expired trials, re-render when needed."""
    st = load_settings()
    if not st.get('domain'):
        return last_ts
    if (cdn_on(st) and not st.get('cdn_trust_any') and time.time() >= _cdn_retry_after
            and time.time() - int(st.get('cdn_ranges_ts') or 0) > CDN_REFRESH):
        cdn_refresh()                              # network call: done before the lock is taken
    with locked():
        users = load_users()
        usage = load_usage()
        now = int(time.time())
        dt = (now - last_ts) if last_ts else 0
        deltas = query_stats(st)
        if deltas is not None:
            accumulate(usage, deltas, now, dt)      # first poll after a start (dt 0): count the traffic, but no speed
        else:
            usage['ts'] = now
        trial_gone = [n for n, u in users.items()
                      if u.get('trial') and u.get('expiry') and now >= u['expiry']]
        if trial_gone:
            for n in trial_gone:
                del users[n]
            save_users(users)
        save_usage(usage, users)
        try:
            enforce_device_limits(users, now)
        except Exception as exc:                   # a log problem must never stop the bandwidth limiter
            sys.stderr.write('ffv2ray device limit error: %s\n' % exc)
        apply_all()
    return now


def cmd_daemon(a):
    last = 0
    while True:
        try:
            last = daemon_tick(last)
        except Exception as exc:                   # never let the limiter die
            sys.stderr.write('ffv2ray daemon error: %s\n' % exc)
        if a.once:
            return
        time.sleep(INTERVAL)


# ------------------------------------------------------------------ Imperva CDN support
# A domain that sits behind Imperva (Cloud WAF / CDN) reaches this server through Imperva's edge servers.
# Two things change:
#   * the connecting address is an Imperva edge IP, so nginx must take the real visitor IP from the
#     Incap-Client-IP (or X-Forwarded-For) header - but ONLY when the request really comes from Imperva
#     (set_real_ip_from + Imperva's published networks), otherwise anybody could fake an IP;
#   * Imperva talks HTTP/1.1 to the origin, so WS and XHTTP (packet-up) are offered and gRPC is hidden.
IMPERVA_IPS_URL = 'https://my.imperva.com/api/integration/v1/ips'
CDN_REFRESH = 12 * 3600          # the daemon re-downloads the Imperva networks this often
CDN_HEADER_RE = re.compile(r'^[A-Za-z0-9-]{1,64}$')
_cdn_retry_after = 0
_nginx_bad = set()


def clean_ranges(items):
    """Keep only valid IPv4 / IPv6 networks (a bare IP becomes /32 or /128), without duplicates."""
    out, seen = [], set()
    for it in items or []:
        try:
            net = ipaddress.ip_network(str(it).strip(), strict=False)
        except ValueError:
            continue
        txt = str(net)
        if txt not in seen:
            seen.add(txt)
            out.append(txt)
    return out


def _json_strings(obj, acc):
    if isinstance(obj, str):
        acc.append(obj)
    elif isinstance(obj, dict):
        for v in obj.values():
            _json_strings(v, acc)
    elif isinstance(obj, list):
        for v in obj:
            _json_strings(v, acc)


def fetch_imperva_ranges(timeout=20):
    """Download the edge networks from Imperva (the answer is read key-agnostic: every CIDR string counts)."""
    data = urllib.parse.urlencode({'resp_format': 'json'}).encode()
    req = urllib.request.Request(IMPERVA_IPS_URL, data=data, headers={'User-Agent': 'ffv2ray'})
    with contextlib.closing(urllib.request.urlopen(req, timeout=timeout)) as r:
        body = r.read().decode('utf-8', 'replace')
    strs = []
    _json_strings(json.loads(body), strs)
    ranges = clean_ranges([x for x in strs if '/' in x])
    if len(ranges) < 5:
        raise ValueError('unexpected answer from Imperva (%d networks found)' % len(ranges))
    return ranges


def cdn_trusted(st):
    """All networks nginx may take the real client IP from."""
    return clean_ranges(list(st.get('cdn_ranges') or []) + list(st.get('cdn_ranges_extra') or []))


def cdn_realip_block(st):
    """nginx real-ip directives for an Imperva domain ('' when the mode is off or nothing is trusted yet)."""
    if not cdn_on(st):
        return ''
    hdr = (st.get('cdn_ip_header') or 'Incap-Client-IP').strip()
    if not CDN_HEADER_RE.match(hdr):
        hdr = 'Incap-Client-IP'
    if st.get('cdn_trust_any'):
        nets = ['0.0.0.0/0', '::/0']
    else:
        nets = cdn_trusted(st)
    if not nets:
        return ''
    out = ['  # Imperva CDN: take the real visitor IP from the %s header (only from Imperva networks)\n' % hdr]
    for n in nets:
        out.append('  set_real_ip_from %s;\n' % n)
    out.append('  real_ip_header %s;\n' % hdr)
    out.append('  real_ip_recursive on;\n')
    return ''.join(out)


def nginx_conf_ok(st, text):
    nb = st.get('nginx_bin') or DEFAULTS['nginx_bin']
    tmp = NGINX_CONF + '.test'
    try:
        write_text(tmp, text, 0o644)
        rc, out, err = run([nb, '-t', '-c', tmp], timeout=20)
        return rc == 0, (err or out).strip()
    finally:
        try:
            os.remove(tmp)
        except OSError:
            pass


def checked_cdn_nginx(st, text):
    """Use the CDN config only when nginx accepts it. If it does not (for example nginx was built
    without the real-ip module) but the plain config works, fall back to the plain config."""
    key = hash(text)
    if key in _nginx_bad:
        return render_nginx(st, realip=False)
    ok, msg = nginx_conf_ok(st, text)
    if ok:
        return text
    plain = render_nginx(st, realip=False)
    ok2, _ = nginx_conf_ok(st, plain)
    if ok2:
        _nginx_bad.add(key)
        sys.stderr.write(red('ffv2ray: nginx refused the Imperva real-IP settings, running without them: %s\n'
                             % msg.replace('\n', ' ')[:300]))
        return plain
    return text


def cdn_refresh():
    """Download and store the Imperva networks. Returns (ok, message)."""
    global _cdn_retry_after
    st = load_settings()
    if not cdn_on(st):
        return False, 'Imperva mode is off.'
    try:
        ranges = fetch_imperva_ranges()
    except Exception as exc:
        _cdn_retry_after = int(time.time()) + 1800
        return False, 'Could not download the Imperva networks: %s' % exc
    with locked():
        st = load_settings()
        old = list(st.get('cdn_ranges') or [])
        st['cdn_ranges'] = ranges
        st['cdn_ranges_ts'] = int(time.time())
        write_json(SETTINGS_FILE, st)
    return True, '%d Imperva networks stored (%s).' % (len(ranges), 'changed' if ranges != old else 'unchanged')


def cdn_summary(st):
    on = cdn_on(st)
    lines = []
    lines.append(row('Imperva mode', grn('ON') if on else dim('off')))
    if on:
        lines.append(row('Real IP header', st.get('cdn_ip_header') or 'Incap-Client-IP'))
        if st.get('cdn_trust_any'):
            lines.append(row('Trusted from', yel('ANY source (firewall must admit Imperva only)')))
        else:
            n, extra = len(st.get('cdn_ranges') or []), len(st.get('cdn_ranges_extra') or [])
            ts = int(st.get('cdn_ranges_ts') or 0)
            lines.append(row('Imperva networks', '%d (+%d extra), updated %s' % (n, extra, fmt_time(ts) if ts else 'never')))
            if not cdn_trusted(st):
                lines.append(row('Warning', red('no networks yet: real IPs are NOT used. Refresh the list.')))
        lines.append(row('gRPC links', 'shown' if st.get('cdn_grpc') else 'hidden (CDN)'))
    return '\n'.join(lines)


def cmd_cdn(a):
    """Show / change the CDN (Imperva) settings."""
    with locked():
        st = need_installed()
        changed = False
        if a.enable:
            st['cdn'] = 'imperva'
            changed = True
        if a.disable:
            st['cdn'] = ''
            changed = True
        if a.header is not None:
            h = a.header.strip()
            if not CDN_HEADER_RE.match(h):
                die('Header name: letters, digits and dash only.')
            st['cdn_ip_header'] = h
            changed = True
        if a.trust_any:
            st['cdn_trust_any'] = True
            changed = True
        if a.no_trust_any:
            st['cdn_trust_any'] = False
            changed = True
        if a.allow_grpc:
            st['cdn_grpc'] = True
            changed = True
        if a.hide_grpc:
            st['cdn_grpc'] = False
            changed = True
        if a.extra_ranges is not None:
            raw = [x for x in re.split(r'[\s,;]+', a.extra_ranges) if x]
            good = clean_ranges(raw)
            if len(good) != len(raw):
                die('Some extra ranges are not valid IPv4 / IPv6 networks.')
            st['cdn_ranges_extra'] = good
            changed = True
        if changed:
            write_json(SETTINGS_FILE, st)
    msg = ''
    st = load_settings()
    if cdn_on(st) and not st.get('cdn_trust_any') and (a.refresh or not st.get('cdn_ranges')):
        ok, msg = cdn_refresh()
        if not ok:
            sys.stderr.write(yel(msg) + '\n')
    if changed or a.refresh:
        with locked():
            apply_all()
    st = load_settings()
    print(cdn_summary(st))
    if msg:
        print(msg)


# ------------------------------------------------------------------ installer (system side)
LIB_DIR = '/usr/local/lib/visibleTech-v2ray'
MANAGER_PATH = LIB_DIR + '/ffv2ray.py'
BIN_LINK = '/usr/local/bin/ffv2ray'
XRAY_UNIT_FILE = '/etc/systemd/system/ff-xray.service'
NGINX_UNIT_FILE = '/etc/systemd/system/ff-v2ray-nginx.service'
LIMITER_UNIT = 'ff-v2ray-limiter'
LIMITER_UNIT_FILE = '/etc/systemd/system/ff-v2ray-limiter.service'
CERT_DIR = '/etc/visibleTech/ssl'
RENEW_HOOK = '/etc/letsencrypt/renewal-hooks/deploy/visibleTech-v2ray.sh'
INSTALL_CONF = os.path.join(V2_DIR, 'install.conf')
# optional extra download source for the Xray binary (same repo folder the menu script uses); set
# FFV2_REPO_BASE="" to skip it. The official Xray-core release is used when it has nothing usable.
REPO_BASE = os.environ.get('FFV2_REPO_BASE', 'https://raw.githubusercontent.com/wavy07/Script4/main/V2RAY%20MODED')
ALL_SERVICES = [XRAY_SERVICE, NGINX_SERVICE, LIMITER_UNIT]
MENU_CMD = '/usr/local/bin/menu'
LOGIN_HOOK = '/etc/profile.d/ffv2ray-menu.sh'
WRAPPER_MARK = '# ffv2ray-wrapper'


class Back(Exception):
    """Input ended (Ctrl-D): leave the current menu."""


def ppl(s): return C.c('1;35', s)
def blu(s): return C.c('0;34', s)


def ask(prompt, default=None):
    try:
        v = input(prompt).strip()
    except EOFError:
        raise Back()
    if v == '' and default is not None:
        return default
    return v


def yesno(prompt, default=False):
    v = ask('%s (%s): ' % (prompt, 'Y/n' if default else 'y/N'), 'y' if default else 'n').lower()
    return v in ('y', 'yes')


def press_enter():
    try:
        input(dim('\nPress Enter to continue...'))
    except EOFError:
        raise Back()


def clear_screen():
    if sys.stdout.isatty():
        sys.stdout.write('\033[2J\033[H')
        sys.stdout.flush()


def banner(sub=''):
    clear_screen()
    w = 56
    title = 'visibleTech  XRAY / V2RAY  INSTALLER + MANAGER'
    print(cyn('┌' + '─' * w + '┐'))
    print(cyn('│') + ' ' * ((w - len(title)) // 2) + wht(title) + ' ' * (w - len(title) - (w - len(title)) // 2) + cyn('│'))
    print(cyn('└' + '─' * w + '┘'))
    if sub:
        print('\n' + ppl(sub))


def need_root():
    if os.geteuid() != 0:
        die('Run this as root (sudo python3 ffv2ray.py).')


def installed():
    return os.path.exists(XRAY_UNIT_FILE) and os.path.exists(SETTINGS_FILE)


def sh(cmd, quiet=True, timeout=None):
    """Run a command; returns the exit code. quiet=False streams the output to the terminal."""
    try:
        if quiet:
            return subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=timeout).returncode
        return subprocess.call(cmd)
    except Exception:
        return 127


def v2(args, quiet=False):
    """Run one ffv2ray sub-command in-process (same as `ffv2ray.py <args>`). Returns (exit code, output)."""
    out, err = io.StringIO(), io.StringIO()
    rc = 0
    try:
        if quiet:
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                main([str(x) for x in args])
        else:
            main([str(x) for x in args])
    except SystemExit as e:
        rc = e.code if isinstance(e.code, int) else (0 if e.code is None else 1)
    except KeyboardInterrupt:
        rc = 130
    if quiet and err.getvalue().strip():
        sys.stderr.write(err.getvalue())
    return rc, out.getvalue()


# ---- packages
def pkg_manager():
    for name in ('apt-get', 'dnf', 'yum', 'zypper', 'pacman'):
        if shutil.which(name):
            return name
    return None


_apt_updated = False


def pkg_install(pkgs):
    global _apt_updated
    pm = pkg_manager()
    if not pm:
        print(red('❌ No supported package manager found (apt, dnf, yum, zypper, pacman).'))
        return False
    env = dict(os.environ, DEBIAN_FRONTEND='noninteractive')
    try:
        if pm == 'apt-get':
            if not _apt_updated:
                subprocess.call(['apt-get', 'update', '-qq'], env=env)
                _apt_updated = True
            cmd = ['apt-get', 'install', '-y', '-qq'] + pkgs
        elif pm in ('dnf', 'yum'):
            cmd = [pm, 'install', '-y', '-q'] + pkgs
        elif pm == 'zypper':
            cmd = ['zypper', '--non-interactive', 'install'] + pkgs
        else:
            cmd = ['pacman', '-S', '--noconfirm', '--needed'] + pkgs
        return subprocess.call(cmd, env=env) == 0
    except Exception as exc:
        print(red('❌ Package install failed: %s' % exc))
        return False


def pkg_purge(pkgs):
    pm = pkg_manager()
    env = dict(os.environ, DEBIAN_FRONTEND='noninteractive')
    if pm == 'apt-get':
        sh(['apt-get', 'purge', '-y'] + pkgs)
        sh(['apt-get', 'autoremove', '-y'])
    elif pm in ('dnf', 'yum'):
        sh([pm, 'remove', '-y', '-q'] + pkgs)
    elif pm == 'zypper':
        sh(['zypper', '--non-interactive', 'remove'] + pkgs)
    elif pm == 'pacman':
        sh(['pacman', '-Rns', '--noconfirm'] + pkgs)


# ---- ports and firewall
def valid_port(p):
    return str(p).isdigit() and 1 <= int(p) <= 65535


def valid_domain(d):
    if not d or len(d) > 253 or '.' not in d:
        return False
    if not re.match(r'^[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?$', d):
        return False
    try:
        ipaddress.ip_address(d)
        return False
    except ValueError:
        return True


def port_listener(port):
    rc, out, err = run(['ss', '-H', '-lntp', '( sport = :%d )' % int(port)], timeout=10)
    out = out.strip()
    if not out:
        return None
    pid = re.search(r'pid=(\d+)', out)
    name = re.search(r'\(\("([^"]+)"', out)
    return (name.group(1) if name else 'unknown', int(pid.group(1)) if pid else None)


def free_ports(ports):
    for port in ports:
        print(blu('\n🔎 Checking if port %s is available...' % port))
        owner = port_listener(port)
        if not owner:
            print(grn('✅ Port %s is free to use.' % port))
            continue
        name, pid = owner
        print(yel("⚠️  Port %s is in use by process '%s' (PID %s)." % (port, name, pid or 'N/A')))
        if not yesno('👉 Do you want to attempt to stop this process?'):
            print(red('❌ Cannot continue without freeing port %s.' % port))
            return False
        if not pid:
            print(red('❌ Could not determine which process owns port %s. Free it manually.' % port))
            return False
        if sh(['systemctl', 'stop', name]) != 0:
            try:
                os.kill(pid, 9)
            except OSError:
                pass
        time.sleep(2)
        if port_listener(port):
            print(red('❌ Failed to free port %s. Handle it manually.' % port))
            return False
        print(grn('✅ Port %s has been freed.' % port))
    return True


def open_firewall(port):
    detected = False
    spec = '%s/tcp' % port
    if shutil.which('ufw'):
        rc, out, _ = run(['ufw', 'status'], timeout=10)
        if 'Status: active' in out:
            detected = True
            if spec in out:
                print(grn('✅ Port %s is already open in UFW.' % spec))
            elif yesno(yel('🔥 UFW is active and %s is closed. Open it now?' % spec), True):
                sh(['ufw', 'allow', spec])
                print(grn('✅ Port %s opened in UFW.' % spec))
            else:
                print(red('❌ %s was not opened. The service may not work.' % spec))
                return False
    if shutil.which('firewall-cmd') and sh(['systemctl', 'is-active', '--quiet', 'firewalld']) == 0:
        detected = True
        rc, out, _ = run(['firewall-cmd', '--list-ports', '--permanent'], timeout=10)
        if spec in out.split():
            print(grn('✅ Port %s is already open in firewalld.' % spec))
        elif yesno(yel('🔥 firewalld is active and %s is closed. Open it now?' % spec), True):
            sh(['firewall-cmd', '--add-port=' + spec, '--permanent'])
            sh(['firewall-cmd', '--reload'])
            print(grn('✅ Port %s opened in firewalld.' % spec))
        else:
            print(red('❌ %s was not opened. The service may not work.' % spec))
            return False
    if not detected:
        print(blu('ℹ️  No active firewall (UFW / firewalld) found. Assuming the port is open.'))
    return True


# ---- download helpers
def download(url, dest, timeout=60, tries=3):
    last = None
    for _ in range(tries):
        try:
            req = urllib.request.Request(url, headers={'User-Agent': 'ffv2ray'})
            with contextlib.closing(urllib.request.urlopen(req, timeout=timeout)) as r, open(dest, 'wb') as f:
                shutil.copyfileobj(r, f)
            return True
        except Exception as exc:
            last = exc
            time.sleep(2)
    sys.stderr.write(dim('   download failed (%s): %s\n' % (url.split('/')[-1], last)))
    return False


def xray_arch():
    m = platform.machine().lower()
    if m in ('x86_64', 'amd64'):
        return 'xray', '64'
    if m in ('aarch64', 'arm64'):
        return 'xray-arm64', 'arm64-v8a'
    if m in ('armv7l', 'armv6l'):
        return 'xray-arm32', 'arm32-v7a'
    if re.match(r'^i.86$', m):
        return 'xray-32', '32'
    return None


def xray_works(path):
    try:
        os.chmod(path, 0o755)
        p = subprocess.run([path, 'version'], stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                           universal_newlines=True, timeout=15)
        return p.returncode == 0 and 'Xray' in p.stdout
    except Exception:
        return False


def fetch_xray():
    """Xray core: custom repo copy first (optional), then the official Xray-core release."""
    arch = xray_arch()
    if not arch:
        print(red('❌ Unsupported CPU: %s' % platform.machine()))
        return False
    repo_name, official = arch
    os.makedirs(LIB_DIR, exist_ok=True)
    binp = DEFAULTS['xray_bin']
    new = binp + '.new'
    if os.path.exists(new):
        os.remove(new)

    if REPO_BASE:
        if download('%s/%s' % (REPO_BASE.rstrip('/'), repo_name), new, 30, 2):
            with open(new, 'rb') as f:
                magic = f.read(4)
            if magic == b'\x7fELF' and xray_works(new):
                os.replace(new, binp)
                print(grn('✅ Xray core loaded from the repo.'))
                return True
        if os.path.exists(new):
            os.remove(new)
        print(dim('ℹ️  The repo has no usable Xray binary, using the official Xray-core release...'))

    tmpd = tempfile.mkdtemp(prefix='ffxray')
    try:
        import zipfile
        zpath = os.path.join(tmpd, 'xray.zip')
        url = 'https://github.com/XTLS/Xray-core/releases/latest/download/Xray-linux-%s.zip' % official
        if download(url, zpath, 90, 3):
            with zipfile.ZipFile(zpath) as z:
                z.extract('xray', tmpd)
            shutil.copy2(os.path.join(tmpd, 'xray'), new)
            if xray_works(new):
                os.replace(new, binp)
                rc, out, _ = run([binp, 'version'], timeout=10)
                print(grn('✅ Xray core installed: %s' % (out.splitlines()[0] if out else '')))
                return True
    except Exception as exc:
        print(red('❌ Xray download failed: %s' % exc))
    finally:
        shutil.rmtree(tmpd, ignore_errors=True)
        if os.path.exists(new):
            os.remove(new)
    print(red('❌ Could not download a working Xray binary (is the server online?).'))
    return False


# ---- certificate
def have_cert(crt=None, key=None):
    crt = crt or DEFAULTS['cert']
    key = key or DEFAULTS['key']
    return os.path.isfile(crt) and os.path.getsize(crt) > 0 and os.path.isfile(key) and os.path.getsize(key) > 0


def self_signed(cn):
    os.makedirs(CERT_DIR, exist_ok=True)
    crt, key = DEFAULTS['cert'], DEFAULTS['key']
    base = ['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '3650',
            '-keyout', key, '-out', crt, '-subj', '/CN=' + cn]
    if sh(base + ['-addext', 'subjectAltName=DNS:' + cn]) != 0 and sh(base) != 0:
        print(red('❌ Could not generate the self-signed certificate (is openssl installed?).'))
        return None
    os.chmod(crt, 0o644)
    os.chmod(key, 0o600)
    print(grn('✅ Self-signed certificate created for %s' % cn))
    return crt, key


def write_renew_hook(domain):
    os.makedirs(os.path.dirname(RENEW_HOOK), exist_ok=True)
    crt, key = DEFAULTS['cert'], DEFAULTS['key']
    write_text(RENEW_HOOK,
               '#!/bin/bash\n'
               'if [ "$RENEWED_LINEAGE" = "/etc/letsencrypt/live/%(d)s" ]; then\n'
               '    cp "$RENEWED_LINEAGE/fullchain.pem" "%(c)s"\n'
               '    cp "$RENEWED_LINEAGE/privkey.pem" "%(k)s"\n'
               '    chmod 644 "%(c)s"; chmod 600 "%(k)s"\n'
               'fi\n'
               'systemctl reload %(n)s 2>/dev/null || systemctl restart %(n)s 2>/dev/null\n'
               % {'d': domain, 'c': crt, 'k': key, 'n': NGINX_SERVICE}, 0o755)


def certbot_cert(domain, email, dns=False):
    if not shutil.which('certbot') and not pkg_install(['certbot']):
        print(red('❌ Failed to install certbot.'))
        return None
    if dns:
        print(yel('\nCertbot will show a TXT record (_acme-challenge.%s). Add it at the DNS provider of the domain,'
                  '\nwait a minute, then press Enter in certbot. This certificate is NOT renewed automatically.' % domain))
        rc = subprocess.call(['certbot', 'certonly', '--manual', '--preferred-challenges', 'dns',
                              '-d', domain, '--agree-tos', '-m', email])
    else:
        if not free_ports([80]):
            return None
        open_firewall(80)
        print(blu('\n🚀 Requesting a certificate for %s' % domain))
        rc = subprocess.call(['certbot', 'certonly', '--standalone', '-d', domain, '--non-interactive',
                              '--agree-tos', '-m', email])
    live = '/etc/letsencrypt/live/%s' % domain
    if rc != 0 or not os.path.isfile(live + '/fullchain.pem'):
        print(red('\n❌ Certbot failed to obtain a certificate.'))
        print(yel('ℹ️  The domain must reach THIS server on port 80 (behind Imperva: the origin of the site must be'
                  '\n   this server and /.well-known must not be blocked). Otherwise use the DNS option.'))
        return None
    os.makedirs(CERT_DIR, exist_ok=True)
    crt, key = DEFAULTS['cert'], DEFAULTS['key']
    shutil.copy(live + '/fullchain.pem', crt)
    shutil.copy(live + '/privkey.pem', key)
    os.chmod(crt, 0o644)
    os.chmod(key, 0o600)
    write_renew_hook(domain)
    print(grn('✅ Certificate stored in %s' % CERT_DIR))
    return crt, key


def select_certificate(domain):
    """Ask which certificate to use. Returns (cert_path, key_path) or None."""
    print('\n' + ppl('--- 🔐 TLS Certificate ---'))
    existing = have_cert()
    n = 1
    opts = {}
    if existing:
        print('  %s Reuse the existing certificate (%s)' % (cyn('[%d]' % n), DEFAULTS['cert']))
        opts[str(n)] = 'reuse'
        n += 1
    for tag, text in (('self', 'Generate a self-signed certificate'),
                      ('http', "Let's Encrypt (Certbot), HTTP validation - domain must reach this server on port 80"),
                      ('dns', "Let's Encrypt (Certbot), DNS TXT validation - for CDN domains, renew by hand"),
                      ('files', 'Use my own certificate + key files')):
        print('  %s %s' % (cyn('[%d]' % n), text))
        opts[str(n)] = tag
        n += 1
    choice = opts.get(ask('\n👉 Enter choice [1]: ', '1'))
    if not choice:
        print(red('❌ Invalid option.'))
        return None
    if choice == 'reuse':
        print(grn('✅ Reusing the existing certificate.'))
        return DEFAULTS['cert'], DEFAULTS['key']
    if choice == 'self':
        cn = ask('👉 Certificate Common Name [%s]: ' % domain, domain)
        return self_signed(cn)
    if choice == 'files':
        crt = ask('👉 Path of the certificate (full chain, PEM): ')
        key = ask('👉 Path of the private key (PEM): ')
        if not have_cert(crt, key):
            print(red('❌ One of the files is missing or empty.'))
            return None
        return crt, key
    email = ask("👉 Email for Let's Encrypt: ")
    if not email or '@' not in email:
        print(red('❌ A valid email is required.'))
        return None
    return certbot_cert(domain, email, dns=(choice == 'dns'))


# ---- services
def write_units():
    py = shutil.which('python3') or sys.executable
    nginx_bin = shutil.which('nginx') or DEFAULTS['nginx_bin']
    write_text(XRAY_UNIT_FILE,
               '[Unit]\nDescription=visibleTech Xray (VMess/VLESS/Trojan)\nAfter=network.target\n\n'
               '[Service]\nType=simple\nUser=root\n'
               'ExecStart=%s run -config %s/config.json\n'
               'Restart=always\nRestartSec=3\nLimitNOFILE=1048576\n\n'
               '[Install]\nWantedBy=multi-user.target\n' % (DEFAULTS['xray_bin'], V2_DIR), 0o644)
    write_text(NGINX_UNIT_FILE,
               '[Unit]\nDescription=visibleTech V2Ray nginx front (WS/gRPC/XHTTP, TLS)\nAfter=network.target ff-xray.service\n\n'
               '[Service]\nType=simple\nUser=root\n'
               'ExecStartPre=%s -t -c %s/nginx.conf\n'
               "ExecStart=%s -c %s/nginx.conf -g 'daemon off;'\n"
               'ExecReload=/bin/kill -HUP $MAINPID\n'
               'Restart=always\nRestartSec=3\nLimitNOFILE=1048576\n\n'
               '[Install]\nWantedBy=multi-user.target\n' % (nginx_bin, V2_DIR, nginx_bin, V2_DIR), 0o644)
    write_text(LIMITER_UNIT_FILE,
               '[Unit]\nDescription=visibleTech V2Ray bandwidth limiter and live counter\nAfter=ff-xray.service\n\n'
               '[Service]\nType=simple\nUser=root\nEnvironment=FFV2_DIR=%s\n'
               'ExecStart=%s %s daemon\nRestart=always\nRestartSec=3\n\n'
               '[Install]\nWantedBy=multi-user.target\n' % (V2_DIR, py, MANAGER_PATH), 0o644)
    if os.path.isdir('/etc/logrotate.d'):
        write_text('/etc/logrotate.d/visibleTech-xray',
                   '/var/log/xray/*.log {\n    daily\n    maxsize 20M\n    rotate 3\n    missingok\n'
                   '    notifempty\n    copytruncate\n    compress\n}\n', 0o644)
    sh(['systemctl', 'daemon-reload'])


def install_self():
    """Copy this script to the fixed manager location (the limiter service runs it) + a `ffv2ray` command."""
    try:
        src = os.path.abspath(__file__)
    except NameError:
        src = ''
    if not src or not os.path.isfile(src):
        die('Save this script to a file first (it cannot install itself from a pipe).')
    os.makedirs(LIB_DIR, exist_ok=True)
    if os.path.abspath(src) != os.path.abspath(MANAGER_PATH):
        shutil.copy2(src, MANAGER_PATH)
    os.chmod(MANAGER_PATH, 0o755)
    try:
        if os.path.islink(BIN_LINK) or os.path.exists(BIN_LINK):
            os.remove(BIN_LINK)
        os.symlink(MANAGER_PATH, BIN_LINK)
    except OSError:
        pass


def install_menu_command():
    """`menu` opens the manager. An existing `menu` that is not ours (the menu.sh script) is never replaced."""
    if os.path.exists(MENU_CMD) and WRAPPER_MARK not in read_text(MENU_CMD):
        return False
    write_text(MENU_CMD, '#!/bin/sh\n%s\nexec python3 %s "$@"\n' % (WRAPPER_MARK, MANAGER_PATH), 0o755)
    return True


def login_menu_enabled():
    return os.path.exists(LOGIN_HOOK)


def set_login_menu(on):
    """Open the manager automatically when root logs in on a terminal (SSH or console)."""
    if not on:
        try:
            os.remove(LOGIN_HOOK)
        except OSError:
            pass
        return
    os.makedirs(os.path.dirname(LOGIN_HOOK), exist_ok=True)
    write_text(LOGIN_HOOK,
               '# ffv2ray: open the V2Ray manager at login (root, interactive terminal only)\n'
               'case $- in *i*) ;; *) return 0 2>/dev/null ;; esac\n'
               '[ "$(id -u)" = "0" ] || return 0 2>/dev/null\n'
               '[ -t 0 ] && [ -t 1 ] || return 0 2>/dev/null\n'
               '[ -n "$FFV2_MENU_SHOWN" ] && return 0 2>/dev/null\n'
               'export FFV2_MENU_SHOWN=1\n'
               '[ -x %s ] && %s menu\n' % (BIN_LINK, BIN_LINK), 0o644)


def restart_services():
    sh(['systemctl', 'restart'] + ALL_SERVICES)
    time.sleep(3)


def service_states():
    return dict((s, sh(['systemctl', 'is-active', '--quiet', s]) == 0) for s in ALL_SERVICES)


def show_service_report():
    ok = True
    for svc, up in service_states().items():
        if up:
            print('  ' + grn('✅ %s is active' % svc))
        else:
            ok = False
            print('  ' + red('❌ %s failed to start' % svc))
            rc, out, _ = run(['journalctl', '-u', svc, '-n', '8', '--no-pager'], timeout=15)
            for ln in out.splitlines():
                print('      ' + ln)
    return ok


def imperva_checklist(st):
    d = st.get('domain', '')
    print('\n' + ppl('--- 🛡️  Imperva setup checklist ---'))
    print(' 1. In the Imperva console, onboard %s with THIS server as the origin (IP of this server).' % wht(d))
    print(' 2. Origin ports: use %s (TLS) and %s (non-TLS) - let Imperva reach both.' % (wht(st['tls_port']), wht(st['http_port'])))
    print(' 3. Clients connect to the domain through Imperva; the app\'s Host / SNI stay as %s.' % wht(d))
    print(' 4. Use WS (TLS / none TLS) or XHTTP links. gRPC is hidden for CDN domains (CDNs talk HTTP/1.1 to the origin).')
    print(' 5. Real visitor IPs come from the %s header, trusted only from Imperva networks,' % wht(st.get('cdn_ip_header') or 'Incap-Client-IP'))
    print('    so the device limit and the online list work. The list refreshes every 12 hours.')
    print(' 6. If Imperva rejects the origin certificate, use a valid (Let\'s Encrypt) certificate on the origin.')
    print(dim('    Optional hardening: let only Imperva networks reach the origin ports in your firewall.'))


def install_flow():
    need_root()
    banner('--- 🛰️  Install V2Ray (Xray): VMess / VLESS / Trojan ---')
    print(dim('\nWS + gRPC + XHTTP on one TLS port and one non-TLS port, bandwidth and device limits per account.'))
    domain = ask('\n👉 Enter your domain (its DNS must lead to this server, directly or through Imperva): ')
    if not valid_domain(domain):
        print(red('\n❌ Invalid domain.'))
        return False
    cdn = yesno('👉 Is this domain behind the Imperva CDN?', False)
    tls_port = ask('👉 TLS port [443]: ', '443')
    http_port = ask('👉 Non-TLS port [80]: ', '80')
    if not valid_port(tls_port) or not valid_port(http_port) or tls_port == http_port:
        print(red('\n❌ Ports must be two different numbers between 1 and 65535.'))
        return False

    nginx_pre = (sh(['systemctl', 'is-active', '--quiet', 'nginx']) == 0
                 or sh(['systemctl', 'is-enabled', '--quiet', 'nginx']) == 0)
    print(blu('\n📦 Installing nginx, python3, curl and openssl...'))
    if not pkg_install(['nginx', 'python3', 'curl', 'openssl']) or not shutil.which('nginx'):
        print(red('❌ Failed to install the required packages.'))
        return False
    if not nginx_pre:
        sh(['systemctl', 'disable', '--now', 'nginx'])        # we run our own nginx instance

    os.makedirs(CERT_DIR, exist_ok=True)
    os.makedirs(V2_DIR, mode=0o700, exist_ok=True)
    print(dim('Tip: use %s as the certificate name.' % domain))
    cert = select_certificate(domain)
    if not cert:
        return False

    if not free_ports([tls_port, http_port]):
        return False
    open_firewall(tls_port)
    open_firewall(http_port)

    print(blu('\n📥 Fetching the Xray core...'))
    if not fetch_xray():
        return False
    install_self()

    print(grn('\n📝 Writing configuration and services...'))
    rc, _ = v2(['init', '--domain', domain, '--tls-port', tls_port, '--http-port', http_port,
                '--cert', cert[0], '--key', cert[1], '--xray-bin', DEFAULTS['xray_bin'],
                '--nginx-bin', shutil.which('nginx')], quiet=True)
    if rc != 0:
        print(red('❌ Could not write the V2Ray settings.'))
        return False
    write_text(INSTALL_CONF, 'NGINX_PREEXISTING="%s"\n' % ('true' if nginx_pre else 'false'), 0o600)
    if cdn:
        print(blu('🛡️  Enabling Imperva mode and downloading the Imperva networks...'))
        rc, out = v2(['cdn', '--enable', '--refresh'], quiet=True)
        print(out.rstrip())
    got_menu = install_menu_command()
    set_login_menu(yesno('👉 Open this manager automatically when you log in?', True))
    write_units()
    sh(['systemctl', 'enable'] + ALL_SERVICES)
    v2(['render', '--restart'], quiet=True)
    restart_services()
    ok = show_service_report()
    st = load_settings()
    if ok:
        print('\n' + grn('✅ SUCCESS: V2Ray (Xray) is installed.'))
        print('   • Domain:       %s' % yel(domain))
        print('   • TLS port:     %s   (WS + gRPC + XHTTP)' % yel(tls_port))
        print('   • Non-TLS port: %s   (WS + XHTTP)' % yel(http_port))
        if got_menu:
            print('   • Manage with:  type %s anywhere' % cyn('menu'))
        else:
            print('   • Manage with:  type %s (the %s command already belongs to menu.sh)' % (cyn('ffv2ray'), cyn('menu')))
        print('   • Auto-open at login: %s' % ('yes' if login_menu_enabled() else 'no'))
        if cert[0] == DEFAULTS['cert'] and not cert_is_trusted(cert[0]):
            print('   ' + yel("⚠️  Self-signed certificate: clients must enable 'allow insecure'."))
        if cdn:
            imperva_checklist(st)
    return ok


def cert_is_trusted(crt):
    """True when the certificate is signed by someone else (issuer differs from subject)."""
    rc, out, _ = run(['openssl', 'x509', '-noout', '-subject', '-issuer', '-in', crt], timeout=10)
    subj = iss = ''
    for ln in out.splitlines():
        if ln.startswith('subject='):
            subj = ln.split('=', 1)[1].strip()
        if ln.startswith('issuer='):
            iss = ln.split('=', 1)[1].strip()
    return bool(subj) and subj != iss


def update_flow():
    need_root()
    print(blu('\n♻️  Updating the Xray core and the manager (accounts are kept)...'))
    sh(['systemctl', 'stop', XRAY_SERVICE, LIMITER_UNIT])
    if not fetch_xray():
        sh(['systemctl', 'start', XRAY_SERVICE, LIMITER_UNIT])
        return False
    install_self()
    write_units()
    v2(['render', '--restart'], quiet=True)
    restart_services()
    if service_states()[XRAY_SERVICE]:
        print(grn('✅ Updated and running.'))
        return True
    print(red('❌ Xray did not start after the update.'))
    show_service_report()
    return False


def uninstall_flow(silent=False):
    need_root()
    print('\n' + ppl('--- 🗑️  Uninstalling V2Ray (Xray) ---'))
    if not installed() and not os.path.isdir(V2_DIR) and not os.path.isdir(LIB_DIR):
        print(yel('ℹ️  V2Ray is not installed.'))
        return False
    if not silent:
        if not yesno('👉 This deletes ALL V2Ray accounts and their bandwidth counters. Continue?'):
            print(yel('\n❌ Uninstallation cancelled.'))
            return False
        if os.path.isdir(V2_DIR) and yesno('👉 Save a backup of the accounts first?', True):
            bk = '/root/ffv2ray-backup-%s.tar.gz' % time.strftime('%Y%m%d-%H%M%S')
            if sh(['tar', '-czf', bk, '-C', os.path.dirname(V2_DIR), os.path.basename(V2_DIR)]) == 0:
                print(grn('✅ Backup saved: %s' % bk))
    pre = True
    txt = read_text(INSTALL_CONF)
    if 'NGINX_PREEXISTING="false"' in txt:
        pre = False
    print(blu('🛑 Stopping services...'))
    sh(['systemctl', 'stop', LIMITER_UNIT, NGINX_SERVICE, XRAY_SERVICE])
    sh(['systemctl', 'disable', LIMITER_UNIT, NGINX_SERVICE, XRAY_SERVICE])
    for f in (XRAY_UNIT_FILE, NGINX_UNIT_FILE, LIMITER_UNIT_FILE, '/etc/logrotate.d/visibleTech-xray', RENEW_HOOK, BIN_LINK, LOGIN_HOOK):
        try:
            os.remove(f)
        except OSError:
            pass
    if os.path.exists(MENU_CMD) and WRAPPER_MARK in read_text(MENU_CMD):
        os.remove(MENU_CMD)
    for d in (LIB_DIR, V2_DIR, '/var/log/xray', '/etc/systemd/system/%s.service.d' % NGINX_SERVICE):
        shutil.rmtree(d, ignore_errors=True)
    sh(['systemctl', 'daemon-reload'])
    if not pre and (silent or yesno('👉 Also remove the nginx package (installed for V2Ray)?')):
        pkg_purge(['nginx', 'nginx-common'])
        print(grn('🗑️  nginx package removed.'))
    print(grn('✅ V2Ray (Xray) has been uninstalled.'))
    return True


# ------------------------------------------------------------------ interactive menu
BW_RE = re.compile(r'^([0-9]+(\.[0-9]{0,4})?|\.[0-9]{1,4})$')    # GB values, up to 4 decimals
CID_RE = re.compile(r'^[A-Za-z0-9._-]{3,30}$')


def valid_gb(s):
    return bool(BW_RE.match(s))


def valid_devices(s):
    return s.isdigit() and len(s) <= 4 and int(s) <= 1000


def fail(msg):
    print('\n' + red('❌ ' + msg))


def pick_user(proto, title):
    """Numbered account list. Returns the chosen name, or None."""
    users, names = select_names(proto)
    if not names:
        print(yel('\nℹ️  No accounts found.'))
        return None
    usage = load_usage()
    now = int(time.time())
    print('\n' + ppl(title) + '\n')
    for i, n in enumerate(names, 1):
        u = users[n]
        usg = usage['users'].get(n, {})
        print('  %s %-14s %-6s %-9s %s' % (cyn('[%2d]' % i), n, u['proto'], user_status(u, usg, now),
                                           fmt_time(u['expiry']) if u.get('expiry') else 'Never'))
    print('\n  %s Cancel\n' % yel('[ 0]'))
    pick = ask('👉 Select account number: ', '')
    if not pick.isdigit() or not 1 <= int(pick) <= len(names):
        return None
    return names[int(pick) - 1]


def ask_expiry_type():
    print('\n  ' + cyn('Expiry type (East Africa Time):'))
    print('   %s From now     - ends exactly N days from this moment, at the same clock time' % cyn('[1]'))
    print('   %s Start of day - valid through the chosen day, ends at 00:00 EAT the next day' % cyn('[2]'))
    return 'day' if ask('Choose [1]: ', '1') == '2' else 'now'


def ask_account_options(default_total='0', want_daily=True):
    """Shared prompts of create / trial. Returns dict or None when an answer is invalid."""
    total = ask('📦 Total bandwidth limit in GB (0 = unlimited) [%s]: ' % default_total, default_total)
    if not valid_gb(total):
        fail('Invalid number.')
        return None
    daily = '0'
    if want_daily:
        daily = ask('📦 DAILY bandwidth limit in GB (0 = unlimited) [0]: ', '0')
        if not valid_gb(daily):
            fail('Invalid number.')
            return None
    conn = ask('📱 Device limit - max devices connected at once (0 = unlimited) [1]: ', '1')
    if not valid_devices(conn):
        fail('Invalid device limit (0-1000).')
        return None
    cid = ask('🆔 Custom ID (e.g. visible, 3-30 chars) - empty = random UUID: ', '')
    if cid and not CID_RE.match(cid):
        fail('ID must be 3-30 characters: letters, digits, dot, _ or -')
        return None
    return {'total': total, 'daily': daily, 'conn': conn, 'cid': cid}


def account_create(proto, label):
    banner('--- ✨ Create XRAY %s WS Account ---' % label)
    name = ask("👤 Username (or '0' to cancel): ", '0')
    if name == '0':
        print(yel('\n❌ Cancelled.'))
        return
    if not NAME_RE.match(name):
        return fail('Username must be 2-24 characters: letters, digits, _ or -')
    if name in load_users():
        return fail("Account '%s' already exists." % name)
    days = ask('🗓️  Account duration in days [30]: ', '30')
    if not days.isdigit() or int(days) < 1:
        return fail('Invalid number of days.')
    o = ask_account_options()
    if not o:
        return
    mode = ask_expiry_type()
    args = ['add', '--proto', proto, '--name', name, '--days', days, '--total', o['total'],
            '--daily', o['daily'], '--conn', o['conn']]
    if o['cid']:
        args += ['--id', o['cid']]
    if v2(args, quiet=True)[0] != 0:
        return
    if mode == 'day' and v2(['setexpiry', name, '--days', days, '--mode', 'day'], quiet=True)[0] != 0:
        return
    banner()
    print(grn("✅ Account '%s' created!" % name))
    v2(['show', name])
    print('\n' + dim('Bandwidth is counted live and the account is switched off automatically when the limit or expiry is reached.'))
    if int(o['conn']) > 0:
        print(dim('Device limit: %s' % o['conn']))


def account_trial(proto, label):
    banner('--- ⏱️  Trial XRAY %s WS ---' % label)
    print('\n' + cyn('Select trial duration:') + '\n')
    for k, t in (('1', '⏱️  1 Hour'), ('2', '⏱️  3 Hours'), ('3', '⏱️  6 Hours'), ('4', '⏱️  12 Hours'),
                 ('5', '📅  1 Day'), ('6', '⚙️  Custom (hours)')):
        print('  %s %s' % (grn('[ %s]' % k), t))
    print('\n  %s ↩️  Cancel\n' % red('[ 0]'))
    choice = ask('👉 Select duration: ', '0')
    hours = {'1': '1', '2': '3', '3': '6', '4': '12', '5': '24'}.get(choice)
    if choice == '6':
        hours = ask('👉 Enter hours: ', '')
        if not hours.isdigit() or int(hours) < 1:
            return fail('Invalid hours.')
    if not hours:
        print(yel('\n❌ Cancelled.'))
        return
    default_name = 'trial_' + ''.join(__import__('random').choice('abcdefghijklmnopqrstuvwxyz0123456789') for _ in range(5))
    name = ask('👤 Username [%s]: ' % default_name, default_name)
    if not NAME_RE.match(name):
        return fail('Invalid username.')
    if name in load_users():
        return fail("Account '%s' already exists." % name)
    total = ask('📦 Bandwidth limit in GB (0 = unlimited) [1]: ', '1')
    if not valid_gb(total):
        return fail('Invalid number.')
    conn = ask('📱 Device limit (0 = unlimited) [1]: ', '1')
    if not valid_devices(conn):
        return fail('Invalid device limit (0-1000).')
    cid = ask('🆔 Custom ID (3-30 chars) - empty = random UUID: ', '')
    if cid and not CID_RE.match(cid):
        return fail('ID must be 3-30 characters: letters, digits, dot, _ or -')
    args = ['add', '--proto', proto, '--name', name, '--hours', hours, '--total', total, '--daily', '0',
            '--conn', conn, '--trial']
    if cid:
        args += ['--id', cid]
    if v2(args, quiet=True)[0] != 0:
        return
    banner()
    print(grn("✅ Trial account '%s' created for %s hour(s)." % (name, hours)))
    v2(['show', name])
    print('\n' + dim('Trial accounts are deleted automatically when they expire.'))


def account_expiry(proto, label):
    banner()
    name = pick_user(proto, '--- 🔄 Set expiry (days from today) XRAY %s WS ---' % label)
    if not name:
        return
    print('\n  %s Set expiry to N days from TODAY' % cyn('[1]'))
    print('  %s Add N days to the current expiry' % cyn('[2]'))
    mode = ask('Choose [1]: ', '1')
    if mode not in ('1', '2'):
        return fail('Invalid choice.')
    days = ask('Number of days from today [30]: ' if mode == '1' else 'Days to add [30]: ', '30')
    if not days.isdigit() or int(days) < 1:
        return fail('Invalid number of days.')
    reset = ask('Reset the bandwidth counters to zero? (y/n) [n]: ', 'n').lower() == 'y'
    if mode == '1':
        em = ask_expiry_type()
        if v2(['setexpiry', name, '--days', days, '--mode', em], quiet=True)[0] != 0:
            return
        if reset and v2(['limit', name, '--reset'], quiet=True)[0] != 0:
            return
        print('\n' + grn("'%s' expiry updated." % name))
    else:
        if v2(['renew', name, '--days', days] + (['--reset'] if reset else []), quiet=True)[0] != 0:
            return
        print('\n' + grn("'%s' extended by %s day(s)." % (name, days)))
    v2(['usage', name])


def account_delete(proto, label):
    banner()
    name = pick_user(proto, '--- 🗑️  Delete XRAY %s WS ---' % label)
    if not name:
        return
    if yesno("👉 Delete '%s'?" % name):
        if v2(['del', name], quiet=True)[0] == 0:
            print('\n' + grn("✅ '%s' deleted." % name))
    else:
        print(yel('\n❌ Cancelled.'))


def account_lock(proto, label):
    banner()
    name = pick_user(proto, '--- 🔒 Lock / Unlock XRAY %s WS ---' % label)
    if not name:
        return
    users = load_users()
    now = int(time.time())
    status = user_status(users[name], load_usage()['users'].get(name, {}), now)
    if status == 'locked':
        if v2(['unlock', name], quiet=True)[0] == 0:
            print('\n' + grn("🔓 '%s' unlocked." % name))
    elif v2(['lock', name], quiet=True)[0] == 0:
        print('\n' + yel("🔒 '%s' locked." % name))


def account_limits(proto, label):
    banner()
    name = pick_user(proto, '--- ✏️  Edit bandwidth / device limit: XRAY %s WS ---' % label)
    if not name:
        return
    print()
    v2(['usage', name])
    print()
    total = ask('📦 New TOTAL limit in GB (0 = unlimited, Enter = keep): ', '')
    daily = ask('📦 New DAILY limit in GB (0 = unlimited, Enter = keep): ', '')
    conn = ask('📱 New DEVICE limit (0 = unlimited, Enter = keep): ', '')
    args = ['limit', name]
    if total:
        if not valid_gb(total):
            return fail('Invalid number.')
        args += ['--total', total]
    if daily:
        if not valid_gb(daily):
            return fail('Invalid number.')
        args += ['--daily', daily]
    if conn:
        if not valid_devices(conn):
            return fail('Invalid device limit (0-1000).')
        args += ['--conn', conn]
    if ask('♻️  Reset the used-data counters to zero? (y/n) [n]: ', 'n').lower() == 'y':
        args.append('--reset')
    if len(args) == 2:
        print('\n' + yel('ℹ️  Nothing changed.'))
        return
    if v2(args, quiet=True)[0] == 0:
        print('\n' + grn('✅ Limits updated.'))


def account_show(proto, label, what='show'):
    banner()
    name = pick_user(proto, ('--- 📋 Show XRAY %s WS Account ---' if what == 'show' else '--- 📊 Bandwidth: XRAY %s WS ---') % label)
    if name:
        v2([what, name])


def proto_menu(proto, label):
    while True:
        banner()
        print(cyn('┌' + '─' * 48 + '┐'))
        print('\n    %s\n' % wht('XRAY %s WS BY visibleTech' % label.upper()))
        for k, t in (('01', 'Create XRAY %s WS'), ('02', 'Trial XRAY %s WS'),
                     ('03', 'Set expiry (days from today) XRAY %s WS'), ('04', 'Delete XRAY %s WS'),
                     ('05', 'Check User Login XRAY %s WS'), ('06', 'List accounts + live bandwidth'),
                     ('07', 'Show account / links'), ('08', 'Lock / Unlock account'),
                     ('09', 'Edit bandwidth / device limit'), ('10', 'Bandwidth details (progress bar)')):
            print('    %s %s' % (cyn('[%s]' % k), t % label if '%s' in t else t))
        print('\n' + cyn('└' + '─' * 48 + '┘') + '\n')
        print('    %s Main Menu\n' % yel('[00]'))
        opt = ask(blu('Select menu : '))
        if opt in ('1', '01'):
            account_create(proto, label)
        elif opt in ('2', '02'):
            account_trial(proto, label)
        elif opt in ('3', '03'):
            account_expiry(proto, label)
        elif opt in ('4', '04'):
            account_delete(proto, label)
        elif opt in ('5', '05'):
            print()
            v2(['online', '--proto', proto])
        elif opt in ('6', '06'):
            print()
            v2(['list', '--proto', proto])
        elif opt in ('7', '07'):
            account_show(proto, label)
        elif opt in ('8', '08'):
            account_lock(proto, label)
        elif opt in ('9', '09'):
            account_limits(proto, label)
        elif opt == '10':
            account_show(proto, label, 'usage')
        elif opt in ('0', '00'):
            return
        else:
            print(red('\nInvalid option.'))
        press_enter()


def cdn_menu():
    while True:
        st = load_settings()
        banner('--- 🛡️  Imperva CDN ---')
        print('\n' + cdn_summary(st) + '\n')
        on = cdn_on(st)
        print('  %s %s' % (cyn('[ 1]'), 'Turn Imperva mode OFF' if on else 'Turn Imperva mode ON (domain is behind Imperva)'))
        print('  %s %s' % (cyn('[ 2]'), 'Refresh the Imperva networks now'))
        print('  %s %s' % (cyn('[ 3]'), 'Real client IP header (Incap-Client-IP / X-Forwarded-For / other)'))
        print('  %s %s' % (cyn('[ 4]'), 'Extra trusted networks (add by hand)'))
        print('  %s %s' % (cyn('[ 5]'), 'Trust the header from ANY source (only if the firewall admits Imperva only)'))
        print('  %s %s' % (cyn('[ 6]'), 'Show / hide gRPC links'))
        print('  %s %s' % (cyn('[ 7]'), 'Setup checklist'))
        print('\n  %s ↩️  Return\n' % yel('[ 0]'))
        opt = ask(blu('👉 Select an option: '))
        if opt == '1':
            rc, out = v2(['cdn', '--disable' if on else '--enable'], quiet=True)
            print('\n' + out.rstrip())
        elif opt == '2':
            if not on:
                fail('Turn Imperva mode on first.')
            else:
                rc, out = v2(['cdn', '--refresh'], quiet=True)
                print('\n' + out.rstrip())
        elif opt == '3':
            print(dim('\nImperva sends the visitor IP in Incap-Client-IP and X-Forwarded-For by default.'))
            cur = st.get('cdn_ip_header') or 'Incap-Client-IP'
            print('  %s Incap-Client-IP\n  %s X-Forwarded-For\n  %s Other header name' % (cyn('[1]'), cyn('[2]'), cyn('[3]')))
            c = ask('Choose [keep %s]: ' % cur, '')
            h = {'1': 'Incap-Client-IP', '2': 'X-Forwarded-For'}.get(c)
            if c == '3':
                h = ask('Header name: ', '')
            if h:
                rc, out = v2(['cdn', '--header', h], quiet=True)
                print('\n' + out.rstrip())
        elif opt == '4':
            cur = ', '.join(st.get('cdn_ranges_extra') or [])
            print(dim('\nNetworks (CIDR) that are trusted in addition to the Imperva list, separated by spaces or commas.'))
            raw = ask('Extra networks [%s] (- = clear): ' % (cur or 'none'), '')
            if raw:
                rc, out = v2(['cdn', '--extra-ranges', '' if raw == '-' else raw], quiet=True)
                print('\n' + out.rstrip())
        elif opt == '5':
            if st.get('cdn_trust_any'):
                rc, out = v2(['cdn', '--no-trust-any'], quiet=True)
                print('\n' + out.rstrip())
            else:
                print(yel('\n⚠️  Anyone who can reach the origin directly could then fake their IP (device limit).'))
                if yesno('Trust the header from every source?'):
                    rc, out = v2(['cdn', '--trust-any'], quiet=True)
                    print('\n' + out.rstrip())
        elif opt == '6':
            rc, out = v2(['cdn', '--hide-grpc' if st.get('cdn_grpc') else '--allow-grpc'], quiet=True)
            print('\n' + out.rstrip())
        elif opt == '7':
            imperva_checklist(st)
        elif opt in ('0', ''):
            return
        else:
            print(red('\nInvalid option.'))
        press_enter()


def change_ports():
    st = load_settings()
    nt = ask('👉 New TLS port [%s]: ' % st['tls_port'], str(st['tls_port']))
    nh = ask('👉 New non-TLS port [%s]: ' % st['http_port'], str(st['http_port']))
    if not valid_port(nt) or not valid_port(nh) or nt == nh:
        return fail('Invalid ports.')
    sh(['systemctl', 'stop', NGINX_SERVICE])
    if free_ports([nt, nh]) and open_firewall(nt) and open_firewall(nh):
        v2(['init', '--tls-port', nt, '--http-port', nh], quiet=True)
        sh(['systemctl', 'restart', NGINX_SERVICE])
        print('\n' + grn('✅ Ports changed. Existing links must be re-shared.'))
    else:
        sh(['systemctl', 'start', NGINX_SERVICE])


def change_certificate():
    st = load_settings()
    sh(['systemctl', 'stop', NGINX_SERVICE])
    cert = select_certificate(st['domain'])
    if cert:
        v2(['init', '--cert', cert[0], '--key', cert[1]], quiet=True)
        print(grn('✅ Certificate updated.'))
    sh(['systemctl', 'restart', NGINX_SERVICE])


def client_options():
    st = load_settings()
    print('\n' + dim("Used in the links and JSON configs. Enter = keep current, '-' = clear (back to default)."))
    print(dim('Address = host the app connects to (bug host). SNI = TLS name. Host = WebSocket Host header (your real domain).\n'))
    args = []
    for flag, key, label in (('--address', 'cfg_address', 'Connect address / bug host'),
                             ('--sni', 'cfg_sni', 'SNI'), ('--host', 'cfg_host', 'Host header')):
        v = ask('👉 %s [%s]: ' % (label, st.get(key, '')), '')
        if v:
            args += [flag, '' if v == '-' else v]
    if not args:
        print('\n' + yel('ℹ️  Nothing changed.'))
    elif v2(['clientopts'] + args, quiet=True)[0] == 0:
        print('\n' + grn("✅ Saved. Open 'Show account' to get the new links / JSON configs."))


def fake_website():
    st = load_settings()
    print('\n%s %s' % (cyn('Fake website:'), yel(st.get('fake_site') or 'not installed')))
    print(dim('Shown to anyone who opens your domain in a browser (http and https), so it looks like a normal website.\n'))
    print('  %s 🏢 Business - IT services company' % cyn('[ 1]'))
    print('  %s ☁️  Cloud hosting company' % cyn('[ 2]'))
    print('  %s 📝 Personal tech / travel blog' % cyn('[ 3]'))
    print('  %s 🗑️  Remove the fake website' % red('[ 4]'))
    print('  %s ↩️  Back\n' % yel('[ 0]'))
    c = ask('👉 Select: ', '0')
    tpl = {'1': 'business', '2': 'cloud', '3': 'blog'}.get(c)
    if c == '4':
        if v2(['fakesite', '--off'], quiet=True)[0] == 0:
            print('\n' + grn('✅ Fake website removed (your domain answers 404 again).'))
    elif tpl and v2(['fakesite', '--template', tpl], quiet=True)[0] == 0:
        print('\n' + grn('✅ Fake website installed (%s).' % tpl))
        print(dim('Open http://%s in a browser to see it.' % st['domain']))


def sni_lock_menu():
    st = load_settings()
    print('\n%s %s' % (cyn('SNI lock:'), grn('ON') if st.get('sni_lock') else dim('off')))
    print(dim('ON: a host checker (SNI = your domain) gets "TLSV1_ALERT_UNRECOGNIZED_NAME". V2Ray users still connect'))
    print(dim('because their app uses the SNI from "Client config options" (it must differ from the domain).\n'))
    print('  Client SNI: %s' % yel(st.get('cfg_sni') or '(not set)'))
    if not (st.get('cfg_sni') or '').strip():
        print('\n' + yel('Set a client SNI first: Settings > [4] Client config options.'))
        return
    if st.get('sni_lock'):
        if yesno('👉 Turn the SNI lock OFF?', False):
            v2(['snilock', '--off'], quiet=False)
    elif yesno('👉 Turn the SNI lock ON?', True):
        v2(['snilock', '--on'], quiet=False)
        print('\n' + yel('Users must connect with SNI "%s" (re-share the links from Show account).' % st['cfg_sni']))


def xhttp_menu():
    st = load_settings()
    fields = (('--path', 'xhttp_path', 'Path base (default /xhttp)'),
              ('--mode', 'xhttp_mode', 'Mode: auto / packet-up / stream-up / stream-one'),
              ('--padding', 'xhttp_padding', 'xPaddingBytes (e.g. 100-1000)'),
              ('--max-post', 'xhttp_max_post', 'scMaxEachPostBytes (e.g. 1000000)'),
              ('--min-interval', 'xhttp_min_interval', 'scMinPostsIntervalMs (e.g. 30)'),
              ('--max-buffered', 'xhttp_max_buffered', 'scMaxBufferedPosts (e.g. 30)'),
              ('--extra', 'xhttp_extra', 'Extra JSON object (advanced, e.g. {"xmux":{...}})'))
    print('\n' + dim("Enter = keep current, '-' = clear. Applies to the server AND to every link / JSON config."))
    print(dim('Paths become <base>-vmess / <base>-vless / <base>-trojan.\n'))
    args = []
    for flag, key, label in fields:
        v = ask('👉 %s [%s]: ' % (label, st.get(key, '')), '')
        if v:
            args += [flag, '' if v == '-' else v]
    if not args:
        print('\n' + yel('ℹ️  Nothing changed.'))
    elif v2(['xhttpopts'] + args, quiet=True)[0] == 0:
        print('\n' + grn("✅ Saved and applied. Re-share the links from 'Show account'."))


def settings_menu():
    while True:
        st = load_settings()
        banner('--- ⚙️  V2Ray Settings ---')
        rc, out, _ = run([st.get('xray_bin') or DEFAULTS['xray_bin'], 'version'], timeout=10)
        print('\n  %s %s' % (cyn('Domain:'), yel(st['domain'])))
        print('  %s %s' % (cyn('TLS port:'), yel(st['tls_port'])))
        print('  %s %s' % (cyn('Non-TLS port:'), yel(st['http_port'])))
        print('  %s %s' % (cyn('Certificate:'), yel(st['cert'])))
        print('  %s %s' % (cyn('Xray core:'), yel(out.splitlines()[0] if out else '?')))
        print('  %s %s' % (cyn('Fake website:'), yel(st.get('fake_site') or '(off)')))
        print('  %s %s' % (cyn('Imperva CDN:'), grn('ON') if cdn_on(st) else dim('off')))
        print('  %s %s' % (cyn('SNI lock:'), grn('ON') if st.get('sni_lock') else dim('off')))
        print('  %s %s   %s %s   %s %s' % (cyn('Config address:'), yel(st.get('cfg_address') or '(domain)'),
                                          cyn('SNI:'), yel(st.get('cfg_sni') or '(same as address)'),
                                          cyn('Host:'), yel(st.get('cfg_host') or '(domain)')))
        print('\n' + wht('Select an action:') + '\n')
        for k, t in (('1', '🌐 Change domain'), ('2', '🔌 Change ports'), ('3', '🔐 Replace / renew certificate'),
                     ('4', '🎯 Client config options (bug host / SNI / Host)'), ('5', '♻️  Reset client config options'),
                     ('6', '🌐 Fake website (decoy page for your domain)'), ('7', '🛡️  Imperva CDN settings'),
                     ('8', '🔒 SNI lock (domain shows "unrecognized_name" in host checkers)'),
                     ('9', '⚡ XHTTP options (path / mode / padding / extra)')):
            print('  %s %s' % (cyn('[ %s]' % k), t))
        print('\n  %s ↩️  Return\n' % yel('[ 0]'))
        opt = ask(blu('👉 Select an option: '))
        if opt == '1':
            nd = ask('👉 New domain: ', '')
            if valid_domain(nd):
                if v2(['init', '--domain', nd], quiet=True)[0] == 0:
                    print('\n' + grn("✅ Domain changed. Existing links must be re-shared (use 'Show account')."))
            else:
                fail('Invalid domain.')
        elif opt == '2':
            change_ports()
        elif opt == '3':
            change_certificate()
        elif opt == '4':
            client_options()
        elif opt == '5':
            if v2(['clientopts', '--reset'], quiet=True)[0] == 0:
                print('\n' + grn('✅ Client config options reset.'))
        elif opt == '6':
            fake_website()
        elif opt == '7':
            cdn_menu()
            continue
        elif opt == '8':
            sni_lock_menu()
        elif opt == '9':
            xhttp_menu()
        elif opt in ('0', ''):
            return
        else:
            print(red('\nInvalid option.'))
        press_enter()


def manager_menu():
    while True:
        banner()
        st = load_settings()
        counts = dict(re.findall(r'(\w+)=(\d+)', v2(['counts'], quiet=True)[1]))
        states = service_states()
        flag = lambda up: grn('ON') if up else dim('OFF')
        rc, out, _ = run([st.get('xray_bin') or DEFAULTS['xray_bin'], 'version'], timeout=10)
        print('\n    %s %s' % (cyn('Core   :'), (out.splitlines()[0] if out else '?')[:40]))
        print('    %s %s   TLS %s / none-TLS %s' % (cyn('Domain :'), st['domain'], st['tls_port'], st['http_port']))
        if cdn_on(st):
            print('    %s Imperva (real IP header: %s)' % (cyn('CDN    :'), st.get('cdn_ip_header') or 'Incap-Client-IP'))
        print('\n      VMESS %s    VLESS %s    TROJAN %s' % (yel(counts.get('vmess', '0')), yel(counts.get('vless', '0')),
                                                           yel(counts.get('trojan', '0'))))
        print('      XRAY : %s   NGINX : %s   LIMITER : %s\n' % (flag(states[XRAY_SERVICE]), flag(states[NGINX_SERVICE]),
                                                               flag(states[LIMITER_UNIT])))
        print(cyn('┌' + '─' * 48 + '┐') + '\n')
        print('    %s VMESS     %s     %s LIVE BANDWIDTH' % (cyn('[01]'), cyn('[Menu]'), cyn('[06]')))
        print('    %s VLESS     %s     %s ALL ACCOUNTS' % (cyn('[02]'), cyn('[Menu]'), cyn('[07]')))
        print('    %s TROJAN    %s     %s CHECK LOGIN (ALL)' % (cyn('[03]'), cyn('[Menu]'), cyn('[08]')))
        print('    %s SETTING   %s     %s CLEANUP EXPIRED' % (cyn('[04]'), cyn('[Menu]'), cyn('[09]')))
        print('    %s RESTART ALL         %s VIEW LOGS' % (cyn('[05]'), cyn('[10]')))
        print('    %s UPDATE XRAY CORE    %s UNINSTALL' % (cyn('[11]'), cyn('[12]')))
        print('    %s IMPERVA CDN         %s AUTO-OPEN AT LOGIN: %s' % (cyn('[13]'), cyn('[14]'), flag(login_menu_enabled())))
        print('\n' + cyn('└' + '─' * 48 + '┘') + '\n')
        print('    %s Exit\n' % yel('[00]'))
        opt = ask(blu('Select menu : '))
        if opt in ('1', '01'):
            proto_menu('vmess', 'Vmess')
            continue
        if opt in ('2', '02'):
            proto_menu('vless', 'Vless')
            continue
        if opt in ('3', '03'):
            proto_menu('trojan', 'Trojan')
            continue
        if opt in ('4', '04'):
            settings_menu()
            continue
        if opt == '13':
            cdn_menu()
            continue
        if opt == '14':
            set_login_menu(not login_menu_enabled())
            install_menu_command()
            continue
        if opt in ('0', '00'):
            return
        if opt in ('5', '05'):
            restart_services()
            print('\n' + grn('✅ Services restarted.'))
        elif opt in ('6', '06'):
            v2(['monitor'])
        elif opt in ('7', '07'):
            print()
            v2(['list'])
        elif opt in ('8', '08'):
            print()
            v2(['online'])
        elif opt in ('9', '09'):
            print()
            v2(['cleanup'])
        elif opt == '10':
            print()
            sh(['journalctl', '-u', XRAY_SERVICE, '-u', NGINX_SERVICE, '-u', LIMITER_UNIT, '-n', '30', '--no-pager'], quiet=False)
        elif opt == '11':
            update_flow()
        elif opt == '12':
            uninstall_flow()
            if not installed():
                press_enter()
                return
        else:
            print(red('\nInvalid option.'))
        press_enter()


def cmd_menu(a):
    need_root()
    try:
        if not installed():
            banner()
            print('\n' + yel('V2Ray (Xray) is not installed on this server.'))
            if not yesno('👉 Install it now?', True):
                return
            if not install_flow():
                return
            press_enter()
        manager_menu()
    except (Back, KeyboardInterrupt):
        print()


def cmd_install(a):
    try:
        if installed():
            print(yel('Already installed. Use "ffv2ray.py menu" or "ffv2ray.py update".'))
            return
        install_flow()
    except (Back, KeyboardInterrupt):
        print()


def cmd_update(a):
    update_flow()


def cmd_uninstall(a):
    try:
        uninstall_flow(silent=a.yes)
    except (Back, KeyboardInterrupt):
        print()


def cmd_autostart(a):
    need_root()
    set_login_menu(a.state == 'on')
    if a.state == 'on':
        install_menu_command()
    print('Auto-open at login: %s' % a.state)


def cmd_status(a):
    st = load_settings()
    print(row('Installed', 'yes' if installed() else 'no'))
    for svc, up in service_states().items():
        print(row(svc, grn('active') if up else red('inactive')))
    if st.get('domain'):
        print(row('Domain', st['domain']))
        print(row('Ports', 'TLS %s / none-TLS %s' % (st['tls_port'], st['http_port'])))
        print(cdn_summary(st))


# ------------------------------------------------------------------ argument parsing
def num(s):
    try:
        v = float(s)
    except ValueError:
        raise argparse.ArgumentTypeError('not a number: %s' % s)
    if v < 0:
        raise argparse.ArgumentTypeError('must not be negative')
    return v


def build_parser():
    p = argparse.ArgumentParser(prog='ffv2ray')
    sub = p.add_subparsers(dest='cmd')
    sub.required = True

    sub.add_parser('api').set_defaults(fn=cmd_api)

    s = sub.add_parser('init')
    for opt in ('domain', 'tls-port', 'http-port', 'cert', 'key', 'xray-bin', 'nginx-bin', 'decoy-port'):
        s.add_argument('--' + opt, dest=opt.replace('-', '_'), default=None)
    s.set_defaults(fn=cmd_init)

    s = sub.add_parser('render')
    s.add_argument('--restart', action='store_true')
    s.set_defaults(fn=cmd_render)

    s = sub.add_parser('get')
    s.add_argument('key')
    s.set_defaults(fn=cmd_get)

    s = sub.add_parser('fakesite')
    s.add_argument('--template', default=None, help='business | cloud | blog')
    s.add_argument('--off', action='store_true', help='remove the fake website')
    s.set_defaults(fn=cmd_fakesite)

    s = sub.add_parser('clientopts')
    s.add_argument('--address', default=None, help='connect address / bug host (empty = use the domain)')
    s.add_argument('--sni', default=None, help='TLS server name (empty = same as the address)')
    s.add_argument('--host', default=None, help='WebSocket Host header (empty = the real domain)')
    s.add_argument('--reset', action='store_true')
    s.set_defaults(fn=cmd_clientopts)

    s = sub.add_parser('xhttpopts', help='XHTTP customizations (path, mode, padding ...)')
    s.add_argument('--path', default=None, help='base path (default /xhttp; final path = <base>-<proto>)')
    s.add_argument('--mode', default=None, help='auto | packet-up | stream-up | stream-one')
    s.add_argument('--padding', default=None, help='xPaddingBytes, e.g. 100-1000')
    s.add_argument('--max-post', dest='max_post', default=None, help='scMaxEachPostBytes')
    s.add_argument('--min-interval', dest='min_interval', default=None, help='scMinPostsIntervalMs')
    s.add_argument('--max-buffered', dest='max_buffered', default=None, help='scMaxBufferedPosts')
    s.add_argument('--extra', default=None, help='raw JSON object merged into xhttpSettings')
    s.add_argument('--reset', action='store_true')
    s.set_defaults(fn=cmd_xhttpopts)

    s = sub.add_parser('snilock', help='refuse the domain as TLS SNI (unrecognized_name), allow only the client SNI')
    s.add_argument('--on', action='store_true')
    s.add_argument('--off', action='store_true')
    s.set_defaults(fn=cmd_snilock)

    s = sub.add_parser('add')
    s.add_argument('--proto', required=True)
    s.add_argument('--name', required=True)
    s.add_argument('--days', type=num, default=0)
    s.add_argument('--hours', type=num, default=0)
    s.add_argument('--minutes', type=num, default=0)
    s.add_argument('--total', type=num, default=0)
    s.add_argument('--daily', type=num, default=0)
    s.add_argument('--trial', action='store_true')
    s.add_argument('--conn', type=int, default=0, help='max devices (0 = unlimited)')
    s.add_argument('--owner', default='admin')
    s.add_argument('--id', default='', help='custom short id / password (default: random UUID)')
    s.set_defaults(fn=cmd_add)

    s = sub.add_parser('exists')
    s.add_argument('name')
    s.set_defaults(fn=cmd_exists)

    for cname, fn in (('del', cmd_del), ('lock', cmd_lock), ('unlock', cmd_unlock),
                      ('show', cmd_show), ('usage', cmd_usage)):
        s = sub.add_parser(cname)
        s.add_argument('name')
        s.set_defaults(fn=fn)

    s = sub.add_parser('renew')
    s.add_argument('name')
    s.add_argument('--days', type=num, required=True)
    s.add_argument('--reset', action='store_true')
    s.set_defaults(fn=cmd_renew)

    s = sub.add_parser('setexpiry')
    s.add_argument('name')
    s.add_argument('--days', type=num, default=None, help='days from today')
    s.add_argument('--never', action='store_true')
    s.add_argument('--mode', choices=['now', 'day'], default='now', help='now = exactly N days from now, day = through that day (00:00 EAT next day)')
    s.set_defaults(fn=cmd_setexpiry)

    s = sub.add_parser('limit')
    s.add_argument('name')
    s.add_argument('--total', type=num, default=None)
    s.add_argument('--daily', type=num, default=None)
    s.add_argument('--conn', type=int, default=None, help='max devices (0 = unlimited)')
    s.add_argument('--reset', action='store_true')
    s.set_defaults(fn=cmd_limit)

    sub.add_parser('cleanup').set_defaults(fn=cmd_cleanup)
    sub.add_parser('counts').set_defaults(fn=cmd_counts)

    s = sub.add_parser('names')
    s.add_argument('--proto', default=None)
    s.set_defaults(fn=cmd_names)

    s = sub.add_parser('list')
    s.add_argument('--proto', default=None)
    s.add_argument('--once', action='store_true', help='print once instead of the live view')
    s.set_defaults(fn=cmd_list)

    s = sub.add_parser('online')
    s.add_argument('name', nargs='?', default=None)
    s.add_argument('--proto', default=None)
    s.add_argument('--minutes', type=int, default=10)
    s.set_defaults(fn=cmd_online)

    s = sub.add_parser('monitor')
    s.add_argument('--once', action='store_true')
    s.set_defaults(fn=cmd_monitor)

    s = sub.add_parser('daemon')
    s.add_argument('--once', action='store_true')
    s.set_defaults(fn=cmd_daemon)

    s = sub.add_parser('cdn', help='Imperva CDN settings')
    s.add_argument('--enable', action='store_true', help='the domain is behind Imperva')
    s.add_argument('--disable', action='store_true')
    s.add_argument('--refresh', action='store_true', help='download the Imperva networks now')
    s.add_argument('--header', default=None, help='header with the real visitor IP (default Incap-Client-IP)')
    s.add_argument('--trust-any', action='store_true', help='trust the header from every source')
    s.add_argument('--no-trust-any', action='store_true')
    s.add_argument('--allow-grpc', action='store_true')
    s.add_argument('--hide-grpc', action='store_true')
    s.add_argument('--extra-ranges', default=None, help='extra trusted networks, comma separated ("" clears)')
    s.set_defaults(fn=cmd_cdn)

    sub.add_parser('menu', help='interactive installer / manager').set_defaults(fn=cmd_menu)
    sub.add_parser('install', help='install V2Ray (Xray)').set_defaults(fn=cmd_install)
    sub.add_parser('update', help='update the Xray core and this script').set_defaults(fn=cmd_update)
    s = sub.add_parser('uninstall', help='remove V2Ray (Xray)')
    s.add_argument('--yes', action='store_true', help='no questions (also removes nginx when it was installed for V2Ray)')
    s.set_defaults(fn=cmd_uninstall)
    sub.add_parser('status', help='services and settings').set_defaults(fn=cmd_status)
    s = sub.add_parser('autostart', help='open the manager automatically at login')
    s.add_argument('state', choices=['on', 'off'])
    s.set_defaults(fn=cmd_autostart)
    return p


def main(argv=None):
    if argv is None:
        argv = sys.argv[1:]
    if not argv:
        argv = ['menu']                              # no arguments: installer / manager menu
    args = build_parser().parse_args(argv)
    try:
        args.fn(args)
    except BrokenPipeError:
        try:
            sys.stdout.close()
        except Exception:
            pass
        sys.exit(0)


if __name__ == '__main__':
    main()
