"""User invites for lldap + Authelia.

Admins (behind Authelia forward-auth) create an invite for an email address and a
set of lldap groups. The invitee gets a one-time link, picks a username and
password, and the account is created in lldap. Python stdlib + vendored ldap3.
"""

import hashlib
import html
import json
import os
import re
import secrets
import smtplib
import sqlite3
import ssl
import sys
import threading
import time
import traceback
import urllib.error
import urllib.request
from email.message import EmailMessage
from email.utils import formataddr, parseaddr
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, quote, urlsplit

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "vendor"))
import ldap3  # noqa: E402


def env(name, default=None):
    # Empty counts as unset, so compose can pass optional settings through as ${VAR:-}.
    value = os.environ.get(name) or default
    if value is None:
        sys.exit(f"missing required environment variable {name}")
    return value


PUBLIC_URL = env("PUBLIC_URL").rstrip("/")
LOGIN_URL = env("LOGIN_URL").rstrip("/")
# Where people land after signing in (Authelia redirects there via ?rd=).
HOME_URL = env("HOME_URL", LOGIN_URL + "/")
SIGNIN_URL = f"{LOGIN_URL}/?rd={quote(HOME_URL, safe='')}"
SITE_NAME = env("SITE_NAME", urlsplit(PUBLIC_URL).netloc)
ADMIN_GROUP = env("ADMIN_GROUP", "invite-users")
# Design-system signature hue (teal, green, purple, amber, orange, pink) and the host in the prompt line.
SIGNATURE = env("SIGNATURE", "teal")
PROMPT_HOST = env("PROMPT_HOST", "eopsin")
DB_PATH = env("DB_PATH", "/data/invites.db")
PORT = int(env("PORT_HTTP", "8080"))

LLDAP_URL = env("LLDAP_URL", "http://lldap:17170").rstrip("/")
LLDAP_LDAP_URL = env("LLDAP_LDAP_URL", "ldap://lldap:3890")
LLDAP_BASE_DN = env("LLDAP_BASE_DN")
LLDAP_USER = env("LLDAP_USER")
LLDAP_PASSWORD = env("LLDAP_PASSWORD")

SMTP_HOST = env("SMTP_HOST")
SMTP_PORT = int(env("SMTP_PORT", "587"))
SMTP_USER = env("SMTP_USER")
SMTP_PASSWORD = env("SMTP_PASSWORD")
SMTP_FROM = env("SMTP_FROM")

USERNAME_RE = re.compile(r"^[a-z][a-z0-9._-]{1,31}$")
USERNAME_PATTERN = r"[a-z][a-z0-9._\-]{1,31}"  # the same, for the HTML pattern attribute
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
MIN_PASSWORD = 10
EXPIRY_CHOICES = [1, 3, 7, 14, 30]
PUBLIC_HOST = urlsplit(PUBLIC_URL).netloc
PUBLIC_ORIGIN = f"{urlsplit(PUBLIC_URL).scheme}://{PUBLIC_HOST}"

claim_lock = threading.Lock()


def log(msg):
    print(time.strftime("%Y-%m-%dT%H:%M:%S"), msg, flush=True)


# ---------------------------------------------------------------- storage

def db():
    conn = sqlite3.connect(DB_PATH, timeout=10)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    with db() as conn:
        conn.execute(
            """CREATE TABLE IF NOT EXISTS invites (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                token_hash TEXT NOT NULL UNIQUE,
                email TEXT NOT NULL,
                display_name TEXT NOT NULL DEFAULT '',
                suggested_username TEXT NOT NULL DEFAULT '',
                groups TEXT NOT NULL DEFAULT '[]',
                note TEXT NOT NULL DEFAULT '',
                created_by TEXT NOT NULL,
                created_by_email TEXT NOT NULL DEFAULT '',
                created_at INTEGER NOT NULL,
                expires_at INTEGER NOT NULL,
                status TEXT NOT NULL DEFAULT 'pending',
                used_at INTEGER,
                used_username TEXT
            )"""
        )


def hash_token(token):
    return hashlib.sha256(token.encode()).hexdigest()


def invite_state(row):
    if row["status"] == "pending" and row["expires_at"] < time.time():
        return "expired"
    return row["status"]


# ---------------------------------------------------------------- lldap

class LldapError(Exception):
    pass


def http_json(url, payload, headers=None):
    req = urllib.request.Request(
        url, json.dumps(payload).encode(),
        {"Content-Type": "application/json", **(headers or {})},
    )
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            return json.load(resp)
    except urllib.error.HTTPError as e:
        raise LldapError(f"{url} returned {e.code}: {e.read()[:300]!r}") from e


def gql(query, variables=None):
    token = http_json(f"{LLDAP_URL}/auth/simple/login",
                      {"username": LLDAP_USER, "password": LLDAP_PASSWORD})["token"]
    result = http_json(f"{LLDAP_URL}/api/graphql",
                       {"query": query, "variables": variables or {}},
                       {"Authorization": f"Bearer {token}"})
    if result.get("errors"):
        raise LldapError("; ".join(e.get("message", "?") for e in result["errors"]))
    return result["data"]


def list_groups():
    groups = gql("{ groups { id displayName } }")["groups"]
    return sorted((g for g in groups if not g["displayName"].startswith("lldap_")),
                  key=lambda g: g["displayName"].lower())


def list_users():
    return gql("{ users { id email } }")["users"]


def set_password(username, password):
    server = ldap3.Server(LLDAP_LDAP_URL, connect_timeout=10)
    bind_dn = f"uid={LLDAP_USER},ou=people,{LLDAP_BASE_DN}"
    user_dn = f"uid={username},ou=people,{LLDAP_BASE_DN}"
    with ldap3.Connection(server, bind_dn, LLDAP_PASSWORD, auto_bind=True,
                          receive_timeout=15) as conn:
        if not conn.extend.standard.modify_password(user_dn, None, password):
            raise LldapError(f"password modify failed: {conn.result}")


def create_account(username, email, display_name, password, group_names):
    gql("mutation($u: CreateUserInput!) { createUser(user: $u) { id } }",
        {"u": {"id": username, "email": email, "displayName": display_name}})
    try:
        set_password(username, password)
    except Exception:
        try:
            gql("mutation($id: String!) { deleteUser(userId: $id) { ok } }", {"id": username})
        except Exception as e:
            log(f"rollback of {username} failed: {e}")
        raise
    by_name = {g["displayName"]: g["id"] for g in list_groups()}
    missing = []
    for name in group_names:
        if name not in by_name:
            missing.append(name)
            continue
        gql("mutation($u: String!, $g: Int!) { addUserToGroup(userId: $u, groupId: $g) { ok } }",
            {"u": username, "g": by_name[name]})
    return missing


# ---------------------------------------------------------------- email

def send_mail(to, subject, text, html_body=None, reply_to=None):
    msg = EmailMessage()
    msg["From"] = SMTP_FROM
    msg["To"] = to
    msg["Subject"] = subject
    if reply_to:
        msg["Reply-To"] = reply_to
    msg.set_content(text)
    if html_body:
        msg.add_alternative(html_body, subtype="html")
    ctx = ssl.create_default_context()
    if SMTP_PORT == 465:
        with smtplib.SMTP_SSL(SMTP_HOST, SMTP_PORT, context=ctx, timeout=20) as s:
            s.login(SMTP_USER, SMTP_PASSWORD)
            s.send_message(msg)
    else:
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=20) as s:
            s.starttls(context=ctx)
            s.login(SMTP_USER, SMTP_PASSWORD)
            s.send_message(msg)


def send_invite_email(row, link, inviter_name):
    days = max(1, round((row["expires_at"] - time.time()) / 86400))
    greeting = f"Hi {row['display_name']}," if row["display_name"] else "Hi,"
    note = row["note"].strip()
    text = (
        f"{greeting}\n\n{inviter_name} has invited you to create an account on {SITE_NAME}.\n\n"
        + (f"{note}\n\n" if note else "")
        + f"Choose your username and password here:\n{link}\n\n"
        f"This link works once and expires in {days} day{'s' if days != 1 else ''}.\n"
        f"After that, sign in at {SIGNIN_URL}\n\n"
        "If you weren't expecting this, you can ignore this email.\n"
    )
    # Email clients ignore stylesheets, so the design-system light theme is inlined here.
    e = html.escape
    sans = "'Fira Sans','Segoe UI',system-ui,-apple-system,sans-serif"
    mono = "'Fira Code',ui-monospace,Menlo,Consolas,monospace"
    note_html = (f'<p style="margin:0 0 24px;padding:16px 24px;background:#eef4f5;border-radius:4px">'
                 f'{e(note).replace(chr(10), "<br>")}</p>') if note else ""
    html_body = f"""<!doctype html><html><body style="margin:0;padding:0;background:#fafcfc;font-family:{sans};font-size:16px;line-height:26px;color:#14282b">
<div style="height:4px;background:#00748a;background-image:linear-gradient(90deg,#00748a,#0087a0)"></div>
<div style="max-width:560px;margin:0 auto;padding:24px 16px 48px">
<p style="margin:0 0 16px;font-weight:600;font-size:18px">{e(SITE_NAME)}</p>
<div style="height:2px;background:#14282b;margin:0 0 32px"></div>
<h1 style="font-size:24px;line-height:30px;font-weight:600;margin:0 0 16px">You're invited to {e(SITE_NAME)}</h1>
<p style="margin:0 0 16px">{e(greeting)}</p>
<p style="margin:0 0 24px">{e(inviter_name)} has invited you to create an account.</p>
{note_html}
<p style="margin:0 0 32px"><a href="{e(link)}" style="background:#00748a;color:#ffffff;text-decoration:none;padding:8px 16px;border-radius:2px;font-weight:500;font-size:14px;line-height:20px;display:inline-block">Create your account</a></p>
<p style="margin:0 0 16px;font-size:14px;line-height:22px;color:#576e71">This link works once and expires in {days} day{'s' if days != 1 else ''}. After that, sign in at <a href="{e(SIGNIN_URL)}" style="color:#00748a">{e(urlsplit(HOME_URL).netloc)}</a>.</p>
<p style="margin:0 0 16px;font-size:14px;line-height:22px;color:#576e71">If the button doesn't work, paste this into your browser:<br><span style="font-family:{mono};font-size:13px;word-break:break-all;color:#14282b">{e(link)}</span></p>
<p style="margin:24px 0 0;padding-top:16px;border-top:1px solid #e4ebec;font-size:14px;line-height:22px;color:#576e71">If you weren't expecting this, you can ignore this email.</p>
</div></body></html>"""
    send_mail(row["email"], f"You're invited to {SITE_NAME}", text, html_body,
              reply_to=row["created_by_email"] or None)


def notify_inviter(row, username):
    if not row["created_by_email"]:
        return
    try:
        send_mail(
            row["created_by_email"],
            f"[{SITE_NAME}] {username} accepted your invite",
            f"{row['email']} accepted your invite and created the account '{username}'.\n"
            f"Groups: {', '.join(json.loads(row['groups'])) or 'none'}\n\n{PUBLIC_URL}/admin\n",
        )
    except Exception as e:
        log(f"inviter notification failed: {e}")


# ---------------------------------------------------------------- html
#
# The look is the bridgewater.digital design system: static/bridgewater.css is its
# tokens and component styles, and the header markup below mirrors its Strip, Wordmark,
# Prompt and ThemeToggle components. Everything is inlined so the 403 page still works
# when Traefik serves it on another site; only the fonts are fetched, from PUBLIC_URL.

STATIC_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "static")
with open(os.path.join(STATIC_DIR, "bridgewater.css")) as f:
    BRAND_CSS = f.read()
FONTS = {  # file -> (family, weight)
    "fira-sans-latin-400-normal.woff2": ("Fira Sans", 400),
    "fira-sans-latin-500-normal.woff2": ("Fira Sans", 500),
    "fira-sans-latin-600-normal.woff2": ("Fira Sans", 600),
    "fira-code-latin-400-normal.woff2": ("Fira Code", 400),
    "fira-code-latin-500-normal.woff2": ("Fira Code", 500),
}
FONT_CSS = "".join(
    f'@font-face{{font-family:"{fam}";font-weight:{w};font-style:normal;font-display:swap;'
    f'src:url("{PUBLIC_URL}/static/fonts/{name}") format("woff2")}}'
    for name, (fam, w) in FONTS.items())

APP_CSS = """
main{padding-top:var(--space-6);padding-bottom:var(--space-8)}
main.narrow>*{max-width:528px}
.page-title{margin-bottom:var(--space-5)}
.lede{color:var(--soft);max-width:var(--measure);margin-bottom:var(--space-5)}
section+section{margin-top:var(--space-7)}
.sec{display:flex;align-items:baseline;gap:var(--space-3);margin-bottom:var(--space-4)}
.sec .bw-secnum{margin-right:0}
.form{display:flex;flex-direction:column;gap:var(--space-4)}
.form>.bw-btn{align-self:flex-start;margin-top:var(--space-2)}
.grid2{display:grid;grid-template-columns:1fr 1fr;gap:var(--space-4)}
@media(max-width:640px){.grid2{grid-template-columns:1fr}}
fieldset{border:0;margin:0;padding:0;min-width:0}
legend{padding:0;margin-bottom:var(--space-2)}
.checks{display:flex;flex-wrap:wrap;gap:var(--space-2) var(--space-5)}
.bw-panel{margin-bottom:var(--space-5)}
.bw-panel p+p,.bw-panel p+.bw-btn,.bw-panel p+.link-row{margin-top:var(--space-3)}
.link-row{display:flex;gap:var(--space-2);align-items:center}
.link-row .bw-field__control{min-width:0}
.table-wrap{overflow-x:auto}
td .bw-mono,td.bw-mono{font-size:14px;line-height:22px}
.sub{display:block;color:var(--comment);font-size:14px;line-height:22px}
td.actions{white-space:nowrap;text-align:right;padding-right:0}
td.actions form{display:inline}
.after{margin-top:var(--space-5)}
"""

# Mark and logotype geometry from the design system's Wordmark component.
_MARK = {"ridge": "M4.0 41.4 L10.8 36.5 L14.1 34.9 L16.2 31.5 L18.3 30.0 L20.2 31.1 L24.9 23.2 L31.9 11.0 "
                  "L33.1 13.3 L34.5 12.5 L37.7 15.9 L43.4 24.3 L49.2 30.8 L56.0 38.0 L60.0 41.8",
         "trace": "M31.9 11 V26 L25.4 32.5 V34.5 M31.9 26 L38.4 32.5 V34.5",
         "dot": (31.9, 11.0, 3.4), "pads": ((25.4, 37.7, 2.7), (38.4, 37.7, 2.7))}
_RING = "A4 4 0 1 0 8 10 A4 4 0 1 0 0 10 Z"
_GLYPHS = [  # (x offset, path) for each letter of "bridgewater.digital"
    (0.0, f"M0 0 V14 M0 10 {_RING}"), (11.6, "M0 6 V14 M0 10 A4 4 0 0 1 4 6 H5.5"), (21.2, "M0 6 V14"),
    (24.8, f"M8 0 V14 M0 10 {_RING}"), (36.4, f"M8 6 V16 A4 4 0 0 1 4 20 H1 M0 10 {_RING}"),
    (48.0, "M0 10 H8 A4 4 0 1 0 6.83 12.83"), (59.6, "M0 6 L2.75 14 L5.5 6 L8.25 14 L11 6"),
    (74.2, f"M8 6 V14 M0 10 {_RING}"), (85.8, "M2 2 V11 A3 3 0 0 0 5 14 H6 M0 6 H5.5"),
    (95.4, "M0 10 H8 A4 4 0 1 0 6.83 12.83"), (107.0, "M0 6 V14 M0 10 A4 4 0 0 1 4 6 H5.5"),
    (121.8, f"M8 0 V14 M0 10 {_RING}"), (133.4, "M0 6 V14"),
    (137.0, f"M8 6 V16 A4 4 0 0 1 4 20 H1 M0 10 {_RING}"), (148.6, "M0 6 V14"),
    (152.2, "M2 2 V11 A3 3 0 0 0 5 14 H6 M0 6 H5.5"), (161.8, f"M8 6 V14 M0 10 {_RING}"), (173.4, "M0 0 V14"),
]
_HBUS = ("M156.40 16.30 V3.00 M156.40 3.00 L158.90 0.50 H185.10 L187.60 3.00 V6.20 M172.40 0.50 V6.20 "
         "M156.40 3.00 L153.90 0.50 H17.45 L15.95 2.00 V4.20 M60.20 0.50 V6.20")


def wordmark_svg(height=28):
    ox, oy = 39, 6
    vb = (-1, -2, 42 + 173.4, 35)
    k = height * 1.5 / 32
    m = _MARK
    pads = "".join(f'<circle class="bw-mark-pad" cx="{x}" cy="{y}" r="{r}"/>' for x, y, r in m["pads"])
    glyphs = "".join(f'<path transform="translate({x} 0)" d="{d}"/>' for x, d in _GLYPHS)
    idots = "".join(f'<circle class="bw-lt-idot" cx="{x + ox}" cy="{1.9 + oy}" r="1.35"/>'
                    for x in (21.2, 133.4, 148.6))
    return (f'<svg class="bw-lt" viewBox="{" ".join(map(str, vb))}" width="{round(vb[2] * k, 1)}" '
            f'height="{round(vb[3] * k, 1)}" aria-hidden="true" focusable="false">'
            f'<g transform="scale(0.5)"><path class="bw-mark-ridge" d="{m["ridge"]}"/>'
            f'<path class="bw-mark-trace" d="{m["trace"]}"/>{pads}'
            f'<circle class="bw-mark-dot" cx="{m["dot"][0]}" cy="{m["dot"][1]}" r="{m["dot"][2]}"/></g>'
            f'<g class="bw-lt-glyph" transform="translate({ox} {oy})">{glyphs}</g>'
            f'<path class="bw-lt-trace" d="{_HBUS}"/>{idots}'
            f'<circle class="bw-lt-pad" cx="{117.4 + ox}" cy="{13.1 + oy}" r="2.8"/>'
            f'<circle class="bw-lt-dot" cx="{117.4 + ox}" cy="{13.1 + oy}" r="1.7"/></svg>')


WORDMARK = wordmark_svg()
ICON_SUN = ('<svg class="bw-icon" viewBox="0 0 24 24" width="20" height="20" aria-hidden="true">'
            '<circle cx="12" cy="12" r="3.8"/><path d="M12 2.5 V5 M12 19 V21.5 M2.5 12 H5 M19 12 H21.5 '
            'M5.3 5.3 L7 7 M17 17 L18.7 18.7 M5.3 18.7 L7 17 M17 7 L18.7 5.3"/></svg>')
ICON_MOON = ('<svg class="bw-icon" viewBox="0 0 24 24" width="20" height="20" aria-hidden="true">'
             '<path d="M20 14.5 A8 8 0 1 1 9.5 4 A6.5 6.5 0 0 0 20 14.5 Z"/></svg>')

# Runs before first paint so the saved theme doesn't flash; same storage key as the
# design system's ThemeToggle, so the choice is shared with its other pages on this host.
THEME_INIT_JS = """<script>try{var t=localStorage.getItem('bw-theme');
if(t==='dark'||t==='light')document.documentElement.setAttribute('data-theme',t)}catch(e){}</script>"""

PAGE_JS = """<script>
document.querySelectorAll('time[data-ts]').forEach(t=>{const d=new Date(+t.dataset.ts*1000);
t.textContent=d.toLocaleString(undefined,{month:'short',day:'numeric',hour:'numeric',minute:'2-digit'});
t.title=d.toString();});
document.querySelectorAll('[data-copy]').forEach(b=>b.addEventListener('click',()=>{
const i=document.getElementById(b.dataset.copy);i.select();navigator.clipboard.writeText(i.value);
b.textContent='Copied';}));
(()=>{const b=document.getElementById('theme-toggle'),r=document.documentElement;if(!b)return;
const cur=()=>r.getAttribute('data-theme')||(matchMedia('(prefers-color-scheme: dark)').matches?'dark':'light');
const paint=()=>{const dark=cur()==='dark';b.setAttribute('aria-pressed',String(dark));
b.setAttribute('aria-label','Switch to '+(dark?'light':'dark')+' theme');
b.innerHTML=dark?b.dataset.sun:b.dataset.moon;};
b.addEventListener('click',()=>{const t=cur()==='dark'?'light':'dark';r.setAttribute('data-theme',t);
try{localStorage.setItem('bw-theme',t)}catch(e){}paint();});b.hidden=false;paint();})();
</script>"""


def prompt(user, path):
    """The prompt line: user@host:~/path. `path` lists segments after `~`."""
    e = html.escape
    segs = [f'<a class="bw-prompt__seg" href="{e(HOME_URL)}">~</a>' if path else
            '<span class="bw-prompt__seg" aria-current="page">~</span>']
    for i, seg in enumerate(path):
        current = ' aria-current="page"' if i == len(path) - 1 else ""
        segs.append(f'<span class="bw-prompt__sep">/</span><span class="bw-prompt__seg"{current}>{e(seg)}</span>')
    return (f'<nav class="bw-prompt" aria-label="You are here"><span class="bw-prompt__user">{e(user or "you")}</span>'
            f'<span class="bw-prompt__sep">@</span><span class="bw-prompt__host">{e(PROMPT_HOST)}</span>'
            f'<span class="bw-prompt__sep">:</span>{"".join(segs)}</nav>')


def page(title, body, user="", path=(), narrow=False):
    e = html.escape
    header = (f'<header class="bw-header"><div class="bw-strip" aria-hidden="true"></div>'
              f'<div class="bw-container bw-header__bar">'
              f'<a class="bw-wordmark" href="{e(HOME_URL)}" aria-label="bridgewater.digital">{WORDMARK}</a>'
              f'<button type="button" id="theme-toggle" class="bw-btn bw-btn--secondary bw-btn--icon" hidden '
              f'aria-label="Switch theme" data-sun="{e(ICON_SUN)}" data-moon="{e(ICON_MOON)}"></button></div>'
              f'<div class="bw-header__rule"></div>'
              f'<div class="bw-container bw-header__where">{prompt(user, list(path))}</div></header>')
    return f"""<!doctype html><html lang="en" data-sig="{e(SIGNATURE)}"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><meta name="robots" content="noindex">
<title>{e(title)}</title>{THEME_INIT_JS}<style>{FONT_CSS}{BRAND_CSS}{APP_CSS}</style></head>
<body>{header}<main class="bw-container{' narrow' if narrow else ''}">{body}</main>{PAGE_JS}</body></html>"""


def panel(role, body):
    """The one panel on a view. Role is a design-system role: green ok, red wrong, orange failed."""
    return f'<section class="bw-panel" data-role="{role}">{body}</section>'


def field(fid, label, control, hint=""):
    """A design-system Field. `control` is the input markup; it gets id=fid and the hint wired to it."""
    described = f' aria-describedby="{fid}-hint"' if hint else ""
    control = re.sub(r"^<(input|select|textarea)", rf'<\1 id="{fid}"{described}', control)
    hint_html = f'<div class="bw-field__hint" id="{fid}-hint">{hint}</div>' if hint else ""
    return (f'<div class="bw-field"><label class="bw-field__label" for="{fid}">{label}</label>'
            f'{control}{hint_html}</div>')


def ts(value):
    return f'<time data-ts="{int(value)}"></time>' if value else ""


# Invite state -> design-system status: (state, label)
STATUS = {"pending": "attention", "used": "ok", "expired": "off", "revoked": "off"}
FLASH_ROLES = {"ok": "green", "err": "red", "fail": "orange"}


def admin_page(user, groups, invites, flash="", flash_kind="ok", form=None, new_link=""):
    e = html.escape
    form = form or {}
    chosen = set(form.get("groups", []))
    msg = ""
    if flash or new_link:
        inner = f"<p>{flash}</p>" if flash else ""
        if new_link:
            inner += ('<p>This is the only time the link is shown. It was also emailed.</p>'
                      '<div class="link-row"><input class="bw-field__control bw-field__control--mono" type="text" '
                      f'id="newlink" readonly aria-label="Invite link" value="{e(new_link)}">'
                      '<button type="button" class="bw-btn bw-btn--secondary" data-copy="newlink">Copy</button></div>')
        msg = panel(FLASH_ROLES.get(flash_kind, "red"), inner)
    group_boxes = "".join(
        f'<div class="bw-field bw-field--check"><input type="checkbox" id="g{i}" name="groups" value="{e(g["displayName"])}"'
        f'{" checked" if g["displayName"] in chosen else ""}>'
        f'<label class="bw-field__label bw-mono" for="g{i}">{e(g["displayName"])}</label></div>'
        for i, g in enumerate(groups))
    expiry = int(form.get("expires_days", 7))
    expiry_opts = "".join(f'<option value="{d}"{" selected" if d == expiry else ""}>{d} day{"s" if d > 1 else ""}</option>'
                          for d in EXPIRY_CHOICES)
    rows = []
    for r in invites:
        state = invite_state(r)
        actions = ""
        if state in ("pending", "expired"):
            actions = (f'<form method="post" action="/admin/invites/{r["id"]}/resend">'
                       f'<button class="bw-btn bw-btn--secondary bw-btn--sm" title="Issue a new link and email it">'
                       f'Resend</button></form> ')
        if state == "pending":
            actions += (f'<form method="post" action="/admin/invites/{r["id"]}/revoke" '
                        f'onsubmit="return confirm(\'Revoke this invite? The link stops working.\')">'
                        f'<button class="bw-btn bw-btn--danger bw-btn--sm">Revoke</button></form>')
        detail = (f'<span class="sub"><span class="bw-mono">{e(r["used_username"])}</span> {ts(r["used_at"])}</span>'
                  if state == "used" else
                  f'<span class="sub">expires {ts(r["expires_at"])}</span>' if state == "pending" else "")
        name = f'<span class="sub">{e(r["display_name"])}</span>' if r["display_name"] else ""
        rows.append(
            f'<tr><td><span class="bw-mono">{e(r["email"])}</span>{name}</td>'
            f'<td class="bw-mono">{e(", ".join(json.loads(r["groups"]))) or "<span class=bw-comment>none</span>"}</td>'
            f'<td><span class="bw-status" data-state="{STATUS.get(state, "off")}">{state}</span>{detail}</td>'
            f'<td>{e(r["created_by"])}<span class="sub">{ts(r["created_at"])}</span></td>'
            f'<td class="actions">{actions}</td></tr>')
    table = ('<div class="table-wrap"><table><thead><tr><th>Invitee</th><th>Groups</th><th>Status</th>'
             '<th>Invited by</th><th></th></tr></thead><tbody>'
             + "".join(rows) + '</tbody></table></div>'
             if rows else '<p class="bw-comment">No invites yet.</p>')
    body = f"""<h1 class="page-title">Invite a user</h1>{msg}
<section><div class="sec"><span class="bw-secnum">01</span><h2>New invite</h2></div>
<form class="form" method="post" action="/admin/invites">
<div class="grid2">{field("f-email", "Email", f'<input class="bw-field__control" type="email" name="email" required autocomplete="off" value="{e(form.get("email", ""))}">')}
{field("f-name", "Name", f'<input class="bw-field__control" type="text" name="display_name" value="{e(form.get("display_name", ""))}">', "Optional.")}</div>
<div class="grid2">{field("f-user", "Suggested username", f'<input class="bw-field__control bw-field__control--mono" type="text" name="suggested_username" autocapitalize="none" spellcheck="false" pattern="{USERNAME_PATTERN}" value="{e(form.get("suggested_username", ""))}">', "Optional. They can change it.")}
{field("f-exp", "Link expires after", f'<select class="bw-field__control" name="expires_days">{expiry_opts}</select>')}</div>
<fieldset><legend class="bw-field__label">Groups</legend><div class="checks">{group_boxes or '<span class="bw-comment">No groups in lldap.</span>'}</div></fieldset>
{field("f-note", "Personal note", f'<textarea class="bw-field__control" name="note" rows="3">{e(form.get("note", ""))}</textarea>', "Optional. Included in the email.")}
<button class="bw-btn bw-btn--primary">Send invite</button></form></section>
<section><div class="sec"><span class="bw-secnum">02</span><h2>Invites</h2><span class="bw-count">{len(invites)}</span></div>{table}</section>"""
    return page(f"Invites · {SITE_NAME}", body, user=user, path=["invites"])


def join_page(row, error="", form=None):
    e = html.escape
    form = form or {}
    username = form.get("username", row["suggested_username"])
    display = form.get("display_name", row["display_name"])
    err = panel("red", f"<p>{error}</p>") if error else ""
    body = f"""<h1 class="page-title">Create your account</h1>
<p class="lede">You've been invited to {e(SITE_NAME)}. Choose a username and password to finish.</p>{err}
<form class="form" method="post" autocomplete="on">
{field("j-email", "Email", f'<input class="bw-field__control bw-field__control--mono" type="email" value="{e(row["email"])}" disabled>')}
{field("j-user", "Username", f'<input class="bw-field__control bw-field__control--mono" type="text" name="username" required autocomplete="username" autocapitalize="none" spellcheck="false" pattern="{USERNAME_PATTERN}" value="{e(username)}">', "Lowercase letters, numbers, <code>.</code> <code>_</code> <code>-</code>. Starts with a letter.")}
{field("j-name", "Your name", f'<input class="bw-field__control" type="text" name="display_name" required autocomplete="name" value="{e(display)}">')}
{field("j-pass", "Password", f'<input class="bw-field__control" type="password" name="password" required minlength="{MIN_PASSWORD}" autocomplete="new-password">', f"At least {MIN_PASSWORD} characters.")}
{field("j-pass2", "Confirm password", f'<input class="bw-field__control" type="password" name="password2" required minlength="{MIN_PASSWORD}" autocomplete="new-password">')}
<button class="bw-btn bw-btn--primary">Create account</button></form>"""
    return page(f"Join {SITE_NAME}", body, path=["join"], narrow=True)


def forbidden_page():
    """Body for Traefik's `errors` middleware: replaces 403 pages on other sites."""
    e = html.escape
    logout = f"{LOGIN_URL}/logout?rd={quote(LOGIN_URL + '/', safe='')}"
    body = (f'<h1 class="page-title">You don\'t have access to this page</h1>'
            f'<p class="lede">Your account isn\'t allowed to use this part of {e(SITE_NAME)}. '
            'If you think it should be, ask the person who manages your account.</p>'
            f'<a class="bw-btn bw-btn--primary" href="{e(HOME_URL)}">Go to {e(urlsplit(HOME_URL).netloc)}</a>'
            f'<p class="after"><a href="{e(logout)}">Sign in as someone else</a></p>')
    return page("Access denied", body, path=["403"], narrow=True)


def message_page(title, text, role="green", path=()):
    body = f'<h1 class="page-title">{html.escape(title)}</h1>{panel(role, f"<p>{text}</p>")}'
    return page(title, body, path=path, narrow=True)


# ---------------------------------------------------------------- http

class Handler(BaseHTTPRequestHandler):
    server_version = "user-invites"

    def log_message(self, fmt, *args):
        log(f"{self.headers.get('X-Forwarded-For', self.client_address[0])} {fmt % args}")

    def send(self, status, body, ctype="text/html; charset=utf-8", headers=None):
        data = body if isinstance(body, bytes) else body.encode()
        # font-src names our own origin because the 403 page is also served on other sites.
        all_headers = {
            "Content-Type": ctype,
            "Content-Length": str(len(data)),
            "Cache-Control": "no-store",
            "Referrer-Policy": "same-origin",
            "Content-Security-Policy":
                "default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; "
                f"font-src {PUBLIC_ORIGIN}; form-action 'self'; frame-ancestors 'none'; base-uri 'none'",
            **(headers or {}),
        }
        self.send_response(status)
        for k, v in all_headers.items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(data)

    def send_font(self, name):
        if name not in FONTS:
            return self.send(404, "not found", "text/plain")
        with open(os.path.join(STATIC_DIR, "fonts", name), "rb") as f:
            data = f.read()
        # Fonts are fetched cross-origin when the 403 page is shown on another site.
        self.send(200, data, "font/woff2", {"Cache-Control": "public, max-age=31536000, immutable",
                                            "Access-Control-Allow-Origin": "*"})

    def redirect(self, location):
        self.send(303, "", headers={"Location": location})

    def form(self):
        length = int(self.headers.get("Content-Length") or 0)
        if length > 64 * 1024:
            raise ValueError("form too large")
        return parse_qs(self.rfile.read(length).decode(), keep_blank_values=True)

    def same_origin(self):
        origin = self.headers.get("Origin") or self.headers.get("Referer") or ""
        return urlsplit(origin).netloc == PUBLIC_HOST

    def admin(self):
        user = self.headers.get("Remote-User", "")
        groups = [g.strip() for g in self.headers.get("Remote-Groups", "").split(",")]
        if user and ADMIN_GROUP in groups:
            return user
        self.send(403, forbidden_page())
        return None

    def do_GET(self):
        try:
            path = urlsplit(self.path).path
            if path == "/healthz":
                return self.send(200, "ok", "text/plain")
            if path == "/error/403":
                return self.send(200, forbidden_page())
            if path.startswith("/static/fonts/"):
                return self.send_font(path[len("/static/fonts/"):])
            if path in ("/", "/admin", "/admin/"):
                user = self.admin()
                if user:
                    self.show_admin(user)
                return
            if path.startswith("/join/"):
                return self.get_join(path[len("/join/"):])
            self.send(404, message_page("Not found", "There's nothing here.", role="amber"))
        except Exception:
            self.fail()

    def do_POST(self):
        try:
            path = urlsplit(self.path).path
            if path == "/error/403":
                return self.send(200, forbidden_page())
            if not self.same_origin():
                return self.send(403, message_page("Not allowed", "Cross-site request blocked.", role="red"))
            if path.startswith("/join/"):
                return self.post_join(path[len("/join/"):])
            user = self.admin()
            if not user:
                return
            if path == "/admin/invites":
                return self.create_invite(user)
            m = re.fullmatch(r"/admin/invites/(\d+)/(revoke|resend)", path)
            if m:
                return self.revoke(int(m[1])) if m[2] == "revoke" else self.resend(user, int(m[1]))
            self.send(404, message_page("Not found", "There's nothing here.", role="amber"))
        except Exception:
            self.fail()

    def fail(self):
        log(traceback.format_exc())
        try:
            self.send(500, message_page("Something went wrong",
                                        "The error was logged. Please try again or contact the admin.", role="orange"))
        except Exception:
            pass

    # ---- admin

    def show_admin(self, user, **kw):
        with db() as conn:
            invites = conn.execute("SELECT * FROM invites ORDER BY created_at DESC LIMIT 200").fetchall()
        self.send(200, admin_page(user, list_groups(), invites, **kw))

    def inviter_name(self, user):
        return self.headers.get("Remote-Name") or user

    def create_invite(self, user):
        f = self.form()
        form = {k: (v if k == "groups" else v[0].strip()) for k, v in f.items()}
        email = form.get("email", "").lower()
        suggested = form.get("suggested_username", "").lower()
        try:
            days = int(form.get("expires_days", 7))
        except ValueError:
            days = 7
        days = days if days in EXPIRY_CHOICES else 7
        valid = {g["displayName"] for g in list_groups()}
        groups = [g for g in form.get("groups", []) if g in valid]

        error = None
        if not EMAIL_RE.match(email):
            error = "Enter a valid email address."
        elif suggested and not USERNAME_RE.match(suggested):
            error = "Suggested username must be 2-32 lowercase letters, numbers, . _ - and start with a letter."
        else:
            users = list_users()
            if any(u["email"].lower() == email for u in users):
                error = f"An account with {html.escape(email)} already exists."
            elif suggested and any(u["id"] == suggested for u in users):
                error = f"The username {html.escape(suggested)} is already taken."
        if error:
            return self.show_admin(user, flash=error, flash_kind="err", form=form)

        token = secrets.token_urlsafe(32)
        now = int(time.time())
        with db() as conn:
            cur = conn.execute(
                """INSERT INTO invites (token_hash, email, display_name, suggested_username, groups, note,
                   created_by, created_by_email, created_at, expires_at)
                   VALUES (?,?,?,?,?,?,?,?,?,?)""",
                (hash_token(token), email, form.get("display_name", ""), suggested, json.dumps(groups),
                 form.get("note", ""), user, self.headers.get("Remote-Email", ""), now, now + days * 86400))
            row = conn.execute("SELECT * FROM invites WHERE id=?", (cur.lastrowid,)).fetchone()
        link = f"{PUBLIC_URL}/join/{token}"
        log(f"{user} invited {email} groups={groups} expires_days={days}")
        try:
            send_invite_email(row, link, self.inviter_name(user))
            flash = f"Invite emailed to {html.escape(email)}."
            kind = "ok"
        except Exception as e:
            log(f"invite email to {email} failed: {e}")
            flash = (f"The invite was created but the email failed ({html.escape(str(e))}). "
                     "Send them the link below yourself.")
            kind = "fail"
        self.show_admin(user, flash=flash, flash_kind=kind, new_link=link)

    def revoke(self, invite_id):
        with db() as conn:
            conn.execute("UPDATE invites SET status='revoked' WHERE id=? AND status='pending'", (invite_id,))
        log(f"invite {invite_id} revoked")
        self.redirect("/admin")

    def resend(self, user, invite_id):
        token = secrets.token_urlsafe(32)
        with db() as conn:
            row = conn.execute("SELECT * FROM invites WHERE id=?", (invite_id,)).fetchone()
            if not row or row["status"] != "pending":
                return self.redirect("/admin")
            days = max(1, round((row["expires_at"] - row["created_at"]) / 86400))
            conn.execute("UPDATE invites SET token_hash=?, expires_at=? WHERE id=?",
                         (hash_token(token), int(time.time()) + days * 86400, invite_id))
            row = conn.execute("SELECT * FROM invites WHERE id=?", (invite_id,)).fetchone()
        link = f"{PUBLIC_URL}/join/{token}"
        log(f"{user} resent invite {invite_id} to {row['email']}")
        try:
            send_invite_email(row, link, self.inviter_name(user))
            flash, kind = f"New link emailed to {html.escape(row['email'])}. The old link no longer works.", "ok"
        except Exception as e:
            flash, kind = f"Email failed ({html.escape(str(e))}). Send them the link below yourself.", "fail"
        self.show_admin(user, flash=flash, flash_kind=kind, new_link=link)

    # ---- join

    def find_invite(self, token):
        if not re.fullmatch(r"[A-Za-z0-9_-]{20,100}", token):
            return None
        with db() as conn:
            return conn.execute("SELECT * FROM invites WHERE token_hash=?", (hash_token(token),)).fetchone()

    def invalid_invite(self, row):
        state = invite_state(row) if row else "missing"
        text = {
            "used": f'This invite has already been used. <a href="{html.escape(SIGNIN_URL)}">Sign in here</a>.',
            "expired": "This invite has expired. Ask the person who invited you to send a new one.",
            "revoked": "This invite was cancelled. Ask the person who invited you if you think that's a mistake.",
        }.get(state, "This invite link isn't valid. Check you copied the whole link from the email.")
        self.send(410 if row else 404, message_page("Invite not available", text, role="amber", path=["join"]))

    def get_join(self, token):
        row = self.find_invite(token)
        if not row or invite_state(row) != "pending":
            return self.invalid_invite(row)
        self.send(200, join_page(row))

    def post_join(self, token):
        f = self.form()
        form = {k: v[0] for k, v in f.items()}
        username = form.get("username", "").strip().lower()
        display = form.get("display_name", "").strip()
        password = form.get("password", "")
        with claim_lock:
            row = self.find_invite(token)
            if not row or invite_state(row) != "pending":
                return self.invalid_invite(row)
            shown = {"username": username, "display_name": display}
            error = None
            if not USERNAME_RE.match(username):
                error = "Username must be 2-32 characters: lowercase letters, numbers, . _ - and start with a letter."
            elif not display or len(display) > 100:
                error = "Enter your name."
            elif len(password) < MIN_PASSWORD:
                error = f"Password must be at least {MIN_PASSWORD} characters."
            elif password != form.get("password2", ""):
                error = "The passwords don't match."
            elif password.lower() in (username, row["email"].lower()):
                error = "Choose a password that isn't your username or email."
            elif any(u["id"] == username for u in list_users()):
                error = f'The username <span class="bw-mono">{html.escape(username)}</span> is taken. Try another.'
            if error:
                return self.send(400, join_page(row, error, shown))
            groups = json.loads(row["groups"])
            try:
                missing = create_account(username, row["email"], display, password, groups)
            except LldapError as e:
                log(f"creating {username} for invite {row['id']} failed: {e}")
                msg = str(e).lower()
                if "unique" in msg or "exist" in msg:
                    error = "That username or email is already in use. Try another username, or contact the admin."
                else:
                    error = "We couldn't create your account. Please try again, or contact the person who invited you."
                return self.send(400, join_page(row, error, shown))
            with db() as conn:
                conn.execute("UPDATE invites SET status='used', used_at=?, used_username=? WHERE id=?",
                             (int(time.time()), username, row["id"]))
        log(f"invite {row['id']} ({row['email']}) accepted as {username}; groups={groups} missing={missing}")
        threading.Thread(target=notify_inviter, args=(row, username), daemon=True).start()
        self.send(200, message_page(
            "You're all set",
            f'Your account <span class="bw-mono">{html.escape(username)}</span> is ready.</p>'
            "<p>Some services ask you to set up two-factor authentication the first time you use them. "
            "When that happens, we'll email you a one-time code to confirm it's you.</p>"
            f'<p><a class="bw-btn bw-btn--primary" href="{html.escape(SIGNIN_URL)}">Sign in</a>',
            path=["join"]))


def main():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    init_db()
    log(f"listening on :{PORT} as {PUBLIC_URL}")
    ThreadingHTTPServer(("0.0.0.0", PORT), Handler).serve_forever()


if __name__ == "__main__":
    main()
