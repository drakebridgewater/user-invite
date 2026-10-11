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
    value = os.environ.get(name, default)
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
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
MIN_PASSWORD = 10
EXPIRY_CHOICES = [1, 3, 7, 14, 30]
PUBLIC_HOST = urlsplit(PUBLIC_URL).netloc

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
    e = html.escape
    note_html = (f'<p style="padding:12px 16px;background:#f3f4f6;border-radius:8px">'
                 f'{e(note).replace(chr(10), "<br>")}</p>') if note else ""
    html_body = f"""<!doctype html><html><body style="margin:0;padding:24px;background:#f6f7f9;font-family:-apple-system,Segoe UI,Roboto,sans-serif;color:#1f2328">
<div style="max-width:520px;margin:0 auto;background:#fff;border-radius:12px;padding:32px;border:1px solid #e5e7eb">
<h1 style="font-size:20px;margin:0 0 16px">You're invited to {e(SITE_NAME)}</h1>
<p>{e(greeting)}</p>
<p>{e(inviter_name)} has invited you to create an account.</p>
{note_html}
<p style="margin:28px 0"><a href="{e(link)}" style="background:#2563eb;color:#fff;text-decoration:none;padding:12px 20px;border-radius:8px;font-weight:600;display:inline-block">Create your account</a></p>
<p style="font-size:14px;color:#57606a">This link works once and expires in {days} day{'s' if days != 1 else ''}. After that, sign in at <a href="{e(SIGNIN_URL)}">{e(urlsplit(HOME_URL).netloc)}</a>.</p>
<p style="font-size:13px;color:#8c959f;word-break:break-all">If the button doesn't work, paste this into your browser:<br>{e(link)}</p>
<p style="font-size:13px;color:#8c959f">If you weren't expecting this, you can ignore this email.</p>
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

CSS = """
:root{--bg:#f6f7f9;--card:#fff;--text:#1f2328;--muted:#57606a;--border:#d8dee4;--accent:#2563eb;
--accent-text:#fff;--ok-bg:#dcfce7;--ok:#166534;--err-bg:#fee2e2;--err:#991b1b;--chip:#eef2f7;--input:#fff}
@media (prefers-color-scheme:dark){:root{--bg:#0d1117;--card:#161b22;--text:#e6edf3;--muted:#8d96a0;
--border:#30363d;--accent:#4c8dff;--accent-text:#fff;--ok-bg:#12351f;--ok:#7ee2a1;--err-bg:#3d1518;
--err:#ffa198;--chip:#21262d;--input:#0d1117}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);
font:15px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif}
main{max-width:960px;margin:0 auto;padding:24px 16px 64px}main.narrow{max-width:460px}
h1{font-size:22px;margin:8px 0 20px}h2{font-size:17px;margin:0 0 14px}
.card{background:var(--card);border:1px solid var(--border);border-radius:12px;padding:20px;margin-bottom:20px}
label{display:block;font-weight:600;font-size:14px;margin:14px 0 4px}
.hint{font-weight:400;color:var(--muted);font-size:13px}
input[type=text],input[type=email],input[type=password],select,textarea{width:100%;padding:9px 11px;
border:1px solid var(--border);border-radius:8px;background:var(--input);color:var(--text);font:inherit}
textarea{min-height:70px;resize:vertical}
.groups{display:flex;flex-wrap:wrap;gap:8px;margin-top:6px}
.groups label{display:flex;align-items:center;gap:6px;margin:0;font-weight:400;background:var(--chip);
padding:5px 10px;border-radius:999px;cursor:pointer}
.row{display:grid;grid-template-columns:1fr 1fr;gap:0 16px}@media(max-width:600px){.row{grid-template-columns:1fr}}
button,.btn{display:inline-block;background:var(--accent);color:var(--accent-text);border:0;border-radius:8px;
padding:10px 18px;font:inherit;font-weight:600;cursor:pointer;text-decoration:none;margin-top:18px}
button.small{padding:5px 10px;font-size:13px;margin:0;background:var(--chip);color:var(--text);border:1px solid var(--border)}
.msg{padding:12px 14px;border-radius:8px;margin-bottom:16px}.ok{background:var(--ok-bg);color:var(--ok)}
.err{background:var(--err-bg);color:var(--err)}
.link{display:flex;gap:8px;margin-top:8px}.link input{font-family:ui-monospace,monospace;font-size:13px}
.table-wrap{overflow-x:auto}table{width:100%;border-collapse:collapse;font-size:14px}
th,td{text-align:left;padding:8px 6px;border-bottom:1px solid var(--border);vertical-align:top}
th{color:var(--muted);font-weight:600;font-size:13px}td.actions{white-space:nowrap}td.actions form{display:inline}
.badge{font-size:12px;padding:2px 8px;border-radius:999px;background:var(--chip);white-space:nowrap}
.badge.pending{background:#dbeafe;color:#1e40af}.badge.used{background:var(--ok-bg);color:var(--ok)}
.badge.revoked,.badge.expired{background:var(--err-bg);color:var(--err)}
.muted{color:var(--muted)}.who{float:right;color:var(--muted);font-size:13px;margin-top:14px}
"""

LOCAL_TIME_JS = """<script>
document.querySelectorAll('time[data-ts]').forEach(t=>{const d=new Date(+t.dataset.ts*1000);
t.textContent=d.toLocaleString(undefined,{month:'short',day:'numeric',hour:'numeric',minute:'2-digit'});
t.title=d.toString();});
document.querySelectorAll('[data-copy]').forEach(b=>b.addEventListener('click',()=>{
const i=document.getElementById(b.dataset.copy);i.select();navigator.clipboard.writeText(i.value);
b.textContent='Copied';}));
</script>"""


def page(title, body, narrow=False):
    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><meta name="robots" content="noindex">
<title>{html.escape(title)}</title><style>{CSS}</style></head>
<body><main{' class="narrow"' if narrow else ''}>{body}</main>{LOCAL_TIME_JS}</body></html>"""


def ts(value):
    return f'<time data-ts="{int(value)}"></time>' if value else ""


def admin_page(user, groups, invites, flash="", flash_kind="ok", form=None, new_link=""):
    e = html.escape
    form = form or {}
    chosen = set(form.get("groups", []))
    msg = f'<div class="msg {flash_kind}">{flash}</div>' if flash else ""
    if new_link:
        msg += (f'<div class="msg ok">Invite link (also emailed). It is only shown once:'
                f'<div class="link"><input type="text" id="newlink" readonly value="{e(new_link)}">'
                f'<button type="button" class="small" data-copy="newlink">Copy</button></div></div>')
    group_boxes = "".join(
        f'<label><input type="checkbox" name="groups" value="{e(g["displayName"])}"'
        f'{" checked" if g["displayName"] in chosen else ""}>{e(g["displayName"])}</label>'
        for g in groups)
    expiry = int(form.get("expires_days", 7))
    expiry_opts = "".join(f'<option value="{d}"{" selected" if d == expiry else ""}>{d} day{"s" if d > 1 else ""}</option>'
                          for d in EXPIRY_CHOICES)
    rows = []
    for r in invites:
        state = invite_state(r)
        actions = ""
        if state in ("pending", "expired"):
            actions = (f'<form method="post" action="/admin/invites/{r["id"]}/resend">'
                       f'<button class="small" title="Issue a new link and email it">Resend</button></form> ')
        if state == "pending":
            actions += (f'<form method="post" action="/admin/invites/{r["id"]}/revoke" '
                        f'onsubmit="return confirm(\'Revoke this invite?\')">'
                        f'<button class="small">Revoke</button></form>')
        detail = (f'<br><span class="muted">→ {e(r["used_username"])} {ts(r["used_at"])}</span>'
                  if state == "used" else
                  f'<br><span class="muted">expires {ts(r["expires_at"])}</span>' if state == "pending" else "")
        rows.append(
            f'<tr><td>{e(r["email"])}<br><span class="muted">{e(r["display_name"])}</span></td>'
            f'<td>{e(", ".join(json.loads(r["groups"]))) or "<span class=muted>none</span>"}</td>'
            f'<td><span class="badge {state}">{state}</span>{detail}</td>'
            f'<td>{e(r["created_by"])}<br><span class="muted">{ts(r["created_at"])}</span></td>'
            f'<td class="actions">{actions}</td></tr>')
    table = ('<div class="table-wrap"><table><thead><tr><th>Invitee</th><th>Groups</th><th>Status</th>'
             '<th>Invited by</th><th></th></tr></thead><tbody>' + "".join(rows) + '</tbody></table></div>'
             if rows else '<p class="muted">No invites yet.</p>')
    body = f"""<span class="who">Signed in as {e(user)}</span><h1>Invite a user</h1>{msg}
<div class="card"><form method="post" action="/admin/invites">
<div class="row"><div><label>Email</label><input type="email" name="email" required value="{e(form.get('email', ''))}"></div>
<div><label>Name <span class="hint">(optional)</span></label><input type="text" name="display_name" value="{e(form.get('display_name', ''))}"></div></div>
<div class="row"><div><label>Suggested username <span class="hint">(they can change it)</span></label>
<input type="text" name="suggested_username" pattern="[a-z][a-z0-9._\\-]{{1,31}}" value="{e(form.get('suggested_username', ''))}"></div>
<div><label>Link expires after</label><select name="expires_days">{expiry_opts}</select></div></div>
<label>Groups</label><div class="groups">{group_boxes}</div>
<label>Personal note <span class="hint">(optional, included in the email)</span></label>
<textarea name="note">{e(form.get('note', ''))}</textarea>
<button>Send invite</button></form></div>
<div class="card"><h2>Invites</h2>{table}</div>"""
    return page(f"Invites · {SITE_NAME}", body)


def join_page(row, error="", form=None):
    e = html.escape
    form = form or {}
    username = form.get("username", row["suggested_username"])
    display = form.get("display_name", row["display_name"])
    err = f'<div class="msg err">{error}</div>' if error else ""
    body = f"""<h1>Create your {e(SITE_NAME)} account</h1>{err}<div class="card">
<form method="post" autocomplete="on">
<label>Email</label><input type="email" value="{e(row['email'])}" disabled>
<label>Username <span class="hint">lowercase letters, numbers, . _ -</span></label>
<input type="text" name="username" required autocomplete="username" autocapitalize="none" spellcheck="false"
 pattern="[a-z][a-z0-9._\\-]{{1,31}}" value="{e(username)}">
<label>Your name</label><input type="text" name="display_name" required autocomplete="name" value="{e(display)}">
<label>Password <span class="hint">at least {MIN_PASSWORD} characters</span></label>
<input type="password" name="password" required minlength="{MIN_PASSWORD}" autocomplete="new-password">
<label>Confirm password</label>
<input type="password" name="password2" required minlength="{MIN_PASSWORD}" autocomplete="new-password">
<button>Create account</button></form></div>"""
    return page(f"Join {SITE_NAME}", body, narrow=True)


def forbidden_page():
    """Body for Traefik's `errors` middleware: replaces 403 pages on other sites."""
    e = html.escape
    logout = f"{LOGIN_URL}/logout?rd={quote(LOGIN_URL + '/', safe='')}"
    body = (f'<h1>You don\'t have access to this page</h1><div class="card">'
            f'<p>Your account isn\'t allowed to use this part of {e(SITE_NAME)}. '
            'If you think it should be, ask the person who manages your account.</p>'
            f'<a class="btn" href="{e(HOME_URL)}">Go to {e(urlsplit(HOME_URL).netloc)}</a>'
            f'<p style="margin-top:18px"><a href="{e(logout)}">Sign in as someone else</a></p></div>')
    return page("Access denied", body, narrow=True)


def message_page(title, text, ok=True):
    body = (f'<h1>{html.escape(title)}</h1><div class="card"><div class="msg {"ok" if ok else "err"}">'
            f'{text}</div></div>')
    return page(title, body, narrow=True)


# ---------------------------------------------------------------- http

class Handler(BaseHTTPRequestHandler):
    server_version = "user-invites"

    def log_message(self, fmt, *args):
        log(f"{self.headers.get('X-Forwarded-For', self.client_address[0])} {fmt % args}")

    def send(self, status, body, ctype="text/html; charset=utf-8", headers=None):
        data = body.encode()
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("Referrer-Policy", "same-origin")
        self.send_header("Content-Security-Policy",
                         "default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; "
                         "form-action 'self'; frame-ancestors 'none'; base-uri 'none'")
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(data)

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
            if path in ("/", "/admin", "/admin/"):
                user = self.admin()
                if user:
                    self.show_admin(user)
                return
            if path.startswith("/join/"):
                return self.get_join(path[len("/join/"):])
            self.send(404, message_page("Not found", "There's nothing here.", ok=False))
        except Exception:
            self.fail()

    def do_POST(self):
        try:
            path = urlsplit(self.path).path
            if path == "/error/403":
                return self.send(200, forbidden_page())
            if not self.same_origin():
                return self.send(403, message_page("Not allowed", "Cross-site request blocked.", ok=False))
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
            self.send(404, message_page("Not found", "There's nothing here.", ok=False))
        except Exception:
            self.fail()

    def fail(self):
        log(traceback.format_exc())
        try:
            self.send(500, message_page("Something went wrong",
                                        "The error was logged. Please try again or contact the admin.", ok=False))
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
            kind = "err"
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
            flash, kind = f"Email failed ({html.escape(str(e))}). Send them the link below yourself.", "err"
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
        self.send(410 if row else 404, message_page("Invite not available", text, ok=False))

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
                error = f"The username <b>{html.escape(username)}</b> is taken. Try another."
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
            f"Your account <b>{html.escape(username)}</b> is ready.<br><br>"
            f'<a class="btn" href="{html.escape(SIGNIN_URL)}">Sign in</a><br><br>'
            "Some services ask you to set up two-factor authentication the first time you use them. "
            "When that happens, we'll email you a one-time code to confirm it's you."))


def main():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    init_db()
    log(f"listening on :{PORT} as {PUBLIC_URL}")
    ThreadingHTTPServer(("0.0.0.0", PORT), Handler).serve_forever()


if __name__ == "__main__":
    main()
