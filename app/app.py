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
# The bridgewater.digital style: a checkout of its repo (optional), the site's signature hue,
# the app's short name in the header's prompt line, and the family hub's apps list for the launcher.
STYLE_DIR = env("STYLE_DIR", "/style")
SIGNATURE = env("SIGNATURE", "teal")
APP_NAME = env("APP_NAME", "invites")
APPS_URL = env("APPS_URL", "")
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
    # Email clients ignore stylesheets, so the style's light-theme colors are inlined here.
    e = html.escape
    c = EMAIL_COLORS
    sans = "'Fira Sans','Segoe UI',system-ui,-apple-system,sans-serif"
    mono = "'Fira Code',ui-monospace,Menlo,Consolas,monospace"
    small = f"font-size:14px;line-height:22px;color:{c['comment']}"
    note_html = (f'<p style="margin:0 0 24px;padding:16px 24px;background:{c["panel"]};border-radius:4px">'
                 f'{e(note).replace(chr(10), "<br>")}</p>') if note else ""
    html_body = f"""<!doctype html><html><body style="margin:0;padding:0;background:{c['page']};font-family:{sans};font-size:16px;line-height:26px;color:{c['ink']}">
<div style="height:4px;background:{c['sig-fill']}"></div>
<div style="max-width:560px;margin:0 auto;padding:24px 16px 48px">
<p style="margin:0 0 16px;font-weight:600;font-size:18px">{e(SITE_NAME)}</p>
<div style="height:2px;background:{c['ink']};margin:0 0 32px"></div>
<h1 style="font-size:24px;line-height:30px;font-weight:600;margin:0 0 16px">You're invited to {e(SITE_NAME)}</h1>
<p style="margin:0 0 16px">{e(greeting)}</p>
<p style="margin:0 0 24px">{e(inviter_name)} has invited you to create an account.</p>
{note_html}
<p style="margin:0 0 32px"><a href="{e(link)}" style="background:{c['sig-fill']};color:{c['on-sig']};text-decoration:none;padding:8px 16px;border-radius:2px;font-weight:500;font-size:14px;line-height:20px;display:inline-block">Create your account</a></p>
<p style="margin:0 0 16px;{small}">This link works once and expires in {days} day{'s' if days != 1 else ''}. After that, sign in at <a href="{e(SIGNIN_URL)}" style="color:{c['sig-fill']}">{e(urlsplit(HOME_URL).netloc)}</a>.</p>
<p style="margin:0 0 16px;{small}">If the button doesn't work, paste this into your browser:<br><span style="font-family:{mono};font-size:13px;word-break:break-all;color:{c['ink']}">{e(link)}</span></p>
<p style="margin:24px 0 0;padding-top:16px;border-top:1px solid {c['line']};{small}">If you weren't expecting this, you can ignore this email.</p>
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
# Pages use the bridgewater.digital style when a release of it is mounted at STYLE_DIR
# (a checkout of the style repo): its bridgewater.css, bundle.js, fonts and favicon are
# served under /static/brand/, the header is its Header component, and emails take their
# colors from its tokens.json. Without it, pages fall back to plain styling.
# Asset URLs are absolute (PUBLIC_URL) because Traefik also serves the 403 page on other sites.

BRAND_TYPES = {".css": "text/css; charset=utf-8", ".js": "text/javascript; charset=utf-8",
               ".woff2": "font/woff2", ".svg": "image/svg+xml"}


def load_style():
    comp = os.path.join(STYLE_DIR, "components")
    css = os.path.join(comp, "bridgewater.css")
    if not os.path.isfile(css):
        log(f"no style at {STYLE_DIR}; using plain styling")
        return None
    files = {"bridgewater.css": css, "bundle.js": os.path.join(comp, "bundle.js")}
    fonts = os.path.join(comp, "fonts")
    for name in sorted(os.listdir(fonts)) if os.path.isdir(fonts) else []:
        if name.endswith(".woff2"):
            files[f"fonts/{name}"] = os.path.join(fonts, name)
    favicon = os.path.join(STYLE_DIR, "assets", "Favicons",
                           "favicon.svg" if SIGNATURE == "teal" else f"favicon-{SIGNATURE}.svg")
    if os.path.isfile(favicon):
        files["favicon.svg"] = favicon
    digest = hashlib.sha256()
    for path in files.values():
        with open(path, "rb") as f:
            digest.update(f.read())
    try:
        with open(os.path.join(STYLE_DIR, "tokens.json")) as f:
            tokens = json.load(f)
    except (OSError, ValueError):
        tokens = None
    log(f"style from {STYLE_DIR}: {len(files)} files")
    return {"files": files, "v": digest.hexdigest()[:12], "tokens": tokens}


STYLE = load_style()
BRAND = f"{PUBLIC_URL}/static/brand"


def light_colors():
    """The style's light-theme colors with the site's signature resolved, for emails."""
    colors = {"page": "#ffffff", "panel": "#f3f4f6", "line": "#e5e7eb", "ink": "#1f2328",
              "comment": "#57606a", "sig-fill": "#1f2328", "on-sig": "#ffffff"}
    tokens = (STYLE or {}).get("tokens")
    if not tokens:
        return colors
    raw = {t["name"]: t["value"] for t in tokens["color"]["tokens"]}
    for s in tokens["color"].get("signatures", []):
        if s["id"] == SIGNATURE:
            raw.update(s["tokens"])

    def resolve(v, depth=0):
        if isinstance(v, dict):
            v = v.get("light")
        m = re.fullmatch(r"\{(.+)\}", v or "")
        return resolve(raw.get(m[1]), depth + 1) if m and depth < 5 else v

    for name in colors:
        colors[name] = resolve(raw.get(name)) or colors[name]
    return colors


EMAIL_COLORS = light_colors()

FALLBACK_CSS = """
body{margin:0;font:16px/1.6 system-ui,sans-serif;color:#1f2328;background:#fff}
main{max-width:960px;margin:0 auto;padding:24px 16px 64px}
.bw-field{margin:0 0 16px}.bw-field__label{display:block;font-weight:600;margin-bottom:4px}
.bw-field__control{width:100%;padding:8px;font:inherit;box-sizing:border-box}
.bw-field__hint,.bw-pagehead__meta,.sub{color:#57606a;font-size:14px}
.bw-panel{padding:12px 16px;margin:0 0 16px;background:#f3f4f6}
table{width:100%;border-collapse:collapse}th,td{text-align:left;padding:8px 8px 8px 0;border-bottom:1px solid #e5e7eb}
.bw-btn{font:inherit;padding:8px 14px;cursor:pointer}.bw-focus{max-width:440px;margin:0 auto}
"""

APP_CSS = """
.checks{display:flex;flex-wrap:wrap;gap:var(--space-2) var(--space-5)}
fieldset{border:0;margin:0;padding:0;min-width:0}
legend{padding:0;margin-bottom:var(--space-2)}
.bw-form>fieldset,.bw-form>.bw-field+fieldset,.bw-form>fieldset+.bw-field{margin-top:var(--space-5)}
.bw-panel{margin-bottom:var(--space-6)}
.bw-panel p+p,.bw-panel p+.link-row{margin-top:var(--space-3)}
.link-row{display:flex;gap:var(--space-2);align-items:center}
.link-row .bw-field__control{min-width:0}
.table-wrap{overflow-x:auto}
.sub{display:block;font:var(--type-small);color:var(--comment)}
td.actions{white-space:nowrap;text-align:right;padding-right:0}
td.actions form{display:inline}
"""

PAGE_JS = """
document.querySelectorAll('time[data-ts]').forEach(t=>{const d=new Date(+t.dataset.ts*1000);
t.textContent=d.toLocaleString(undefined,{month:'short',day:'numeric',hour:'numeric',minute:'2-digit'});
t.title=d.toString();});
document.querySelectorAll('[data-copy]').forEach(b=>b.addEventListener('click',()=>{
const i=document.getElementById(b.dataset.copy);i.select();navigator.clipboard.writeText(i.value);
b.textContent='Copied';}));
document.querySelectorAll('form[data-confirm]').forEach(f=>f.addEventListener('submit',async ev=>{
if(f.dataset.confirmed)return;ev.preventDefault();const d=f.dataset;let ok;
if(window.Bridgewater){const m=document.createElement('span'),c=document.createElement('span');
c.className='bw-mono';c.textContent=d.subject;m.append(d.before,c,d.after);
ok=await Bridgewater.confirm({title:d.title,message:m,confirm:d.confirm});}
else ok=window.confirm(d.title);
if(ok){f.dataset.confirmed='1';f.submit();}}));
"""


def header_config(user, path, account=None):
    """Props for the style's Header component."""
    cfg = {"user": user, "userHref": HOME_URL, "home": HOME_URL,
           "app": {"label": APP_NAME, "href": PUBLIC_URL + "/"},
           "path": [{"label": "~", "href": PUBLIC_URL + "/"}] + list(path),
           "apps": APPS_URL or False}
    if account:
        cfg["account"] = account
    elif user in ("you", "nobody"):
        cfg["signIn"] = SIGNIN_URL
    return cfg


def page(title, body, header):
    e = html.escape
    if STYLE:
        v = STYLE["v"]
        head = (f'<link rel="icon" type="image/svg+xml" href="{BRAND}/favicon.svg?v={v}">'
                f'<link rel="stylesheet" href="{BRAND}/bridgewater.css?v={v}"><style>{APP_CSS}</style>'
                f'<script src="{BRAND}/bundle.js?v={v}"></script>'
                f'<script>Bridgewater.init({{sig:{json.dumps(SIGNATURE)}}})</script>')
    else:
        head = f"<style>{FALLBACK_CSS}</style>"
    # Embedded as JSON inside a script element, so "<" is escaped to keep "</script>" out of it.
    cfg = json.dumps(header).replace("<", "\\u003c")
    mount = (f"if(window.Bridgewater)document.body.prepend(Bridgewater.Header({cfg}));" if STYLE else "")
    footer = (f'<footer class="bw-footer"><div class="bw-container"><span>{e(PUBLIC_HOST)}</span>'
              f'<a href="{e(HOME_URL)}">{e(urlsplit(HOME_URL).netloc)}</a></div></footer>')
    return f"""<!doctype html><html lang="en" data-sig="{e(SIGNATURE)}"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><meta name="robots" content="noindex">
<title>{e(title)}</title>{head}</head>
<body class="bw-page"><main class="bw-main bw-container">{body}</main>{footer}<script>{mount}{PAGE_JS}</script></body></html>"""


def panel(role, body):
    """The one panel on a view. Role is a style role: green ok, red wrong, orange failed, amber attention."""
    return f'<section class="bw-panel" data-role="{role}">{body}</section>'


def field(fid, label, control, hint=""):
    """A style Field. `control` is the input markup; it gets id=fid and the hint wired to it."""
    described = f' aria-describedby="{fid}-hint"' if hint else ""
    control = re.sub(r"^<(input|select|textarea)", rf'<\1 id="{fid}"{described}', control)
    hint_html = f'<div class="bw-field__hint" id="{fid}-hint">{hint}</div>' if hint else ""
    return (f'<div class="bw-field"><label class="bw-field__label" for="{fid}">{label}</label>'
            f'{control}{hint_html}</div>')


def section(num, title, body, aside=""):
    return (f'<section class="bw-section"><div class="bw-section__head"><h2><span class="bw-secnum">{num}</span>'
            f'{title}</h2>{aside}</div>{body}</section>')


def focus(title, lede, body="", actions=""):
    """The style's focus layout: one task in a narrow column, actions stacked full width."""
    lede_html = f'<p class="bw-focus__lede">{lede}</p>' if lede else ""
    actions_html = f'<div class="bw-focus__actions">{actions}</div>' if actions else ""
    return f'<div class="bw-focus"><h1>{html.escape(title)}</h1>{lede_html}{body}{actions_html}</div>'


def ts(value):
    return f'<time data-ts="{int(value)}"></time>' if value else ""


# Invite state -> style Status state.
STATUS = {"pending": "attention", "used": "ok", "expired": "off", "revoked": "off"}
FLASH_ROLES = {"ok": "green", "err": "red", "fail": "orange"}


def admin_page(admin, groups, invites, flash="", flash_kind="ok", form=None, new_link=""):
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
    pending = 0
    for r in invites:
        state = invite_state(r)
        pending += state == "pending"
        actions = ""
        if state in ("pending", "expired"):
            actions = (f'<form method="post" action="/admin/invites/{r["id"]}/resend">'
                       f'<button class="bw-btn bw-btn--secondary bw-btn--sm" title="Issue a new link and email it">'
                       f'Resend</button></form> ')
        if state == "pending":
            actions += (f'<form method="post" action="/admin/invites/{r["id"]}/revoke" data-confirm="Revoke invite" '
                        f'data-title="Revoke invite?" data-before="The link sent to " data-subject="{e(r["email"])}" '
                        f'data-after=" stops working. This cannot be undone.">'
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
             '<th>Invited by</th><th></th></tr></thead><tbody>' + "".join(rows) + '</tbody></table></div>'
             if rows else '<p class="bw-comment">No invites yet.</p>')
    new_form = f"""<form class="bw-form" method="post" action="/admin/invites">
{field("f-email", "Email", f'<input class="bw-field__control" type="email" name="email" required autocomplete="off" value="{e(form.get("email", ""))}">')}
{field("f-name", "Name", f'<input class="bw-field__control" type="text" name="display_name" value="{e(form.get("display_name", ""))}">', "Optional.")}
{field("f-user", "Suggested username", f'<input class="bw-field__control bw-field__control--mono" type="text" name="suggested_username" autocapitalize="none" spellcheck="false" pattern="{USERNAME_PATTERN}" value="{e(form.get("suggested_username", ""))}">', "Optional. They can change it.")}
{field("f-exp", "Link expires after", f'<select class="bw-field__control" name="expires_days">{expiry_opts}</select>')}
<fieldset><legend class="bw-field__label">Groups</legend><div class="checks">{group_boxes or '<span class="bw-comment">No groups in lldap.</span>'}</div></fieldset>
{field("f-note", "Personal note", f'<textarea class="bw-field__control" name="note" rows="3">{e(form.get("note", ""))}</textarea>', "Optional. Included in the email.")}
<div class="bw-form__actions"><button class="bw-btn bw-btn--primary">Send invite</button></div></form>"""
    count = f"{len(invites)} invite{'s' if len(invites) != 1 else ''}"
    body = (f'<div class="bw-pagehead"><div class="bw-pagehead__text"><h1>Invites</h1>'
            f'<p class="bw-pagehead__meta"><span class="bw-mono">{count}</span> · {pending} pending</p></div></div>'
            f'{msg}{section("01", "New invite", new_form)}'
            f'{section("02", "Sent", table, f"<span class=bw-count>{len(invites)}</span>")}')
    return page(f"Invites · {SITE_NAME}", body, header_config(admin["user"], ["invites"], admin["account"]))


def join_page(row, error="", form=None):
    e = html.escape
    form = form or {}
    username = form.get("username", row["suggested_username"])
    display = form.get("display_name", row["display_name"])
    err = panel("red", f"<p>{error}</p>") if error else ""
    body = f"""<div class="bw-focus"><h1>Create your account</h1>
<p class="bw-focus__lede">You've been invited to {e(SITE_NAME)}. Choose a username and password to finish.</p>{err}
<form method="post" autocomplete="on">
{field("j-email", "Email", f'<input class="bw-field__control bw-field__control--mono" type="email" value="{e(row["email"])}" disabled>')}
{field("j-user", "Username", f'<input class="bw-field__control bw-field__control--mono" type="text" name="username" required autocomplete="username" autocapitalize="none" spellcheck="false" pattern="{USERNAME_PATTERN}" value="{e(username)}">', "Lowercase letters, numbers, <code>.</code> <code>_</code> <code>-</code>. Starts with a letter.")}
{field("j-name", "Your name", f'<input class="bw-field__control" type="text" name="display_name" required autocomplete="name" value="{e(display)}">')}
{field("j-pass", "Password", f'<input class="bw-field__control" type="password" name="password" required minlength="{MIN_PASSWORD}" autocomplete="new-password">', f"At least {MIN_PASSWORD} characters.")}
{field("j-pass2", "Confirm password", f'<input class="bw-field__control" type="password" name="password2" required minlength="{MIN_PASSWORD}" autocomplete="new-password">')}
<div class="bw-focus__actions"><button class="bw-btn bw-btn--primary">Create account</button></div></form></div>"""
    return page(f"Join {SITE_NAME}", body, header_config("you", ["join"]))


def forbidden_page():
    """Body for Traefik's `errors` middleware: replaces 403 pages on other sites."""
    e = html.escape
    logout = f"{LOGIN_URL}/logout?rd={quote(LOGIN_URL + '/', safe='')}"
    body = focus("You don't have access to this page",
                 f"Your account isn't allowed to use this part of {e(SITE_NAME)}. "
                 "If you think it should be, ask the person who manages your account.",
                 actions=(f'<a class="bw-btn bw-btn--primary" href="{e(HOME_URL)}">Go to {e(urlsplit(HOME_URL).netloc)}</a>'
                          f'<a class="bw-btn bw-btn--secondary" href="{e(logout)}">Sign in as someone else</a>'))
    # Traefik doesn't pass the session to the error page, so who is signed in is unknown here.
    return page("Access denied", body, header_config("nobody", ["403"]))


def message_page(title, text, role="green", path=(), actions=""):
    return page(title, focus(title, "", panel(role, f"<p>{text}</p>"), actions), header_config("you", path))


# ---------------------------------------------------------------- http

class Handler(BaseHTTPRequestHandler):
    server_version = "user-invites"

    def log_message(self, fmt, *args):
        log(f"{self.headers.get('X-Forwarded-For', self.client_address[0])} {fmt % args}")

    def send(self, status, body, ctype="text/html; charset=utf-8", headers=None):
        data = body if isinstance(body, bytes) else body.encode()
        # Brand assets are named by our own origin because the 403 page is also served on other sites.
        apps = f" connect-src {urlsplit(APPS_URL).scheme}://{urlsplit(APPS_URL).netloc};" if APPS_URL else ""
        all_headers = {
            "Content-Type": ctype,
            "Content-Length": str(len(data)),
            "Cache-Control": "no-store",
            "Referrer-Policy": "same-origin",
            "Content-Security-Policy":
                f"default-src 'none'; style-src 'unsafe-inline' {PUBLIC_ORIGIN}; "
                f"script-src 'unsafe-inline' {PUBLIC_ORIGIN}; font-src {PUBLIC_ORIGIN}; "
                f"img-src {PUBLIC_ORIGIN} https: data:;{apps} form-action 'self'; frame-ancestors 'none'; base-uri 'none'",
            **(headers or {}),
        }
        self.send_response(status)
        for k, v in all_headers.items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(data)

    def send_brand(self, name):
        path = (STYLE or {}).get("files", {}).get(name)
        if not path:
            return self.send(404, "not found", "text/plain")
        with open(path, "rb") as f:
            data = f.read()
        # Versioned URLs (?v=) can be cached for good; fonts are referenced from the CSS without one.
        cache = "public, max-age=31536000, immutable" if "v=" in urlsplit(self.path).query else "public, max-age=86400"
        # Fetched cross-origin when the 403 page is shown on another site.
        self.send(200, data, BRAND_TYPES[os.path.splitext(name)[1]],
                  {"Cache-Control": cache, "Access-Control-Allow-Origin": "*"})

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
            if path.startswith("/static/brand/"):
                return self.send_brand(path[len("/static/brand/"):])
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
        self.send(200, admin_page({"user": user, "account": self.account(user)}, list_groups(), invites, **kw))

    def account(self, user):
        """The header's account menu, from the headers Authelia's forward-auth sets."""
        name = self.headers.get("Remote-Name") or user
        return {"label": name.split()[0], "name": name, "detail": self.headers.get("Remote-Email") or user,
                "items": [{"label": "Account settings", "href": f"{LOGIN_URL}/settings"},
                          {"label": "Sign out", "href": f"{LOGIN_URL}/logout"}]}

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
            "When that happens, we'll email you a one-time code to confirm it's you.",
            path=["join"], actions=f'<a class="bw-btn bw-btn--primary" href="{html.escape(SIGNIN_URL)}">Sign in</a>'))


def main():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    init_db()
    log(f"listening on :{PORT} as {PUBLIC_URL}")
    ThreadingHTTPServer(("0.0.0.0", PORT), Handler).serve_forever()


if __name__ == "__main__":
    main()
