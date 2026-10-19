# user-invites

Invitation links for an [lldap](https://github.com/lldap/lldap) + [Authelia](https://www.authelia.com) setup.

Neither lldap nor Authelia can invite people: an admin has to create the account and hand over a password.
This small service adds that missing step:

1. An admin opens `/admin` (protected by Authelia), enters an email address, picks the lldap groups and
   optionally a name, suggested username, expiry and personal note.
2. The invitee gets an email with a one-time link (the link is also shown to the admin so it can be texted).
3. They open `/join/<token>`, choose a username and password, and the account is created in lldap with
   those groups. They are then sent to the Authelia portal, which redirects them to `HOME_URL` after login.
4. The admin who sent the invite gets an email when it's accepted.

Invites can be revoked or resent (resending issues a new link and invalidates the old one).
Tokens are random, single-use and only their SHA-256 is stored.

It's one Python file using the standard library plus [`ldap3`](https://pypi.org/project/ldap3/)
(lldap only accepts new passwords over the LDAP password-modify operation, not GraphQL).

## Requirements

- **An lldap service account in `lldap_admin`.** Creating users needs admin rights in lldap;
  `lldap_password_manager` isn't enough. Use a dedicated account (e.g. `invite-svc`).
- **An lldap group for people allowed to send invites** (default `invite-users`).
- **SMTP credentials** for sending invites.
- **Traefik (or another proxy) with Authelia forward-auth** that passes `Remote-User`, `Remote-Groups`,
  `Remote-Name` and `Remote-Email`. Don't publish the container's port: the app trusts those headers.

### Authelia access control

`/join/` (and the web fonts it loads) must be reachable without logging in; everything else is admin-only:

```yaml
access_control:
  rules:
    - domain: "invite.example.com"
      resources: ["^/join/.*$", "^/static/fonts/.*$"]
      policy: "bypass"
    - domain: "invite.example.com"
      subject: "group:invite-users"
      policy: "two_factor"
    - domain: "invite.example.com"
      policy: "deny"
```

Put these before any wildcard catch-all rule. The app also checks `Remote-Groups` for `ADMIN_GROUP` itself.

## Configuration

| Variable | Required | Default | Notes |
|---|---|---|---|
| `PUBLIC_URL` | yes | | Public base URL of this service, used in links and the CSRF origin check |
| `LOGIN_URL` | yes | | Authelia portal URL |
| `HOME_URL` | no | `LOGIN_URL/` | Where users land after signing in (passed to Authelia as `rd`) |
| `SITE_NAME` | no | host of `PUBLIC_URL` | Shown in pages and emails |
| `ADMIN_GROUP` | no | `invite-users` | lldap group allowed to use `/admin` |
| `LLDAP_URL` | no | `http://lldap:17170` | lldap HTTP (GraphQL) URL |
| `LLDAP_LDAP_URL` | no | `ldap://lldap:3890` | lldap LDAP URL |
| `LLDAP_BASE_DN` | yes | | e.g. `dc=example,dc=com` |
| `LLDAP_USER` | yes | | Service account in `lldap_admin` |
| `LLDAP_PASSWORD` | yes | | |
| `SMTP_HOST` | yes | | |
| `SMTP_PORT` | no | `587` | 587 = STARTTLS, 465 = implicit TLS |
| `SMTP_USER` / `SMTP_PASSWORD` | yes | | |
| `SMTP_FROM` | yes | | e.g. `example.com <accounts@example.com>` |
| `SIGNATURE` | no | `teal` | Signature hue: `teal`, `green`, `purple`, `amber`, `orange` or `pink` |
| `PROMPT_HOST` | no | `eopsin` | Host shown in the header's `user@host:~/path` line |
| `DB_PATH` | no | `/data/invites.db` | SQLite file holding invites |
| `PORT_HTTP` | no | `8080` | |

Empty values count as unset. Keep the secrets (`LLDAP_PASSWORD`, `SMTP_USER`, `SMTP_PASSWORD`, `SMTP_FROM`) in
`user-invites.env` next to `compose.yaml`; it's gitignored and loaded if present.

## Running

`compose.yaml` builds the image from this repo and reads its settings from variables. Copy `.env.example`
to `.env`, fill it in, put the secrets in `user-invites.env`, then:

```sh
docker compose up -d --build
```

The compose file sets `PUBLIC_URL` from `INVITE_HOST`, joins the external `proxy` network and adds Traefik
labels; `TRAEFIK_MIDDLEWARES` must include your Authelia forward-auth middleware. It also works as a git-backed
stack in tools like Dockhand or Portainer: set the variables in the stack and drop `user-invites.env` into the
stack folder.

Or without building an image, on the stock `python:3.13-alpine` image with `ldap3` vendored next to the app:

```sh
docker run --rm -v "$PWD/app:/out" python:3.13-alpine pip install --target /out/vendor -r /dev/stdin < requirements.txt
```

then mount `./app` at `/app` and run `python -u /app/app.py`.

## Look

Pages and emails follow the bridgewater.digital design system: Fira Sans and Fira Code, the signature strip,
wordmark and `user@host:~/path` prompt line, hairline-separated layout, and light and dark themes (system
preference by default, with a toggle that remembers your choice).

- `app/static/bridgewater.css` holds the design-system tokens and component styles. It's generated; to
  update it, export `tokens.json` and `components/bundle.css` from the design system and run
  `python scripts/build_brand_css.py tokens.json bundle.css app/static/bridgewater.css`.
- CSS is inlined into every page so the 403 page also works when Traefik serves it on other sites.
  Fonts are self-hosted under `app/static/fonts` (SIL Open Font License, see the `LICENSE-*.txt` files there)
  and loaded from `PUBLIC_URL`. If they can't load, pages fall back to system fonts.

## Notes

- Usernames: 2–32 characters, lowercase letters, digits, `.`, `_`, `-`, starting with a letter.
- Passwords: at least 10 characters, not equal to the username or email.
- Groups whose names start with `lldap_` are never offered.
- If setting the password fails after the user was created, the user is deleted again.
