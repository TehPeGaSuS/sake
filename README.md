# sake

sake is a personal IRC bouncer, forked from [soju](https://codeberg.org/emersion/soju) by emersion.

It inherits soju's IRCv3 support (multi-client handling, chat history playback,
CHATHISTORY, message tags, and the rest of the extensions soju already
implements), while adding quality-of-life features inspired by ZNC: per-account/
per-network source IP binding, `certfp import`/account-wide default
certificates, self-signed certificate acceptance, relaxed network uniqueness
constraints for bouncer chaining, and a self-service web admin panel.

## Table of contents

- [Differences from soju](#differences-from-soju)
- [Quickstart](#quickstart)
- [Connecting a client](#connecting-a-client)
- [Web admin panel](#web-admin-panel)
- [IRC service (BouncerServ)](#irc-service-bouncerserv)
- [Building and installing](#building-and-installing)
- [Documentation](#documentation)
- [License](#license)

## Differences from soju

- **Per-account/per-network source IP binding** (like ZNC's bindhost) — set a
  default bind address for a user's upstream connections, overridable per
  network. Admin-only, to prevent IP abuse on shared/hosted instances.
- **`certfp import [-network name | -default] <path-or-https-url>`** — bring
  your own client certificate (PEM, concatenated cert+key, the same one-file
  format as ZNC's `user.pem`) instead of always generating a fresh one.
- **Per-account default SASL EXTERNAL certificate** (`certfp generate
  -default` / `certfp import -default` / `sasl set-external`) — set once, then
  any network that enables SASL EXTERNAL without its own certificate falls
  back to it automatically.
- **`-tls-insecure`** per network — skip TLS certificate verification
  entirely, for self-signed servers where pinning a fingerprint via `-certfp`
  isn't practical.
- Removed the `UNIQUE(user, addr, nick)` constraint — allows connecting to the
  same address with the same nick under different network names (bouncer
  chaining).
- **Self-service web admin panel** (see below), in the spirit of ZNC's
  webadmin module — a web UI for account/network/channel management that
  soju itself only exposes through the `BouncerServ` IRC service, including
  channel detach/reattach/relay behavior and per-network connect commands.

## Quickstart

```
make
sudo make install
```

This installs the `sake`, `sakectl` and `sakedb` binaries, man pages, and a
default config at `/etc/sake/config` (see [`config.in`](config.in) for the
template). For local development, skip `make install` and just run:

```
go run ./cmd/sake -config /path/to/sake.conf
```

A minimal config to get started:

```
db sqlite3 /var/lib/sake/main.db
listen ircs://
listen unix+admin:///run/sake/admin
listen http+insecure://localhost:8080
```

- `listen ircs://` — TLS IRC listener for your clients (needs a `tls <cert>
  <key>` directive, or terminate TLS at a reverse proxy and use
  `listen irc://localhost` instead).
- `listen unix+admin://...` — required for `sakectl` and `sakedb`.
- `listen http+insecure://localhost:8080` — enables the [web admin
  panel](#web-admin-panel) at `/admin/`. Only bind this to `localhost` unless
  you're terminating TLS in front of it.

Create your first (admin) user:

```
sakectl user create -username <username> -admin -password <password>
```

Then start sake (directly, via `systemd` with
[`contrib/sake.service`](contrib/sake.service), or your supervisor of choice)
and reload the config later with `SIGHUP`.

If you're migrating from ZNC, `contrib/znc-import` can import users, networks
and channels from a ZNC config file.

## Connecting a client

To connect to the bouncer, use the bouncer username and password.

- If your client supports the `soju.im/bouncer-networks` IRC extension, just
  connect with your username/password — networks show up automatically.
- Otherwise, set up one connection per network in your client, with the
  network name in the username: `<username>/<network>`. If the network
  doesn't exist yet and the name looks like a hostname, it's created
  automatically on first connect.
- To connect from multiple clients at once with correct per-client history,
  append a client name: `<username>/<network>@<client>`.
- Part a channel with the reason `detach` to detach it (stay joined, hide it)
  instead of actually leaving.

See [`doc/getting-started.md`](doc/getting-started.md) for more detail, and
`/msg BouncerServ help` or [`sake(1)`](doc/sake.1.scd) for the full command
reference.

## Web admin panel

sake ships a self-service web admin panel, mounted at `/admin/` on any
`http://`/`https://` listener already configured via `listen`. Every user can
manage their own account and networks; users with the `Admin` flag can
additionally manage any other user's account and networks.

```
listen http+insecure://localhost:8080
```

Then browse to `http://localhost:8080/admin/login` and sign in with any
existing user's credentials (create one with `sakectl user create` first).

Pages:
- `/admin/` — dashboard listing your networks
- `/admin/networks/new`, `/admin/networks/{id}` — add/edit/delete a network:
  address, nick/username/realname, server password, SASL PLAIN or EXTERNAL
  (paste a client certificate as a concatenated PEM, like ZNC's `user.pem`, or
  rely on your account's default certificate), a server TLS pinning
  fingerprint, source IP and TLS-insecure (admin-only), and connect commands
  (raw lines sent right after connecting, e.g. to identify with NickServ)
- `/admin/networks/{id}/channels/{id}` — add/edit/delete a channel: join key,
  detached state, and the relay-while-detached / reattach-on / auto-detach-on
  message filters plus auto-detach-after timeout
- `/admin/account` — change your own nick, realname, password, and your
  account-wide default SASL EXTERNAL certificate
- `/admin/users` — **admin-only**: list, create, edit and delete any user

Security notes:
- Sessions are signed, HttpOnly cookies. The signing key is generated on
  first run and persisted at `webadmin-secret` next to your config file
  (`0600` permissions) so restarts don't invalidate open sessions.
- All state-changing requests are protected by a CSRF token derived from
  the session cookie.
- Login attempts are rate-limited per source IP + username (5 failures per
  5 minutes triggers a 1 minute lockout).
- Password checks go through the same configured `auth` driver as SASL
  PLAIN (internal, PAM, HTTP, OAuth2), so policy stays consistent.

## IRC service (BouncerServ)

Everything the web admin panel can do (and more — device certificates, raw
network commands, server-wide broadcasts for admins) is also available as IRC
commands via the `BouncerServ` service: `/msg BouncerServ help`, or run
commands remotely with `sakectl` (requires a `listen unix+admin://` directive).
See [`sake(1)`](doc/sake.1.scd) for the full reference, including the
sake-specific additions (`-source-ip`, `-tls-insecure`, `certfp import`,
`certfp generate/import -default`, `sasl set-external`).

## Building and installing

Dependencies: Go, BSD or GNU make, a C89 compiler (optional, for SQLite),
scdoc (optional, for man pages).

```
make
sudo make install
```

For development: `go run ./cmd/sake`. Tests: `go test ./...`.

## Documentation

- [`doc/sake.1.scd`](doc/sake.1.scd) — full CLI/config/IRC-service reference
  (renders to the `sake(1)` man page via `scdoc`)
- [`doc/sakectl.1.scd`](doc/sakectl.1.scd) — `sakectl(1)` man page
- [`doc/getting-started.md`](doc/getting-started.md) — server and client setup
  walkthrough
- [`doc/architecture.md`](doc/architecture.md), [`doc/dev-setup.md`](doc/dev-setup.md) — internals, for contributors
- [`doc/per-user-ip.md`](doc/per-user-ip.md) — more on source IP binding
- [`doc/file-upload.md`](doc/file-upload.md) — IRCv3 file upload support
- [`contrib/`](contrib/) — reverse proxy configs (Caddy, Nginx, tlstunnel,
  OpenBSD relayd, Certbot), migration tools, and the systemd unit
  ([`contrib/sake.service`](contrib/sake.service))

## License

AGPLv3, see LICENSE.

Forked from [soju](https://codeberg.org/emersion/soju) — Copyright (C) 2020 The soju Contributors
