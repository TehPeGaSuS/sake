# sake

sake is a personal IRC bouncer, forked from [soju](https://codeberg.org/emersion/soju) by emersion.

It inherits soju's excellent IRCv3 support, multi-client handling and chat history playback, while adding quality-of-life features inspired by ZNC: per-network source IP binding, CERTFP import, self-signed certificate acceptance, and relaxed network uniqueness constraints to allow bouncer chaining.

## Differences from soju

- Per-network source IP binding (like ZNC's bindhost)
- `certfp import [-network name | -default] <path-or-https-url>` — bring your own
  client certificate (PEM, concatenated cert+key) instead of generating one,
  either for a specific network or as your account-wide default
- Per-account default SASL EXTERNAL certificate (`certfp generate -default` /
  `certfp import -default`) — used by any network that enables SASL EXTERNAL
  without its own certificate, so you don't need to set one up per network
- Self-signed certificate acceptance per network
- Removed `UNIQUE(user, addr, nick)` constraint — allows connecting to the same address with the same nick under different network names (bouncer chaining)
- Self-service web admin panel (see below), in the spirit of ZNC's webadmin module

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
- `/admin/networks/new`, `/admin/networks/{id}` — add/edit/delete a network,
  including SASL PLAIN/EXTERNAL setup and pasting a client certificate
  (concatenated PEM, like ZNC's `user.pem`) or a server TLS pinning fingerprint
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

## Building and installing

Dependencies: Go, BSD or GNU make, a C89 compiler (optional, for SQLite), scdoc (optional, for man pages).

```
make
sudo make install
```

For development: `go run ./cmd/sake`

## License

AGPLv3, see LICENSE.

Forked from [soju](https://codeberg.org/emersion/soju) — Copyright (C) 2020 The soju Contributors
