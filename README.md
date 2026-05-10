# sake

sake is a personal IRC bouncer, forked from [soju](https://codeberg.org/emersion/soju) by emersion.

It inherits soju's excellent IRCv3 support, multi-client handling and chat history playback, while adding quality-of-life features inspired by ZNC: per-network source IP binding, CERTFP import, self-signed certificate acceptance, and relaxed network uniqueness constraints to allow bouncer chaining.

## Differences from soju

- Per-network source IP binding (like ZNC's bindhost)
- `certfp import` — bring your own client certificate instead of generating one
- Self-signed certificate acceptance per network
- Removed `UNIQUE(user, addr, nick)` constraint — allows connecting to the same address with the same nick under different network names (bouncer chaining)

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
