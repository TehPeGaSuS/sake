# Getting started

## Server side

Build sake from source (see the [README]) — there's no distribution package or
container image for this fork yet.

sake's configuration file (located at `/etc/sake/config` by default, see
[`config.in`](../config.in)) needs to be adjusted to enable TLS. This can be
done in several ways:

- By setting up a reverse proxy which takes care of terminating TLS
  connections, and configuring sake to listen on local unencrypted connections
  on port 6667:

      listen irc://localhost

- By specifying the path to the TLS certificate in the sake configuration file:

      tls <cert> <key>

  The certificate must be readable by sake, and sake needs to be reloaded when
  the certificate is renewed.

Some [user-contributed guides] are available for popular reverse proxies and
TLS certificate tools (written for soju, but equally applicable to sake).

Next, create an initial user:

    sakedb create-user <username> -admin

(or, if sake is already running with a `listen unix+admin://` directive:
`sakectl user create -username <username> -admin -password <password>`)

Once TLS is set up and an initial user has been created, sake can be started
(e.g. via systemd with [`contrib/sake.service`](../contrib/sake.service), or
another supervisor daemon).

If you're migrating from ZNC, a tool is available to import users, networks and
channels from a ZNC config file:

    go run ./contrib/znc-import <znc config file>

## Client side

### Client supporting `soju.im/bouncer-networks`

If you are using a client supporting the `soju.im/bouncer-networks` IRC
extension (see the [client list]), then you can just connect to sake with your
username and password.

If your client doesn't provide a UI to manage IRC networks, you can talk to
`BouncerServ`. See the [man page] or use `/msg BouncerServ help`. You can also
use the [web admin panel](../README.md#web-admin-panel).

### Other clients

You will need to setup one separate server in your client for each server you
want sake to connect to.

The easiest way to get started is to specify the IRC server address directly in
the username in the client configuration. For example to connect to Libera Chat,
your username will be: `<username>/irc.libera.chat`. Also set your sake
password in the password field of your client configuration.

This will autoconfigure sake by adding a network with the address
`irc.libera.chat` and then autoconnect to it. You will now be able to join
any channel like you would normally do.

For more advanced configuration options, you can talk to `BouncerServ` or use
the web admin panel. See the [man page] or use `/msg BouncerServ help`.

If you intend to connect to the bouncer from multiple clients, you will need to
append a client name in your username. For instance, to connect from a laptop
and a workstation, you can setup each client to use the respective usernames
`<username>/irc.libera.chat@laptop` and
`<username>/irc.libera.chat@workstation`.

[README]: ../README.md
[user-contributed guides]: ../contrib/README.md
[man page]: ../doc/sake.1.scd
[client list]: ../contrib/clients.md
