# Setting up Apache httpd as a proxy to sake

Apache httpd can front sake's HTTP listener (WebSocket, file uploads, and the
[web admin panel](https://github.com/TehPeGaSuS/sake/wiki/Web-Admin-Panel)),
handling TLS termination and letting Apache's existing certificate tooling
(e.g. `certbot --apache`) manage renewals.

Apache doesn't have a generic TLS+TCP passthrough module comparable to
nginx's `stream` module or Caddy's `layer4`, so this setup only covers the
HTTP side. For the plain IRC listener, either let sake terminate TLS itself
(`tls <cert> <key>` in the sake config, simplest) or use a separate TCP/TLS
proxy such as [tlstunnel](tlstunnel.md) or HAProxy in front of a plain-text
`listen irc://localhost` if you want a single external TLS cert manager for
both.

Required Apache modules: `mod_proxy`, `mod_proxy_http`,
`mod_proxy_wstunnel`, `mod_ssl` (enable with `a2enmod proxy proxy_http
proxy_wstunnel ssl` on Debian/Ubuntu).

## sake configuration

Have sake listen for HTTP on a Unix domain socket, so it isn't exposed
directly:

```
listen http+unix:///run/sake/http.sock
```

## Apache virtual host

```apache
<VirtualHost *:443>
    ServerName chat.example.com

    SSLEngine on
    SSLCertificateFile      /etc/letsencrypt/live/chat.example.com/fullchain.pem
    SSLCertificateKeyFile   /etc/letsencrypt/live/chat.example.com/privkey.pem

    ProxyPreserveHost On
    # Don't forward a client-supplied Forwarded header - it takes
    # precedence over X-Forwarded-* and would let clients spoof it.
    RequestHeader unset Forwarded

    # WebSocket (gamja and other web clients)
    ProxyPass        "/socket" "ws://unix:/run/sake/http.sock|ws://localhost/socket"
    ProxyPassReverse "/socket" "ws://unix:/run/sake/http.sock|ws://localhost/socket"

    # File uploads - keep the body size unlimited (0) for large uploads
    ProxyPass        "/uploads" "unix:/run/sake/http.sock|http://localhost/uploads"
    ProxyPassReverse "/uploads" "unix:/run/sake/http.sock|http://localhost/uploads"
    LimitRequestBody 0

    # Web admin panel
    ProxyPass        "/admin" "unix:/run/sake/http.sock|http://localhost/admin"
    ProxyPassReverse "/admin" "unix:/run/sake/http.sock|http://localhost/admin"

    # Serve gamja (or another web client) for everything else
    DocumentRoot /var/www/gamja
</VirtualHost>

<VirtualHost *:80>
    ServerName chat.example.com
    RewriteEngine On
    RewriteRule ^ https://%{HTTP_HOST}%{REQUEST_URI} [END,NE,R=permanent]
</VirtualHost>
```

Unix-socket proxying (the `unix:/path|http://...` syntax above) requires
Apache 2.4.7+ built with `mod_proxy`'s Unix domain socket support, which is
the default on current distributions.

## Socket file permissions

`/run/sake/http.sock` is created by sake, but needs to be readable/writable
by the Apache user (`www-data` on Debian/Ubuntu, `apache` on RHEL/Fedora).
Run sake with a matching group, e.g. via a systemd drop-in on
[`contrib/sake.service`](sake.service):

```
[Service]
Group=www-data
```
