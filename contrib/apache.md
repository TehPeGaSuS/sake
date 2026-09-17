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

Have sake listen for HTTP on localhost:

```
listen http://localhost:3030
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
    ProxyPass        "/socket" "ws://localhost:3030/socket"
    ProxyPassReverse "/socket" "ws://localhost:3030/socket"

    # File uploads - keep the body size unlimited (0) for large uploads
    ProxyPass        "/uploads" "http://localhost:3030/uploads"
    ProxyPassReverse "/uploads" "http://localhost:3030/uploads"
    LimitRequestBody 0

    # Web admin panel
    ProxyPass        "/admin" "http://localhost:3030/admin"
    ProxyPassReverse "/admin" "http://localhost:3030/admin"

    # Serve gamja (or another web client) for everything else
    DocumentRoot /var/www/gamja
</VirtualHost>

<VirtualHost *:80>
    ServerName chat.example.com
    RewriteEngine On
    RewriteRule ^ https://%{HTTP_HOST}%{REQUEST_URI} [END,NE,R=permanent]
</VirtualHost>
```
