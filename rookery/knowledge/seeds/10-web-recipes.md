# Web CTF Recipes

Fast sweep:

```bash
curl -k -i --max-time 8 URL
curl -k -A 'Mozilla/5.0' -i URL
ffuf -u URL/FUZZ -w wordlist -mc all -t 50
rg -n "flag|ctf|TODO|debug|admin|secret|token|jwt|api" .
```

Common lanes:

- Source disclosure: `.git/`, backups, `~`, `.bak`, `.swp`, `/static/`, source maps.
- Auth/session: JWT alg none, weak secret, role in cookie, flask/django/rails signing, remember-me tokens.
- Access control: IDOR, path traversal, forced browsing, hidden endpoints in JS.
- Injection: SQLi, SSTI, command injection, LDAP/XPath/NoSQL, template filters.
- Deserialization: pickle, PHP serialize, Java gadget hints, YAML/object loaders.
- SSRF: metadata endpoints, localhost admin, redirects, DNS rebinding-like patterns.
- Uploads: extension bypass, polyglot, MIME confusion, image processing, path write.
- Cache/proxy: host header, X-Forwarded-*, request smuggling signs.

Always preserve raw request/response and make exploit scripts reproducible.
