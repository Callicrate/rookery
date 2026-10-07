# Web CTF Pattern Seed

Use this as a memory aid, not proof.

## First pass

- Capture headers, cookies, robots.txt, sitemap.xml, source, JS bundle names, API paths.
- Try browser-like headers when curl gets blocked.
- Check static assets, source maps, backup files, dotfiles, old routes, exposed admin panels, and profile objects.
- Build a small endpoint map before deep exploitation.

## Common web lanes

- Auth bypass: weak JWT, `alg:none`, missing signature verification, confusion between user-controlled claims and server state.
- IDOR: predictable IDs, numeric object IDs, team/user/challenge records, unprotected API endpoints.
- Template injection: Jinja/Twig/EJS/Handlebars payloads; verify with arithmetic before file read/RCE.
- SSRF: URL fetchers, webhooks, preview cards, PDF generators, metadata IPs, loopback-only services.
- Deserialization: pickle, PHP serialize, Java, Node object prototypes.
- SQLi/NoSQLi: login forms, search, JSON filters, Mongo operators, SQLite quirks.
- File upload: polyglots, extension confusion, content-type confusion, path traversal in filenames.
- Race conditions: redeem/use endpoints, balances, coupons, invite codes, rate-limited state transitions.

## Good artifacts

- Scope-mediated selected-adapter attachment capture when the artifact has a
  declared attachment origin.
- An operator-side request transcript when manual HTTP research is necessary;
  it is not Rookery-owned evidence until generic HTTP is fully scope-mediated.
- Minimal exploit script or shell one-liner.
- Explanation of why the response proves the flag/candidate.
