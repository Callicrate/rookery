# Immersive Adapter

Optional adapter for Immersive-style dynamic labs. It is inactive unless `PLATFORM_ADAPTER=immersive`. Platform-specific command wrappers, dynamic-attempt helpers, and the optional Guacamole extension remain isolated here. Submission aliases accept only a canonical Immersive plan ID and delegate to the shared executor; raw submission argv belongs in `ADAPTER_CONFIG_SUBMIT_ARGV` and runs only inside canonical plan execution.

See [Session and platform patterns](./knowledge/session_patterns.md) for the adapter's operator guidance.

Put all selected-adapter values in the workspace's single private `.env`; do not edit this adapter's example. `ADAPTER_CONFIG_INVENTORY_ARGV` and `ADAPTER_CONFIG_SUBMIT_ARGV` are JSON argv arrays, with separate exact name arrays in `ADAPTER_CONFIG_INVENTORY_ENV_KEYS` and `ADAPTER_CONFIG_SUBMIT_ENV_KEYS`. The selected-lab path uses `IMMERSIVE_SELECTED_LAB_REFRESH_ARGV`, `IMMERSIVE_SELECTED_LAB_REFRESH_ENV_KEYS`, `IMMERSIVE_GRAPHQL_URL`, `IMMERSIVE_SELECTED_LAB_QUERY`, `IMMERSIVE_ACTIONCABLE_URL`, `IMMERSIVE_ORIGIN`, `IMMERSIVE_COOKIES_FILE`, and `IMMERSIVE_NETWORK_ENV_KEYS`. The reviewed `env.example` gives the complete selected-adapter subset to copy into `.env`.

The selected-lab refresh helper is read-only. It resolves its URL, query, and
cookie-file references from the declared Immersive names only; values in the
workspace `.env` take precedence over same-named parent values.

Custom refresh commands use `IMMERSIVE_SELECTED_LAB_REFRESH_ARGV` as a JSON
argv array, run with `shell=False`, and have an 8 MiB default combined output
cap. They receive the minimal runtime environment plus exactly the names in
`IMMERSIVE_SELECTED_LAB_REFRESH_ENV_KEYS`; they do not inherit adapter,
session, provider, VPN, proxy, or owner-token values by default.

`IMMERSIVE_NETWORK_ENV_KEYS` is the only authority for Immersive HTTP or
WebSocket proxy/CA settings. It is a JSON array containing only these exact
names: `HTTP_PROXY`, `HTTPS_PROXY`, `ALL_PROXY`, `NO_PROXY`,
`CODEX_CA_CERTIFICATE`, `SSL_CERT_FILE`, `REQUESTS_CA_BUNDLE`,
`CURL_CA_BUNDLE`, `NODE_EXTRA_CA_CERTS`, and `GIT_SSL_CAINFO`. With no
declaration, the helpers use no proxy and the compiled system trust store.
Certificate verification is never disabled; an invalid declared CA fails
before a connection and does not trigger an insecure retry.
Lowercase standard proxy aliases are accepted only when they are also named
explicitly in that JSON array.
Cookie paths are consumed only by the helper that opens them; cookie contents
never enter a child environment or environment metadata.

## Private output containment

`immersive-cluster-capture` and `immersive-selected-lab-refresh` write only
beneath `evidence/immersive`; `immersive-cookie-filter` writes only beneath
`platform/cookies`. An explicit `--outdir` may use an absolute spelling only
when it resolves inside that helper's fixed family. Dot components, parent
components, backslashes, controls, links, special files, and hard-linked files
are refused. New directories receive a private ownership marker created with
descriptor-relative no-clobber operations. A later run may migrate only a
directory bearing the matching marker; an arbitrary pre-existing directory is
not treated as Rookery-owned evidence. Output metadata records workspace-
relative paths, never a caller-provided external path.

Legacy shell templates and mutation overrides fail closed; GraphQL responses have the same default byte ceiling.
