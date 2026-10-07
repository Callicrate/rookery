# CTFd adapter

Optional adapter for CTFd-compatible events. It is inactive unless `PLATFORM_ADAPTER=ctfd`. Copy only the required values from `env.example` into `.env`. Platform reads and scoring mutations stay behind the normalized adapter and independent review boundary.

Configure the selected adapter in the single private `.env`:

```dotenv
PLATFORM_ADAPTER=ctfd
CTFD_URL=https://ctf.example
CTFD_TOKEN=
CTFD_NETWORK_ENV_KEYS=[]
ADAPTER_CONFIG_BASE_URL=https://ctf.example
ADAPTER_CONFIG_TOKEN_ENV=CTFD_TOKEN
ADAPTER_CONFIG_TIMEOUT=30
ADAPTER_CONFIG_MAX_RESPONSE_BYTES=262144
```

`ADAPTER_CONFIG_BASE_URL` must agree with `CTFD_URL`. `ADAPTER_CONFIG_TOKEN_ENV` names the private credential slot; it does not contain the token. `CTFD_NETWORK_ENV_KEYS` is an exact JSON array of reviewed proxy or CA environment names and should remain empty when none are needed.

## Inventory failures

At startup, the adapter reads `/api/v1/challenges` through Rookery's scoped transport. Only a successful `application/json` response containing `success: true` and a `data` list of challenge objects establishes platform inventory. HTTP failures, non-JSON responses, malformed JSON, and unexpected payload shapes fail closed with bounded diagnostics. Rookery does not treat an access-control page or other invalid response as an empty challenge list.

When inventory cannot be established, platform inventory, challenge details, and scoring fail their health checks, and the CTFd workspace stays blocked. Fix the official API access and rerun `./go`; do not bypass upstream access controls or loosen event scope to make the check pass.

If an authorized event requires an existing Chrome login instead of a CTFd API token, prepare a fresh workspace with the [`ctfd_browser` adapter](../ctfd_browser/README.md). It reads only bounded session material through CDP and sends platform requests through Rookery's scoped HTTP transport. Cloudflare can still reject those requests; the adapter does not bypass the challenge or submit through Chrome.

If the platform API cannot be read but authorized challenge files are available, prepare a fresh release workspace with `PLATFORM_ADAPTER=manual`. Declare only their paths in `ALLOWED_FILE_ORIGINS`, review the remaining scope keys, set `EVENT_SCOPE_ACK=1` only after that review, and create a new measurement baseline before the first `./go`. The manual adapter has no platform scoring mutation capability. See [Configuration](../../docs/configuration.md), [Event scope](../../docs/scope.md), and the [Operator guide](../../docs/operator.md).

Inventory and scoring response bodies use the selected profile's default ceiling; `ADAPTER_CONFIG_MAX_RESPONSE_BYTES` accepts 1 KiB through 16 MiB.
Oversized bodies fail visibly before JSON parsing.
