# Guacamole extension

Optional streamed-console extension. It is inactive unless selected by an adapter or `EVENT_EXTENSIONS=guacamole`. It adds console leases, terminal evidence export, and Guacamole helpers.

Custom transport commands use JSON `*_ARGV` arrays with one-pass whole-argument placeholders, `shell=False`, bounded output, and owner-only evidence.
Legacy `*_COMMAND` shell templates fail closed.
File-export transports emit the exported bytes on stdout; the helper atomically writes only the bounded captured bytes and never exposes a direct local output path to the transport.

Every Guacamole helper writes only below the workspace-owned
`evidence/guac/` family. A custom `--outdir` may be either an absolute path
under that family or a relative spelling such as `evidence/guac/session-01`.
Paths containing dot/parent components, backslashes, control characters,
links, special files, or hard-linked evidence are rejected before an output
directory is created or a transport is started. Evidence names are
no-clobber: use a new contained directory for a new capture rather than
replacing a prior record. Nested helpers receive a contained child directory
under their caller's evidence bundle.

Each helper parses only its declared Guacamole controls from `.env` or the
invoking parent; a nonempty `.env` setting wins. A configured transport receives
the minimal runtime environment plus exactly the names in its matching
`*_ENV_KEYS` JSON array. The arrays contain names, never assignments or
wildcards, and a requested key must exist before Rookery creates evidence or
starts a child. Environment metadata records policy names and key classes only,
never values.

`GUAC_SSH_EXEC_ENV_KEYS` is the sole custom-sender path for `SSH_AUTH_SOCK`.
Every other transport selector rejects agent capabilities. All custom transport
selectors reject provider, adapter, session, VPN, and Rookery owner
credentials. The SSH selector admits no other agent capability besides the
exact `SSH_AUTH_SOCK` name.
The xdotool fallback has a separate interactive-desktop policy limited to
`DISPLAY`, `WAYLAND_DISPLAY`, `XAUTHORITY`, and `DBUS_SESSION_BUS_ADDRESS`; it
does not inherit SSH, provider, adapter, session, VPN, or owner-token state.
`guac-contact-sheet` resolves only `GUAC_STREAM_DIR`; its ImageMagick fallback
uses the minimal policy. Nested Guac helpers also use minimal environments and
resolve their own declared configuration at their own boundary.

Copy only the needed JSON argv and matching names-only variables from
`env.example` into the live `.env`.

## Configuration schema

Guacamole settings are accepted only when `EVENT_EXTENSIONS` selects
`guacamole`. An unselected nonblank `GUAC_*` setting fails configuration
validation; blank catalogue entries remain inert. The extension descriptor
types the public settings before launch:

- `GUAC_*_ARGV` values are JSON string arrays. Rookery passes each decoded
  argument directly with no shell.
- `GUAC_*_ENV_KEYS` values are JSON arrays of exact environment variable names.
  Wildcards and `KEY=value` entries are invalid.
- `GUAC_STREAM_DIR` is an optional relative or absolute stream/tile path.
- `GUAC_EXEC_TIMEOUT` is an integer from 1 through 3600 seconds and defaults to
  `120` in the example configuration.

All extension settings are optional. Selecting Guacamole adds the console
surface without requiring a custom transport. Legacy `GUAC_*_COMMAND` shell
templates are deliberately absent from the public schema and fail before
launch.
