# Opt-in keyed admission

When `FUSION_MCP_ADMISSION_PROVISION` is unset, the add-in does not expose
`/admission/v1` and does not open an admission database. SDK-producing `/mcp`
calls now fail closed without the private physical grant described in
[the physical ownership contract](physical-grant.md). Do not provision keyed admission on an active runtime.
As with the legacy listener, admission does not bind a socket on cold start
until Fusion has serviced a real main-thread readiness event.

## Trusted inputs

Set `FUSION_MCP_ADMISSION_PROVISION` to the absolute path of a private UTF-8
JSON file containing `database` (absolute local SQLite path), `pid` (integer),
`birth` (string), `instance`, `epoch`, `source`, `build` (nonempty strings),
and `credentials` (object mapping each bearer token to its principal).
The provisioner must verify the actual installed add-in artifact for
`source`/`build`, assign a process-specific instance and verify the process
identity independently before supplying those pins and credentials to the
client. The add-in checks `pid` and `birth` against its own process: Windows
uses decimal creation FILETIME; Linux uses boot ID and `/proc` start ticks
joined with `:`. Other platforms fail closed for this opt-in.

Keep the file, canonical database and its `.lease` sidecar in a private local
directory; do not copy, replace or delete them during runtime or handoff.
The OS-backed sidecar lease excludes another cooperating bootstrap while this
process owns the database. The bootstrap fails on a stale epoch; it does not
create a new generation to work around an unresolved old one.
The trusted provisioner initializes the database once with
`AdmissionStore(path, instance=…, epoch=…)` before the first opt-in. Runtime
bootstrap opens it without creating it, so a missing database cannot be
mistaken for an empty receipt history. Do not reinitialize a lost database.

## Typed operation

The only admitted JSON-RPC tool is `get_open_document_metadata`, with
`params.arguments` exactly `{"fileId":"…","version":2}` (example version).
The positive integer version and file ID must identify exactly one already
open, saved SDK document. The add-in resolves it on the main thread without
using the active tab or opening anything. The binding's `document` is the
compact JSON string `{"creationId":"…","fileId":"…","version":2}` (key order
as shown, Unicode unescaped). The server compares it to the actual SDK
identity and reads the metadata from that same handle.
If target resolution fails, the request is refused before the execution
claim. Its accepted key can be inspected or withdrawn and is never
automatically dispatched a second time.

The versioned endpoint and exact UTF-8 payload hash are unchanged. This
capability does not authorize general Python or the generic Autodesk API
tool, and never falls back to them. The legacy endpoint does not acquire the
new tool. The lease and bearer boundary do not isolate the add-in from
code already trusted to run arbitrary Python in the Fusion process.

## Generation handoff

The local trusted operator uses `python3 -m lib.physical_lifecycle handoff`
with the exact private request documented in [the ownership contract](physical-grant.md).
Its mailbox invokes `fusion_bridge.runtime.handoff_admission_generation`
on the Fusion main thread, with a durable handoff ID. This is not an MCP or SDK method. It cuts off intake
on both dispatch paths and abandons only queued, not-yet-started envelopes.
If a handler remains on the stack, the SDK is still processing a call to
fire a Custom Event, or an admission API call remains active, handoff
returns `False` without advancing, closing SQLite, or releasing the lease.
Status and withdrawal remain available at that point; the trusted caller
may retry once work settles. Pending work signals are generation-bound and
cannot enter the SDK once rundown starts.

When quiescent, the handoff seals API access to the old database, commits
the explicit generation CAS, retires the listener, and releases the lease.
The next bootstrap needs a matching provision against the same database.
Claimed records without terminal evidence remain in SQLite as `UNKNOWN`;
they are not replayed or exposed under a different generation's binding.
An explicit epoch-reuse rejection leaves status and withdrawal available,
but an indeterminate store failure keeps the old API sealed and disables
further handoff attempts from that runtime.

Ordinary host stop does not advance the generation and does not require
another stop callback. If immediate retirement is unsafe, a generation-bound
control event finishes cleanup once the handler, signal and HTTP rundown are
complete and the Fusion main thread services the event.
