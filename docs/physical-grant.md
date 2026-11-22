# Private physical execution contract (v1)

This is a trusted local operator interface, not an MCP tool. It never invokes
the Fusion SDK. All lifecycle requests are serviced by the running add-in on
its main thread. The physical authority is independent of any broker queue
directory. Missing provisioning or a missing/revoked grant denies SDK dispatch.

## Grant file and header

The operator writes a regular private JSON file (POSIX mode `0600`, private
parent directory; no symlinks). The exact v1 shape is:

```json
{
  "kind": "fmcad-physical-grant",
  "version": 1,
  "handoffId": "operator-generated-unique-id",
  "generation": {"instance": "addin-instance", "epoch": "generation"},
  "brokerOwner": {
    "pid": 123,
    "birth": "process-birth",
    "nonce": "random-process-nonce",
    "clientId": "broker-client",
    "queueDirectory": "/absolute/canonical/queue"
  },
  "endpointURL": "http://127.0.0.1:8765/mcp",
  "physicalRuntime": {
    "pid": 456,
    "birth": "sdk-process-birth",
    "version": "Fusion-version",
    "source": "runtime-source",
    "build": "runtime-build"
  },
  "token": "private-random-bearer"
}
```

Every `/mcp` and `/admission/v1` POST supplies exactly one
`X-Fmcad-Physical-Grant: <token>` header, independently of admission's
`Authorization: Bearer ...`. Never log this token, place it in public
configuration, or return it through MCP metadata. The broker must pin the
entire descriptor to its exact process owner and canonical queue directory;
an inherited descriptor is not authority for a successor broker.
`queueDirectory` remains in the **broker's** namespace. A Linux/WSL broker
uses its canonical POSIX path even when Fusion runs on Windows. The fork
validates absolute lexical form (POSIX or native Windows), rejects aliases
such as `..`, repeated separators and trailing separators, and preserves the
exact string; it never resolves the path on the Fusion host. The broker
independently checks its real queue directory and lock nonce.
`brokerOwner.clientId` identifies the sole physical broker, **not** the logical
request caller. Several logical clients may share that broker. Admission still
authenticates each separate bearer principal and checks it against
`binding.owner`; neither is required to equal the broker client ID. A physical
grant never replaces or broadens admission's per-request authorization.

## Physical turn quiescence (separate from job outcome)

Every SDK-producing POST additionally supplies:

```text
X-Fmcad-Physical-Turn: <unique request/turn ID, ASCII, at most 256 characters>
X-Fmcad-Physical-Target: <unpadded base64url of UTF-8 exact document descriptor>
```

For admission, the turn ID must equal `binding.request` and the decoded target
must equal `binding.document`. MCP initialize/discovery does not allocate a
turn. SDK calls without these headers are rejected. A turn ID is never reused,
including after release. Duplicate admission receipt reads are still passive.

The private, grant-authenticated `POST /physical/v1/turn-status` accepts exactly:

```json
{
  "version": 1,
  "grantDigest": "sha256-of-exact-private-grant-file-bytes",
  "generation": {"instance": "addin-instance", "epoch": "generation"},
  "physicalRuntime": {
    "pid": 456, "birth": "sdk-process-birth", "version": "Fusion-version",
    "source": "runtime-source", "build": "runtime-build"
  },
  "turnId": "unique-request-id",
  "target": "{\"creationId\":\"exact-document\"}"
}
```

The target is an exact string, not a reserialized object. The grant file writer
emits UTF-8 JSON with sorted keys, standard Python JSON separators (including
spaces), ASCII escaping, and no trailing newline. Hash the **actual pinned file
bytes**, not a JavaScript reserialization. Querying this endpoint never calls SDK.

Responses are `{state: "unknown" | "active" | "released", binding: <exact input>}`.
Only `released` also contains `physicalEvidenceReference` and `evidenceDigest`.
The reference is `fmcad-physical-turn:sha256:<digest>` and is backed by the
immutable binding and release marker in the same admission SQLite database.
Foreign generation, runtime, grant or target bindings return `unknown`; absent
or revoked authentication is refused. Queued and actually running turns both
return `active`. SDK/worker death alone is not release evidence.

`released` means that the physical dispatch completed its `finally`, or its
queued-only claim was durably sealed before any SDK start. A late envelope
cannot start after that seal. This is **not** a terminal job receipt, settlement,
success, or permission to replay the original ID. In particular, an admission
may remain UNKNOWN while its physical turn is durably released. A broker can
then release its global SDK lane while retaining quarantine of that exact
document and preserving the UNKNOWN job.

### Ancestor turn evidence after a real handoff

`POST /physical/v1/turn-history` is a **read-only** private query for an
original turn binding from an older generation. Authenticate with exactly one
**current** `X-Fmcad-Physical-Grant`; the old grant token is neither needed nor
accepted. The request body is the exact original `PhysicalTurnBinding` v1 above,
without a wrapper. Do not substitute the current grant digest, generation or
physical runtime. No turn/target headers or SDK dispatch are needed for queries.

The response has the same shape as `turn-status`. A historical `released`
response is allowed only when:

- the full original binding exactly matches an immutable `physical_turns` row
  in the current authority's same existing AdmissionStore;
- that row was already released by `dispatch-finally` or
  `cancelled-before-sdk`;
- native immutable `physical_handoffs` receipts prove the old generation is a
  strict ancestor of the current generation, using nonempty exact handoff IDs
  and `state: "committed"` records consistent with `generation_history`;
- the bounded lineage is unambiguous and has no cycles or spliced/duplicate
  parent/successor edges. At most 1024 handoff records and 1025 generation
  history rows are examined; an over-limit history fails closed.

Unproved lineage, a foreign/spliced binding, a current-generation binding,
missing rows or old queued/active snapshots return `unknown` with no evidence.
Malformed binding shapes return HTTP 400; missing, old or lost-current
authentication returns HTTP 401. `turn-status` remains strict current-only.
Unknown legacy lineage is not migrated or guessed.

The historical evidence digest is **identical to the original release proof**:

```text
SHA256(UTF8(_encode({
  "binding": ORIGINAL_BINDING,
  "state": "released",
  "releasedBy": STORED_REASON
})))
```

`_encode` is Python JSON with `sort_keys=True`, `separators=(",", ":")` and
`ensure_ascii=True` (including surrogate-pair escaping for non-BMP characters).
`physicalEvidenceReference` remains `fmcad-physical-turn:sha256:<digest>`.
The new grant authenticates access; it is not inserted into this old proof.

History performs no SQL writes/schema creation and does not enqueue events.
It never manufactures a release from worker/SDK death, advances a generation,
renews an old grant, replays a turn or settles UNKNOWN. This permits a successor
broker to recover an already durable release after its predecessor died before
publishing quarantine, while preserving the original job and document quarantine.

## Local CLI

Run from the installed fork directory:

```text
python -m lib.physical_lifecycle grant --request request.json --output grant.json
python -m lib.physical_lifecycle handoff --request handoff.json
python -m lib.physical_lifecycle query --database /absolute/admission.sqlite --handoff-id ID
```

The grant request contains the exact grant shape above **without `token`**.
All runtime, endpoint and generation pins must match the provisioned runtime.
A runtime issues at most one owner grant; a different owner needs a completed
generation handoff. Repeating a request for that owner returns the same grant.
Grant publication never overwrites an existing inode. An existing file is
accepted only when it contains the exact bytes of this runtime's same grant.
Authority/mailbox, admission database, SQLite sidecars and lease paths are
forbidden outputs. On Windows the effective ACL of the empty temporary file
is validated **before** writing the token, not inferred from its parent.

The handoff request is:

```json
{
  "handoffId": "operator-generated-unique-id",
  "generation": {"instance": "old-instance", "epoch": "old-epoch"},
  "nextGeneration": {"instance": "new-instance", "epoch": "new-epoch"}
}
```

The CLI uses the fixed private per-user lifecycle mailbox, never the queue
directory, and prints only a token-free acknowledgement. A timeout is not
permission to repeat a transition with a new ID. Query the same handoff ID.
The handoff result is committed in the existing admission SQLite transaction
alongside generation CAS. Queries are read-only and do not replay CAS.
Missing, null and empty handoff IDs are rejected before rundown. The immutable
query receipt has `state: "committed"`: this proves CAS, not successful
retirement. Only a successful runtime retirement yields the CLI acknowledgement
`state: "completed"`. An exception after handoff begins produces
`{state:"unknown", handoffId, retirement:"unconfirmed", queryRequired:true}`
(CLI exit 3), never a definitive rejection; query that same ID. The runtime
does not attempt a second CAS after a committed or indeterminate transition.
Receipts and claimed/UNKNOWN records are not rewritten.
An old durable UNKNOWN is not an active physical lease: it neither blocks a
new independent request nor prevents handoff once actual SDK/HTTP work drains.
The old request still cannot be replayed or automatically settled.

The runtime uses a fixed per-user OS lease plus a pinned admission database
path. Another provision naming a different database is denied even after
ordinary restart. An ordinary restart does not advance generation.

On POSIX the authority directory is
`~/.local/state/autodesk-fusion-mcp/physical`; on Windows it is
`%LOCALAPPDATA%/AutodeskFusionMCP/physical`. Do not delete or replace its lock
or database binding while any runtime might still be alive.
