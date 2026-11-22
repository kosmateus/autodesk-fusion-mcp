# Private durable rebaseline fence v1

Administrative module/CLI only. No MCP method, SDK call, host CAS, new database,
TTL or force-clear operation. The running runtime must contain the new fence
guards and register its exact physical binding in the same AdmissionStore.
The older 29b/b915 runtime does not implement this protocol.

## Native CLI

```text
python -m lib.rebaseline_fence begin   --operator-file PRIVATE.json --request BEGIN.json
python -m lib.rebaseline_fence query   --operator-file PRIVATE.json --request QUERY.json
python -m lib.rebaseline_fence consume --operator-file PRIVATE.json --request CONSUME.json
```

No secret is printed or accepted in ordinary request JSON. `--operator-file`
is a separate OS-owned, private regular file (no symlink, private parent and
effective child ACL) provided only by verified administrative composition:

```text
{
  kind: "fmcad-rebaseline-operator", version: 1,
  operatorId: "current-authorized-local-operator",
  database: "<absolute native AdmissionStore path>",
  runtime: {
    handoffId, generation: {instance,epoch},
    physicalRuntime: {pid,birth,version,source,build}, endpointURL
  },
  publicationVerifier: {keyId, keyHex: "<32-byte secret, 64 lowercase hex>"}
}
```

This is an operator capability, **not** a modeling/client/broker grant. ROOT's
verified local composition provisions it after verifying the installed runtime
artifact/process binding. It must not be constructed from MCP/request fields.
The CLI additionally observes the actual SDK PID/birth through read-only OS
process APIs and compares the full binding with the runtime's registered row.
No SDK import/probe is involved.

The verifier key belongs to the persistent administrative source, not an old
agent/session. A new authorized operator receives its own private carrier with
its own operatorId and the same approved keyId/key, through that same local
administrative source. No predecessor token is needed. The SQLite fence pins
the key fingerprint; a different key/realm cannot consume an existing operation.
The administrative source durably provisions that key on the Linux POSIX side
before begin; an ephemeral Windows carrier can be recreated from it. The key's
durability is not inferred from an unqualified Windows/UNC directory flush.

The key is injected only into the trusted Linux POSIX publication capability and
the native verifier. The publication capability signs **only after** successful
fsync/readback of the immutable record/references/head/directories under the
maintained Linux writer lock. It exposes no public arbitrary-sign operation.
The native CLI exposes no key/sign command. Supplying JSON or a boolean is not
source authentication. The native verifier does not pretend to verify UNC
directory durability.

## Begin and query

Begin body (exact keys):

```text
{
  requestId, handoffId, expectedHead, writerGeneration,
  store: {path: "<canonical absolute POSIX store>", device: <safe integer>, inode: <safe integer>},
  intentReferences: [{path,sha256}, ...]
}
```

`expectedHead` and reference hashes are lowercase SHA-256. Intent references are
the immutable original evidence/intent inputs known before publishing the new
record. No newHead is guessed before the callback constructs that record.

Begin requires the exact registered runtime/current committed handoff and zero
issued owners/grants, admissions and physical turns in the current generation.
Historical data is retained. Its SQLite transaction durably creates singleton
PENDING before returning. Every issuance/bind/admit/claim/turn/handoff/generation
granting path checks that fence in its own SQLite transaction. Child/operator
death and runtime restart cannot remove or expire PENDING.

Query body: `{requestId}`. Authenticated query is strictly read-only. No row
returns exit 0 with exactly
`{kind:"fmcad-provision-fence",version:1,state:"absent",requestId}`.
Errors/parse failures are refused (exit 1), never interpreted as absent.
Query/resume uses today's operator capability, without the old session token.
Resume begin/consume audit actor is separate; it does not alter the frozen
initiator or operation identity.

Begin/query response:

```text
{
  kind: "fmcad-provision-fence", version: 1, state: "pending" | "consumed",
  binding: {
    requestId, fenceNonce, handoffId, generation, physicalRuntime, endpointURL,
    store: {path,device,inode}, oldHead, intentReferences,
    initiatorOperatorId, writerGeneration
  },
  publicationJson?, receiptJson?, receiptDigest?, receiptMac?
}
```

Native begin generates the durable random fenceNonce. Idempotent begin compares
the original facts, never the resumer's operatorId. `initiatorOperatorId` comes
from the first authenticated begin and remains immutable across resumes.
The same applies to `binding.writerGeneration`: it is the original generation
from durable begin, including in QUERY and barrier evidence used to reconstruct
newHead. A new resumer's held Linux writer generation is a separate lease
assertion/audit fact, never substituted into the frozen operation. Repeating
begin with the same facts and a new held writer is allowed and audits that
writer separately; it returns the original frozen binding. The consume ABI
and HMAC domain remain unchanged and sign that frozen binding.

## Consume: exact bytes from the authenticated POSIX writer port

Consume body:

```text
{
  requestId, fenceNonce,
  publicationJson: "<EXACT JSON.stringify(RuntimeActivationPublication) bytes as UTF-8 text>",
  attestation: {keyId,mac}
}
```

`RuntimeActivationPublication` retains the existing 3bp.4/.6 shape:

```text
{store,storeDevice,storeInode,expectedHead,expectedFiles,
 activationFile,activationBytes,record:{path,sha256}}
```

`activationBytes` is the exact published pointer JSON with
`{version:1,newHead,record}`. Store identity, old head, record path/ref,
activation path/pointer and all original native/fence bindings are checked.
`publicationDigest = SHA256(UTF8(publicationJson))`, preserving the writer's
literal JSON.stringify bytes, not a Python reserialization.

The trusted POSIX port computes:

```text
mac = HMAC-SHA256(keyBytes,
  UTF8("fmcad-posix-publication-v1\0") +
  UTF8(_encode({binding: ORIGINAL_FENCE_BINDING, publicationDigest})))
```

`_encode` is Python JSON, sorted keys, compact separators, ensure_ascii=True.
The native verifier reconstructs these signed bytes from the durable binding
and exact publicationJson. The public request cannot substitute an initiator,
physical binding, nonce, store, old head, intent refs or verifier.

The Linux writer lock is held through native consume ACK. OLD plus the valid
intent publishes exactly once; exact NEW re-verifies/re-fsyncs without another
CAS; OTHER refuses. A crash after Linux CAS before native consume leaves PENDING.
A new authorized operator queries the SAME ID, verifies exact NEW/re-fsyncs
under its own maintained lock and consumes the same operation.

Consume commits its immutable receipt and approved activation in a separate
SQLite transaction. It does not issue a grant or change generation/UNKNOWN.
ACK loss returns the exact original receipt on repeat/query. Receipt JSON is
stored as its canonical `_encode` bytes. `receiptDigest` hashes those bytes;
`receiptMac` is HMAC-SHA256 over
`UTF8("fmcad-native-consume-v1\0") + UTF8(receiptJson)`.
Its exact object is:

```text
{
  kind:"fmcad-rebaseline-consumed",version:1,
  fence: ORIGINAL_FENCE_BINDING,
  activation: {
    requestId,fenceNonce,newHead,publicationDigest,record:{path,sha256},
    initiatorOperatorId
  },
  consumedBy: FIRST_CONSUMING_OPERATOR_ID
}
```

The immutable `consumedBy` is receipt audit, not an input to old/new-head
identity. Later resumers get separate audit entries, the same receipt bytes
and the same original publicationJson.
The adapter verifies that authenticated original receipt/query, persists its
exact bytes as private Linux evidence and returns:

```text
{
  binding: {requestId,newHead,publicationDigest,initiatorOperatorId},
  evidence: [{path,sha256}, ...]
}
```

Only after that ACK does 3bp.4 publish its immutable local completion record.
Idempotent exact-NEW resume must still consume; an early old-root return must
not leave PENDING.

## Ordinary grant is separate

Consumption itself never creates a physical grant. Subsequent ordinary private
grant issuance additionally supplies:

```text
activation: {requestId,fenceNonce,newHead,publicationDigest,receiptDigest}
```

This must exactly match the terminal SQLite approval. The descriptor must match
the approved physical generation/runtime/handoff/endpoint and its broker queue
must be the approved POSIX store path. A delayed old grant with no activation,
another store/root/generation or another receipt is refused. The public grant
file v1 and SDK header schema do not acquire operator secrets.

History/status reads retain their existing semantics. No query manufactures a
per-turn release or settlement, and no rebaseline operation advances the native
handoff CAS counter.
