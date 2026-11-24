# Private bootstrap entry receipts

`FUSION_MCP_BOOTSTRAP_INTENT` optionally names an existing private intent file.
An absent variable preserves ordinary startup. An empty or invalid value never
falls back to ordinary startup. Denial uses the existing entrypoint error handler
and occurs before importing `addon_runtime`.

This is an operator-only startup input, not HTTP or invocation input. The OS,
operator and reviewed bootstrap are trusted. No receipt proves global Python
history, all-autoload-off, an SDK-ready runtime, admission closure, or a clean
host. There is no signature, grant, capability, freshness flag or authority token.
A future native consumer must bind the original evidence using its existing
authenticated baseline and current private admission lease.

## Intent v2 (audited controlled startup)

All objects have exactly the following fields; duplicate JSON keys, nonfinite
numbers, unknown fields and wrong types are rejected.

```json
{
  "kind": "fmcad-bootstrap-entry-intent",
  "version": 2,
  "nonce": "32 lowercase hexadecimal characters",
  "process": {"pid": 123, "birth": "OS process birth"},
  "executable": {"path": "absolute canonical OS process image", "sha256": "SHA-256"},
  "purpose": "isolated-stdout-v1",
  "engineVersion": 2,
  "installed": {
    "directory": "absolute canonical deployed directory",
    "source": "40 lowercase hexadecimal source revision",
    "files": {"AutodeskFusionMCP.py": "64 lowercase hexadecimal SHA-256"}
  },
  "profile": {"path": "absolute canonical private profile", "sha256": "SHA-256"},
  "receipts": {
    "directory": "existing absolute canonical private output directory",
    "entry": "entry.json",
    "returned": "returned.json"
  }
}
```

The example's `files` object is abbreviated: it must contain **every installed
regular file**, including resources and any bytecode, with no exclusions.
It must include `AutodeskFusionMCP.py`, `addon_runtime.py` and
`lib/bootstrap_entry.py`. All installed directories and files, inputs and output
directory require private owner/permissions (or the existing private Windows
DACL checks). Symlinks, reparse points, special files and hard-linked input files
are refused. No directory is created automatically.

The source revision is an operator pin, not an independently reconstructed Git
commit: full file bytes are independently compared against the closed manifest.
The consumer must connect that manifest to the qualified source/build.
Use a controlled deployment, not a checkout containing mutable `.git` state.
Configure `PYTHONDONTWRITEBYTECODE=1` at process launch to avoid import-created
files invalidating the full manifest. Existing caches must themselves be pinned
or removed by the authorized operator before the manifest is produced.

The two receipt names must differ and contain only lowercase ASCII letters,
digits, underscores, hyphens and the `.json` suffix. DOS device basenames
(`con`, `prn`, `aux`, `nul`, `com1`–`com9`, `lpt1`–`lpt9`) are forbidden.
This also excludes case-only aliases on Windows. Outputs cannot be inside the
installed tree or alias the intent/profile. The operator allocates a fresh nonce
and paths per attempt; previously created receipts cannot be resumed or replaced.

The process image is independently observed using `/proc/self/exe` on Linux or
`QueryFullProcessImageNameW` on Windows, not inferred from `sys.executable`.
Its bytes must match the executable pin. Unsupported platforms refuse.

## Queue ordering and recorded facts

After validating the original OS/executable/intent/source/profile/output fences,
controlled startup registers the existing custom event and schedules one fixed
private operation in the same dispatcher `_pending` and `_run_lock` used by SDK
work. Registration and signaling are bootstrap infrastructure, not audit data.
The operation accepts the original `BootstrapEntry`, never arbitrary callbacks,
code or caller-provided audit results. Public dispatch's physical guards remain
unchanged.

On the main-thread queue turn, the fixed getter audit completes and fences are
rechecked. The exclusive `entry-audited-before-addon-import` receipt is written
and synced before importing `addon_runtime`. Controlled startup omits optional
command/UI setup. The runtime reuses that dispatcher rather than resetting it.
Only after addon startup explicitly succeeds is `run-returned` written with the
original entry's exact hash. The worker's readiness ping runs after this queue
turn; it verifies original entry and returned bytes plus all fences before
constructing admission or starting the listener.

Both closed v2 receipts contain `kind: fmcad-bootstrap-entry-receipt`, `version: 2`,
`phase`, `nonce`, `process`, `purpose`, `engineVersion`, the original
`executable`, `intent: {path, sha256}`, the original `profile` reference, and
`installed: {directory, source, filesDigest}`.
`filesDigest` hashes the UTF-8, sorted-key compact JSON encoding of the complete
`installed.files` object (the existing native `_encode` function).
Only the return receipt also contains `entry: {path, sha256}`.
Only the entry contains `startupAudit`:

```json
{
  "kind": "fmcad-startup-sdk-audit",
  "version": 1,
  "applicationVersion": "SDK application version",
  "preferences": {"defaultPathForScriptsAndAddIns": "absolute effective parent"},
  "scripts": {
    "countBefore": 1,
    "countAfter": 1,
    "items": [{
      "index": 0,
      "folder": "absolute SDK script folder",
      "location": {"name": "UserDefinedScriptSourceLocation", "value": 2},
      "isAddIn": true,
      "isRunOnStartup": false,
      "isRunning": true,
      "isVisible": true,
      "manifest": {
        "content": "{}",
        "sha256": "SHA-256 of exact UTF-8 content",
        "parseStatus": "json-object"
      }
    }]
  }
}
```

The enum value is read from the SDK's six named `ScriptSourceLocations`
constants, not a persisted profile enum. Unknown values refuse qualification;
they are never mapped to another name. `isRunOnStartup` is read only for add-ins;
ordinary scripts record `null` because the SDK declares the getter inapplicable.
SDK `isRunning` and `isVisible` apply to both scripts and add-ins. Hidden entries
are included. The effective API parent has `Scripts`/`AddIns` subdirectories;
the audit does not infer these preferences from profile defaults.

Limits are 1,024 items, 256 KiB exact UTF-8 per manifest and 4 MiB serialized
audit. Manifest content must parse as a strict JSON object (duplicate keys and
nonfinite numbers refuse); raw content is data, never executed or rendered.
Null/missing/wrong-type getters, unknown enums, inconsistent counts, preference
changes and exceeded budgets refuse without truncation or empty fallback. A
genuinely empty collection records both zero counts. The collection is a bounded
observation with count checks, not an atomic global autorun snapshot.

The existing consumer must bind original audit-bearing entry bytes through its
original reference and existing MAC `intentReferences`. These data create no
grant or dispatch authority, do not audit `PythonAutorunScripts.enabledModules`,
and do not themselves establish all-startup-OFF.

Every phase re-reads original input bytes, full installed files and current OS
birth. No mtime-only validation or authority cache is used. An import/run failure
leaves the entry receipt without a return receipt. A write or post-write fence
failure preserves any partial/original artifacts; it does not delete, retry or
settle them. A consumer must reject incomplete or inconsistent evidence.
Queue timeout or shutdown refuses/retains UNKNOWN; no direct-SDK fallback runs.
Existing artifacts on a post-write failure remain evidence, not success.

## Legacy v1

Version 1 accepts only `purpose: bootstrap-entry-data-v1`, without `executable`
or SDK audit. It retains `entry-before-addon-import` and normal-return recording
for data-only legacy consumers. A v1 intent requesting `isolated-stdout-v1` is
rejected before SDK access; a v1 receipt can never qualify that purpose.

## Offline verification

```sh
python3 -I -B -m unittest discover -s tests -p test_bootstrap_entry.py -v
python3 -I -B -m unittest discover -s tests -p test_startup_audit.py -v
```

Tests execute the actual entrypoint and copied helper files in benign subprocess
packages with a fake `addon_runtime`, real OS process-birth observations, private
temporary files and no Fusion SDK modules. Run the same suite with the pinned
native Windows Python to exercise its real OS birth and private ACL checks.
Windows public-input fixtures add an actual Everyone read ACE instead of using
POSIX `chmod`; successful receipts are checked with the existing private DACL
helper. Junction and hard-link fixtures also exercise Windows alias rejection.
Symbolic-link fixtures report NOTRUN if the token lacks the required Windows
privilege; tests do not request elevation or count that refusal as a PASS.
Neither platform's fixtures qualify the deployed add-in, the operator's
controlled profile, or a real Fusion host.

The startup audit suite uses real entrypoint, producer, addon runtime, bridge
runtime, admission runtime and shared queue modules, with an explicit fake SDK,
fake server and empty operations registry. No sockets or real SDK calls occur.
Its private copied-package fixture currently targets POSIX; it is not Windows
ACL or real Fusion evidence.
It checks main-thread/lock origin, pre-import and pre-listener ordering, exact
receipt hashes, replay/reentry, concurrent changes, timeout, malformed getters,
manifests, budgets, and public-input rejection.
