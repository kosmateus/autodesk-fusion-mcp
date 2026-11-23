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

## Intent v1

All objects have exactly the following fields; duplicate JSON keys, nonfinite
numbers, unknown fields and wrong types are rejected.

```json
{
  "kind": "fmcad-bootstrap-entry-intent",
  "version": 1,
  "nonce": "32 lowercase hexadecimal characters",
  "process": {"pid": 123, "birth": "OS process birth"},
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

## Recorded facts

The exclusive private `entry-before-addon-import` receipt is written and synced
after OS PID/birth, original intent/profile bytes, full installed inventory and
output-directory identity have been checked, before importing `addon_runtime`.
Only after `addon_runtime.run(context)` returns normally is `run-returned`
written, with a reference/hash to the original entry receipt.

Both closed receipts contain `kind: fmcad-bootstrap-entry-receipt`, `version: 1`,
`phase`, `nonce`, `process`, `purpose`, `engineVersion`, the original
`intent: {path, sha256}`, the original `profile` reference, and
`installed: {directory, source, filesDigest}`.
`filesDigest` hashes the UTF-8, sorted-key compact JSON encoding of the complete
`installed.files` object (the existing native `_encode` function).
Only the return receipt also contains `entry: {path, sha256}`.

Every phase re-reads original input bytes, full installed files and current OS
birth. No mtime-only validation or authority cache is used. An import/run failure
leaves the entry receipt without a return receipt. A write or post-write fence
failure preserves any partial/original artifacts; it does not delete, retry or
settle them. A consumer must reject incomplete or inconsistent evidence.

## Offline verification

```sh
python3 -I -B -m unittest discover -s tests -p test_bootstrap_entry.py -v
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
