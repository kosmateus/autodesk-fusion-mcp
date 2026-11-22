"""Trusted local lifecycle CLI/mailbox. No Fusion imports, sockets or SDK calls."""

import argparse
from contextlib import closing
import json
from pathlib import Path
import secrets
import sqlite3
import time

from .physical_authority import (
    authority_directory, private_directory, read_private, write_private,
)
from .request_admission import AdmissionError, GenerationUnchangedError


def query_handoff(database, handoff_id):
    database = Path(database)
    if not database.is_absolute():
        raise AdmissionError("An absolute existing admission database is required")
    with closing(sqlite3.connect(database.resolve().as_uri() + "?mode=ro", uri=True)) as db:
        if db.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name='physical_handoffs'",
        ).fetchone() is None:
            return None
        row = db.execute(
            "SELECT result FROM physical_handoffs WHERE id=?", (handoff_id,),
        ).fetchone()
        return json.loads(row[0]) if row else None


class LifecycleMailbox:
    def __init__(self, authority, handoff, *, retry=None):
        self.authority = authority
        self.handoff = handoff
        self.retry = retry
        self.directory = private_directory(authority.directory / "mailbox")

    def poll(self):
        """Called only from the runtime's main-thread custom event."""
        for path in sorted(self.directory.glob("*.request.json")):
            result_path = path.with_name(path.name.replace(".request.", ".result."))
            if result_path.exists():
                continue
            operation = None
            handoff_started = False
            try:
                envelope = read_private(path)
                operation = envelope["operation"]
                request = envelope["request"]
                if operation == "grant":
                    output = Path(envelope["output"])
                    grant = self.authority.publish_grant(request, output)
                    result = dict(state="granted", handoffId=grant["handoffId"])
                elif operation == "handoff":
                    if (set(request) != {"handoffId", "generation", "nextGeneration"}
                            or not isinstance(request["handoffId"], str) or not request["handoffId"]
                            or request["generation"] != self.authority._pins["generation"]
                            or set(request["nextGeneration"]) != {"instance", "epoch"}):
                        raise AdmissionError("Exact handoff generation pins required")
                    handoff_started = True
                    completed = self.handoff(
                        instance=request["nextGeneration"]["instance"],
                        epoch=request["nextGeneration"]["epoch"],
                        handoff_id=request["handoffId"],
                    )
                    if not completed:
                        if self.retry is not None:
                            self.retry(self.poll)
                        return False
                    result = dict(state="completed", **request)
                else:
                    raise AdmissionError("Unsupported private lifecycle operation")
            except Exception as exc:
                # No descriptor, token, path or request data in failure output.
                if handoff_started and not isinstance(exc, GenerationUnchangedError):
                    result = dict(state="unknown", handoffId=request["handoffId"],
                                  retirement="unconfirmed", queryRequired=True)
                else:
                    result = dict(state="rejected", error="Private lifecycle request rejected")
                if operation == "handoff" and self.retry is not None:
                    self.retry(self.poll)
            write_private(result_path, result)
            path.unlink()
            if operation == "handoff" and result["state"] == "completed":
                return True
        return False


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="operation", required=True)
    for operation in ("grant", "handoff"):
        sub = commands.add_parser(operation)
        sub.add_argument("--request", required=True)
        if operation == "grant":
            sub.add_argument("--output", required=True)
        sub.add_argument("--timeout", type=float, default=30)
    query = commands.add_parser("query")
    query.add_argument("--database", required=True)
    query.add_argument("--handoff-id", required=True)
    args = parser.parse_args(argv)
    if args.operation == "query":
        result = query_handoff(args.database, args.handoff_id)
        print(json.dumps(result if result is not None else dict(state="not_found")))
        return 0 if result is not None else 2
    request = read_private(Path(args.request))
    envelope = dict(operation=args.operation, request=request)
    if args.operation == "grant":
        output = Path(args.output)
        if not output.is_absolute():
            parser.error("--output must be absolute")
        envelope["output"] = str(output)
    directory = private_directory(authority_directory() / "mailbox")
    request_id = secrets.token_hex(16)
    path = directory / (request_id + ".request.json")
    result_path = directory / (request_id + ".result.json")
    write_private(path, envelope)
    deadline = time.monotonic() + args.timeout
    while time.monotonic() < deadline:
        if result_path.exists():
            result = read_private(result_path)
            print(json.dumps(result))
            return (0 if result["state"] in ("granted", "completed")
                    else 3 if result["state"] == "unknown" else 1)
        time.sleep(0.05)
    print(json.dumps(dict(state="pending", message="Query the same handoff ID; do not replay CAS")))
    return 3


if __name__ == "__main__":
    raise SystemExit(main())
