"""Real offline grant fixtures for pre-existing positive dispatch tests."""

import copy
import os
from pathlib import Path
import tempfile
import itertools
from unittest.mock import patch

from lib import physical_authority
from lib.request_admission import AdmissionStore
from fusion_bridge import admission_runtime, dispatch


def descriptor(authority, *, queue="/offline/queue", owner="owner"):
    return dict(
        kind="fmcad-physical-grant", version=1, handoffId="offline-bootstrap",
        brokerOwner=dict(pid=os.getpid(), birth="offline-birth", nonce="offline-nonce",
                         clientId=owner, queueDirectory=str(Path(queue).resolve())),
        **copy.deepcopy(authority._pins),
    )


def authorize_offline_dispatch(test):
    """Give old dispatcher-focused tests a real private fake-runtime grant.

    These tests predate the HTTP ownership layer. Negative ownership coverage
    lives in test_physical_authority and does NOT use this envelope adapter.
    """
    directory = Path(test.enterContext(tempfile.TemporaryDirectory()))
    test.enterContext(patch.object(physical_authority, "authority_directory",
                                  return_value=directory / "physical"))
    store = AdmissionStore(directory / "admission.sqlite", instance="offline", epoch="one")
    test.addCleanup(store.close)
    provision = dict(database=str(directory / "admission.sqlite"), instance="offline",
                     epoch="one", pid=os.getpid(), birth="offline-birth",
                     source="offline", build="offline")
    authority = physical_authority.PhysicalAuthority(
        provision, store, admission_runtime._lease, version="offline",
        endpoint="http://127.0.0.1:0/mcp",
    )
    test.addCleanup(authority.close)
    grant = authority.issue(descriptor(authority))
    capability = authority.authenticate([grant["token"]])
    original = dispatch._execute
    ids = itertools.count()

    def authorized(shutdown, payload, consumer):
        turn = capability.prepare_turn("offline-turn-" + str(next(ids)), "offline-document")
        try:
            return original(shutdown, dict(payload, _physical_capability=capability,
                                           _physical_turn=turn), consumer)
        finally:
            turn.cancel_queued()

    test.enterContext(patch.object(dispatch, "_execute", side_effect=authorized))
