"""The only production capability on the keyed admission endpoint."""

import json
import threading

from ..lib.admission_receiver import AdmissionTargetError
from ..lib.request_admission import AdmissionError
from .dispatch import get_app


def select_operation(payload):
    params = payload.get("params")
    if (payload.get("jsonrpc") != "2.0" or payload.get("method") != "tools/call"
            or not isinstance(params, dict)
            or params.get("name") != "get_open_document_metadata"):
        raise AdmissionError("Unsupported admission capability")
    arguments = params.get("arguments")
    if not isinstance(arguments, dict) or set(arguments) != {"fileId", "version"}:
        raise AdmissionError("An exact file/version selector is required")
    file_id, version = arguments["fileId"], arguments["version"]
    if not isinstance(file_id, str) or not file_id or type(version) is not int or version < 1:
        raise AdmissionError("Invalid file/version selector")

    def resolve():
        if threading.current_thread() is not threading.main_thread():
            raise RuntimeError("Document resolution requires the Fusion main thread")
        matches = []
        for document in get_app().documents:
            if not document.isSaved:
                continue
            data_file = document.dataFile
            if data_file is None:
                continue
            actual_file_id, actual_version = data_file.id, data_file.versionNumber
            if (actual_file_id == file_id and type(actual_version) is int
                    and actual_version == version):
                matches.append((document, actual_file_id, actual_version))
        if len(matches) != 1:
            raise AdmissionTargetError("Expected one open document for this file/version")
        target, actual_file_id, actual_version = matches[0]
        creation_id = target.creationId
        if not isinstance(creation_id, str) or not creation_id:
            raise AdmissionTargetError("Open document has no stable identity")
        identity = dict(creationId=creation_id, fileId=actual_file_id, version=actual_version)
        descriptor = json.dumps(identity, separators=(",", ":"), ensure_ascii=False)

        def execute():
            metadata = dict(identity, name=target.name, isModified=target.isModified)
            return {"content": [{"type": "text", "text": json.dumps(metadata, ensure_ascii=False)}]}

        return descriptor, execute

    return resolve
