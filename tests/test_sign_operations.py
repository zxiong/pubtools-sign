from pubtools.sign.operations import (
    ClearSignOperation,
    ContainerSignOperation,
)


def test_containersign_operation_doc_argument():
    assert ContainerSignOperation.doc_arguments() == {
        "digests": "List of digest to sign",
        "references": "List of references to sign",
        "signing_key": "Signing key short id which should be used for signing",
        "task_id": "Usually pub task id, serves as identifier for in signing request",
    }


def test_clearsign_operation_doc_argument():
    assert ClearSignOperation.doc_arguments() == {
        "inputs": "Signing key short id which should be used for signing",
        "signing_key": "Signing key short id which should be used for signing",
        "task_id": "Usually pub task id, serves as identifier for in signing request",
    }
