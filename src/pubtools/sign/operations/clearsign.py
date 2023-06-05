from __future__ import annotations

from dataclasses import field, dataclass

from typing import List, ClassVar

from ..results.operation_result import OperationResult

from .base import SignOperation


@dataclass
class ClearSignOperation(SignOperation):
    """ClearsSignOperation model class."""

    ResultType: ClassVar[OperationResult]
    inputs: List[str] = field(
        metadata={"description": "Signing key short id which should be used for signing"}
    )
    signing_key: str = field(
        metadata={"description": "Signing key short id which should be used for signing"}
    )
    task_id: str = field(
        metadata={"description": "Usually pub task id, serves as identifier for in signing request"}
    )
