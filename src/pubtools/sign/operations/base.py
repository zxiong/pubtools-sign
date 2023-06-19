from __future__ import annotations

from abc import ABC

from dataclasses import dataclass
from typing import ClassVar, Dict, Any

from ..results.operation_result import OperationResult


@dataclass
class SignOperation(ABC):
    """SignOperation Abstract class."""

    ResultType: ClassVar[OperationResult]

    @classmethod
    def doc_arguments(cls: SignOperation) -> Dict[str, Any]:
        """Return dictionary with arguments description of the operation."""
        doc_arguments = {}
        for fn, fv in cls.__dataclass_fields__.items():
            if fv.metadata.get("description"):
                doc_arguments[fn] = fv.metadata.get("description")
        return doc_arguments
