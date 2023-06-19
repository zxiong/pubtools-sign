from typing import List
from typing_extensions import Self

from .operation_result import OperationResult


import dataclasses


@dataclasses.dataclass()
class ClearSignResult(OperationResult):
    """ClearOperationResult model."""

    outputs: List[str]
    signing_key: str

    def to_dict(self: Self):
        """Return dict representation of ClearOperationResult."""
        return {"outputs": self.outputs, "signing_key": self.signing_key}
