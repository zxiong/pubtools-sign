from typing import List
from typing_extensions import Self

from .sign_results import SignResults


import dataclasses


@dataclasses.dataclass()
class ClearSignResult(SignResults):
    """ClearSignResults model."""

    outputs: List[str]
    signing_key: str

    def to_dict(self: Self):
        """Return dict representation of ClearSignResult."""
        return {"outputs": self.outputs, "signing_key": self.signing_key}
