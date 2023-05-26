from __future__ import annotations
import dataclasses

from typing import List, ClassVar
from typing_extensions import Self

from ..results.sign_results import SignResults


@dataclasses.dataclass
class ContainerSignResult(SignResults):
    """ContainerSignResults model."""

    ResultType: ClassVar[SignResults]
    signed_claims: List[str]
    signing_key: str

    def to_dict(self: Self):
        """Return dict representation of ContainerSignResult."""
        return {"signed_claims": self.signed_claims, "signing_key": self.signing_key}
