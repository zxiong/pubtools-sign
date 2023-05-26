from __future__ import annotations

import dataclasses

from typing import ForwardRef

from pubtools.sign.operations.base import SignOperation
from pubtools.sign.results import SignerResults
from pubtools.sign.results.sign_results import SignResults


Signer = ForwardRef("Signer")


@dataclasses.dataclass
class SigningResults:
    """SigningResults model."""

    signer: Signer
    operation: SignOperation
    signer_results: SignerResults
    sign_results: SignResults
