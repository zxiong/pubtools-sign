from __future__ import annotations

from abc import ABC, abstractmethod
import dataclasses


@dataclasses.dataclass()
class SignResults(ABC):
    """SignResults abstract class."""

    @abstractmethod
    def to_dict(self: SignResults):
        """Return dict representation of SignResults."""
        ...  # pragma: no cover
