"""Verification Result & Status for TànPhá V25.9."""
from dataclasses import dataclass
from enum import Enum
from typing import Optional


class VerificationStatus(Enum):
    """
    F-12: INCONCLUSIVE added for AI-derived findings that
    couldn't be independently confirmed.
    """
    VALIDATED = "VALIDATED"
    REJECTED = "REJECTED"
    INCONCLUSIVE = "INCONCLUSIVE"


@dataclass
class VerificationResult:
    status: VerificationStatus
    confidence: float
    reason_code: str
    reason_detail: str
    verify_payload: str = ""

    @property
    def is_validated(self) -> bool:
        return self.status == VerificationStatus.VALIDATED

    @property
    def is_rejected(self) -> bool:
        return self.status == VerificationStatus.REJECTED

    @property
    def is_inconclusive(self) -> bool:
        return self.status == VerificationStatus.INCONCLUSIVE
