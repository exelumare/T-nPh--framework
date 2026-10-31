from dataclasses import dataclass
from enum import Enum

class VerificationStatus(Enum):
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
