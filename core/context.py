from dataclasses import dataclass, field
from typing import List, Dict, Any
from datetime import datetime
from urllib.parse import urlparse

@dataclass
class TargetInfo:
    base_url: str = ""
    host: str = ""
    scheme: str = ""
    def __post_init__(self):
        if self.base_url:
            parsed = urlparse(self.base_url)
            if not self.host: self.host = parsed.hostname or "unknown_host"
            if not self.scheme: self.scheme = parsed.scheme or "http"

@dataclass
class DiscoveryInfo:
    endpoints: List[str] = field(default_factory=list)
    parameters: List[str] = field(default_factory=list)

@dataclass
class FingerprintInfo:
    server: str = "Unknown"
    framework: str = "Unknown"

@dataclass
class BaselineInfo:
    status_code: int = 0
    headers: Dict[str, str] = field(default_factory=dict)

@dataclass
class Evidence:
    attempt_id: str
    module_id: str
    module_version: str
    location: str
    parameter: str
    outcome: str
    reason_code: str
    reason_detail: str
    confidence: float
    evidence_text: str
    assess_payload: str = ""
    baseline_reference: str = ""

@dataclass
class Finding:
    module_id: str
    location: str
    parameter: str
    vulnerability: str
    verification: str
    impact: str = "UNCLASSIFIED"
    privilege: str = "UNKNOWN"
    confidence: float = 0.0
    evidence: str = ""
    assess_payload: str = ""
    verify_payload: str = ""
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())

@dataclass
class AssessmentResults:
    evidence_pool: List[Evidence] = field(default_factory=list)
    validated: List[Finding] = field(default_factory=list)
    rejected: List[Evidence] = field(default_factory=list)
    inconclusive: List[Evidence] = field(default_factory=list)
    skipped: List[Evidence] = field(default_factory=list)

@dataclass
class TargetContext:
    target: TargetInfo = field(default_factory=TargetInfo)
    discovery: DiscoveryInfo = field(default_factory=DiscoveryInfo)
    fingerprint: FingerprintInfo = field(default_factory=FingerprintInfo)
    baseline: BaselineInfo = field(default_factory=BaselineInfo)
    results: AssessmentResults = field(default_factory=AssessmentResults)
    http_client: Any = None
