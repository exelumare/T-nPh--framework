from dataclasses import dataclass, field
from enum import Enum
from typing import Optional, Tuple
from datetime import datetime
import hashlib
import re
import time
import requests

class Outcome(Enum):
    NOT_ATTEMPTED = "NOT_ATTEMPTED"
    TRANSPORT_FAILED = "TRANSPORT_FAILED"
    SERVER_REJECTED = "SERVER_REJECTED"
    NO_EFFECT = "NO_EFFECT"
    CHANGED_RESPONSE = "CHANGED_RESPONSE"
    NOT_COMPARABLE = "NOT_COMPARABLE"

class ReasonCode(Enum):
    TRANSPORT_ERROR = "TRANSPORT_ERROR"
    STATUS_REJECTED = "STATUS_REJECTED"
    BASELINE_UNAVAILABLE = "BASELINE_UNAVAILABLE"
    STATUS_CHANGED = "STATUS_CHANGED"
    HEADERS_CHANGED = "HEADERS_CHANGED"
    BODY_CHANGED = "BODY_CHANGED"
    FINGERPRINT_MATCH = "FINGERPRINT_MATCH"

@dataclass(frozen=True)
class ResponseFingerprint:
    status_code: int
    headers_hash: str
    normalized_exact_hash: str
    body_length: int
    
    def matches(self, other: 'ResponseFingerprint') -> bool:
        return (self.status_code == other.status_code and
                self.headers_hash == other.headers_hash and
                self.normalized_exact_hash == other.normalized_exact_hash)
    
    @classmethod
    def from_response(cls, response: requests.Response):
        # Tambahin 'etag' dan 'last-modified' biar nggak bikin false positive
        ignore_headers = {"date", "set-cookie", "content-length", "connection", "etag", "last-modified"}
        norm_headers = {k.lower(): v for k, v in response.headers.items() if k.lower() not in ignore_headers}
        headers_hash = hashlib.md5(str(sorted(norm_headers.items())).encode()).hexdigest()
        
        body = response.text or ""
        body = re.sub(r'<script\b.*?</script>', ' ', body, flags=re.DOTALL | re.I)
        body = re.sub(r'<style\b.*?</style>',  ' ', body, flags=re.DOTALL | re.I)
        body = re.sub(r'\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b', ' ', body, flags=re.I) 
        body = re.sub(r'\b\d{10,13}\b', ' ', body)
        body = re.sub(r'<script\b.*?</script>', ' ', body, flags=re.DOTALL | re.I)
        body = re.sub(r'<style\b.*?</style>',  ' ', body, flags=re.DOTALL | re.I)
        body = re.sub(r'\b[a-f0-9]{32}\b', ' ', body) # <--- FIX: Buat nangkep user_token DVWA
        norm_body = re.sub(r'\s+', ' ', body).strip()
        
        return cls(
            status_code=response.status_code,
            headers_hash=headers_hash,
            normalized_exact_hash=hashlib.md5(norm_body.encode()).hexdigest(),
            body_length=len(norm_body)
        )

@dataclass
class MutationAttempt:
    id: str = field(default_factory=lambda: hashlib.md5(str(time.time_ns()).encode()).hexdigest()[:8])
    strategy: str = ""
    parameter: str = ""
    method: str = ""
    outcome: Outcome = Outcome.NOT_ATTEMPTED
    response_status: int = 0
    elapsed: float = 0.0
    reason_code: ReasonCode = ReasonCode.TRANSPORT_ERROR
    reason_detail: str = ""
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())

@dataclass
class ExperimentContext:
    method: str
    base_url: str 
    parameter: Optional[str] = None
    baseline_fingerprint: Optional[ResponseFingerprint] = None
    is_baseline_stable: bool = False

class BaselineCollector:
    def __init__(self, http_client):
        self.http_client = http_client

    def collect(self, context: ExperimentContext, samples: int = 3, scope_checker=None, target_param=None) -> ExperimentContext:
        if samples < 1: raise ValueError("samples must be >= 1")
        fingerprints = []
        for _ in range(samples):
            result = self.http_client.request(context.method, context.base_url, target_param=target_param, scope_checker=scope_checker)
            if result.success and result.response:
                fingerprints.append(ResponseFingerprint.from_response(result.response))
            else:
                context.is_baseline_stable = False
                return context
        if not fingerprints:
            context.is_baseline_stable = False
            return context

        first_fp = fingerprints[0]
        context.is_baseline_stable = all(first_fp.matches(fp) for fp in fingerprints)
        if context.is_baseline_stable:
            context.baseline_fingerprint = first_fp
        return context

class BaselineComparator:
    def __init__(self, context: ExperimentContext):
        self.context = context

    def classify(self, mutated_response: Optional[requests.Response], error: Optional[Exception] = None) -> Tuple[Outcome, ReasonCode, str]:
        if error or not mutated_response:
            return Outcome.TRANSPORT_FAILED, ReasonCode.TRANSPORT_ERROR, str(error) if error else "No response"
            
        if mutated_response.status_code in (403, 406, 429):
            return Outcome.SERVER_REJECTED, ReasonCode.STATUS_REJECTED, f"Status_{mutated_response.status_code}"
            
        if not self.context.is_baseline_stable or not self.context.baseline_fingerprint:
            return Outcome.NOT_COMPARABLE, ReasonCode.BASELINE_UNAVAILABLE, "baseline_unstable_or_unavailable"
            
        mutated_fp = ResponseFingerprint.from_response(mutated_response)
        base = self.context.baseline_fingerprint
        
        if mutated_fp.status_code != base.status_code:
            return Outcome.CHANGED_RESPONSE, ReasonCode.STATUS_CHANGED, f"{base.status_code}->{mutated_fp.status_code}"
        if mutated_fp.headers_hash != base.headers_hash:
            return Outcome.CHANGED_RESPONSE, ReasonCode.HEADERS_CHANGED, "headers_diff"
        if mutated_fp.normalized_exact_hash != base.normalized_exact_hash:
            return Outcome.CHANGED_RESPONSE, ReasonCode.BODY_CHANGED, f"len_{base.body_length}->{mutated_fp.body_length}"
            
        return Outcome.NO_EFFECT, ReasonCode.FINGERPRINT_MATCH, "exact_match"
