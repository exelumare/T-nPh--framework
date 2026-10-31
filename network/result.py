from dataclasses import dataclass
from typing import Optional
import requests

@dataclass
class RequestResult:
    response: Optional[requests.Response] = None
    error: Optional[Exception] = None
    attempts: int = 0
    elapsed: float = 0.0
    retry_reason: Optional[str] = None

    @property
    def success(self) -> bool:
        return self.response is not None and self.error is None
