from dataclasses import dataclass
from collections.abc import Mapping
from typing import Optional, Any


class CaseInsensitiveHeaders(Mapping):
    """Read-only HTTP headers with case-insensitive lookup."""

    def __init__(self, headers=None):
        self._headers = {}

        for key, value in (headers or {}).items():
            normalized = str(key).lower()
            self._headers[normalized] = str(value)

    def __getitem__(self, key):
        return self._headers[str(key).lower()]

    def __iter__(self):
        return iter(self._headers)

    def __len__(self):
        return len(self._headers)

    def get(self, key, default=None):
        return self._headers.get(str(key).lower(), default)


class NormalizedResponse:
    """Transport-independent representation of an HTTP response."""

    __slots__ = (
        "status_code",
        "text",
        "content",
        "headers",
        "url",
    )

    def __init__(self, raw_response):
        self.status_code = int(raw_response.status_code)
        self.text = str(raw_response.text)
        self.content = bytes(raw_response.content)
        self.headers = CaseInsensitiveHeaders(
            raw_response.headers
        )
        self.url = str(raw_response.url)


@dataclass
class RequestResult:
    response: Optional[NormalizedResponse] = None
    error: Optional[Exception] = None
    attempts: int = 0
    elapsed: float = 0.0
    retry_reason: Optional[str] = None

    @property
    def success(self) -> bool:
        return self.response is not None and self.error is None
