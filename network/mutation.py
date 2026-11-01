import random
import urllib.parse
from typing import Any, Dict, Iterator, Tuple, Union
from network.config import EvasionLevel


class RequestMutator:
    BINARY_CONTENT_TYPES = (
        "multipart/form-data",
        "application/octet-stream",
        "image/",
        "audio/",
        "video/",
    )

    def __init__(self, level: EvasionLevel, rng: random.Random, allow_ct_confusion: bool = False):
        self.level = level
        self.rng = rng
        self.allow_ct_confusion = allow_ct_confusion

    def mutate_headers(self, headers: Dict[str, str]) -> Dict[str, str]:
        mutated = dict(headers)
        if self.level in (EvasionLevel.STANDARD, EvasionLevel.AGGRESSIVE):
            mutated.update({"X-Forwarded-For": "127.0.0.1", "X-Originating-IP": "127.0.0.1"})
        return mutated

    def mutate_url_parameters(self, url: str, target_param: str = None) -> str:
        if self.level == EvasionLevel.NONE: return url
        parsed = urllib.parse.urlparse(url)
        if not parsed.query: return url
        qs = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
        mutated_qs = []
        for k, v in qs:
            if target_param is None or k == target_param:
                if self.level in (EvasionLevel.STANDARD, EvasionLevel.AGGRESSIVE):
                    v = v.replace(" ", "/**/")
                    for w in ["SELECT", "UNION", "AND", "OR"]:
                        if w in v.upper():
                            mix = ''.join(c.upper() if self.rng.choice([True, False]) else c.lower() for c in w)
                            v = v.replace(w, mix).replace(w.lower(), mix)
                if self.level == EvasionLevel.AGGRESSIVE:
                    v = urllib.parse.quote(urllib.parse.quote(v))
            mutated_qs.append((k, v))
        new_query = urllib.parse.urlencode(mutated_qs, safe="")
        return urllib.parse.urlunparse(parsed._replace(query=new_query))

    def mutate_body(self, method, headers, data):
        if self.level != EvasionLevel.AGGRESSIVE:
            return headers, data
        if method.upper() not in ("POST", "PUT", "PATCH"):
            return headers, data
        if data is None:
            return headers, data
        ct = (headers.get("Content-Type") or "").lower()
        if any(binary in ct for binary in self.BINARY_CONTENT_TYPES):
            return headers, data
        new_headers = dict(headers)
        new_data = self._to_chunked(data)
        new_headers.pop("Content-Length", None)
        new_headers.pop("content-length", None)
        if self.allow_ct_confusion:
            new_headers = self._apply_ct_confusion(new_headers)
        return new_headers, new_data

    def _to_chunked(self, data):
        if isinstance(data, dict):
            encoded = urllib.parse.urlencode(data, doseq=True).encode()
        elif isinstance(data, str):
            encoded = data.encode()
        elif isinstance(data, (bytes, bytearray)):
            encoded = bytes(data)
        else:
            yield str(data).encode()
            return
        chunk_size = self.rng.randint(4, 16)
        for i in range(0, len(encoded), chunk_size):
            yield encoded[i:i + chunk_size]

    def _apply_ct_confusion(self, headers):
        original = headers.get("Content-Type", "application/x-www-form-urlencoded")
        if "charset=" in original.lower():
            return headers
        suffixes = [
            "; charset=utf-16le",
            "; charset=utf-16be",
            "; charset=iso-8859-1",
            "; charset=windows-1252",
        ]
        headers["Content-Type"] = original + self.rng.choice(suffixes)
        return headers
