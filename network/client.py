import time
import random
import requests
import traceback
from urllib.parse import urljoin, urlparse
from email.utils import parsedate_to_datetime
from datetime import datetime, timezone
from typing import Dict, Optional, Callable
from network.config import HTTPConfig, EvasionLevel
from network.result import RequestResult
from network.mutation import RequestMutator
from network.exceptions import ScopeViolationError, RedirectLimitExceeded, NonComparableResponseError

class HTTPClient:
    def __init__(self, config: HTTPConfig):
        self.config = config
        self.session = requests.Session()
        self._rng = random.Random(self.config.random_seed)
        self.mutator = RequestMutator(level=self.config.evasion_level, rng=self._rng)
        
        if self.config.proxy:
            self.session.proxies = {"http": self.config.proxy, "https": self.config.proxy}
        # Di dalam __init__ HTTPClient:
        self.session.verify = self.config.verify_tls
        self.session.headers.update({
            "User-Agent": self.config.user_agent,
            "Connection": "close" # <--- FIX: Matikan Keep-Alive biar gak error sama Mock Server
        })

        if self.config.cookie:
            self.session.headers.update({"Cookie": self.config.cookie})

    def __enter__(self): return self
    def __exit__(self, exc_type, exc_val, exc_tb): self.close()
    def close(self): self.session.close()

    def _parse_retry_after(self, headers: Dict[str, str], default: int = 5, max_wait: int = 60) -> int:
        val = headers.get("Retry-After")
        if not val: return default
        try: wait_time = int(val)
        except ValueError:
            try:
                dt = parsedate_to_datetime(val)
                now = datetime.now(timezone.utc)
                wait_time = max(0, (dt - now).total_seconds())
            except Exception: return default
        return min(wait_time, max_wait)

    def _check_redirect_scope(self, current_url: str, next_url: str, scope_checker: Optional[Callable]) -> bool:
        if scope_checker:
            return scope_checker(next_url)
        curr_host = (urlparse(current_url).hostname or "").lower()
        next_host = (urlparse(next_url).hostname or "").lower()
        norm = lambda h: h[4:] if h.startswith("www.") else h
        return norm(curr_host) == norm(next_host)

    def request(self, method: str, url: str, target_param: str = None, scope_checker: Optional[Callable[[str], bool]] = None, **kwargs) -> RequestResult:
        result = RequestResult()
        start_time = time.perf_counter()
        
        timeout_val = kwargs.pop("timeout", 10)
        kwargs.pop("allow_redirects", None)
        bypass_mutation = kwargs.pop("bypass_mutation", False)
        
        headers = dict(kwargs.get("headers", {}))
        headers.setdefault("User-Agent", self.config.user_agent)
        
        if not bypass_mutation:
            kwargs["headers"] = self.mutator.mutate_headers(headers)
            url = self.mutator.mutate_url_parameters(url, target_param)
        else:
            kwargs["headers"] = headers

        if self.config.delay > 0: time.sleep(self.config.delay)
        last_error = None
        
        for attempt in range(1, self.config.max_attempts + 1):
            result.attempts = attempt
            try:
                current_url = url
                max_redirects = 5
                hops = 0
                
                while True:
                    response = self.session.request(method, current_url, timeout=timeout_val, allow_redirects=False, **kwargs)
                    
                    if response.status_code in (300, 304):
                        raise NonComparableResponseError(response.status_code)

                    if response.is_redirect and hops < max_redirects:
                        loc = response.headers.get("Location", "")
                        next_url = urljoin(current_url, loc)
                        
                        if not self._check_redirect_scope(current_url, next_url, scope_checker):
                            raise ScopeViolationError(f"Redirect out of scope: {next_url}")
                            
                        current_url = next_url
                        hops += 1
                        continue
                        
                    elif response.is_redirect and hops >= max_redirects:
                        raise RedirectLimitExceeded(f"Max redirects ({max_redirects}) exceeded")
                        
                    break

                if response.status_code == 429:
                    wait = self._parse_retry_after(response.headers)
                    result.retry_reason = "http_429"
                    time.sleep(wait)
                    continue
                    
                if response.status_code in (502, 503, 504):
                    result.retry_reason = f"http_{response.status_code}"
                    backoff = (2 ** attempt) + self._rng.uniform(0, 1)
                    time.sleep(backoff)
                    continue
                
                result.response = response
                result.elapsed = time.perf_counter() - start_time
                result.retry_reason = None
                return result
                
            except ScopeViolationError as e:
                last_error = e
                result.retry_reason = "SCOPE_VIOLATION"
                break
            except RedirectLimitExceeded as e:
                last_error = e
                result.retry_reason = "REDIRECT_LIMIT_EXCEEDED"
                break
            except NonComparableResponseError as e:
                last_error = e
                result.retry_reason = f"HTTP_{e.status_code}_NON_COMPARABLE"
                break
            except requests.exceptions.RequestException as e:
                last_error = e
                result.retry_reason = type(e).__name__
                if attempt < self.config.max_attempts: time.sleep(2 * attempt)
            except Exception as e:
                last_error = e
                result.retry_reason = f"UNEXPECTED_{type(e).__name__}"
                traceback.print_exc() 
                break

        result.error = last_error
        result.elapsed = time.perf_counter() - start_time
        if not result.error and not result.response:
            result.retry_reason = result.retry_reason or "exhausted_retries"
        return result
