import time
import random
import json
import socket
import traceback
import ipaddress
import logging
import os
from urllib.parse import urljoin, urlparse
from email.utils import parsedate_to_datetime
from datetime import datetime, timezone
from typing import Dict, Optional, Callable, Any, Tuple
import urllib3

from curl_cffi import requests
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

from network.config import HTTPConfig, EvasionLevel
from network.result import RequestResult, NormalizedResponse
from network.mutation import RequestMutator
from network.exceptions import ScopeViolationError, RedirectLimitExceeded, NonComparableResponseError
from core.scope import parse_origin

logger = logging.getLogger(__name__)

class HTTPClient:
    ALLOWED_CROSS_ORIGIN_HEADERS = {
        "user-agent", "accept", "accept-language", "accept-encoding", 
        "connection", "host"
    }

    def __init__(self, config: HTTPConfig, lab_checker=None):
        self.config = config
        self._lab_checker = lab_checker
        self.session = requests.Session(impersonate="chrome")
        self._verify_tls = self.config.verify_tls
        self._rng = random.Random(self.config.random_seed)
        self.mutator = RequestMutator(level=self.config.evasion_level, rng=self._rng)
        
        if self.config.proxy:
            self.session.proxies = {"http": self.config.proxy, "https": self.config.proxy}
        
        self.session.headers.update({"User-Agent": self.config.user_agent, "Connection": "close"})
        if self.config.cookie:
            self.session.headers.update({"Cookie": self.config.cookie})

    def __enter__(self): return self
    def __exit__(self, exc_type, exc_val, exc_tb): self.close()
    def close(self): self.session.close()

    def _is_aggressive_authorized(self, url: str) -> bool:
        if os.environ.get("TANPHA_LAB_MODE") != "1":
            return False
        if not self._lab_checker:
            return False
        try:
            return self._lab_checker(url)
        except Exception:
            return False

    def _is_ip_safe(self, ip_str: str) -> bool:
        try:
            ip = ipaddress.ip_address(ip_str)
            if ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_unspecified: return False
            if not ip.is_global: return False
            return True
        except ValueError:
            return False

    def _check_dns_rebinding(self, url: str, auth_checker: Callable[[str], bool] = None) -> Tuple[bool, str]:
        try:
            parsed = urlparse(url)
            host = parsed.hostname
            if not host: return False, "INVALID_HOST"
            try:
                ipaddress.ip_address(host)
                if host in ("127.0.0.1", "::1", "localhost"): return True, ""
                if not self._is_ip_safe(host):
                    if auth_checker:
                        try:
                            if auth_checker(url): return True, ""
                        except Exception: return False, "AUTH_CHECKER_ERROR"
                    return False, "DNS_REBINDING_DETECTED"
                return True, ""
            except ValueError: pass
            addr_info = socket.getaddrinfo(host, None)
            if not addr_info: return False, "DNS_EMPTY"
            for res in addr_info:
                ip_str = res[4][0]
                if host in ("localhost", "127.0.0.1", "::1"): continue
                if not self._is_ip_safe(ip_str):
                    if auth_checker:
                        try:
                            if auth_checker(url): continue
                        except Exception: return False, "AUTH_CHECKER_ERROR"
                    return False, "DNS_REBINDING_DETECTED"
            return True, ""
        except Exception:
            return False, "DNS_RESOLUTION_FAILED"

    def resolve_dns(self, hostname: str, parent_url: str, auth_checker: Callable[[str], bool] = None) -> list:
        if not auth_checker:
            return []

        parent = parse_origin(parent_url)
        if not parent:
            return []

        scheme, _, port = parent
        test_url = f"{scheme}://{hostname}:{port}"

        try:
            if not auth_checker(test_url):
                return []
        except Exception:
            return []

        try:
            return [
                res[4][0]
                for res in socket.getaddrinfo(hostname, None)
            ]
        except Exception:
            return []

    def request(self, method: str, url: str, target_param: str = None, auth_checker: Optional[Callable[[str], bool]] = None, **kwargs) -> RequestResult:
        result = RequestResult()
        start_time = time.perf_counter()

        if not auth_checker:
            result.error = ScopeViolationError("Missing auth_checker. Fail-closed.")
            result.retry_reason = "MISSING_AUTH_CHECKER"
            result.elapsed = time.perf_counter() - start_time
            return result

        if not parse_origin(url):
            result.error = ScopeViolationError(f"Invalid URL format: {url}")
            result.retry_reason = "INVALID_URL"
            result.elapsed = time.perf_counter() - start_time
            return result

        effective_evasion = self.config.evasion_level
        if effective_evasion == EvasionLevel.AGGRESSIVE:
            if not self._is_aggressive_authorized(url):
                print(f"          [!] Aggressive DOWNGRADED to STANDARD (not authorized)")
                effective_evasion = EvasionLevel.STANDARD

        timeout_val = kwargs.pop("timeout", 10)
        kwargs.pop("allow_redirects", None)
        bypass_mutation = kwargs.pop("bypass_mutation", False)
        
        headers = dict(kwargs.get("headers") or {})
        headers.setdefault("User-Agent", self.config.user_agent)
        
        original_data = kwargs.get("data")
        original_json = kwargs.get("json")

        if self.config.delay > 0: time.sleep(self.config.delay)
        last_error = None

        original_mutator_level = self.mutator.level
        try:
            for attempt in range(1, self.config.max_attempts + 1):
                result.attempts = attempt
                self.mutator.level = effective_evasion

                if not bypass_mutation:
                    current_url = self.mutator.mutate_url_parameters(url, target_param)
                    current_headers = self.mutator.mutate_headers(headers)
                    current_data = original_data
                    current_json = original_json
                    
                    if method.upper() in ("POST", "PUT", "PATCH"):
                        if current_json is not None:
                            str_data = json.dumps(current_json)
                            current_headers, current_data = self.mutator.mutate_body(method, current_headers, str_data)
                            current_json = None
                            current_headers.setdefault("Content-Type", "application/json")
                        elif current_data is not None:
                            if isinstance(current_data, dict):
                                current_headers.setdefault("Content-Type", "application/x-www-form-urlencoded")
                            current_headers, current_data = self.mutator.mutate_body(method, current_headers, current_data)
                else:
                    current_url = url
                    current_headers = headers
                    current_data = original_data
                    current_json = original_json

                if not parse_origin(current_url):
                    result.error = ScopeViolationError(f"Invalid URL after mutation: {current_url}")
                    result.retry_reason = "INVALID_URL"
                    result.elapsed = time.perf_counter() - start_time
                    return result

                is_dns_safe, dns_reason = self._check_dns_rebinding(current_url, auth_checker)
                if not is_dns_safe:
                    result.error = ScopeViolationError(f"DNS check failed: {dns_reason}")
                    result.retry_reason = dns_reason
                    result.elapsed = time.perf_counter() - start_time
                    return result

                try:
                    is_allowed = auth_checker(current_url)
                except Exception as e:
                    result.error = ScopeViolationError(f"Auth checker exception: {e}")
                    result.retry_reason = "AUTH_CHECKER_ERROR"
                    result.elapsed = time.perf_counter() - start_time
                    return result
                
                if not is_allowed:
                    result.error = ScopeViolationError(f"Initial URL out of scope: {current_url}")
                    result.retry_reason = "SCOPE_VIOLATION"
                    result.elapsed = time.perf_counter() - start_time
                    return result

                try:
                    max_redirects = 5
                    hops = 0
                    cur_method = method
                    cur_headers = dict(current_headers)
                    cur_data = current_data
                    cur_json = current_json
                    original_origin = parse_origin(current_url)

                    while True:
                        if "Host" in cur_headers:
                            host_header = cur_headers["Host"]
                            expected_origin = parse_origin(current_url)
                            if expected_origin:
                                host_url = f"{expected_origin[0]}://{host_header}"
                                header_origin = parse_origin(host_url)
                                if not header_origin or header_origin[1] != expected_origin[1] or header_origin[2] != expected_origin[2]:
                                    del cur_headers["Host"]
                        
                        curr_origin = parse_origin(current_url)
                        strip_credentials = (curr_origin != original_origin)

                        if strip_credentials:
                            for k in list(cur_headers.keys()):
                                if k.lower() not in self.ALLOWED_CROSS_ORIGIN_HEADERS:
                                    del cur_headers[k]

                        _req_verify = self._verify_tls
                        try:
                            _host = (urlparse(current_url).hostname or "").lower()
                            if _host in ("127.0.0.1", "::1", "localhost") or _host.startswith("127."):
                                _req_verify = False
                        except Exception:
                            pass

                        req_kwargs = {
                            "method": cur_method,
                            "url": current_url,
                            "headers": cur_headers,
                            "timeout": timeout_val,
                            "allow_redirects": False,
                            "verify": _req_verify
                        }
                        
                        if cur_data is not None:
                            if hasattr(cur_data, '__iter__') and not isinstance(cur_data, (dict, list, tuple, str, bytes)):
                                cur_data = b"".join(cur_data)
                            req_kwargs["data"] = cur_data
                            
                        if cur_json is not None:
                            req_kwargs["json"] = cur_json

                        response = self.session.request(**req_kwargs)

                        if response.status_code in (300, 304):
                            response.close()
                            raise NonComparableResponseError(response.status_code)

                        if response.status_code in (301, 302, 303, 307, 308):
                            if hops >= max_redirects:
                                response.close()
                                raise RedirectLimitExceeded(f"Max redirects exceeded")
                            loc = response.headers.get("Location", "")
                            if not loc:
                                response.close()
                                raise ScopeViolationError(f"Redirect missing Location")
                            try:
                                next_url = urljoin(current_url, loc)
                            except ValueError as e:
                                response.close()
                                result.error = ScopeViolationError(
                                    f"Invalid redirect URL: {e}"
                                )
                                result.retry_reason = "INVALID_URL"
                                result.elapsed = time.perf_counter() - start_time
                                return result
                            
                            if not parse_origin(next_url):
                                response.close()
                                result.error = ScopeViolationError(f"Invalid redirect: {next_url}")
                                result.retry_reason = "INVALID_URL"
                                result.elapsed = time.perf_counter() - start_time
                                return result

                            is_dns_safe, dns_reason = self._check_dns_rebinding(next_url, auth_checker)
                            if not is_dns_safe:
                                response.close()
                                result.error = ScopeViolationError(f"DNS failed on redirect: {dns_reason}")
                                result.retry_reason = dns_reason
                                result.elapsed = time.perf_counter() - start_time
                                return result

                            try:
                                is_allowed_redirect = auth_checker(next_url)
                            except Exception as e:
                                response.close()
                                result.error = ScopeViolationError(f"Redirect auth exception: {e}")
                                result.retry_reason = "AUTH_CHECKER_ERROR"
                                result.elapsed = time.perf_counter() - start_time
                                return result
                                
                            if not is_allowed_redirect:
                                response.close()
                                raise ScopeViolationError(f"Redirect out of scope: {next_url}")

                            next_origin = parse_origin(next_url)
                            if not curr_origin or not next_origin:
                                response.close()
                                raise ScopeViolationError("Invalid URL during redirect")
                            is_cross_origin_hop = (curr_origin != next_origin)

                            if is_cross_origin_hop:
                                if getattr(self.session, 'cert', None) is not None:
                                    response.close()
                                    result.error = ScopeViolationError("Cross-origin blocked (cert set).")
                                    result.retry_reason = "SCOPE_VIOLATION"
                                    result.elapsed = time.perf_counter() - start_time
                                    return result

                            def remove_header_ci(headers_dict, header_name):
                                for k in list(headers_dict.keys()):
                                    if k.lower() == header_name.lower():
                                        del headers_dict[k]

                            if response.status_code == 301:
                                if cur_method.upper() == "POST":
                                    cur_method = "GET"
                                    cur_data = None
                                    cur_json = None
                                    remove_header_ci(cur_headers, "Content-Type")
                                    remove_header_ci(cur_headers, "Content-Length")
                            elif response.status_code == 302:
                                if cur_method.upper() != "HEAD":
                                    cur_method = "GET"
                                    cur_data = None
                                    cur_json = None
                                    remove_header_ci(cur_headers, "Content-Type")
                                    remove_header_ci(cur_headers, "Content-Length")
                            elif response.status_code == 303:
                                if cur_method.upper() != "HEAD":
                                    cur_method = "GET"
                                    cur_data = None
                                    cur_json = None
                                    remove_header_ci(cur_headers, "Content-Type")
                                    remove_header_ci(cur_headers, "Content-Length")
                            elif response.status_code in (307, 308):
                                if is_cross_origin_hop:
                                    cur_data = None
                                    cur_json = None
                                    remove_header_ci(cur_headers, "Content-Type")
                                    remove_header_ci(cur_headers, "Content-Length")

                            response.close()
                            current_url = next_url
                            hops += 1
                            continue
                        break


                    if response.status_code == 429:
                        wait = self._parse_retry_after(response.headers)
                        result.retry_reason = "http_429"

                        if attempt >= self.config.max_attempts:
                            result.response = NormalizedResponse(response)
                            response.close()
                            result.elapsed = time.perf_counter() - start_time
                            return result

                        response.close()
                        time.sleep(wait)
                        continue

                    if response.status_code in (502, 503, 504):
                        result.retry_reason = f"http_{response.status_code}"

                        if attempt >= self.config.max_attempts:
                            result.response = NormalizedResponse(response)
                            response.close()
                            result.elapsed = time.perf_counter() - start_time
                            return result

                        response.close()
                        time.sleep(
                            (2 ** attempt) + self._rng.uniform(0, 1)
                        )
                        continue

                    if response.status_code == 500:
                        result.response = NormalizedResponse(response)
                        response.close()
                        result.elapsed = time.perf_counter() - start_time
                        result.retry_reason = "http_500"
                        return result

                    result.response = NormalizedResponse(response)
                    response.close()
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
            return result
        finally:
            self.mutator.level = original_mutator_level

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
